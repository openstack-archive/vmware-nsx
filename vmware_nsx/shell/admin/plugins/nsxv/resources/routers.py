# Copyright 2016 VMware, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import logging

from vmware_nsx.shell.admin.plugins.common import constants
import vmware_nsx.shell.admin.plugins.common.utils as admin_utils
import vmware_nsx.shell.admin.plugins.nsxv.resources.utils as utils
import vmware_nsx.shell.resources as shell

from neutron.callbacks import registry
from neutron import context as n_context
from oslo_config import cfg

from vmware_nsx._i18n import _LE, _LI, _LW
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.extensions import routersize
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.plugins.nsx_v.vshield import vcns_driver

LOG = logging.getLogger(__name__)


def delete_old_edge(context, old_edge_id):
    LOG.info(_LI("Deleting the old edge: %s"), old_edge_id)

    # clean it up from the DB
    nsxv_db.clean_edge_router_binding(context.session, old_edge_id)
    nsxv_db.clean_edge_vnic_binding(context.session, old_edge_id)
    nsxv_db.cleanup_nsxv_edge_firewallrule_binding(context.session,
                                                   old_edge_id)

    with locking.LockManager.get_lock(old_edge_id):
        # Delete from NSXv backend
        # Note - If we will not delete the edge, but free it - it will be
        # immediately used as the new one, So it is better to delete it.
        try:
            nsxv = utils.get_nsxv_client()
            nsxv.delete_edge(old_edge_id)
        except Exception as e:
            LOG.warning(_LW("Failed to delete the old edge %(id)s: %(e)s"),
                        {'id': old_edge_id, 'e': e})
            # Continue the process anyway
            # The edge may have been already deleted at the backend


@admin_utils.output_header
def nsx_recreate_router_edge(resource, event, trigger, **kwargs):
    """Recreate a router edge with all the data on a new NSXv edge"""
    if not kwargs.get('property'):
        LOG.error(_LE("Need to specify edge-id parameter"))
        return

    # input validation
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    old_edge_id = properties.get('edge-id')
    if not old_edge_id:
        LOG.error(_LE("Need to specify edge-id parameter"))
        return
    LOG.info(_LI("ReCreating NSXv Router Edge: %s"), old_edge_id)

    # init the plugin and edge manager
    cfg.CONF.set_override('core_plugin',
                          'vmware_nsx.shell.admin.plugins.nsxv.resources'
                          '.utils.NsxVPluginWrapper')
    plugin = utils.NsxVPluginWrapper()
    nsxv_manager = vcns_driver.VcnsDriver(edge_utils.NsxVCallbacks(plugin))
    edge_manager = edge_utils.EdgeManager(nsxv_manager, plugin)
    context = n_context.get_admin_context()

    # verify that this is a Router edge
    router_ids = edge_manager.get_routers_on_edge(context, old_edge_id)
    if not router_ids:
        LOG.error(_LE("Edge %(edge_id)s is not a router edge"),
                 {'edge_id': old_edge_id})
        return

    # all the routers on the same edge have the same type, so it
    # is ok to check the type once
    example_router = plugin.get_router(context, router_ids[0])
    router_driver = plugin._router_managers.get_tenant_router_driver(
        context, example_router['router_type'])
    if router_driver.get_type() == "distributed":
        LOG.error(_LE("Recreating a distributed  driver edge is not "
                      "supported"))
        return

    # load all the routers before deleting their binding
    routers = []
    for router_id in router_ids:
        routers.append(plugin.get_router(context, router_id))

    # delete the backend edge and all the relevant DB entries
    delete_old_edge(context, old_edge_id)

    # Go over all the relevant routers
    for router in routers:
        router_id = router['id']
        # clean up other objects related to this router
        if plugin.metadata_proxy_handler:
            plugin.metadata_proxy_handler.cleanup_router_edge(
                context, router_id)

        # attach the router to a new edge
        appliance_size = router.get(routersize.ROUTER_SIZE)
        router_driver.attach_router(context, router_id,
                                    {'router': router},
                                    appliance_size=appliance_size)
        # find out who is the new edge to print it
        new_edge_id = router_driver._get_edge_id_or_raise(context, router_id)
        LOG.info(_LI("Router %(router)s was attached to edge %(edge)s"),
                 {'router': router_id, 'edge': new_edge_id})


registry.subscribe(nsx_recreate_router_edge,
                   constants.ROUTERS,
                   shell.Operations.NSX_RECREATE.value)
