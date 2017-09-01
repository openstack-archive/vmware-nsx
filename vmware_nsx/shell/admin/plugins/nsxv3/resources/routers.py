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

import sys

from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
from vmware_nsx.shell import resources as shell
from vmware_nsxlib.v3 import exceptions as nsx_exc

from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron_lib.callbacks import registry
from neutron_lib import context as neutron_context
from oslo_log import log as logging

LOG = logging.getLogger(__name__)
neutron_client = utils.NeutronDbClient()


class RoutersPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                    l3_db.L3_NAT_db_mixin):
    pass


@admin_utils.output_header
def list_missing_routers(resource, event, trigger, **kwargs):
    """List neutron routers that are missing the NSX backend router
    """
    nsxlib = utils.get_connected_nsxlib()
    plugin = RoutersPlugin()
    admin_cxt = neutron_context.get_admin_context()
    neutron_routers = plugin.get_routers(admin_cxt)
    routers = []
    for router in neutron_routers:
        neutron_id = router['id']
        # get the router nsx id from the mapping table
        nsx_id = nsx_db.get_nsx_router_id(admin_cxt.session,
                                          neutron_id)
        if not nsx_id:
            routers.append({'name': router['name'],
                            'neutron_id': neutron_id,
                            'nsx_id': None})
        else:
            try:
                nsxlib.logical_router.get(nsx_id)
            except nsx_exc.ResourceNotFound:
                routers.append({'name': router['name'],
                              'neutron_id': neutron_id,
                              'nsx_id': nsx_id})
    if len(routers) > 0:
        title = ("Found %d routers missing from the NSX "
                 "manager:") % len(routers)
        LOG.info(formatters.output_formatter(
            title, routers,
            ['name', 'neutron_id', 'nsx_id']))
    else:
        LOG.info("All routers exist on the NSX manager")


@admin_utils.output_header
def update_nat_rules(resource, event, trigger, **kwargs):
    """Update all routers NAT rules to not bypass the firewall"""
    # This feature is supported only since nsx version 2
    nsxlib = utils.get_connected_nsxlib()
    version = nsxlib.get_version()
    if not nsx_utils.is_nsx_version_2_0_0(version):
        LOG.info("NAT rules update only supported from 2.0 onwards")
        LOG.info("Version is %s", version)
        return

    # Go over all neutron routers
    plugin = RoutersPlugin()
    admin_cxt = neutron_context.get_admin_context()
    neutron_routers = plugin.get_routers(admin_cxt)
    num_of_updates = 0
    for router in neutron_routers:
        neutron_id = router['id']
        # get the router nsx id from the mapping table
        nsx_id = nsx_db.get_nsx_router_id(admin_cxt.session,
                                          neutron_id)
        if nsx_id:
            # get all NAT rules:
            rules = nsxlib.logical_router.list_nat_rules(nsx_id)['results']
            for rule in rules:
                if 'nat_pass' not in rule or rule['nat_pass']:
                    nsxlib.logical_router.update_nat_rule(
                        nsx_id, rule['id'], nat_pass=False)
                    num_of_updates = num_of_updates + 1
    if num_of_updates:
        LOG.info("Done updating %s NAT rules", num_of_updates)
    else:
        LOG.info("Did not find any NAT rule to update")


@admin_utils.output_header
def list_orphaned_routers(resource, event, trigger, **kwargs):
    nsxlib = utils.get_connected_nsxlib()
    nsx_routers = nsxlib.logical_router.list()['results']
    missing_routers = []
    for nsx_router in nsx_routers:
        # check if it exists in the neutron DB
        if not neutron_client.lrouter_id_to_router_id(nsx_router['id']):
            # Skip non-neutron routers, by tags
            for tag in nsx_router.get('tags', []):
                if tag.get('scope') == 'os-neutron-router-id':
                    missing_routers.append(nsx_router)
                    break

    LOG.info(formatters.output_formatter(constants.ORPHANED_ROUTERS,
                                         missing_routers,
                                         ['id', 'display_name']))


@admin_utils.output_header
def delete_backend_router(resource, event, trigger, **kwargs):
    nsxlib = utils.get_connected_nsxlib()
    errmsg = ("Need to specify nsx-id property. Add --property nsx-id=<id>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    nsx_id = properties.get('nsx-id')
    if not nsx_id:
        LOG.error("%s", errmsg)
        return

    # check if the router exists
    try:
        nsxlib.logical_router.get(nsx_id, silent=True)
    except nsx_exc.ResourceNotFound:
        # prevent logger from logging this exception
        sys.exc_clear()
        LOG.warning("Backend router %s was not found.", nsx_id)
        return

    # try to delete it
    try:
        # first delete its ports
        ports = nsxlib.logical_router_port.get_by_router_id(nsx_id)
        for port in ports:
            nsxlib.logical_router_port.delete(port['id'])
        nsxlib.logical_router.delete(nsx_id)
    except Exception as e:
        LOG.error("Failed to delete backend router %(id)s : %(e)s.", {
            'id': nsx_id, 'e': e})
        return

    # Verify that the router was deleted since the backend does not always
    # throws errors
    try:
        nsxlib.logical_router.get(nsx_id, silent=True)
    except nsx_exc.ResourceNotFound:
        # prevent logger from logging this exception
        sys.exc_clear()
        LOG.info("Backend router %s was deleted.", nsx_id)
    else:
        LOG.error("Failed to delete backend router %s.", nsx_id)


registry.subscribe(list_missing_routers,
                   constants.ROUTERS,
                   shell.Operations.LIST_MISMATCHES.value)

registry.subscribe(update_nat_rules,
                   constants.ROUTERS,
                   shell.Operations.NSX_UPDATE_RULES.value)

registry.subscribe(list_orphaned_routers,
                   constants.ORPHANED_ROUTERS,
                   shell.Operations.LIST.value)

registry.subscribe(delete_backend_router,
                   constants.ORPHANED_ROUTERS,
                   shell.Operations.NSX_CLEAN.value)
