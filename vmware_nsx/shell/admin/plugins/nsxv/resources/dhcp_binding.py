# Copyright 2015 VMware, Inc.  All rights reserved.
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
import pprint

from vmware_nsx.shell.admin.plugins.common import constants
import vmware_nsx.shell.admin.plugins.common.utils as admin_utils
import vmware_nsx.shell.admin.plugins.nsxv.resources.utils as utils

import vmware_nsx.shell.nsxadmin as shell

from neutron.callbacks import registry
from neutron.db import db_base_plugin_v2

from vmware_nsx._i18n import _LE, _LI
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.plugins.nsx_v.vshield import vcns_driver


LOG = logging.getLogger(__name__)
nsxv = utils.get_nsxv_client()
neutron_db = utils.NeutronDbClient()


def nsx_get_static_bindings_by_edge(edge_id):
    nsx_dhcp_static_bindings = set()

    nsx_dhcp_bindings = nsxv.query_dhcp_configuration(edge_id)
    # nsx_dhcp_bindings[0] contains response headers;
    # nsx_dhcp_bindings[1] contains response payload
    sbindings = nsx_dhcp_bindings[1].get('staticBindings').get(
        'staticBindings')

    for binding in sbindings:
        nsx_dhcp_static_bindings.add(
            (edge_id, binding.get('macAddress').lower(),
             binding.get('bindingId').lower()))

    return nsx_dhcp_static_bindings


def neutron_get_static_bindings_by_edge(edge_id):
    neutron_db_dhcp_bindings = set()
    for binding in nsxv_db.get_dhcp_static_bindings_by_edge(
            neutron_db.context.session, edge_id):
        neutron_db_dhcp_bindings.add(
            (binding.edge_id, binding.mac_address.lower(),
             binding.binding_id.lower()))
    return neutron_db_dhcp_bindings


@admin_utils.output_header
def list_missing_dhcp_bindings(resource, event, trigger, **kwargs):
    """List missing DHCP bindings from NSXv backend.

    Missing DHCP bindings are those that exist in Neutron DB;
    but are not present on corresponding NSXv Edge.
    """

    for (edge_id, _) in nsxv_db.get_nsxv_dhcp_bindings_count_per_edge(
            neutron_db.context.session):
        LOG.info(_LI("%s"), "=" * 60)
        LOG.info(_LI("For edge: %s"), edge_id)
        nsx_dhcp_static_bindings = nsx_get_static_bindings_by_edge(edge_id)
        neutron_dhcp_static_bindings = \
            neutron_get_static_bindings_by_edge(edge_id)
        LOG.info(_LI("# of DHCP bindings in Neutron DB: %s"),
                 len(neutron_dhcp_static_bindings))
        LOG.info(_LI("# of DHCP bindings on NSXv backend: %s"),
                 len(nsx_dhcp_static_bindings))
        missing = neutron_dhcp_static_bindings - nsx_dhcp_static_bindings
        if not missing:
            LOG.info(_LI("No missing DHCP bindings found."))
            LOG.info(_LI("Neutron DB and NSXv backend are in sync"))
        else:
            LOG.info(_LI("Missing DHCP bindings:"))
            LOG.info(_LI("%s"), pprint.pformat(missing))


@admin_utils.output_header
def nsx_update_dhcp_edge_binding(resource, event, trigger, **kwargs):
    """Resync DHCP bindings on NSXv Edge"""

    if not kwargs['property']:
        LOG.error(_LE("Need to specify edge-id parameter"))
        return
    else:
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        edge_id = properties.get('edge-id')
        LOG.info(_LI("Updating NSXv Edge: %s"), edge_id)
        # Need to create a NeutronDbPlugin object; so that we are able to
        # do neutron list-ports.
        plugin = db_base_plugin_v2.NeutronDbPluginV2()
        nsxv_manager = vcns_driver.VcnsDriver(
                           edge_utils.NsxVCallbacks(plugin))
        edge_manager = edge_utils.EdgeManager(nsxv_manager, plugin)
        try:
            edge_manager.update_dhcp_service_config(
                neutron_db.context, edge_id)
        except exceptions.ResourceNotFound:
            LOG.error(_LE("Edge %s not found"), edge_id)


registry.subscribe(list_missing_dhcp_bindings,
                   constants.DHCP_BINDING,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_update_dhcp_edge_binding,
                   constants.DHCP_BINDING,
                   shell.Operations.NSX_UPDATE.value)
