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

from admin.plugins.common import constants
from admin.plugins.common.utils import output_header
import admin.plugins.nsxv.resources.utils as utils
from admin.shell import Operations

from neutron.callbacks import registry

from vmware_nsx._i18n import _LI
from vmware_nsx.db import nsxv_db

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


@output_header
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
        LOG.info(_LI("Missing DHCP bindings:"))
        LOG.info(neutron_dhcp_static_bindings - nsx_dhcp_static_bindings)


registry.subscribe(list_missing_dhcp_bindings,
                   constants.DHCP_BINDING,
                   Operations.LIST.value)
