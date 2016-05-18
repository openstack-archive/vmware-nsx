# Copyright 2016 VMware, Inc.
# All Rights Reserved
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

from neutron.callbacks import registry
from neutron.db import models_v2
from oslo_config import cfg

from vmware_nsx._i18n import _LE
from vmware_nsx.common import locking
from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v import md_proxy
from vmware_nsx.plugins.nsx_v.vshield.common import constants as vcns_constants
from vmware_nsx.plugins.nsx_v.vshield import nsxv_loadbalancer as nsxv_lb
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils as utils
from vmware_nsx.shell import nsxadmin as shell


LOG = logging.getLogger(__name__)
nsxv = utils.get_nsxv_client()


@admin_utils.output_header
def nsx_redo_metadata_cfg(resource, event, trigger, **kwargs):
    edgeapi = utils.NeutronDbClient()
    net_list = nsxv_db.get_nsxv_internal_network(
        edgeapi.context.session,
        vcns_constants.InternalEdgePurposes.INTER_EDGE_PURPOSE)

    internal_net = None
    internal_subnet = None
    if net_list:
        internal_net = net_list[0]['network_id']
        internal_subnet = edgeapi.context.session.query(
            models_v2.Subnet).filter_by(
            network_id=internal_net).first().get('id')

    edge_list = nsxv_db.get_nsxv_internal_edges_by_purpose(
        edgeapi.context.session,
        vcns_constants.InternalEdgePurposes.INTER_EDGE_PURPOSE)

    md_rtr_ids = [edge['router_id'] for edge in edge_list]

    edge_internal_ips = []
    for edge in edge_list:
        edge_internal_port = edgeapi.context.session.query(
            models_v2.Port).filter_by(network_id=internal_net,
                                      device_id=edge['router_id']).first()
        if edge_internal_port:
            edge_internal_ip = edgeapi.context.session.query(
                models_v2.IPAllocation).filter_by(
                port_id=edge_internal_port['id']).first()
            edge_internal_ips.append(edge_internal_ip['ip_address'])

    if not internal_net or not internal_subnet or not edge_internal_ips:
        LOG.error(_LE("Metadata infrastructure is missing or broken. "
                      "It is recommended to restart neutron service before "
                      "proceeding with configuration restoration"))
        return

    router_bindings = nsxv_db.get_nsxv_router_bindings(
        edgeapi.context.session,
        filters={'edge_type': [nsxv_constants.SERVICE_EDGE]})
    edge_ids = list(set([binding['edge_id'] for binding in router_bindings
                         if (binding['router_id'] not in set(md_rtr_ids)
                             and not binding['router_id'].startswith(
                                 vcns_constants.BACKUP_ROUTER_PREFIX)
                             and not binding['router_id'].startswith(
                                    vcns_constants.PLR_EDGE_PREFIX))]))

    for edge_id in edge_ids:
        with locking.LockManager.get_lock(edge_id):
            lb = nsxv_lb.NsxvLoadbalancer.get_loadbalancer(nsxv, edge_id)
            virt = lb.virtual_servers.get(md_proxy.METADATA_VSE_NAME)
            if virt:
                pool = virt.default_pool
                pool.members = {}

                i = 0
                s_port = cfg.CONF.nsxv.nova_metadata_port
                for member_ip in edge_internal_ips:
                    i += 1
                    member = nsxv_lb.NsxvLBPoolMember(
                        name='Member-%d' % i,
                        ip_address=member_ip,
                        port=s_port,
                        monitor_port=s_port)
                    pool.add_member(member)

                lb.submit_to_backend(nsxv, edge_id, False)


registry.subscribe(nsx_redo_metadata_cfg,
                   constants.METADATA,
                   shell.Operations.NSX_UPDATE.value)
