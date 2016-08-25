# Copyright 2015 VMware, Inc.
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

"""
NSX-V3 Plugin router module
"""
import copy

from neutron_lib import exceptions as n_exc
from oslo_log import log

from vmware_nsx._i18n import _, _LW
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils
from vmware_nsx.nsxlib.v3 import exceptions

LOG = log.getLogger(__name__)

MIN_EDGE_NODE_NUM = 1

TIER0_ROUTER_LINK_PORT_NAME = "TIER0-RouterLinkPort"
TIER1_ROUTER_LINK_PORT_NAME = "TIER1-RouterLinkPort"
ROUTER_INTF_PORT_NAME = "Tier1-RouterDownLinkPort"

FIP_NAT_PRI = 900
GW_NAT_PRI = 1000


class RouterLib(object):

    def __init__(self, router_client, router_port_client, nsxlib):
        self._router_client = router_client
        self._router_port_client = router_port_client
        self.nsxlib = nsxlib

    def validate_tier0(self, tier0_groups_dict, tier0_uuid):
        err_msg = None
        try:
            lrouter = self._router_client.get(tier0_uuid)
        except exceptions.ResourceNotFound:
            err_msg = (_("Tier0 router %s not found at the backend. Either a "
                         "valid UUID must be specified or a default tier0 "
                         "router UUID must be configured in nsx.ini") %
                       tier0_uuid)
        else:
            edge_cluster_uuid = lrouter.get('edge_cluster_id')
            if not edge_cluster_uuid:
                err_msg = _("Failed to get edge cluster uuid from tier0 "
                            "router %s at the backend") % lrouter
            else:
                edge_cluster = self.nsxlib.get_edge_cluster(edge_cluster_uuid)
                member_index_list = [member['member_index']
                                     for member in edge_cluster['members']]
                if len(member_index_list) < MIN_EDGE_NODE_NUM:
                    err_msg = _("%(act_num)s edge members found in "
                                "edge_cluster %(cluster_id)s, however we "
                                "require at least %(exp_num)s edge nodes "
                                "in edge cluster for use.") % {
                        'act_num': len(member_index_list),
                        'exp_num': MIN_EDGE_NODE_NUM,
                        'cluster_id': edge_cluster_uuid}
        if err_msg:
            raise n_exc.InvalidInput(error_message=err_msg)
        else:
            tier0_groups_dict[tier0_uuid] = {
                'edge_cluster_uuid': edge_cluster_uuid,
                'member_index_list': member_index_list}

    def add_router_link_port(self, tier1_uuid, tier0_uuid, tags):
        # Create Tier0 logical router link port
        t0_tags = copy.copy(tags)
        t0_tags = utils.add_v3_tag(t0_tags, 'os-tier0-uuid', tier0_uuid)
        tier0_link_port = self._router_port_client.create(
            tier0_uuid, display_name=TIER0_ROUTER_LINK_PORT_NAME, tags=t0_tags,
            resource_type=nsx_constants.LROUTERPORT_LINKONTIER0,
            logical_port_id=None,
            address_groups=None)
        linked_logical_port_id = tier0_link_port['id']
        # Create Tier1 logical router link port
        t1_tags = copy.copy(tags)
        t1_tags = utils.add_v3_tag(t1_tags, 'os-tier1-uuid', tier1_uuid)
        self._router_port_client.create(
            tier1_uuid, display_name=TIER1_ROUTER_LINK_PORT_NAME, tags=t1_tags,
            resource_type=nsx_constants.LROUTERPORT_LINKONTIER1,
            logical_port_id=linked_logical_port_id,
            address_groups=None)

    def remove_router_link_port(self, tier1_uuid, tier0_uuid):
        try:
            tier1_link_port = (
                self._router_port_client.get_tier1_link_port(tier1_uuid))
        except exceptions.ResourceNotFound:
            LOG.warning(_LW("Logical router link port for tier1 router: %s "
                            "not found at the backend"), tier1_uuid)
            return
        tier1_link_port_id = tier1_link_port['id']
        tier0_link_port_id = (
            tier1_link_port['linked_logical_router_port_id'].get('target_id'))
        self._router_port_client.delete(tier1_link_port_id)
        self._router_port_client.delete(tier0_link_port_id)

    def update_advertisement(self, logical_router_id,
                             advertise_route_nat,
                             advertise_route_connected,
                             advertise_route_static=False,
                             enabled=True):
        return self.nsxlib.update_logical_router_advertisement(
            logical_router_id,
            advertise_nat_routes=advertise_route_nat,
            advertise_nsx_connected_routes=advertise_route_connected,
            advertise_static_routes=advertise_route_static,
            enabled=enabled)

    def delete_gw_snat_rule(self, logical_router_id, gw_ip):
        return self.nsxlib.delete_nat_rule_by_values(logical_router_id,
                                                     translated_network=gw_ip)

    def add_gw_snat_rule(self, logical_router_id, gw_ip):
        return self.nsxlib.add_nat_rule(logical_router_id, action="SNAT",
                                        translated_network=gw_ip,
                                        rule_priority=GW_NAT_PRI)

    def update_router_edge_cluster(self, nsx_router_id, edge_cluster_uuid):
        return self._router_client.update(nsx_router_id,
                                          edge_cluster_id=edge_cluster_uuid)

    def create_logical_router_intf_port_by_ls_id(self, logical_router_id,
                                                 display_name,
                                                 tags,
                                                 ls_id,
                                                 logical_switch_port_id,
                                                 address_groups):
        try:
            port = self._router_port_client.get_by_lswitch_id(ls_id)
        except exceptions.ResourceNotFound:
            return self._router_port_client.create(
                logical_router_id,
                display_name,
                tags,
                nsx_constants.LROUTERPORT_DOWNLINK,
                logical_switch_port_id,
                address_groups)
        else:
            return self._router_port_client.update(
                port['id'], subnets=address_groups)

    def add_fip_nat_rules(self, logical_router_id, ext_ip, int_ip):
        self.nsxlib.add_nat_rule(logical_router_id, action="SNAT",
                                 translated_network=ext_ip,
                                 source_net=int_ip,
                                 rule_priority=FIP_NAT_PRI)
        self.nsxlib.add_nat_rule(logical_router_id, action="DNAT",
                                 translated_network=int_ip,
                                 dest_net=ext_ip,
                                 rule_priority=FIP_NAT_PRI)

    def delete_fip_nat_rules(self, logical_router_id, ext_ip, int_ip):
        self.nsxlib.delete_nat_rule_by_values(logical_router_id,
                                              action="SNAT",
                                              translated_network=ext_ip,
                                              match_source_network=int_ip)
        self.nsxlib.delete_nat_rule_by_values(logical_router_id,
                                              action="DNAT",
                                              translated_network=int_ip,
                                              match_destination_network=ext_ip)

    def add_static_routes(self, nsx_router_id, route):
        return self.nsxlib.add_static_route(nsx_router_id,
                                            route['destination'],
                                            route['nexthop'])

    def delete_static_routes(self, nsx_router_id, route):
        return self.nsxlib.delete_static_route_by_values(
            nsx_router_id, dest_cidr=route['destination'],
            nexthop=route['nexthop'])
