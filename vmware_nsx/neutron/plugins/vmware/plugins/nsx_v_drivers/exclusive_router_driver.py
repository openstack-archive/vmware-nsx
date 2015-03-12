# Copyright 2014 VMware, Inc
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

from oslo_log import log as logging

from neutron.api.v2 import attributes as attr

from vmware_nsx.neutron.plugins.vmware.plugins import nsx_v
from vmware_nsx.neutron.plugins.vmware.plugins.nsx_v_drivers import (
    abstract_router_driver as router_driver)
from vmware_nsx.neutron.plugins.vmware.vshield import edge_utils

LOG = logging.getLogger(__name__)


class RouterExclusiveDriver(router_driver.RouterBaseDriver):

    def get_type(self):
        return "exclusive"

    def create_router(self, context, lrouter, allow_metadata=True):
        self.edge_manager.create_lrouter(context, lrouter, dist=False)
        if allow_metadata:
            self.plugin.metadata_proxy_handler.configure_router_edge(
                lrouter['id'])

    def update_router(self, context, router_id, router):
        gw_info = self.plugin._extract_external_gw(context, router,
                                                   is_extract=True)
        super(nsx_v.NsxVPluginV2, self.plugin).update_router(
            context, router_id, router)
        if gw_info != attr.ATTR_NOT_SPECIFIED:
            self._update_router_gw_info(context, router_id, gw_info)
        else:
            # here is used to handle routes which tenant updates.
            router_db = self.plugin._get_router(context, router_id)
            nexthop = self.plugin._get_external_attachment_info(
                context, router_db)[2]
            self.update_routes(context, router_id, nexthop)
        return self.plugin.get_router(context, router_id)

    def delete_router(self, context, router_id):
        self.edge_manager.delete_lrouter(context, router_id, dist=False)
        if self.plugin.metadata_proxy_handler:
            self.plugin.metadata_proxy_handler.cleanup_router_edge(router_id)

    def update_routes(self, context, router_id, nexthop):
        self.plugin._update_routes(context, router_id, nexthop)

    def _update_router_gw_info(self, context, router_id, info):
        router = self.plugin._get_router(context, router_id)
        org_ext_net_id = router.gw_port_id and router.gw_port.network_id
        org_enable_snat = router.enable_snat
        orgaddr, orgmask, orgnexthop = (
            self.plugin._get_external_attachment_info(
                context, router))

        super(nsx_v.NsxVPluginV2, self.plugin)._update_router_gw_info(
            context, router_id, info, router=router)

        new_ext_net_id = router.gw_port_id and router.gw_port.network_id
        new_enable_snat = router.enable_snat
        newaddr, newmask, newnexthop = (
            self.plugin._get_external_attachment_info(
                context, router))

        if new_ext_net_id != org_ext_net_id and orgnexthop:
            # network changed, so need to remove default gateway before
            # vnic can be configured
            LOG.debug("Delete default gateway %s", orgnexthop)
            edge_utils.clear_gateway(self.nsx_v, context, router_id)
            # Delete SNAT rules
            if org_enable_snat:
                edge_utils.clear_nat_rules(self.nsx_v, context, router_id)

        # Update external vnic if addr or mask is changed
        if orgaddr != newaddr or orgmask != newmask:
            edge_utils.update_external_interface(
                self.nsx_v, context, router_id,
                new_ext_net_id, newaddr, newmask)

        # Update SNAT rules if ext net changed and snat enabled
        # or ext net not changed but snat is changed.
        if ((new_ext_net_id != org_ext_net_id and
             newnexthop and new_enable_snat) or
            (new_ext_net_id == org_ext_net_id and
             new_enable_snat != org_enable_snat)):
            self.plugin._update_nat_rules(context, router)

        # Update static routes in all.
        self.plugin._update_routes(context, router_id, newnexthop)

    def add_router_interface(self, context, router_id, interface_info):
        self.plugin._check_intf_number_of_router(context, router_id)
        info = super(nsx_v.NsxVPluginV2, self.plugin).add_router_interface(
            context, router_id, interface_info)

        router_db = self.plugin._get_router(context, router_id)
        subnet = self.plugin.get_subnet(context, info['subnet_id'])
        network_id = subnet['network_id']
        address_groups = self.plugin._get_address_groups(
            context, router_id, network_id)
        edge_utils.update_internal_interface(
            self.nsx_v, context, router_id, network_id, address_groups)
        # Update edge's firewall rules to accept subnets flows.
        self.plugin._update_subnets_and_dnat_firewall(context, router_db)

        if router_db.gw_port and router_db.enable_snat:
            # Update Nat rules on external edge vnic
            self.plugin._update_nat_rules(context, router_db)
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        info = super(nsx_v.NsxVPluginV2, self.plugin).remove_router_interface(
            context, router_id, interface_info)
        router_db = self.plugin._get_router(context, router_id)
        subnet = self.plugin.get_subnet(context, info['subnet_id'])
        network_id = subnet['network_id']
        if router_db.gw_port and router_db.enable_snat:
            # First update nat rules
            self.plugin._update_nat_rules(context, router_db)
        ports = self.plugin._get_router_interface_ports_by_network(
            context, router_id, network_id)
        self.plugin._update_subnets_and_dnat_firewall(context, router_db)
        # No subnet on the network connects to the edge vnic
        if not ports:
            edge_utils.delete_interface(self.nsx_v, context,
                                        router_id, network_id,
                                        dist=False)
        else:
            address_groups = self.plugin._get_address_groups(
                context, router_id, network_id)
            edge_utils.update_internal_interface(self.nsx_v, context,
                                                 router_id, network_id,
                                                 address_groups)
        return info

    def _update_edge_router(self, context, router_id):
        router = self.plugin._get_router(context, router_id)
        self.plugin._update_external_interface(context, router)
        self.plugin._update_nat_rules(context, router)
        self.plugin._update_subnets_and_dnat_firewall(context, router)
