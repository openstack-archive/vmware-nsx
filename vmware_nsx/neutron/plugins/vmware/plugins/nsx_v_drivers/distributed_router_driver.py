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

from oslo_utils import excutils

from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as n_exc

from vmware_nsx.neutron.plugins.vmware.plugins import nsx_v
from vmware_nsx.neutron.plugins.vmware.plugins.nsx_v_drivers import (
    abstract_router_driver as router_driver)
from vmware_nsx.neutron.plugins.vmware.vshield.common import (
    constants as vcns_const)
from vmware_nsx.neutron.plugins.vmware.vshield import edge_utils


class RouterDistributedDriver(router_driver.RouterBaseDriver):

    def get_type(self):
        return "distributed"

    def _update_routes_on_plr(self, context, router_id, plr_id, newnexthop):
        lswitch_id = edge_utils.get_internal_lswitch_id_of_plr_tlr(
            context, router_id)
        subnets = self.plugin._find_router_subnets_cidrs(
            context.elevated(), router_id)
        routes = []
        for subnet in subnets:
            routes.append({
                'destination': subnet,
                'nexthop': (vcns_const.INTEGRATION_LR_IPADDRESS.
                            split('/')[0]),
                'network_id': lswitch_id
            })

        # Add extra routes referring to external network on plr
        extra_routes = self.plugin._prepare_edge_extra_routes(
            context, router_id)
        routes.extend([route for route in extra_routes
                       if route.get('external')])
        edge_utils.update_routes(self.nsx_v, context,
                                 plr_id, routes, newnexthop)

    def _update_routes_on_tlr(
        self, context, router_id,
        newnexthop=vcns_const.INTEGRATION_EDGE_IPADDRESS):
        internal_vnic_index = None
        if newnexthop:
            internal_vnic_index = (
                edge_utils.get_internal_vnic_index_of_plr_tlr(
                    context, router_id))
        routes = []
        # Add extra routes referring to internal network on tlr
        extra_routes = self.plugin._prepare_edge_extra_routes(
            context, router_id)
        routes.extend([route for route in extra_routes
                       if not route.get('external')])
        edge_utils.update_routes(self.nsx_v, context,
                                 router_id, routes, newnexthop,
                                 gateway_vnic_index=internal_vnic_index)

    def create_router(self, context, lrouter, allow_metadata=True):
        self.edge_manager.create_lrouter(context, lrouter, dist=True)
        # TODO(kobi) can't configure metadata service on VDR at present.

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
        self.edge_manager.delete_lrouter(context, router_id, dist=True)

    def update_routes(self, context, router_id, newnexthop):
        plr_id = self.edge_manager.get_plr_by_tlr_id(context, router_id)
        if plr_id:
            self._update_routes_on_plr(context, router_id, plr_id, newnexthop)
            self._update_routes_on_tlr(context, router_id)
        else:
            self._update_routes_on_tlr(context, router_id, newnexthop=None)

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

        plr_id = self.edge_manager.get_plr_by_tlr_id(context, router_id)
        if not new_ext_net_id:
            if plr_id:
                # delete all plr relative conf
                self.edge_manager.delete_plr_by_tlr_id(
                    context, plr_id, router_id)
        else:
            # Connecting plr to the tlr if new_ext_net_id is not None.
            if not plr_id:
                plr_id = self.edge_manager.create_plr_with_tlr_id(
                    context, router_id, router.get('name'))
            if new_ext_net_id != org_ext_net_id and orgnexthop:
                # network changed, so need to remove default gateway
                # and all static routes before vnic can be configured
                edge_utils.clear_gateway(self.nsx_v, context, plr_id)

            # Update external vnic if addr or mask is changed
            if orgaddr != newaddr or orgmask != newmask:
                edge_utils.update_external_interface(
                    self.nsx_v, context, plr_id,
                    new_ext_net_id, newaddr, newmask)

            # Update SNAT rules if ext net changed
            # or ext net not changed but snat is changed.
            if (new_ext_net_id != org_ext_net_id or
                (new_ext_net_id == org_ext_net_id and
                 new_enable_snat != org_enable_snat)):
                self.plugin._update_nat_rules(context, router, plr_id)
                # Open firewall flows on plr
                self.plugin._update_subnets_and_dnat_firewall(
                    context, router, router_id=plr_id)

        # update static routes in all
        self.update_routes(context, router_id, newnexthop)

    def add_router_interface(self, context, router_id, interface_info):
        info = super(nsx_v.NsxVPluginV2, self.plugin).add_router_interface(
            context, router_id, interface_info)

        router_db = self.plugin._get_router(context, router_id)
        subnet = self.plugin.get_subnet(context, info['subnet_id'])
        network_id = subnet['network_id']
        address_groups = self.plugin._get_address_groups(
            context, router_id, network_id)
        try:
            edge_utils.add_vdr_internal_interface(
                self.nsx_v, context, router_id,
                network_id, address_groups)
        except n_exc.BadRequest:
            with excutils.save_and_reraise_exception():
                super(nsx_v.NsxVPluginV2, self.plugin).remove_router_interface(
                    context, router_id, interface_info)
        # Update edge's firewall rules to accept subnets flows.
        self.plugin._update_subnets_and_dnat_firewall(context, router_db)

        if router_db.gw_port and router_db.enable_snat:
            plr_id = self.edge_manager.get_plr_by_tlr_id(context, router_id)
            self.plugin._update_nat_rules(context, router_db, plr_id)
            # Open firewall flows on plr
            self.plugin._update_subnets_and_dnat_firewall(
                context, router_db, router_id=plr_id)
            # Update static routes of plr
            nexthop = self.plugin._get_external_attachment_info(
                context, router_db)[2]
            self.update_routes(context, router_id, nexthop)
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        info = super(nsx_v.NsxVPluginV2, self.plugin).remove_router_interface(
            context, router_id, interface_info)
        router_db = self.plugin._get_router(context, router_id)
        subnet = self.plugin.get_subnet(context, info['subnet_id'])
        network_id = subnet['network_id']
        if router_db.gw_port and router_db.enable_snat:
            plr_id = self.edge_manager.get_plr_by_tlr_id(
                context, router_id)
            self.plugin._update_nat_rules(context, router_db, plr_id)
            # Open firewall flows on plr
            self.plugin._update_subnets_and_dnat_firewall(
                context, router_db, router_id=plr_id)
            # Update static routes of plr
            nexthop = self.plugin._get_external_attachment_info(
                context, router_db)[2]
            self.update_routes(context, router_id, nexthop)

        ports = self.plugin._get_router_interface_ports_by_network(
            context, router_id, network_id)
        self.plugin._update_subnets_and_dnat_firewall(context, router_db)
        # No subnet on the network connects to the edge vnic
        if not ports:
            edge_utils.delete_interface(self.nsx_v, context,
                                        router_id, network_id,
                                        dist=True)
        else:
            address_groups = self.plugin._get_address_groups(
                context, router_id, network_id)
            edge_utils.update_vdr_internal_interface(
                self.nsx_v, context, router_id,
                network_id, address_groups)
        return info

    def _update_edge_router(self, context, router_id):
        router = self.plugin._get_router(context, router_id)
        plr_id = self.edge_manager.get_plr_by_tlr_id(context, router_id)
        self.plugin._update_external_interface(
            context, router, router_id=plr_id)
        self.plugin._update_nat_rules(context, router, router_id=plr_id)
        self.plugin._update_subnets_and_dnat_firewall(context, router,
                                                      router_id=plr_id)
