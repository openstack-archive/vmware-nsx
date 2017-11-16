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
from oslo_utils import excutils

from neutron.db import api as db_api
from neutron.db import l3_db

from neutron_lib import constants
from neutron_lib import exceptions as n_exc

from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.drivers import (
    abstract_router_driver as router_driver)
from vmware_nsx.plugins.nsx_v import plugin as nsx_v
from vmware_nsx.plugins.nsx_v.vshield import edge_utils

LOG = logging.getLogger(__name__)


class RouterDistributedDriver(router_driver.RouterBaseDriver):

    def get_type(self):
        return "distributed"

    def _get_edge_id(self, context, router_id):
        binding = nsxv_db.get_nsxv_router_binding(context.session, router_id)
        return binding.get('edge_id')

    def _update_routes_on_plr(self, context, router_id, plr_id, newnexthop):
        lswitch_id = edge_utils.get_internal_lswitch_id_of_plr_tlr(
            context, router_id)
        subnets = self.plugin._find_router_subnets_cidrs(
            context.elevated(), router_id)
        routes = []
        for subnet in subnets:
            routes.append({
                'destination': subnet,
                'nexthop': (edge_utils.get_vdr_transit_network_tlr_address()),
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
        newnexthop=edge_utils.get_vdr_transit_network_plr_address()):
        routes = []

        # Add extra routes referring to internal network on tlr
        extra_routes = self.plugin._prepare_edge_extra_routes(
            context, router_id)
        routes.extend([route for route in extra_routes
                       if not route.get('external')])
        edge_utils.update_routes(self.nsx_v, context,
                                 router_id, routes, newnexthop)

    def create_router(self, context, lrouter, appliance_size=None,
                      allow_metadata=True):
        az = self.get_router_az(lrouter)
        self.edge_manager.create_lrouter(context, lrouter, dist=True,
                                         availability_zone=az)

    def update_router(self, context, router_id, router):
        r = router['router']
        is_routes_update = True if 'routes' in r else False
        gw_info = self.plugin._extract_external_gw(context, router,
                                                   is_extract=True)
        super(nsx_v.NsxVPluginV2, self.plugin).update_router(
            context, router_id, router)
        if gw_info != constants.ATTR_NOT_SPECIFIED:
            self.plugin._update_router_gw_info(context, router_id, gw_info,
                                               is_routes_update)
        elif is_routes_update:
            # here is used to handle routes which tenant updates.
            router_db = self.plugin._get_router(context, router_id)
            nexthop = self.plugin._get_external_attachment_info(
                context, router_db)[2]
            with locking.LockManager.get_lock(self._get_edge_id(context,
                                                                router_id)):
                self.plugin._update_subnets_and_dnat_firewall(context,
                                                              router_db)
                self._update_routes(context, router_id, nexthop)
        if 'admin_state_up' in r:
            self.plugin._update_router_admin_state(
                context, router_id, self.get_type(), r['admin_state_up'])
        if 'name' in r:
            self.edge_manager.rename_lrouter(context, router_id, r['name'])
            # if we have a plr router - rename it too
            plr_id = self.edge_manager.get_plr_by_tlr_id(context, router_id)
            if plr_id:
                self.edge_manager.rename_lrouter(context, plr_id, r['name'])

        return self.plugin.get_router(context, router_id)

    def delete_router(self, context, router_id):
        self.edge_manager.delete_lrouter(context, router_id, dist=True)

    def update_routes(self, context, router_id, newnexthop):
        with locking.LockManager.get_lock(self._get_edge_id(context,
                                                            router_id)):
            self._update_routes(context, router_id, newnexthop)

    def _update_routes(self, context, router_id, newnexthop):
        plr_id = self.edge_manager.get_plr_by_tlr_id(context, router_id)
        if plr_id:
            self._update_routes_on_plr(context, router_id, plr_id,
                                       newnexthop)
            self._update_routes_on_tlr(context, router_id)
        else:
            self._update_routes_on_tlr(context, router_id, newnexthop=None)

    def _update_nexthop(self, context, router_id, newnexthop):
        plr_id = self.edge_manager.get_plr_by_tlr_id(context, router_id)
        if plr_id:
            self._update_routes_on_plr(context, router_id, plr_id,
                                       newnexthop)

    @db_api.retry_db_errors
    def _update_router_gw_info(self, context, router_id, info,
                               is_routes_update=False,
                               force_update=False):
        router = self.plugin._get_router(context, router_id)
        org_ext_net_id = router.gw_port_id and router.gw_port.network_id
        org_enable_snat = router.enable_snat
        orgaddr, orgmask, orgnexthop = (
            self.plugin._get_external_attachment_info(
                context, router))

        # verify the edge was deployed before calling super code.
        tlr_edge_id = self._get_edge_id_or_raise(context, router_id)

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
                with locking.LockManager.get_lock(tlr_edge_id):
                    self.edge_manager.delete_plr_by_tlr_id(
                        context, plr_id, router_id)
        else:
            # Connecting plr to the tlr if new_ext_net_id is not None.
            if not plr_id:
                # Get the availability zone by ID because the router dict
                # retrieved by +get_router does not contain this information
                availability_zone = self.get_router_az_by_id(
                    context, router['id'])
                with locking.LockManager.get_lock(tlr_edge_id):
                    plr_id = self.edge_manager.create_plr_with_tlr_id(
                        context, router_id, router.get('name'),
                        availability_zone)
            if new_ext_net_id != org_ext_net_id and orgnexthop:
                # network changed, so need to remove default gateway
                # and all static routes before vnic can be configured
                with locking.LockManager.get_lock(tlr_edge_id):
                    edge_utils.clear_gateway(self.nsx_v, context, plr_id)

            # Update external vnic if addr or mask is changed
            if orgaddr != newaddr or orgmask != newmask:
                with locking.LockManager.get_lock(tlr_edge_id):
                    self.edge_manager.update_external_interface(
                        self.nsx_v, context, plr_id,
                        new_ext_net_id, newaddr, newmask)

            # Update SNAT rules if ext net changed
            # or ext net not changed but snat is changed.
            if (new_ext_net_id != org_ext_net_id or
                (new_ext_net_id == org_ext_net_id and
                 new_enable_snat != org_enable_snat)):
                self.plugin._update_nat_rules(context, router, plr_id)

            if (new_ext_net_id != org_ext_net_id or
                new_enable_snat != org_enable_snat or
                is_routes_update):
                # Open firewall flows on plr
                self.plugin._update_subnets_and_dnat_firewall(
                    context, router, router_id=plr_id)

        # update static routes in all
        with locking.LockManager.get_lock(tlr_edge_id):
            self._update_routes(context, router_id, newnexthop)

        if new_ext_net_id:
            self._notify_after_router_edge_association(context, router)

    def _validate_multiple_subnets_routers(self, context, router_id,
                                           interface_info):
        _nsxv_plugin = self.plugin
        net_id, subnet_id = _nsxv_plugin._get_interface_info(context,
                                                             interface_info)

        port_filters = {'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                        'network_id': [net_id]}
        intf_ports = _nsxv_plugin.get_ports(context.elevated(),
                                            filters=port_filters)
        router_ids = [port['device_id'] for port in intf_ports]
        all_routers = _nsxv_plugin.get_routers(context,
                                               filters={'id': router_ids})
        dist_routers = [router['id'] for router in all_routers
                        if router.get('distributed') is True]
        if len(dist_routers) > 0:
            err_msg = _("network can only be attached to just one distributed "
                        "router, the network is already attached to router "
                        "%(router_id)s") % {'router_id': dist_routers[0]}
            if router_id in dist_routers:
                # attach to the same router again
                raise n_exc.InvalidInput(error_message=err_msg)
            else:
                # attach to multiple routers
                raise n_exc.Conflict(error_message=err_msg)

    def add_router_interface(self, context, router_id, interface_info):
        self._validate_multiple_subnets_routers(
            context, router_id, interface_info)
        info = super(nsx_v.NsxVPluginV2, self.plugin).add_router_interface(
            context, router_id, interface_info)

        router_db = self.plugin._get_router(context, router_id)
        subnet = self.plugin.get_subnet(context, info['subnet_id'])
        network_id = subnet['network_id']
        address_groups = self.plugin._get_address_groups(
            context, router_id, network_id)
        edge_id = self._get_edge_id(context, router_id)
        interface_created = False
        try:
            with locking.LockManager.get_lock(str(edge_id)):
                edge_utils.add_vdr_internal_interface(self.nsx_v, context,
                                                      router_id, network_id,
                                                      address_groups,
                                                      router_db.admin_state_up)
                interface_created = True
                # Update edge's firewall rules to accept subnets flows.
                self.plugin._update_subnets_and_dnat_firewall(context,
                                                              router_db)

                if router_db.gw_port:
                    plr_id = self.edge_manager.get_plr_by_tlr_id(context,
                                                                 router_id)
                    if router_db.enable_snat:
                        self.plugin._update_nat_rules(context,
                                                      router_db, plr_id)

                    # Open firewall flows on plr
                    self.plugin._update_subnets_and_dnat_firewall(
                        context, router_db, router_id=plr_id)
                    # Update static routes of plr
                    nexthop = self.plugin._get_external_attachment_info(
                        context, router_db)[2]

                    self._update_routes(context, router_id,
                                        nexthop)

        except Exception:
            with excutils.save_and_reraise_exception():
                if not interface_created:
                    super(nsx_v.NsxVPluginV2,
                          self.plugin).remove_router_interface(
                              context, router_id, interface_info)
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        info = super(nsx_v.NsxVPluginV2, self.plugin).remove_router_interface(
            context, router_id, interface_info)
        router_db = self.plugin._get_router(context, router_id)
        subnet = self.plugin.get_subnet(context, info['subnet_id'])
        network_id = subnet['network_id']

        with locking.LockManager.get_lock(self._get_edge_id(context,
                                                            router_id)):
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
                self._update_routes(context, router_id, nexthop)

            self.plugin._update_subnets_and_dnat_firewall(context, router_db)
            # Safly remove interface, VDR can have interface to only one subnet
            # in a given network.
            edge_utils.delete_interface(
                self.nsx_v, context, router_id, network_id, dist=True)

            return info

    def _update_edge_router(self, context, router_id):
        router = self.plugin._get_router(context.elevated(), router_id)
        plr_id = self.edge_manager.get_plr_by_tlr_id(context, router_id)
        self.plugin._update_external_interface(
            context, router, router_id=plr_id)
        self.plugin._update_nat_rules(context, router, router_id=plr_id)
        self.plugin._update_subnets_and_dnat_firewall(context, router,
                                                      router_id=plr_id)

    def update_router_interface_ip(self, context, router_id,
                                   port_id, int_net_id,
                                   old_ip, new_ip, subnet_mask):
        """Update the fixed ip of a distributed router interface. """
        router = self.plugin._get_router(context, router_id)
        if port_id == router.gw_port_id:
            # external port / Uplink
            plr_id = self.edge_manager.get_plr_by_tlr_id(context, router_id)
            edge_id = self._get_edge_id_or_raise(context, plr_id)
            self.edge_manager.update_interface_addr(
                context, edge_id, old_ip, new_ip, subnet_mask, is_uplink=True)
            # Also update the nat rules
            self.plugin._update_nat_rules(context, router, plr_id)
        else:
            # Internal port:
            # get the edge-id of this router
            edge_id = self._get_edge_id_or_raise(context, router_id)
            # Get the vnic index
            edge_vnic_binding = nsxv_db.get_edge_vnic_binding(
                context.session, edge_id, int_net_id)
            vnic_index = edge_vnic_binding.vnic_index
            self.edge_manager.update_vdr_interface_addr(
                context, edge_id, vnic_index, old_ip, new_ip,
                subnet_mask)
