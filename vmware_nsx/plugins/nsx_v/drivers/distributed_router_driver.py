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

from neutron.db import l3_db

from neutron_lib import constants
from neutron_lib import exceptions as n_exc

from vmware_nsx._i18n import _LE, _LW
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.drivers import (
    abstract_router_driver as router_driver)
from vmware_nsx.plugins.nsx_v import plugin as nsx_v
from vmware_nsx.plugins.nsx_v.vshield.common import (
    constants as vcns_const)
from vmware_nsx.plugins.nsx_v.vshield import edge_utils

LOG = logging.getLogger(__name__)
METADATA_CIDR = '169.254.169.254/32'


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
        newnexthop=vcns_const.INTEGRATION_EDGE_IPADDRESS,
        metadata_gateway=None):
        routes = []

        # If metadata service is configured, add a static route to direct
        # metadata requests to a DHCP Edge on one of the attached networks
        if metadata_gateway:
            routes.append({'destination': METADATA_CIDR,
                           'nexthop': metadata_gateway['ip_address'],
                           'network_id': metadata_gateway['network_id']})

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
            md_gw_data = self._get_metadata_gw_data(context, router_id)
            self._update_routes(context, router_id, nexthop, md_gw_data)
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

        # This should address cases where the binding remains due to breakage
        if nsxv_db.get_vdr_dhcp_binding_by_vdr(context.session, router_id):
            LOG.warning(_LW("DHCP bind wasn't cleaned for router %s. "
                            "Cleaning up entry"), router_id)
            nsxv_db.delete_vdr_dhcp_binding(context.session, router_id)

    def update_routes(self, context, router_id, newnexthop,
                      metadata_gateway=None):
        with locking.LockManager.get_lock(self._get_edge_id(context,
                                                            router_id)):
            self._update_routes(context, router_id, newnexthop,
                                metadata_gateway)

    def _update_routes(self, context, router_id, newnexthop,
                      metadata_gateway=None):
        plr_id = self.edge_manager.get_plr_by_tlr_id(context, router_id)
        if plr_id:
            self._update_routes_on_plr(context, router_id, plr_id,
                                       newnexthop)
            self._update_routes_on_tlr(context, router_id,
                                       metadata_gateway=metadata_gateway)
        else:
            self._update_routes_on_tlr(context, router_id, newnexthop=None,
                                       metadata_gateway=metadata_gateway)

    def _update_router_gw_info(self, context, router_id, info,
                               is_routes_update=False,
                               force_update=False):
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
                # Get the availability zone by ID because the router dict
                # retrieved by +get_router does not contain this information
                availability_zone = self.get_router_az_by_id(
                    context, router['id'])
                plr_id = self.edge_manager.create_plr_with_tlr_id(
                    context, router_id, router.get('name'), availability_zone)
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

            if (new_ext_net_id != org_ext_net_id or
                new_enable_snat != org_enable_snat or
                is_routes_update):
                # Open firewall flows on plr
                self.plugin._update_subnets_and_dnat_firewall(
                    context, router, router_id=plr_id)

        # update static routes in all
        md_gw_data = self._get_metadata_gw_data(context, router_id)
        self._update_routes(context, router_id, newnexthop, md_gw_data)

    def _validate_multiple_subnets_routers(self, context, router_id,
                                           interface_info):
        _nsxv_plugin = self.plugin
        net_id = _nsxv_plugin._get_interface_info_net_id(context,
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
        with locking.LockManager.get_lock(self._get_edge_id(context,
                                                            router_id)):
            port = self.plugin.get_port(context, info['port_id'])
            try:
                edge_utils.add_vdr_internal_interface(self.nsx_v, context,
                                                      router_id, network_id,
                                                      address_groups,
                                                      router_db.admin_state_up)
            except Exception:
                with excutils.save_and_reraise_exception():
                    super(nsx_v.NsxVPluginV2, self.plugin
                          ).remove_router_interface(context,
                                                    router_id,
                                                    interface_info)
            # Update edge's firewall rules to accept subnets flows.
            self.plugin._update_subnets_and_dnat_firewall(context, router_db)

            do_metadata = False
            if self.plugin.metadata_proxy_handler:
                for fixed_ip in port.get("fixed_ips", []):
                    if fixed_ip['ip_address'] == subnet['gateway_ip']:
                        do_metadata = True

                if do_metadata:
                    self.edge_manager.configure_dhcp_for_vdr_network(
                        context, network_id, router_id)

            if router_db.gw_port:
                plr_id = self.edge_manager.get_plr_by_tlr_id(context,
                                                             router_id)
                if router_db.enable_snat:
                    self.plugin._update_nat_rules(context, router_db, plr_id)

                # Open firewall flows on plr
                self.plugin._update_subnets_and_dnat_firewall(
                    context, router_db, router_id=plr_id)
                # Update static routes of plr
                nexthop = self.plugin._get_external_attachment_info(
                    context, router_db)[2]
                if do_metadata:
                    md_gw_data = self._get_metadata_gw_data(context, router_id)
                else:
                    md_gw_data = None
                self._update_routes(context, router_id, nexthop, md_gw_data)

            elif do_metadata and self._metadata_cfg_required_after_port_add(
                    context, router_id, subnet):
                self._metadata_route_update(context, router_id)

        return info

    def _metadata_route_update(self, context, router_id):
        """Update metadata relative routes.
        The func can only be used when there is no gateway on vdr.
        """
        md_gw_data = self._get_metadata_gw_data(context, router_id)

        # Setup metadata route on VDR
        self._update_routes_on_tlr(
            context, router_id, newnexthop=None,
            metadata_gateway=md_gw_data)
        if not md_gw_data:
            # No more DHCP interfaces on VDR. Remove DHCP binding
            nsxv_db.delete_vdr_dhcp_binding(context.session, router_id)
        return md_gw_data

    def _get_metadata_gw_data(self, context, router_id):
        if not self.plugin.metadata_proxy_handler:
            return
        # Get all subnets which are attached to the VDR and have DHCP enabled
        vdr_ports = self.plugin._get_port_by_device_id(
            context, router_id, l3_db.DEVICE_OWNER_ROUTER_INTF)
        vdr_subnet_ids = [port['fixed_ips'][0]['subnet_id']
                          for port in vdr_ports if port.get('fixed_ips')]
        vdr_subnets = None
        if vdr_subnet_ids:
            subnet_filters = {'id': vdr_subnet_ids,
                              'enable_dhcp': [True]}
            vdr_subnets = self.plugin.get_subnets(context,
                                                  filters=subnet_filters)

        # Choose the 1st subnet, and get the DHCP interface IP address
        if vdr_subnets:
            dhcp_ports = self.plugin.get_ports(
                context,
                filters={'device_owner': ['network:dhcp'],
                         'fixed_ips': {'subnet_id': [vdr_subnets[0]['id']]}},
                fields=['fixed_ips'])

            if (dhcp_ports
                and dhcp_ports[0].get('fixed_ips')
                and dhcp_ports[0]['fixed_ips'][0]):
                ip_subnet = dhcp_ports[0]['fixed_ips'][0]
                ip_address = ip_subnet['ip_address']
                network_id = self.plugin.get_subnet(
                    context, ip_subnet['subnet_id']).get('network_id')

                return {'ip_address': ip_address,
                        'network_id': network_id}

    def _metadata_cfg_required_after_port_add(
            self, context, router_id, subnet):
        # On VDR, metadata is supported by applying metadata LB on DHCP
        # Edge, and routing the metadata requests from VDR to the DHCP Edge.
        #
        # If DHCP is enabled on this subnet, we can, potentially, use it
        # for metadata.
        # Verify if there are networks which are connected to DHCP and to
        # this router. If so, one of these is serving metadata.
        # If not, route metadata requests to DHCP on this subnet
        if self.plugin.metadata_proxy_handler and subnet['enable_dhcp']:
            vdr_ports = self.plugin.get_ports(
                context,
                filters={'device_id': [router_id]})
            if vdr_ports:
                for port in vdr_ports:
                    subnet_id = port['fixed_ips'][0]['subnet_id']
                    port_subnet = self.plugin.get_subnet(
                        context, subnet_id)
                    if (port_subnet['id'] != subnet['id']
                        and port_subnet['enable_dhcp']):
                        # We already have a subnet which is connected to
                        # DHCP - hence no need to change the metadata route
                        return False
            return True
        # Metadata routing change is irrelevant if this point is reached
        return False

    def _metadata_cfg_required_after_port_remove(
            self, context, router_id, subnet):
        # When a VDR is detached from a subnet, verify if the subnet is used
        # to transfer metadata requests to the assigned DHCP Edge.
        routes = edge_utils.get_routes(self.nsx_v, context, router_id)

        for route in routes:
            if (route['destination'] == METADATA_CIDR
                and subnet['network_id'] == route['network_id']):

                # Metadata requests are transferred via this port
                return True
        return False

    def remove_router_interface(self, context, router_id, interface_info):
        info = super(nsx_v.NsxVPluginV2, self.plugin).remove_router_interface(
            context, router_id, interface_info)
        router_db = self.plugin._get_router(context, router_id)
        subnet = self.plugin.get_subnet(context, info['subnet_id'])
        network_id = subnet['network_id']
        vdr_dhcp_binding = nsxv_db.get_vdr_dhcp_binding_by_vdr(
            context.session, router_id)

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
                md_gw_data = self._get_metadata_gw_data(context, router_id)
                self._update_routes(context, router_id, nexthop, md_gw_data)

            # If DHCP is disabled, this remove cannot trigger metadata change
            # as metadata is served via DHCP Edge
            elif (subnet['enable_dhcp']
                  and self.plugin.metadata_proxy_handler):
                md_gw_data = self._get_metadata_gw_data(context, router_id)
                if self._metadata_cfg_required_after_port_remove(
                    context, router_id, subnet):
                    self._metadata_route_update(context, router_id)

            self.plugin._update_subnets_and_dnat_firewall(context, router_db)
            # Safly remove interface, VDR can have interface to only one subnet
            # in a given network.
            edge_utils.delete_interface(
                self.nsx_v, context, router_id, network_id, dist=True)

            if self.plugin.metadata_proxy_handler and subnet['enable_dhcp']:
                self._attach_network_to_regular_dhcp(
                    context, router_id, network_id, subnet, vdr_dhcp_binding)

            return info

    def _attach_network_to_regular_dhcp(
            self, context, router_id, network_id, subnet, vdr_dhcp_binding):
        # Detach network from VDR-dedicated DHCP Edge

        # A case where we do not have a vdr_dhcp_binding indicates a DB
        # inconsistency. We check for this anyway, in case that
        # something is broken.
        if vdr_dhcp_binding:
            self.edge_manager.reset_sysctl_rp_filter_for_vdr_dhcp(
                context, vdr_dhcp_binding['dhcp_edge_id'], network_id)

            self.edge_manager.remove_network_from_dhcp_edge(
                context, network_id, vdr_dhcp_binding['dhcp_edge_id'])
        else:
            LOG.error(_LE('VDR DHCP binding is missing for %s'),
                      router_id)

        # Reattach to regular DHCP Edge
        dhcp_id = self.edge_manager.create_dhcp_edge_service(
            context, network_id, subnet)

        address_groups = self.plugin._create_network_dhcp_address_group(
            context, network_id)
        self.edge_manager.update_dhcp_edge_service(
            context, network_id, address_groups=address_groups)
        if dhcp_id:
            edge_id = self.plugin._get_edge_id_by_rtr_id(context,
                                                         dhcp_id)
            if edge_id:
                with locking.LockManager.get_lock(str(edge_id)):
                    md_proxy_handler = (
                        self.plugin.metadata_proxy_handler)
                    if md_proxy_handler:
                        md_proxy_handler.configure_router_edge(
                            context, dhcp_id)

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
