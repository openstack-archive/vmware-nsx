# Copyright 2017 VMware, Inc.
#
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
import netaddr

from neutron_dynamic_routing.extensions import bgp as bgp_ext
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from neutron_lib.api.definitions import address_scope
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import locking
from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import nsxv_db
from vmware_nsx.extensions import edge_service_gateway_bgp_peer as ext_esg_peer
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as vcns_exc

LOG = logging.getLogger(__name__)


def ip_prefix(name, ip_address):
    return {'ipPrefix': {'name': name, 'ipAddress': ip_address}}


def redistribution_rule(advertise_static_routes, prefix_name, action='permit'):
    rule = {
        'prefixName': prefix_name,
        'action': action,
        'from': {
            'ospf': False,
            'bgp': False,
            'connected': not advertise_static_routes,
            'static': advertise_static_routes
        }
    }
    return {'rule': rule}


def _get_bgp_neighbour(ip_address, remote_as, password, direction):
    bgp_filter = {'bgpFilter': [{'direction': direction, 'action': 'permit'}]}
    nbr = {
        'ipAddress': ip_address,
        'remoteAS': remote_as,
        'bgpFilters': bgp_filter,
        'holdDownTimer': cfg.CONF.nsxv.bgp_neighbour_hold_down_timer,
        'keepAliveTimer': cfg.CONF.nsxv.bgp_neighbour_keep_alive_timer
    }
    if password:
        nbr['password'] = password
    return {'bgpNeighbour': nbr}


def bgp_neighbour_from_peer(bgp_peer):
    return _get_bgp_neighbour(bgp_peer['peer_ip'],
                              bgp_peer['remote_as'],
                              bgp_peer['password'],
                              direction='out')


def gw_bgp_neighbour(ip_address, remote_as, password):
    return _get_bgp_neighbour(ip_address, remote_as, password,
                              direction='in')


class NSXvBgpDriver(object):
    """Class driver to address the neutron_dynamic_routing API"""

    def __init__(self, plugin):
        super(NSXvBgpDriver, self).__init__()
        self._plugin = plugin
        self._core_plugin = directory.get_plugin()
        if self._core_plugin.is_tvd_plugin():
            self._core_plugin = self._core_plugin.get_plugin_by_type(
                projectpluginmap.NsxPlugins.NSX_V)
        if not self._core_plugin:
            err_msg = _("NSXv BGP cannot work without the NSX-V core plugin")
            raise n_exc.InvalidInput(error_message=err_msg)
        self._nsxv = self._core_plugin.nsx_v
        self._edge_manager = self._core_plugin.edge_manager

    def prefix_name(self, subnet_id):
        return 'subnet-%s' % subnet_id

    def _get_router_edge_info(self, context, router_id):
        edge_binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                       router_id)
        if not edge_binding:
            return None, None

        # Indicates which routes should be advertised - connected or static.
        advertise_static_routes = False
        if edge_binding['edge_type'] != nsxv_constants.SERVICE_EDGE:
            # Distributed router
            plr_id = self._edge_manager.get_plr_by_tlr_id(context, router_id)
            edge_binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                           plr_id)
            if not edge_binding:
                # Distributed router isn't bound to plr
                return None, None
            # PLR for distributed router, advertise static routes.
            advertise_static_routes = True
        return edge_binding['edge_id'], advertise_static_routes

    def get_advertised_routes(self, context, bgp_speaker_id):
        routes = []
        bgp_speaker = self._plugin.get_bgp_speaker(context, bgp_speaker_id)
        edge_router_dict = (
            self._get_dynamic_routing_edge_list(context,
                                                bgp_speaker['networks'][0],
                                                bgp_speaker_id))
        for edge_id, edge_router_config in edge_router_dict.items():
            bgp_identifier = edge_router_config['bgp_identifier']
            subnets = self._query_tenant_subnets(
                context, edge_router_config['no_snat_routers'])
            routes.extend([(subnet['cidr'], bgp_identifier)
                           for subnet in subnets])
        routes = self._plugin._make_advertised_routes_list(routes)
        return self._plugin._make_advertised_routes_dict(routes)

    def _get_dynamic_routing_edge_list(self, context,
                                       gateway_network_id, bgp_speaker_id):
        # Filter the routers attached this network as gateway interface
        filters = {'network_id': [gateway_network_id],
                   'device_owner': [n_const.DEVICE_OWNER_ROUTER_GW]}
        fields = ['device_id', 'fixed_ips']
        gateway_ports = self._core_plugin.get_ports(context, filters=filters,
                                                    fields=fields)

        bgp_bindings = nsxv_db.get_nsxv_bgp_speaker_bindings(
            context.session, bgp_speaker_id)
        binding_info = {bgp_binding['edge_id']: bgp_binding['bgp_identifier']
                        for bgp_binding in bgp_bindings}

        edge_router_dict = {}
        for port in gateway_ports:
            router_id = port['device_id']
            router = self._core_plugin._get_router(context, router_id)
            edge_id, advertise_static_routes = (
                self._get_router_edge_info(context, router_id))
            if not edge_id:
                # Shared router is not attached on any edge
                continue

            if edge_id not in edge_router_dict:
                bgp_identifier = binding_info.get(
                    edge_id, port['fixed_ips'][0]['ip_address'])
                edge_router_dict[edge_id] = {'no_snat_routers': [],
                                             'bgp_identifier':
                                             bgp_identifier,
                                             'advertise_static_routes':
                                             advertise_static_routes}
            if not router.enable_snat:
                edge_router_dict[edge_id]['no_snat_routers'].append(router_id)
        return edge_router_dict

    def _get_md_proxy_for_router(self, context, router_id):
        binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                  router_id)
        md_proxy = None
        if binding:
            az_name = binding['availability_zone']
            md_proxy = self._core_plugin.get_metadata_proxy_handler(
                az_name)
        return md_proxy

    def _query_tenant_subnets(self, context, router_ids):
        # Query subnets attached to all of routers attached to same edge
        subnets = []
        for router_id in router_ids:
            filters = {'device_id': [router_id],
                       'device_owner': [n_const.DEVICE_OWNER_ROUTER_INTF]}
            int_ports = self._core_plugin.get_ports(context,
                                                    filters=filters,
                                                    fields=['fixed_ips'])
            # We need to skip metadata subnets
            md_proxy = self._get_md_proxy_for_router(context, router_id)
            for p in int_ports:
                subnet_id = p['fixed_ips'][0]['subnet_id']
                if md_proxy and md_proxy.is_md_subnet(subnet_id):
                    continue
                subnet = self._core_plugin.get_subnet(context, subnet_id)
                subnets.append({'id': subnet_id,
                                'cidr': subnet['cidr']})
        LOG.debug("Got related subnets %s", subnets)
        return subnets

    def _get_bgp_speakers_by_bgp_peer(self, context, bgp_peer_id):
        fields = ['id', 'peers']
        bgp_speakers = self._plugin.get_bgp_speakers(context, fields=fields)
        bgp_speaker_ids = [bgp_speaker['id'] for bgp_speaker in bgp_speakers
                           if bgp_peer_id in bgp_speaker['peers']]
        return bgp_speaker_ids

    def _get_prefixes_and_redistribution_rules(self, subnets,
                                               advertise_static_routes):
        prefixes = []
        redis_rules = []
        for subnet in subnets:
            prefix_name = self.prefix_name(subnet['id'])
            prefix = ip_prefix(prefix_name, subnet['cidr'])
            prefixes.append(prefix)
            rule = redistribution_rule(advertise_static_routes, prefix_name)
            redis_rules.append(rule)
        return prefixes, redis_rules

    def create_bgp_speaker(self, context, bgp_speaker):
        bgp_speaker_data = bgp_speaker['bgp_speaker']
        ip_version = bgp_speaker_data.get('ip_version')
        if ip_version and ip_version == 6:
            err_msg = _("NSXv BGP does not support for IPv6")
            raise n_exc.InvalidInput(error_message=err_msg)

    def update_bgp_speaker(self, context, bgp_speaker_id, bgp_speaker):
        bgp_obj = bgp_speaker['bgp_speaker']
        old_speaker_info = self._plugin.get_bgp_speaker(context,
                                                        bgp_speaker_id)
        enabled_state = old_speaker_info['advertise_tenant_networks']
        new_enabled_state = bgp_obj.get('advertise_tenant_networks',
                                        enabled_state)
        if new_enabled_state == enabled_state:
            return

        bgp_bindings = nsxv_db.get_nsxv_bgp_speaker_bindings(
            context.session, bgp_speaker_id)
        edge_ids = [bgp_binding['edge_id'] for bgp_binding in bgp_bindings]
        action = 'Enabling' if new_enabled_state else 'Disabling'
        LOG.info("%s BGP route redistribution on edges: %s.", action, edge_ids)
        for edge_id in edge_ids:
            try:
                self._nsxv.update_routing_redistribution(edge_id,
                                                         new_enabled_state)
            except vcns_exc.VcnsApiException:
                LOG.warning("Failed to update BGP on edge '%s'.", edge_id)

    def delete_bgp_speaker(self, context, bgp_speaker_id):
        bgp_bindings = nsxv_db.get_nsxv_bgp_speaker_bindings(
            context.session, bgp_speaker_id)
        self._stop_bgp_on_edges(context, bgp_bindings, bgp_speaker_id)

    def _validate_bgp_configuration_on_peer_esg(self, bgp_peer):
        if not bgp_peer.get('esg_id'):
            return
        # TBD(roeyc): Validate peer_ip is on subnet

        bgp_config = self._nsxv.get_routing_bgp_config(bgp_peer['esg_id'])
        remote_as = bgp_peer['remote_as']
        esg_id = bgp_peer['esg_id']
        esg_as = bgp_config['bgp'].get('localAS')
        if not bgp_config['bgp']['enabled']:
            raise ext_esg_peer.BgpDisabledOnEsgPeer(esg_id=esg_id)
        if esg_as != int(remote_as):
            raise ext_esg_peer.EsgRemoteASDoNotMatch(remote_as=remote_as,
                                                     esg_id=esg_id,
                                                     esg_as=esg_as)
        h, resp = self._nsxv.vcns.get_interfaces(esg_id)
        for iface in resp['vnics']:
            address_groups = iface['addressGroups']['addressGroups']
            matching_iface = [ag for ag in address_groups
                              if ag['primaryAddress'] == bgp_peer['peer_ip']]
            if matching_iface:
                break
        else:
            raise ext_esg_peer.EsgInternalIfaceDoesNotMatch(esg_id=esg_id)

    def create_bgp_peer(self, context, bgp_peer):
        bgp_peer = bgp_peer['bgp_peer']
        remote_ip = bgp_peer['peer_ip']
        if not netaddr.valid_ipv4(remote_ip):
            err_msg = _("NSXv BGP does not support for IPv6")
            raise n_exc.InvalidInput(error_message=err_msg)
        self._validate_bgp_configuration_on_peer_esg(bgp_peer)

    def update_bgp_peer(self, context, bgp_peer_id, bgp_peer):
        password = bgp_peer['bgp_peer'].get('password')
        old_bgp_peer = self._plugin.get_bgp_peer(context, bgp_peer_id)

        # Only password update is relevant for backend.
        if old_bgp_peer['password'] == password:
            return

        bgp_speaker_ids = self._get_bgp_speakers_by_bgp_peer(context,
                                                             bgp_peer_id)
        # Update the password for the old bgp peer and update NSX
        old_bgp_peer['password'] = password
        neighbour = bgp_neighbour_from_peer(old_bgp_peer)
        for bgp_speaker_id in bgp_speaker_ids:
            with locking.LockManager.get_lock(bgp_speaker_id):
                peers = self._plugin.get_bgp_peers_by_bgp_speaker(
                    context, bgp_speaker_id)
                if bgp_peer_id not in [p['id'] for p in peers]:
                    continue
                bgp_bindings = nsxv_db.get_nsxv_bgp_speaker_bindings(
                    context.session, bgp_speaker_id)
                for binding in bgp_bindings:
                    try:
                        # Neighbours are identified by their ip address
                        self._nsxv.update_bgp_neighbours(binding['edge_id'],
                                                         [neighbour],
                                                         [neighbour])
                    except vcns_exc.VcnsApiException:
                        LOG.error("Failed to update BGP neighbor '%s' on "
                                  "edge '%s'", old_bgp_peer['peer_ip'],
                                  binding['edge_id'])

    def _validate_bgp_peer(self, context, bgp_speaker_id, new_peer_id):
        new_peer = self._plugin._get_bgp_peer(context, new_peer_id)
        peers = self._plugin._get_bgp_peers_by_bgp_speaker_binding(
            context, bgp_speaker_id)
        self._plugin._validate_peer_ips(bgp_speaker_id, peers, new_peer)

    def add_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        bgp_peer_id = self._plugin._get_id_for(bgp_peer_info, 'bgp_peer_id')
        bgp_peer_obj = self._plugin.get_bgp_peer(context,
                                                 bgp_peer_id)

        nbr = bgp_neighbour_from_peer(bgp_peer_obj)
        bgp_bindings = nsxv_db.get_nsxv_bgp_speaker_bindings(context.session,
                                                             bgp_speaker_id)
        self._validate_bgp_peer(context, bgp_speaker_id, bgp_peer_obj['id'])

        speaker = self._plugin.get_bgp_speaker(context, bgp_speaker_id)
        # list of tenant edge routers to be removed as bgp-neighbours to this
        # peer if it's associated with specific ESG.
        neighbours = []
        for binding in bgp_bindings:
            try:
                self._nsxv.add_bgp_neighbours(binding['edge_id'], [nbr])
            except vcns_exc.VcnsApiException:
                LOG.error("Failed to add BGP neighbour on '%s'",
                          binding['edge_id'])
            else:
                gw_nbr = gw_bgp_neighbour(binding['bgp_identifier'],
                                          speaker['local_as'],
                                          bgp_peer_obj['password'])
                neighbours.append(gw_nbr)
                LOG.debug("Succesfully added BGP neighbor '%s' on '%s'",
                          bgp_peer_obj['peer_ip'], binding['edge_id'])

        if bgp_peer_obj.get('esg_id'):
            edge_gw = bgp_peer_obj['esg_id']
            try:
                self._nsxv.add_bgp_neighbours(edge_gw, neighbours)
            except vcns_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    LOG.error("Failed to add BGP neighbour on GW Edge '%s'",
                              edge_gw)

    def remove_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        bgp_peer_id = bgp_peer_info['bgp_peer_id']
        bgp_peer_obj = self._plugin.get_bgp_peer(context, bgp_peer_id)
        nbr = bgp_neighbour_from_peer(bgp_peer_obj)
        bgp_bindings = nsxv_db.get_nsxv_bgp_speaker_bindings(
            context.session, bgp_speaker_id)
        speaker = self._plugin.get_bgp_speaker(context, bgp_speaker_id)
        # list of tenant edge routers to be removed as bgp-neighbours to this
        # peer if it's associated with specific ESG.
        neighbours = []
        for binding in bgp_bindings:
            try:
                self._nsxv.remove_bgp_neighbours(binding['edge_id'], [nbr])
            except vcns_exc.VcnsApiException:
                LOG.error("Failed to remove BGP neighbour on '%s'",
                          binding['edge_id'])
            else:
                gw_nbr = gw_bgp_neighbour(binding['bgp_identifier'],
                                          speaker['local_as'],
                                          bgp_peer_obj['password'])
                neighbours.append(gw_nbr)
                LOG.debug("Succesfully removed BGP neighbor '%s' on '%s'",
                          bgp_peer_obj['peer_ip'], binding['edge_id'])

        if bgp_peer_obj.get('esg_id'):
            edge_gw = bgp_peer_obj['esg_id']
            try:
                self._nsxv.remove_bgp_neighbours(edge_gw, neighbours)
            except vcns_exc.VcnsApiException:
                LOG.error("Failed to remove BGP neighbour on GW Edge '%s'",
                          edge_gw)

    def _validate_gateway_network(self, context, speaker_id, network_id):
        ext_net = self._core_plugin.get_network(context, network_id)

        if not ext_net.get(extnet_apidef.EXTERNAL):
            raise nsx_exc.NsxBgpNetworkNotExternal(net_id=network_id)
        if not ext_net['subnets']:
            raise nsx_exc.NsxBgpGatewayNetworkHasNoSubnets(net_id=network_id)

        # REVISIT(roeyc): Currently not allowing more than one bgp speaker per
        # gateway network.
        speakers_on_network = self._plugin._bgp_speakers_for_gateway_network(
            context, network_id)
        if speakers_on_network:
            raise bgp_ext.BgpSpeakerNetworkBindingError(
                network_id=network_id,
                bgp_speaker_id=speakers_on_network[0]['id'])

        subnet_id = ext_net['subnets'][0]
        ext_subnet = self._core_plugin.get_subnet(context, subnet_id)

        if ext_subnet.get('gateway_ip'):
            raise ext_esg_peer.ExternalSubnetHasGW(
                network_id=network_id, subnet_id=subnet_id)

        if not ext_net[address_scope.IPV4_ADDRESS_SCOPE]:
            raise nsx_exc.NsxBgpSpeakerUnableToAddGatewayNetwork(
                network_id=network_id, bgp_speaker_id=speaker_id)
        return True

    def add_gateway_network(self, context, bgp_speaker_id, network_info):
        gateway_network_id = network_info['network_id']

        if not self._validate_gateway_network(context, bgp_speaker_id,
                                              gateway_network_id):
            return

        edge_router_dict = self._get_dynamic_routing_edge_list(
            context, gateway_network_id, bgp_speaker_id)

        speaker = self._plugin.get_bgp_speaker(context, bgp_speaker_id)
        bgp_peers = self._plugin.get_bgp_peers_by_bgp_speaker(
            context, bgp_speaker_id)
        local_as = speaker['local_as']
        peers = []
        for edge_id, edge_router_config in edge_router_dict.items():
            router_ids = edge_router_config['no_snat_routers']
            advertise_static_routes = (
                edge_router_config['advertise_static_routes'])
            subnets = self._query_tenant_subnets(context, router_ids)
            # router_id here is in IP address format and is required for
            # the BGP configuration.
            bgp_identifier = edge_router_config['bgp_identifier']
            try:
                self._start_bgp_on_edge(context, edge_id, speaker,
                                        bgp_peers, bgp_identifier, subnets,
                                        advertise_static_routes)
            except vcns_exc.VcnsApiException:
                LOG.error("Failed to configure BGP speaker %s on edge '%s'.",
                          bgp_speaker_id, edge_id)
            else:
                peers.append(bgp_identifier)

        for edge_gw, password in [(peer['esg_id'], peer['password'])
                                  for peer in bgp_peers if peer.get('esg_id')]:
            neighbours = [gw_bgp_neighbour(bgp_id, local_as, password)
                          for bgp_id in peers]
            try:
                self._nsxv.add_bgp_neighbours(edge_gw, neighbours)
            except vcns_exc.VcnsApiException:
                LOG.error("Failed to add BGP neighbour on GW Edge '%s'",
                          edge_gw)

    def _start_bgp_on_edge(self, context, edge_id, speaker, bgp_peers,
                           bgp_identifier, subnets, advertise_static_routes):
        enabled_state = speaker['advertise_tenant_networks']
        local_as = speaker['local_as']
        prefixes, redis_rules = self._get_prefixes_and_redistribution_rules(
            subnets, advertise_static_routes)

        bgp_neighbours = [bgp_neighbour_from_peer(bgp_peer)
                          for bgp_peer in bgp_peers]
        try:
            self._nsxv.add_bgp_speaker_config(edge_id, bgp_identifier,
                                              local_as, enabled_state,
                                              bgp_neighbours, prefixes,
                                              redis_rules)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.error("Failed to configure BGP speaker '%s' on edge '%s'.",
                          speaker['id'], edge_id)
        else:
            nsxv_db.add_nsxv_bgp_speaker_binding(context.session, edge_id,
                                                 speaker['id'], bgp_identifier)

    def _stop_bgp_on_edges(self, context, bgp_bindings, speaker_id):
        peers_to_remove = []
        speaker = self._plugin.get_bgp_speaker(context, speaker_id)
        local_as = speaker['local_as']
        for bgp_binding in bgp_bindings:
            edge_id = bgp_binding['edge_id']
            try:
                self._nsxv.delete_bgp_speaker_config(edge_id)
            except vcns_exc.VcnsApiException:
                LOG.error("Failed to delete BGP speaker '%s' config on edge "
                          "'%s'.", speaker_id, edge_id)
            else:
                nsxv_db.delete_nsxv_bgp_speaker_binding(context.session,
                                                        edge_id)
                peers_to_remove.append(bgp_binding['bgp_identifier'])

        # We should also remove all bgp neighbours on gw-edges which
        # corresponds with tenant routers that are associated with this bgp
        # speaker.
        bgp_peers = self._plugin.get_bgp_peers_by_bgp_speaker(context,
                                                              speaker_id)
        gw_edges = [(peer['esg_id'], peer['password'])
                    for peer in bgp_peers if peer.get('esg_id')]
        for gw_edge, password in gw_edges:
            neighbours_to_remove = [gw_bgp_neighbour(bgp_identifier,
                                                     local_as,
                                                     password)
                                    for bgp_identifier in peers_to_remove]
            try:
                self._nsxv.remove_bgp_neighbours(gw_edge, neighbours_to_remove)
            except vcns_exc.VcnsApiException:
                LOG.error("Failed to remove BGP neighbour on GW edge '%s'.",
                          gw_edge)

    def remove_gateway_network(self, context, bgp_speaker_id, network_info):
        bgp_bindings = nsxv_db.get_nsxv_bgp_speaker_bindings(
            context.session, bgp_speaker_id)
        self._stop_bgp_on_edges(context, bgp_bindings, bgp_speaker_id)

    def _update_edge_bgp_identifier(self, context, bgp_binding, speaker,
                                    new_bgp_identifier):
        local_as = speaker['local_as']
        bgp_peers = self._plugin.get_bgp_peers_by_bgp_speaker(context,
                                                              speaker['id'])
        self._nsxv.update_router_id(bgp_binding['edge_id'], new_bgp_identifier)
        for gw_edge_id, password in [(peer['esg_id'], peer['password'])
                                     for peer in bgp_peers
                                     if peer.get('esg_id')]:
            nbr_to_remove = gw_bgp_neighbour(bgp_binding['bgp_identifier'],
                                             local_as, password)
            nbr_to_add = gw_bgp_neighbour(new_bgp_identifier, local_as,
                                          password)
            self._nsxv.update_bgp_neighbours(gw_edge_id,
                                             [nbr_to_add],
                                             [nbr_to_remove])

        with context.session.begin(subtransactions=True):
            bgp_binding['bgp_identifier'] = new_bgp_identifier

    def process_router_gw_port_update(self, context, speaker,
                                      router, updated_port):
        router_id = router['id']
        gw_fixed_ip = router.gw_port['fixed_ips'][0]['ip_address']

        edge_id, advertise_static_routes = (
            self._get_router_edge_info(context, router_id))
        if not edge_id:
            # shared router is not attached on any edge
            return

        bgp_binding = nsxv_db.get_nsxv_bgp_speaker_binding(
            context.session, edge_id)

        if bgp_binding:
            new_fixed_ip = updated_port['fixed_ips'][0]['ip_address']
            fixed_ip_updated = gw_fixed_ip != new_fixed_ip
            subnets = self._query_tenant_subnets(context, [router_id])
            prefixes, redis_rules = (
                self._get_prefixes_and_redistribution_rules(
                    subnets, advertise_static_routes))
            # Handle possible snat/no-nat update
            if router.enable_snat:
                self._nsxv.remove_bgp_redistribution_rules(edge_id, prefixes)
            else:
                self._nsxv.add_bgp_redistribution_rules(edge_id, prefixes,
                                                        redis_rules)
            if bgp_binding['bgp_identifier'] == gw_fixed_ip:
                if fixed_ip_updated:
                    self._update_edge_bgp_identifier(context,
                                                     bgp_binding,
                                                     speaker,
                                                     new_fixed_ip)

    def enable_bgp_on_router(self, context, speaker, router_id):
        local_as = speaker['local_as']
        edge_id, advertise_static_routes = (
            self._get_router_edge_info(context, router_id))
        if not edge_id:
            # shared router is not attached on any edge
            return
        router = self._core_plugin._get_router(context, router_id)
        subnets = self._query_tenant_subnets(context, [router_id])

        bgp_peers = self._plugin.get_bgp_peers_by_bgp_speaker(
            context, speaker['id'])
        bgp_binding = nsxv_db.get_nsxv_bgp_speaker_binding(
            context.session, edge_id)

        if bgp_binding and subnets:
            # Edge already configured with BGP (e.g - shared router edge),
            # Add the router attached subnets.
            if router.enable_snat:
                prefixes = [self.prefix_name(subnet['id'])
                            for subnet in subnets]
                self._nsxv.remove_bgp_redistribution_rules(edge_id, prefixes)
            else:
                prefixes, redis_rules = (
                    self._get_prefixes_and_redistribution_rules(
                        subnets, advertise_static_routes))
                self._nsxv.add_bgp_redistribution_rules(edge_id, prefixes,
                                                        redis_rules)
        elif not bgp_binding:
            if router.enable_snat:
                subnets = []
            bgp_identifier = router.gw_port['fixed_ips'][0]['ip_address']
            self._start_bgp_on_edge(context, edge_id, speaker, bgp_peers,
                                    bgp_identifier, subnets,
                                    advertise_static_routes)
            for gw_edge_id, password in [(peer['esg_id'], peer['password'])
                                         for peer in bgp_peers
                                         if peer.get('esg_id')]:
                nbr = gw_bgp_neighbour(bgp_identifier, local_as, password)
                self._nsxv.add_bgp_neighbours(gw_edge_id, [nbr])

    def disable_bgp_on_router(self, context, speaker, router_id, gw_ip,
                              edge_id=None):
        speaker = self._plugin.get_bgp_speaker(context, speaker['id'])
        current_edge_id, advertise_static_routes = (
            self._get_router_edge_info(context, router_id))
        edge_id = edge_id or current_edge_id

        if not edge_id:
            return

        bgp_binding = nsxv_db.get_nsxv_bgp_speaker_binding(context.session,
                                                           edge_id)
        if not bgp_binding:
            return

        # Need to ensure that we do not use the metadata IP's
        md_proxy = self._get_md_proxy_for_router(context, router_id)

        routers_ids = (
            self._core_plugin.edge_manager.get_routers_on_same_edge(
                context, router_id))
        routers_ids.remove(router_id)

        # We need to find out what other routers are hosted on the edges and
        # whether they have a gw addresses that could replace the current
        # bgp-identifier (if required).
        filters = {'device_owner': [n_const.DEVICE_OWNER_ROUTER_GW],
                   'device_id': routers_ids}
        edge_gw_ports = self._core_plugin.get_ports(context, filters=filters)
        alt_bgp_identifiers = [
            p['fixed_ips'][0]['ip_address'] for p in edge_gw_ports
            if (not md_proxy or
                not md_proxy.is_md_subnet(
                    p['fixed_ips'][0]['subnet_id']))]
        if alt_bgp_identifiers:
            # Shared router, only remove prefixes and redistribution
            # rules.
            subnets = self._query_tenant_subnets(context, [router_id])
            prefixes = [self.prefix_name(subnet['id'])
                        for subnet in subnets]
            self._nsxv.remove_bgp_redistribution_rules(edge_id, prefixes)
            if bgp_binding['bgp_identifier'] == gw_ip:
                self._update_edge_bgp_identifier(context, bgp_binding, speaker,
                                                 alt_bgp_identifiers[0])
        else:
            self._stop_bgp_on_edges(context, [bgp_binding], speaker['id'])

    def advertise_subnet(self, context, speaker_id, router_id, subnet):
        router = self._core_plugin._get_router(context, router_id)
        if router.enable_snat:
            # Do nothing, by default, only when advertisement is needed we add
            # a new redistribution rule
            return

        edge_id, advertise_static_routes = (
            self._get_router_edge_info(context, router_id))
        if not edge_id:
            # shared router is not attached on any edge
            return
        prefixes, redis_rules = self._get_prefixes_and_redistribution_rules(
            [subnet], advertise_static_routes)
        self._nsxv.add_bgp_redistribution_rules(edge_id, prefixes, redis_rules)

    def withdraw_subnet(self, context, speaker_id, router_id, subnet_id):
        router = self._core_plugin._get_router(context, router_id)
        if router.enable_snat:
            # Do nothing, by default, only when advertisement is needed we add
            # a new redistribution rule
            return

        edge_id, advertise_static_routes = (
            self._get_router_edge_info(context, router_id))
        prefix_name = self.prefix_name(subnet_id)
        self._nsxv.remove_bgp_redistribution_rules(edge_id, [prefix_name])
