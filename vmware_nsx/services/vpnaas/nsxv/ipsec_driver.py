# Copyright 2016 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
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
from neutron_lib.plugins import directory
from neutron_vpnaas.services.vpn import service_drivers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsxv_exc
from vmware_nsx.common import locking
from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import nsxv_db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as vcns_exc
from vmware_nsx.services.vpnaas.nsxv import ipsec_validator

LOG = logging.getLogger(__name__)
IPSEC = 'ipsec'


class NSXvIPsecVpnDriver(service_drivers.VpnDriver):

    def __init__(self, service_plugin):
        self._core_plugin = directory.get_plugin()
        if self._core_plugin.is_tvd_plugin():
            self._core_plugin = self._core_plugin.get_plugin_by_type(
                projectpluginmap.NsxPlugins.NSX_V)
        self._vcns = self._core_plugin.nsx_v.vcns
        validator = ipsec_validator.IPsecValidator(service_plugin)
        super(NSXvIPsecVpnDriver, self).__init__(service_plugin, validator)

    @property
    def l3_plugin(self):
        return self._core_plugin

    @property
    def service_type(self):
        return IPSEC

    def _get_router_edge_id(self, context, vpnservice_id):
        vpnservice = self.service_plugin._get_vpnservice(context,
                                                         vpnservice_id)
        router_id = vpnservice['router_id']
        edge_binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                       router_id)
        if not edge_binding:
            msg = _("Couldn't find edge binding for router %s") % router_id
            raise nsxv_exc.NsxPluginException(err_msg=msg)

        if edge_binding['edge_type'] == nsxv_constants.VDR_EDGE:
            edge_manager = self._core_plugin.edge_manager
            router_id = edge_manager.get_plr_by_tlr_id(context, router_id)
            binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                      router_id)
            edge_id = binding['edge_id']
        else:
            # Get exclusive edge id
            edge_id = edge_binding['edge_id']
        return router_id, edge_id

    def _convert_ipsec_conn(self, context, ipsec_site_connection):
        ipsec_id = ipsec_site_connection['ipsecpolicy_id']
        vpnservice_id = ipsec_site_connection['vpnservice_id']
        ipsecpolicy = self.service_plugin.get_ipsecpolicy(context, ipsec_id)
        vpnservice = self.service_plugin._get_vpnservice(context,
                                                         vpnservice_id)
        local_cidr = vpnservice['subnet']['cidr']
        router_id = vpnservice['router_id']
        router = self._core_plugin.get_router(context, router_id)
        local_addr = (router['external_gateway_info']['external_fixed_ips']
                      [0]["ip_address"])
        encrypt = nsxv_constants.ENCRYPTION_ALGORITHM_MAP.get(
            ipsecpolicy.get('encryption_algorithm'))
        site = {
            'enabled': True,
            'enablePfs': True,
            'dhGroup': nsxv_constants.PFS_MAP.get(ipsecpolicy.get('pfs')),
            'name': ipsec_site_connection.get('name'),
            'description': ipsec_site_connection.get('description'),
            'localId': local_addr,
            'localIp': local_addr,
            'peerId': ipsec_site_connection['peer_id'],
            'peerIp': ipsec_site_connection.get('peer_address'),
            'localSubnets': {
                'subnets': [local_cidr]},
            'peerSubnets': {
                'subnets': ipsec_site_connection.get('peer_cidrs')},
            'authenticationMode': ipsec_site_connection.get('auth_mode'),
            'psk': ipsec_site_connection.get('psk'),
            'encryptionAlgorithm': encrypt
        }
        return site

    def _generate_new_sites(self, edge_id, ipsec_site_conn):
        # Fetch the previous ipsec vpn configuration
        ipsecvpn_configs = self._get_ipsec_config(edge_id)
        vse_sites = []
        if ipsecvpn_configs[1]['enabled']:
            vse_sites = ([site for site
                          in ipsecvpn_configs[1]['sites']['sites']])
        vse_sites.append(ipsec_site_conn)
        return vse_sites

    def _generate_ipsecvpn_firewall_rules(self, plugin_type, context,
                                          edge_id=None):
        ipsecvpn_configs = self._get_ipsec_config(edge_id)
        ipsec_vpn_fw_rules = []
        if ipsecvpn_configs[1]['enabled']:
            for site in ipsecvpn_configs[1]['sites']['sites']:
                peer_subnets = site['peerSubnets']['subnets']
                local_subnets = site['localSubnets']['subnets']
                ipsec_vpn_fw_rules.append({
                    'name': 'VPN ' + site.get('name', 'rule'),
                    'action': 'allow',
                    'enabled': True,
                    'source_ip_address': peer_subnets,
                    'destination_ip_address': local_subnets})
        return ipsec_vpn_fw_rules

    def _update_firewall_rules(self, context, vpnservice_id):
        vpnservice = self.service_plugin._get_vpnservice(context,
                                                         vpnservice_id)
        router_db = (
            self._core_plugin._get_router(context, vpnservice['router_id']))
        self._core_plugin._update_subnets_and_dnat_firewall(context,
                                                            router_db)

    def _update_status(self, context, vpn_service_id, ipsec_site_conn_id,
                       status, updated_pending_status=True):
        status_list = []
        vpn_status = {}
        ipsec_site_conn = {}
        vpn_status['id'] = vpn_service_id
        vpn_status['updated_pending_status'] = updated_pending_status
        vpn_status['status'] = status
        ipsec_site_conn['status'] = status
        ipsec_site_conn['updated_pending_status'] = updated_pending_status
        vpn_status['ipsec_site_connections'] = {ipsec_site_conn_id:
                                                ipsec_site_conn}
        status_list.append(vpn_status)
        self.service_plugin.update_status_by_agent(context, status_list)

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        LOG.debug('Creating ipsec site connection %(conn_info)s.',
                  {"conn_info": ipsec_site_connection})
        new_ipsec = self._convert_ipsec_conn(context, ipsec_site_connection)
        vpnservice_id = ipsec_site_connection['vpnservice_id']
        edge_id = self._get_router_edge_id(context, vpnservice_id)[1]
        with locking.LockManager.get_lock(edge_id):
            vse_sites = self._generate_new_sites(edge_id, new_ipsec)
            ipsec_id = ipsec_site_connection["id"]
            try:
                LOG.debug('Updating ipsec vpn configuration %(vse_sites)s.',
                          {'vse_sites': vse_sites})
                self._update_ipsec_config(edge_id, vse_sites, enabled=True)
            except vcns_exc.VcnsApiException:
                self._update_status(context, vpnservice_id, ipsec_id,
                                    "ERROR")
                msg = (_("Failed to create ipsec site connection "
                         "configuration with %(edge_id)s.") %
                       {'edge_id': edge_id})
                raise nsxv_exc.NsxPluginException(err_msg=msg)

            LOG.debug('Updating ipsec vpn firewall')
            try:
                self._update_firewall_rules(context, vpnservice_id)
            except vcns_exc.VcnsApiException:
                self._update_status(context, vpnservice_id, ipsec_id, "ERROR")
                msg = (_("Failed to update firewall rule for ipsec vpn "
                         "with %(edge_id)s.") % {'edge_id': edge_id})
                raise nsxv_exc.NsxPluginException(err_msg=msg)
            self._update_status(context, vpnservice_id, ipsec_id, "ACTIVE")

    def _get_ipsec_config(self, edge_id):
        return self._vcns.get_ipsec_config(edge_id)

    def delete_ipsec_site_connection(self, context, ipsec_site_conn):
        LOG.debug('Deleting ipsec site connection %(site)s.',
                  {"site": ipsec_site_conn})
        ipsec_id = ipsec_site_conn['id']
        edge_id = self._get_router_edge_id(context,
                                           ipsec_site_conn['vpnservice_id'])[1]
        with locking.LockManager.get_lock(edge_id):
            del_site, vse_sites = self._find_vse_site(context, edge_id,
                                                      ipsec_site_conn)
            if not del_site:
                LOG.error("Failed to find ipsec_site_connection "
                          "%(ipsec_site_conn)s with %(edge_id)s.",
                          {'ipsec_site_conn': ipsec_site_conn,
                           'edge_id': edge_id})
                raise nsxv_exc.NsxIPsecVpnMappingNotFound(conn=ipsec_id)

            vse_sites.remove(del_site)
            enabled = True if vse_sites else False
            try:
                self._update_ipsec_config(edge_id, vse_sites, enabled)
            except vcns_exc.VcnsApiException:
                msg = (_("Failed to delete ipsec site connection "
                         "configuration with edge_id: %(edge_id)s.") %
                       {'egde_id': edge_id})
                raise nsxv_exc.NsxPluginException(err_msg=msg)
            try:
                self._update_firewall_rules(context,
                                            ipsec_site_conn['vpnservice_id'])
            except vcns_exc.VcnsApiException:
                msg = _("Failed to update firewall rule for ipsec vpn with "
                        "%(edge_id)s.") % {'edge_id': edge_id}
                raise nsxv_exc.NsxPluginException(err_msg=msg)

    def _find_vse_site(self, context, edge_id, site):
        # Fetch the previous ipsec vpn configuration
        ipsecvpn_configs = self._get_ipsec_config(edge_id)[1]
        vpnservice = self.service_plugin._get_vpnservice(context,
                                                         site['vpnservice_id'])
        local_cidr = vpnservice['subnet']['cidr']
        old_site = None
        vse_sites = None
        if ipsecvpn_configs['enabled']:
            vse_sites = ipsecvpn_configs['sites'].get('sites')
            for s in vse_sites:
                if ((s['peerSubnets'].get('subnets') == site['peer_cidrs']) and
                    (s['localSubnets'].get('subnets')[0] == local_cidr)):
                    old_site = s
                    break
        return old_site, vse_sites

    def _update_site_dict(self, context, edge_id, site,
                          ipsec_site_connection):
        # Fetch the previous ipsec vpn configuration
        old_site, vse_sites = self._find_vse_site(context, edge_id, site)
        if old_site:
            vse_sites.remove(old_site)
            if 'peer_addresses' in ipsec_site_connection:
                old_site['peerIp'] = ipsec_site_connection['peer_address']
            if 'peer_cidrs' in ipsec_site_connection:
                old_site['peerSubnets']['subnets'] = (ipsec_site_connection
                                                      ['peer_cidrs'])
            vse_sites.append(old_site)
            return vse_sites

    def update_ipsec_site_connection(self, context, old_ipsec_conn,
                                     ipsec_site_connection):
        LOG.debug('Updating ipsec site connection %(site)s.',
                  {"site": ipsec_site_connection})
        vpnservice_id = old_ipsec_conn['vpnservice_id']
        ipsec_id = old_ipsec_conn['id']
        edge_id = self._get_router_edge_id(context, vpnservice_id)[1]
        with locking.LockManager.get_lock(edge_id):
            vse_sites = self._update_site_dict(context, edge_id,
                                               old_ipsec_conn,
                                               ipsec_site_connection)
            if not vse_sites:
                self._update_status(context, vpnservice_id, ipsec_id,
                                    "ERROR")
                LOG.error("Failed to find ipsec_site_connection "
                          "%(ipsec_site_conn)s with %(edge_id)s.",
                          {'ipsec_site_conn': ipsec_site_connection,
                           'edge_id': edge_id})
                raise nsxv_exc.NsxIPsecVpnMappingNotFound(conn=ipsec_id)
            try:
                LOG.debug('Updating ipsec vpn configuration %(vse_sites)s.',
                          {'vse_sites': vse_sites})
                self._update_ipsec_config(edge_id, vse_sites)
            except vcns_exc.VcnsApiException:
                self._update_status(context, vpnservice_id, ipsec_id, "ERROR")
                msg = (_("Failed to create ipsec site connection "
                         "configuration with %(edge_id)s.") %
                       {'edge_id': edge_id})
                raise nsxv_exc.NsxPluginException(err_msg=msg)

            if 'peer_cidrs' in ipsec_site_connection:
                # Update firewall
                old_ipsec_conn['peer_cidrs'] = (
                    ipsec_site_connection['peer_cidrs'])
                try:
                    self._update_firewall_rules(context, vpnservice_id)
                except vcns_exc.VcnsApiException:
                    self._update_status(context, vpnservice_id, ipsec_id,
                                        "ERROR")
                    msg = (_("Failed to update firewall rule for ipsec "
                             "vpn with %(edge_id)s.") % {'edge_id': edge_id})
                    raise nsxv_exc.NsxPluginException(err_msg=msg)

    def _get_gateway_ips(self, router):
        """Obtain the IPv4 and/or IPv6 GW IP for the router.

        If there are multiples, (arbitrarily) use the first one.
        """
        v4_ip = v6_ip = None
        for fixed_ip in router.gw_port['fixed_ips']:
            addr = fixed_ip['ip_address']
            vers = netaddr.IPAddress(addr).version
            if vers == 4:
                if v4_ip is None:
                    v4_ip = addr
            elif v6_ip is None:
                v6_ip = addr
        return v4_ip, v6_ip

    def create_vpnservice(self, context, vpnservice):
        LOG.debug('Creating VPN service %(vpn)s', {'vpn': vpnservice})
        vpnservice_id = vpnservice['id']
        try:
            self.validator.validate_vpnservice(context, vpnservice)
        except Exception:
            with excutils.save_and_reraise_exception():
                # Rolling back change on the neutron
                self.service_plugin.delete_vpnservice(context, vpnservice_id)

        vpnservice = self.service_plugin._get_vpnservice(context,
                                                         vpnservice_id)
        v4_ip, v6_ip = self._get_gateway_ips(vpnservice.router)
        if v4_ip:
            vpnservice['external_v4_ip'] = v4_ip
        if v6_ip:
            vpnservice['external_v6_ip'] = v6_ip
        self.service_plugin.set_external_tunnel_ips(context,
                                                    vpnservice_id,
                                                    v4_ip=v4_ip, v6_ip=v6_ip)

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        pass

    def delete_vpnservice(self, context, vpnservice):
        pass

    def _update_ipsec_config(self, edge_id, sites, enabled=True):
        ipsec_config = {'featureType': "ipsec_4.0",
                        'enabled': enabled}

        ipsec_config['sites'] = {'sites': sites}
        try:
            self._vcns.update_ipsec_config(edge_id, ipsec_config)
        except vcns_exc.VcnsApiException:
            msg = _("Failed to update ipsec vpn configuration with "
                    "edge_id: %s") % edge_id
            raise nsxv_exc.NsxPluginException(err_msg=msg)
