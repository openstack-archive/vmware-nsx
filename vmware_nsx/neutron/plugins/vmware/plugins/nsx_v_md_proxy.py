# Copyright 2014 VMware, Inc.
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

import hashlib
import hmac

import netaddr
from oslo.config import cfg
from oslo.db import exception as db_exc

from neutron.api.v2 import attributes as attr
from neutron.common import constants
from neutron import context as neutron_context
from neutron.openstack.common import log as logging
from vmware_nsx.neutron.plugins.vmware.common import nsxv_constants
from vmware_nsx.neutron.plugins.vmware.dbexts import nsxv_db
from vmware_nsx.neutron.plugins.vmware.vshield import (
    nsxv_loadbalancer as nsxv_lb)
from vmware_nsx.neutron.plugins.vmware.vshield.common import (
    constants as vcns_const)
from vmware_nsx.neutron.plugins.vmware.vshield import edge_utils


METADATA_IP_ADDR = '169.254.169.254'
METADATA_TCP_PORT = 80
INTERNAL_SUBNET = '169.254.0.0/16'

LOG = logging.getLogger(__name__)


class NsxVMetadataProxyHandler:

    def __init__(self, nsxv_plugin):
        self.nsxv_plugin = nsxv_plugin
        self.context = neutron_context.get_admin_context()

        self.internal_net, self.internal_subnet = self._get_internal_network()

        if not self.internal_net or not self.internal_subnet:
            self.internal_net, self.internal_subnet = (
                self._create_internal_network())

        self.proxy_edge_ids, self.proxy_edge_ips = self._get_proxy_edges()
        if not self.proxy_edge_ids or not self.proxy_edge_ips:
            self.proxy_edge_ids, self.proxy_edge_ips = (
                self._create_proxy_edges())

    def _create_metadata_internal_network(self, cidr):
        net_data = {'network': {'name': 'inter-edge-net',
                                'admin_state_up': True,
                                'port_security_enabled': False,
                                'shared': False,
                                'tenant_id': None}}
        net = self.nsxv_plugin.create_network(self.context, net_data)

        subnet_data = {'subnet':
                       {'cidr': cidr,
                        'name': 'inter-edge-subnet',
                        'gateway_ip': attr.ATTR_NOT_SPECIFIED,
                        'allocation_pools': attr.ATTR_NOT_SPECIFIED,
                        'ip_version': 4,
                        'dns_nameservers': attr.ATTR_NOT_SPECIFIED,
                        'host_routes': attr.ATTR_NOT_SPECIFIED,
                        'enable_dhcp': False,
                        'network_id': net['id'],
                        'tenant_id': None}}

        subnet = self.nsxv_plugin.create_subnet(
            self.context,
            subnet_data)

        return net['id'], subnet['id']

    def _get_internal_network(self):
        internal_net = None
        internal_subnet = None

        net_list = nsxv_db.get_nsxv_internal_network(
            self.context.session,
            nsxv_constants.INTER_EDGE_PURPOSE)

        if net_list:
            internal_net = net_list[0]['network_id']
            internal_subnet = self.nsxv_plugin.get_subnets(
                self.context,
                fields=['id'],
                filters={'network_id': [internal_net]})[0]['id']

        return internal_net, internal_subnet

    def _create_internal_network(self):
        internal_net, internal_subnet = (
            self._create_metadata_internal_network(INTERNAL_SUBNET))

        try:
            nsxv_db.create_nsxv_internal_network(
                self.context.session,
                nsxv_constants.INTER_EDGE_PURPOSE,
                internal_net)
        except db_exc.DBDuplicateEntry:
            # We may have a race condition, where another Neutron instance
            #  initialized these elements. Delete and use existing elements
            self.nsxv_plugin.delete_network(self.context, internal_net)
            internal_net, internal_subnet = self._get_internal_network()

        return internal_net, internal_subnet

    def _get_proxy_edges(self):
        proxy_edge_ids = []
        proxy_edge_ips = []

        rtr_list = nsxv_db.get_nsxv_internal_edges_by_purpose(
            self.context.session,
            nsxv_constants.INTER_EDGE_PURPOSE)

        for rtr in rtr_list:
            rtr_id = rtr['router_id']
            proxy_edge_ids.append(rtr_id)
            proxy_edge_ips.append(self._get_edge_internal_ip(rtr_id))

        return proxy_edge_ids, proxy_edge_ips

    def _get_edge_internal_ip(self, rtr_id):
            filters = {
                'network_id': [self.internal_net],
                'device_id': [rtr_id]}
            ports = self.nsxv_plugin.get_ports(self.context, filters=filters)
            return ports[0]['fixed_ips'][0]['ip_address']

    def _create_proxy_edges(self):
        proxy_edge_ids = []
        proxy_edge_ips = []

        for rtr_ip in cfg.CONF.nsxv.mgt_net_proxy_ips:
            router_data = {
                'router': {
                    'name': 'metadata_proxy_router',
                    'admin_state_up': True,
                    'tenant_id': None}}

            rtr = self.nsxv_plugin.create_router(
                self.context,
                router_data,
                allow_metadata=False)

            rtr_id = rtr['id']
            binding = nsxv_db.get_nsxv_router_binding(
                self.context.session,
                rtr_id)

            self.nsxv_plugin.nsx_v.update_interface(
                rtr['id'],
                binding['edge_id'],
                vcns_const.EXTERNAL_VNIC_INDEX,
                cfg.CONF.nsxv.mgt_net_moid,
                address=rtr_ip,
                netmask=cfg.CONF.nsxv.mgt_net_proxy_netmask,
                secondary=[])

            port_data = {
                'port': {
                    'network_id': self.internal_net,
                    'name': None,
                    'admin_state_up': True,
                    'device_id': rtr_id,
                    'device_owner': constants.DEVICE_OWNER_ROUTER_INTF,
                    'fixed_ips': attr.ATTR_NOT_SPECIFIED,
                    'mac_address': attr.ATTR_NOT_SPECIFIED,
                    'port_security_enabled': False,
                    'tenant_id': None}}

            port = self.nsxv_plugin.create_port(self.context, port_data)

            address_groups = self._get_address_groups(
                self.context, self.internal_net, rtr_id, is_proxy=True)

            edge_ip = port['fixed_ips'][0]['ip_address']
            edge_utils.update_internal_interface(
                self.nsxv_plugin.nsx_v, self.context, rtr_id,
                self.internal_net, address_groups)

            self._setup_metadata_lb(rtr_id,
                                    port['fixed_ips'][0]['ip_address'],
                                    cfg.CONF.nsxv.nova_metadata_port,
                                    cfg.CONF.nsxv.nova_metadata_port,
                                    cfg.CONF.nsxv.nova_metadata_ips,
                                    proxy_lb=True)

            firewall_rule = {
                'action': 'allow',
                'enabled': True,
                'source_ip_address': [INTERNAL_SUBNET]}

            edge_utils.update_firewall(
                self.nsxv_plugin.nsx_v,
                self.context,
                rtr_id,
                {'firewall_rule_list': [firewall_rule]},
                allow_external=False)

            # If DB Entry already defined by another Neutron instance, remove
            #  and resume
            try:
                nsxv_db.create_nsxv_internal_edge(
                    self.context.session,
                    rtr_ip,
                    nsxv_constants.INTER_EDGE_PURPOSE,
                    rtr_id)
            except db_exc.DBDuplicateEntry:
                self.nsxv_plugin.delete_router(self.context, rtr_id)
                rtr_id = nsxv_db.get_nsxv_internal_edge(self.context, rtr_ip)
                edge_ip = self._get_edge_internal_ip(rtr_id)

            proxy_edge_ids.append(rtr_id)
            proxy_edge_ips.append(edge_ip)
        return proxy_edge_ids, proxy_edge_ips

    def _get_address_groups(self, context, network_id, device_id, is_proxy):

        filters = {'network_id': [network_id],
                   'device_id': [device_id]}
        ports = self.nsxv_plugin.get_ports(context, filters=filters)

        subnets = self.nsxv_plugin.get_subnets(context, filters=filters)

        address_groups = []
        for subnet in subnets:
            address_group = {}
            net = netaddr.IPNetwork(subnet['cidr'])
            address_group['subnetMask'] = str(net.netmask)
            address_group['subnetPrefixLength'] = str(net.prefixlen)
            for port in ports:
                fixed_ips = port['fixed_ips']
                for fip in fixed_ips:
                    s_id = fip['subnet_id']
                    ip_addr = fip['ip_address']
                    if s_id == subnet['id'] and netaddr.valid_ipv4(ip_addr):
                        address_group['primaryAddress'] = ip_addr
                        break

            # For Edge appliances which aren't the metadata proxy Edge
            #  we add the metadata IP address
            if not is_proxy and network_id == self.internal_net:
                address_group['secondaryAddresses'] = {
                    'type': 'secondary_addresses',
                    'ipAddress': [METADATA_IP_ADDR]}

            address_groups.append(address_group)
        return address_groups

    def _setup_metadata_lb(
            self, rtr_id, vip, v_port, s_port, member_ips, proxy_lb=False):

        binding = nsxv_db.get_nsxv_router_binding(self.context.session, rtr_id)
        edge_id = binding['edge_id']
        LOG.debug('Setting up Edge device %s', edge_id)

        lb_obj = nsxv_lb.NsxvLoadbalancer()

        # Create virtual server
        virt_srvr = nsxv_lb.NsxvLBVirtualServer(
            name='MdSrv',
            ip_address=vip,
            port=v_port)

        # For router Edge, we add X-LB-Proxy-ID header
        if not proxy_lb:
            md_app_rule = nsxv_lb.NsxvLBAppRule(
                'insert-mdp',
                'reqadd X-Metadata-Provider:' + edge_id)
            virt_srvr.add_app_rule(md_app_rule)

            # When shared proxy is configured, insert authentication string
            if cfg.CONF.nsxv.metadata_shared_secret:
                signature = hmac.new(
                    cfg.CONF.nsxv.metadata_shared_secret,
                    edge_id,
                    hashlib.sha256).hexdigest()
                sign_app_rule = nsxv_lb.NsxvLBAppRule(
                    'insert-auth',
                    'reqadd X-Metadata-Provider-Signature:' + signature)
                virt_srvr.add_app_rule(sign_app_rule)

        # Create app profile
        #  XFF is inserted in router LBs
        app_profile = nsxv_lb.NsxvLBAppProfile(
            name='MDSrvProxy',
            template='HTTP',
            insert_xff=not proxy_lb)

        virt_srvr.set_app_profile(app_profile)

        # Create pool, members and monitor
        pool = nsxv_lb.NsxvLBPool(
            name='MDSrvPool')

        monitor = nsxv_lb.NsxvLBMonitor(
            name='MDSrvMon')
        pool.add_monitor(monitor)

        i = 0
        for member_ip in member_ips:
            i += 1
            member = nsxv_lb.NsxvLBPoolMember(
                name='Member-%d' % i,
                ip_address=member_ip,
                port=s_port,
                monitor_port=s_port)
            pool.add_member(member)

        virt_srvr.set_default_pool(pool)
        lb_obj.add_virtual_server(virt_srvr)

        lb_obj.submit_to_backend(
            self.nsxv_plugin.nsx_v.vcns,
            edge_id)

    def configure_router_edge(self, rtr_id):
        # Connect router interface to inter-edge network
        port_data = {
            'port': {
                'network_id': self.internal_net,
                'name': None,
                'admin_state_up': True,
                'device_id': rtr_id,
                'device_owner': constants.DEVICE_OWNER_ROUTER_GW,
                'fixed_ips': attr.ATTR_NOT_SPECIFIED,
                'mac_address': attr.ATTR_NOT_SPECIFIED,
                'port_security_enabled': False,
                'tenant_id': None}}

        self.nsxv_plugin.create_port(self.context, port_data)

        address_groups = self._get_address_groups(
            self.context,
            self.internal_net,
            rtr_id,
            is_proxy=False)

        edge_utils.update_internal_interface(
            self.nsxv_plugin.nsx_v,
            self.context,
            rtr_id,
            self.internal_net,
            address_groups=address_groups)

        self._setup_metadata_lb(rtr_id,
                                METADATA_IP_ADDR,
                                METADATA_TCP_PORT,
                                cfg.CONF.nsxv.nova_metadata_port,
                                self.proxy_edge_ips,
                                proxy_lb=False)

    def cleanup_router_edge(self, rtr_id):
        filters = {
            'network_id': [self.internal_net],
            'device_id': [rtr_id]}
        ports = self.nsxv_plugin.get_ports(self.context, filters=filters)

        if ports:
            self.nsxv_plugin.delete_port(
                self.context, ports[0]['id'],
                l3_port_check=False)

    def get_router_fw_rules(self):
        fw_rules = [
            {
                'name': 'MDServiceIP',
                'enabled': True,
                'action': 'allow',
                'destination_ip_address': [METADATA_IP_ADDR]
            },
            {
                'name': 'MDInterEdgeNet',
                'enabled': True,
                'action': 'deny',
                'destination_ip_address': [INTERNAL_SUBNET]
            }]

        return fw_rules
