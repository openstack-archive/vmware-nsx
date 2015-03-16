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

import eventlet
import hashlib
import hmac
import time

import netaddr
from neutron.api.v2 import attributes as attr
from neutron.common import constants
from neutron import context as neutron_context
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsxv_exc
from vmware_nsx.neutron.plugins.vmware.common import nsxv_constants
from vmware_nsx.neutron.plugins.vmware.dbexts import nsxv_db
from vmware_nsx.neutron.plugins.vmware.vshield import (
    nsxv_loadbalancer as nsxv_lb)
from vmware_nsx.neutron.plugins.vmware.vshield.common import (
    constants as vcns_const)
from vmware_nsx.neutron.plugins.vmware.vshield import edge_utils
from vmware_nsx.openstack.common._i18n import _LE

METADATA_IP_ADDR = '169.254.169.254'
METADATA_TCP_PORT = 80
INTERNAL_SUBNET = '169.254.128.0/17'
MAX_INIT_THREADS = 3

NET_WAIT_INTERVAL = 240
NET_CHECK_INTERVAL = 10
EDGE_WAIT_INTERVAL = 900
EDGE_CHECK_INTERVAL = 10

LOG = logging.getLogger(__name__)


class NsxVMetadataProxyHandler:

    def __init__(self, nsxv_plugin):
        self.nsxv_plugin = nsxv_plugin
        self.context = neutron_context.get_admin_context()

        self.internal_net, self.internal_subnet = (
            self._get_internal_network_and_subnet())

        self.proxy_edge_ips = self._get_proxy_edges()

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

    def _get_internal_net_wait_for_creation(self):
        ctr = 0
        net_id = None
        while net_id is None and ctr < NET_WAIT_INTERVAL:
            # Another neutron instance may be in the process of creating this
            # network. If so, we will have a network with a NULL network id.
            # Therefore, if we have a network entry, we wail for its ID to show
            # up in the DB entry. If no entry exists, we exit and create the
            # network.
            net_list = nsxv_db.get_nsxv_internal_network(
                self.context.session,
                vcns_const.InternalEdgePurposes.INTER_EDGE_PURPOSE)

            if net_list:
                net_id = net_list[0]['network_id']

                # Network found - do we have an ID?
                if net_id:
                    return net_id
            else:
                # No network creation in progress - exit.
                return

            self.context.session.expire_all()
            ctr += NET_CHECK_INTERVAL
            time.sleep(NET_CHECK_INTERVAL)

        error = _('Network creation on other neutron instance timed out')
        raise nsxv_exc.NsxPluginException(err_msg=error)

    def _get_internal_network(self):
        internal_net = self._get_internal_net_wait_for_creation()
        internal_subnet = None

        if internal_net:
            internal_subnet = self.nsxv_plugin.get_subnets(
                self.context,
                fields=['id'],
                filters={'network_id': [internal_net]})[0]['id']

        return internal_net, internal_subnet

    def _get_internal_network_and_subnet(self):
        internal_net = None
        internal_subnet = None

        try:
            nsxv_db.create_nsxv_internal_network(
                self.context.session,
                nsxv_constants.INTER_EDGE_PURPOSE,
                None)
        except db_exc.DBDuplicateEntry:
            # We may have a race condition, where another Neutron instance
            #  initialized these elements. Use existing elements
            return self._get_internal_network()

        try:
            internal_net, internal_subnet = (
                self._create_metadata_internal_network(INTERNAL_SUBNET))
        except Exception as e:
            with excutils.save_and_reraise_exception():
                nsxv_db.delete_nsxv_internal_network(
                    self.context.session,
                    vcns_const.InternalEdgePurposes.INTER_EDGE_PURPOSE)

                # if network is created, clean up
                if internal_net:
                    self.nsxv_plugin.delete_network(self.context, internal_net)

                LOG.exception(_LE("Exception %s while creating internal "
                                  "network for metadata service"), e)

        # Update the new network_id in DB
        nsxv_db.update_nsxv_internal_network(
            self.context.session,
            nsxv_constants.INTER_EDGE_PURPOSE,
            internal_net)

        return internal_net, internal_subnet

    def _get_edge_internal_ip(self, rtr_id):
            filters = {
                'network_id': [self.internal_net],
                'device_id': [rtr_id]}
            ports = self.nsxv_plugin.get_ports(self.context, filters=filters)
            return ports[0]['fixed_ips'][0]['ip_address']

    def _get_proxy_edges(self):
        proxy_edge_ips = []

        pool = eventlet.GreenPool(min(MAX_INIT_THREADS,
                                      len(cfg.CONF.nsxv.mgt_net_proxy_ips)))

        for edge_ip in pool.imap(
                self._get_proxy_edge,
                cfg.CONF.nsxv.mgt_net_proxy_ips):
            proxy_edge_ips.append(edge_ip)

        pool.waitall()
        return proxy_edge_ips

    def _get_proxy_edge(self, rtr_ip):

        # If DB Entry already defined by another Neutron instance, retrieve
        # its IP address and exit
        try:
            nsxv_db.create_nsxv_internal_edge(
                self.context.session,
                rtr_ip,
                vcns_const.InternalEdgePurposes.INTER_EDGE_PURPOSE,
                None)
        except db_exc.DBDuplicateEntry:
            edge_ip = None
            ctr = 0
            while edge_ip is None and ctr < EDGE_WAIT_INTERVAL:
                rtr_list = nsxv_db.get_nsxv_internal_edge(
                    self.context.session, rtr_ip)
                if rtr_list:
                    rtr_id = rtr_list[0]['router_id']
                    if rtr_id:
                        edge_ip = self._get_edge_internal_ip(rtr_id)
                        if edge_ip:
                            return edge_ip

                self.context.session.expire_all()
                ctr += EDGE_CHECK_INTERVAL
                time.sleep(EDGE_CHECK_INTERVAL)

            error = _('Metadata proxy creation on other neutron instance '
                      'timed out')
            raise nsxv_exc.NsxPluginException(err_msg=error)

        rtr_id = None
        try:
            router_data = {
                'router': {
                    'name': 'metadata_proxy_router',
                    'admin_state_up': True,
                    'router_type': 'exclusive',
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

            if cfg.CONF.nsxv.mgt_net_default_gateway:
                self.nsxv_plugin._update_routes(
                    self.context, rtr_id,
                    cfg.CONF.nsxv.mgt_net_default_gateway)

            nsxv_db.update_nsxv_internal_edge(
                self.context.session,
                rtr_ip,
                rtr_id)

            return edge_ip

        except Exception as e:
            with excutils.save_and_reraise_exception():
                nsxv_db.delete_nsxv_internal_edge(
                    self.context.session,
                    rtr_ip)

                if rtr_id:
                    self.nsxv_plugin.delete_router(self.context, rtr_id)
                LOG.exception(_LE("Exception %s while creating internal edge "
                                  "for metadata service"), e)

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

    def _setup_metadata_lb(self, rtr_id, vip, v_port, s_port, member_ips,
                           proxy_lb=False, context=None):

        if context is None:
            context = self.context

        binding = nsxv_db.get_nsxv_router_binding(context.session, rtr_id)
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

    def configure_router_edge(self, rtr_id, context=None):
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

        if context is None:
            context = self.context

        edge_utils.update_internal_interface(
            self.nsxv_plugin.nsx_v,
            context,
            rtr_id,
            self.internal_net,
            address_groups=address_groups)

        self._setup_metadata_lb(rtr_id,
                                METADATA_IP_ADDR,
                                METADATA_TCP_PORT,
                                cfg.CONF.nsxv.nova_metadata_port,
                                self.proxy_edge_ips,
                                proxy_lb=False,
                                context=context)

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
