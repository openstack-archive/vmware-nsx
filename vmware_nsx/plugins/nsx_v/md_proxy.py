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

import eventlet
import netaddr
from neutron_lib import constants
from neutron_lib import context as neutron_context
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsxv_exc
from vmware_nsx.common import locking
from vmware_nsx.common import nsxv_constants
from vmware_nsx.common import utils
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield import (
    nsxv_loadbalancer as nsxv_lb)
from vmware_nsx.plugins.nsx_v.vshield.common import (
    constants as vcns_const)
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.services.lbaas.nsx_v import lbaas_common

METADATA_POOL_NAME = 'MDSrvPool'
METADATA_VSE_NAME = 'MdSrv'
METADATA_IP_ADDR = '169.254.169.254'
METADATA_TCP_PORT = 80
METADATA_HTTPS_PORT = 443
METADATA_HTTPS_VIP_PORT = 8775
INTERNAL_SUBNET = '169.254.128.0/17'
MAX_INIT_THREADS = 3

NET_WAIT_INTERVAL = 240
NET_CHECK_INTERVAL = 10
EDGE_WAIT_INTERVAL = 900
EDGE_CHECK_INTERVAL = 10

LOG = logging.getLogger(__name__)

DEFAULT_EDGE_FIREWALL_RULE = {
    'name': 'VSERule',
    'enabled': True,
    'action': 'allow',
    'source_vnic_groups': ['vse']}


def get_router_fw_rules():
    # build the allowed destination ports list
    int_ports = [METADATA_TCP_PORT,
                 METADATA_HTTPS_PORT,
                 METADATA_HTTPS_VIP_PORT]
    str_ports = [str(p) for p in int_ports]
    # the list of ports can be extended by configuration
    if cfg.CONF.nsxv.metadata_service_allowed_ports:
        str_metadata_ports = [str(p) for p in
                              cfg.CONF.nsxv.metadata_service_allowed_ports]
        str_ports = str_ports + str_metadata_ports
    separator = ','
    dest_ports = separator.join(str_ports)

    fw_rules = [
        DEFAULT_EDGE_FIREWALL_RULE,
        {
            'name': 'MDServiceIP',
            'enabled': True,
            'action': 'allow',
            'destination_ip_address': [METADATA_IP_ADDR],
            'protocol': 'tcp',
            'destination_port': dest_ports
        },
        {
            'name': 'MDInterEdgeNet',
            'enabled': True,
            'action': 'deny',
            'destination_ip_address': [INTERNAL_SUBNET]
        }]

    return fw_rules


def get_db_internal_edge_ips(context, az_name):
    ip_list = []
    edge_list = nsxv_db.get_nsxv_internal_edges_by_purpose(
        context.session,
        vcns_const.InternalEdgePurposes.INTER_EDGE_PURPOSE)

    if edge_list:
        # Take only the edges on this availability zone
        ip_list = [edge['ext_ip_address'] for edge in edge_list
        if nsxv_db.get_router_availability_zone(
            context.session, edge['router_id']) == az_name]
    return ip_list


class NsxVMetadataProxyHandler(object):
    """A metadata proxy handler for a specific availability zone"""
    def __init__(self, nsxv_plugin, availability_zone):
        self.nsxv_plugin = nsxv_plugin
        context = neutron_context.get_admin_context()
        self.az = availability_zone

        # Init cannot run concurrently on multiple nodes
        with locking.LockManager.get_lock('nsx-metadata-init'):
            self.internal_net, self.internal_subnet = (
                self._get_internal_network_and_subnet(context))

            self.proxy_edge_ips = self._get_proxy_edges(context)

    def _create_metadata_internal_network(self, context, cidr):
        # Neutron requires a network to have some tenant_id
        tenant_id = nsxv_constants.INTERNAL_TENANT_ID
        net_name = 'inter-edge-net'
        if not self.az.is_default():
            net_name = '%s-%s' % (net_name, self.az.name)
        net_data = {'network': {'name': net_name,
                                'admin_state_up': True,
                                'port_security_enabled': False,
                                'shared': False,
                                'availability_zone_hints': [self.az.name],
                                'tenant_id': tenant_id}}
        net = self.nsxv_plugin.create_network(context, net_data)

        subnet_data = {'subnet':
                       {'cidr': cidr,
                        'name': 'inter-edge-subnet',
                        'gateway_ip': constants.ATTR_NOT_SPECIFIED,
                        'allocation_pools': constants.ATTR_NOT_SPECIFIED,
                        'ip_version': 4,
                        'dns_nameservers': constants.ATTR_NOT_SPECIFIED,
                        'host_routes': constants.ATTR_NOT_SPECIFIED,
                        'enable_dhcp': False,
                        'network_id': net['id'],
                        'tenant_id': tenant_id}}

        subnet = self.nsxv_plugin.create_subnet(
            context,
            subnet_data)

        return net['id'], subnet['id']

    def _get_internal_net_by_az(self, context):
        # Get the internal network for the current az
        int_net = nsxv_db.get_nsxv_internal_network_for_az(
            context.session,
            vcns_const.InternalEdgePurposes.INTER_EDGE_PURPOSE,
            self.az.name)

        if int_net:
            return int_net['network_id']

    def _get_internal_network_and_subnet(self, context):

        # Try to find internal net, internal subnet. If not found, create new
        internal_net = self._get_internal_net_by_az(context)
        internal_subnet = None

        if internal_net:
            internal_subnet = self.nsxv_plugin.get_subnets(
                context,
                fields=['id'],
                filters={'network_id': [internal_net]})[0]['id']

        if internal_net is None or internal_subnet is None:
            if cfg.CONF.nsxv.metadata_initializer:
                # Couldn't find net, subnet - create new
                try:
                    internal_net, internal_subnet = (
                        self._create_metadata_internal_network(
                            context, INTERNAL_SUBNET))
                except Exception as e:
                    nsxv_db.delete_nsxv_internal_network(
                        context.session,
                        vcns_const.InternalEdgePurposes.INTER_EDGE_PURPOSE,
                        internal_net)

                    # if network is created, clean up
                    if internal_net:
                        self.nsxv_plugin.delete_network(context,
                                                        internal_net)

                    LOG.exception("Exception %s while creating internal "
                                  "network for metadata service", e)
                    return

                # Update the new network_id in DB
                nsxv_db.create_nsxv_internal_network(
                    context.session,
                    nsxv_constants.INTER_EDGE_PURPOSE,
                    self.az.name,
                    internal_net)
            else:
                error = _('Metadata initialization is incomplete on '
                          'initializer node')
                raise nsxv_exc.NsxPluginException(err_msg=error)

        return internal_net, internal_subnet

    def _get_edge_internal_ip(self, context, rtr_id):
        filters = {
            'network_id': [self.internal_net],
            'device_id': [rtr_id]}
        ports = self.nsxv_plugin.get_ports(context, filters=filters)
        if ports:
            return ports[0]['fixed_ips'][0]['ip_address']
        else:
            LOG.error("No port found for metadata for %s", rtr_id)

    def _get_edge_rtr_id_by_ext_ip(self, context, edge_ip):
        rtr_list = nsxv_db.get_nsxv_internal_edge(
            context.session, edge_ip)
        if rtr_list:
            return rtr_list[0]['router_id']

    def _get_edge_id_by_rtr_id(self, context, rtr_id):
        binding = nsxv_db.get_nsxv_router_binding(
            context.session,
            rtr_id)

        if binding:
            return binding['edge_id']

    def _get_proxy_edges(self, context):
        proxy_edge_ips = []

        db_edge_ips = get_db_internal_edge_ips(context, self.az.name)
        if len(db_edge_ips) > len(self.az.mgt_net_proxy_ips):
            error = (_('Number of configured metadata proxy IPs is smaller '
                      'than number of Edges which are already provisioned '
                      'for availability zone %s'), self.az.name)
            raise nsxv_exc.NsxPluginException(err_msg=error)

        pool = eventlet.GreenPool(min(MAX_INIT_THREADS,
                                      len(self.az.mgt_net_proxy_ips)))

        # Edge IPs that exist in both lists have to be validated that their
        # Edge appliance settings are valid
        for edge_inner_ip in pool.imap(
                self._setup_proxy_edge_route_and_connectivity,
                list(set(db_edge_ips) & set(self.az.mgt_net_proxy_ips))):
            proxy_edge_ips.append(edge_inner_ip)

        # Edges that exist only in the CFG list, should be paired with Edges
        # that exist only in the DB list. The existing Edge from the list will
        # be reconfigured to match the new config
        edge_to_convert_ips = (
            list(set(db_edge_ips) - set(self.az.mgt_net_proxy_ips)))
        edge_ip_to_set = (
            list(set(self.az.mgt_net_proxy_ips) - set(db_edge_ips)))

        if edge_to_convert_ips:
            if cfg.CONF.nsxv.metadata_initializer:
                for edge_inner_ip in pool.imap(
                        self._setup_proxy_edge_external_interface_ip,
                        zip(edge_to_convert_ips, edge_ip_to_set)):
                    proxy_edge_ips.append(edge_inner_ip)
            else:
                error = _('Metadata initialization is incomplete on '
                          'initializer node')
                raise nsxv_exc.NsxPluginException(err_msg=error)

        # Edges that exist in the CFG list but do not have a matching DB
        # element will be created.
        remaining_cfg_ips = edge_ip_to_set[len(edge_to_convert_ips):]
        if remaining_cfg_ips:
            if cfg.CONF.nsxv.metadata_initializer:
                for edge_inner_ip in pool.imap(
                        self._setup_new_proxy_edge, remaining_cfg_ips):
                    proxy_edge_ips.append(edge_inner_ip)

                pool.waitall()
            else:
                error = _('Metadata initialization is incomplete on '
                          'initializer node')
                raise nsxv_exc.NsxPluginException(err_msg=error)

        return proxy_edge_ips

    def _setup_proxy_edge_route_and_connectivity(self, rtr_ext_ip,
                                                 rtr_id=None, edge_id=None):
        # Use separate context per each as we use this in tread context
        context = neutron_context.get_admin_context()
        if not rtr_id:
            rtr_id = self._get_edge_rtr_id_by_ext_ip(context, rtr_ext_ip)
        if not edge_id:
            edge_id = self._get_edge_id_by_rtr_id(context, rtr_id)
        if not rtr_id or not edge_id:
            # log this error and return without the ip, but don't fail
            LOG.error("Failed find edge for router %(rtr_id)s with ip "
                      "%(rtr_ext_ip)s",
                      {'rtr_id': rtr_id, 'rtr_ext_ip': rtr_ext_ip})
            return

        # Read and validate DGW. If different, replace with new value
        try:
            # This may fail if the edge was deleted on backend
            h, routes = self.nsxv_plugin.nsx_v.vcns.get_routes(edge_id)
        except exceptions.ResourceNotFound as e:
            # log this error and return without the ip, but don't fail
            LOG.error("Failed to get routes for metadata proxy edge "
                      "%(edge)s: %(err)s",
                      {'edge': edge_id, 'err': e})
            return

        dgw = routes.get('defaultRoute', {}).get('gatewayAddress')

        if dgw != self.az.mgt_net_default_gateway:
            if cfg.CONF.nsxv.metadata_initializer:
                self.nsxv_plugin._update_routes(
                    context, rtr_id,
                    self.az.mgt_net_default_gateway)
            else:
                error = _('Metadata initialization is incomplete on '
                          'initializer node')
                raise nsxv_exc.NsxPluginException(err_msg=error)

        # Read and validate connectivity
        h, if_data = self.nsxv_plugin.nsx_v.get_interface(
            edge_id, vcns_const.EXTERNAL_VNIC_INDEX)
        cur_ip = if_data.get('addressGroups', {}
                             ).get('addressGroups', {}
                                   )[0].get('primaryAddress')
        cur_pgroup = if_data['portgroupId']
        if (if_data and cur_pgroup != self.az.mgt_net_moid
                or cur_ip != rtr_ext_ip):
            if cfg.CONF.nsxv.metadata_initializer:
                self.nsxv_plugin.nsx_v.update_interface(
                    rtr_id,
                    edge_id,
                    vcns_const.EXTERNAL_VNIC_INDEX,
                    self.az.mgt_net_moid,
                    address=rtr_ext_ip,
                    netmask=self.az.mgt_net_proxy_netmask,
                    secondary=[])
            else:
                error = _('Metadata initialization is incomplete on '
                          'initializer node')
                raise nsxv_exc.NsxPluginException(err_msg=error)

        # Read and validate LB pool member configuration
        # When the Nova IP address is changed in the ini file, we should apply
        # this change to the LB pool
        lb_obj = nsxv_lb.NsxvLoadbalancer.get_loadbalancer(
            self.nsxv_plugin.nsx_v.vcns, edge_id)

        vs = lb_obj.virtual_servers.get(METADATA_VSE_NAME)
        update_md_proxy = False
        if vs:
            md_members = {member.payload['ipAddress']: member.payload['name']
                          for member in vs.default_pool.members.values()}

            if len(cfg.CONF.nsxv.nova_metadata_ips) == len(md_members):
                m_ips = md_members.keys()
                m_to_convert = (list(set(m_ips) -
                                     set(cfg.CONF.nsxv.nova_metadata_ips)))
                m_ip_to_set = (list(set(cfg.CONF.nsxv.nova_metadata_ips)
                                    - set(m_ips)))
                if m_to_convert or m_ip_to_set:
                    update_md_proxy = True
                for m_ip in m_to_convert:
                    m_name = md_members[m_ip]
                    vs.default_pool.members[m_name].payload['ipAddress'] = (
                        m_ip_to_set.pop())
            else:
                error = _('Number of metadata members should not change')
                raise nsxv_exc.NsxPluginException(err_msg=error)

            try:
                # This may fail if the edge is powered off right now
                if update_md_proxy:
                    lb_obj.submit_to_backend(self.nsxv_plugin.nsx_v.vcns,
                                             edge_id)
            except exceptions.RequestBad as e:
                # log the error and continue
                LOG.error("Failed to update load balancer on metadata "
                          "proxy edge %(edge)s: %(err)s",
                          {'edge': edge_id, 'err': e})

        edge_ip = self._get_edge_internal_ip(context, rtr_id)

        if edge_ip:
            return edge_ip

    def _setup_proxy_edge_external_interface_ip(self, rtr_ext_ips):
        # Use separate context per each as we use this in tread context
        context = neutron_context.get_admin_context()

        rtr_old_ext_ip, rtr_new_ext_ip = rtr_ext_ips

        rtr_id = self._get_edge_rtr_id_by_ext_ip(context, rtr_old_ext_ip)
        edge_id = self._get_edge_id_by_rtr_id(context, rtr_id)

        # Replace DB entry as we cannot update the table PK
        nsxv_db.delete_nsxv_internal_edge(context.session, rtr_old_ext_ip)

        edge_ip = self._setup_proxy_edge_route_and_connectivity(
            rtr_new_ext_ip, rtr_id, edge_id)

        nsxv_db.create_nsxv_internal_edge(
            context.session, rtr_new_ext_ip,
            vcns_const.InternalEdgePurposes.INTER_EDGE_PURPOSE, rtr_id)

        if edge_ip:
            return edge_ip

    def _setup_new_proxy_edge(self, rtr_ext_ip):
        # Use separate context per each as we use this in tread context
        context = neutron_context.get_admin_context()

        rtr_id = None

        try:
            rtr_name = 'metadata_proxy_router'
            if not self.az.is_default():
                rtr_name = '%s-%s' % (rtr_name, self.az.name)
            router_data = {
                'router': {
                    'name': rtr_name,
                    'admin_state_up': True,
                    'router_type': 'exclusive',
                    'availability_zone_hints': [self.az.name],
                    'tenant_id': nsxv_constants.INTERNAL_TENANT_ID}}

            rtr = self.nsxv_plugin.create_router(
                context,
                router_data,
                allow_metadata=False)

            rtr_id = rtr['id']
            edge_id = self._get_edge_id_by_rtr_id(context, rtr_id)
            if not edge_id:
                LOG.error('No edge create for router - %s', rtr_id)
                if rtr_id:
                    self.nsxv_plugin.delete_router(context, rtr_id)
                return

            self.nsxv_plugin.nsx_v.update_interface(
                rtr['id'],
                edge_id,
                vcns_const.EXTERNAL_VNIC_INDEX,
                self.az.mgt_net_moid,
                address=rtr_ext_ip,
                netmask=self.az.mgt_net_proxy_netmask,
                secondary=[])

            port_data = {
                'port': {
                    'network_id': self.internal_net,
                    'name': None,
                    'admin_state_up': True,
                    'device_id': rtr_id,
                    'device_owner': (constants.DEVICE_OWNER_NETWORK_PREFIX +
                                     'md_interface'),
                    'fixed_ips': constants.ATTR_NOT_SPECIFIED,
                    'mac_address': constants.ATTR_NOT_SPECIFIED,
                    'port_security_enabled': False,
                    'tenant_id': nsxv_constants.INTERNAL_TENANT_ID}}

            port = self.nsxv_plugin.base_create_port(context, port_data)

            address_groups = self._get_address_groups(
                context, self.internal_net, rtr_id, is_proxy=True)

            edge_ip = port['fixed_ips'][0]['ip_address']
            with locking.LockManager.get_lock(edge_id):
                edge_utils.update_internal_interface(
                    self.nsxv_plugin.nsx_v, context, rtr_id,
                    self.internal_net, address_groups)

            self._setup_metadata_lb(rtr_id,
                                    port['fixed_ips'][0]['ip_address'],
                                    cfg.CONF.nsxv.nova_metadata_port,
                                    cfg.CONF.nsxv.nova_metadata_port,
                                    cfg.CONF.nsxv.nova_metadata_ips,
                                    proxy_lb=True)

            firewall_rules = [
                DEFAULT_EDGE_FIREWALL_RULE,
                {
                    'action': 'allow',
                    'enabled': True,
                    'source_ip_address': [INTERNAL_SUBNET]}]

            edge_utils.update_firewall(
                self.nsxv_plugin.nsx_v,
                context,
                rtr_id,
                {'firewall_rule_list': firewall_rules},
                allow_external=False)

            if self.az.mgt_net_default_gateway:
                self.nsxv_plugin._update_routes(
                    context, rtr_id,
                    self.az.mgt_net_default_gateway)

            nsxv_db.create_nsxv_internal_edge(
                context.session, rtr_ext_ip,
                vcns_const.InternalEdgePurposes.INTER_EDGE_PURPOSE, rtr_id)

            return edge_ip

        except Exception as e:
            LOG.exception("Exception %s while creating internal edge "
                          "for metadata service", e)

            ports = self.nsxv_plugin.get_ports(
                context, filters={'device_id': [rtr_id]})

            for port in ports:
                self.nsxv_plugin.delete_port(context, port['id'],
                                             l3_port_check=True,
                                             nw_gw_port_check=True,
                                             allow_delete_internal=True)

            nsxv_db.delete_nsxv_internal_edge(
                context.session,
                rtr_ext_ip)

            if rtr_id:
                self.nsxv_plugin.delete_router(context, rtr_id)

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

    def _create_ssl_cert(self, edge_id=None):
        # Create a self signed certificate in the backend if both Cert details
        # and private key are not supplied in nsx.ini
        if (not cfg.CONF.nsxv.metadata_nova_client_cert and
            not cfg.CONF.nsxv.metadata_nova_client_priv_key):
            h = self.nsxv_plugin.nsx_v.vcns.create_csr(edge_id)[0]
            # Extract the CSR ID from header
            csr_id = lbaas_common.extract_resource_id(h['location'])
            # Create a self signed certificate
            cert = self.nsxv_plugin.nsx_v.vcns.create_csr_cert(csr_id)[1]
            cert_id = cert['objectId']
        else:
            # Raise an error if either the Cert path or the private key is not
            # configured
            error = None
            if not cfg.CONF.nsxv.metadata_nova_client_cert:
                error = _('Metadata certificate path not configured')
            elif not cfg.CONF.nsxv.metadata_nova_client_priv_key:
                error = _('Metadata client private key not configured')
            if error:
                raise nsxv_exc.NsxPluginException(err_msg=error)
            pem_encoding = utils.read_file(
                cfg.CONF.nsxv.metadata_nova_client_cert)
            priv_key = utils.read_file(
                cfg.CONF.nsxv.metadata_nova_client_priv_key)
            request = {
                'pemEncoding': pem_encoding,
                'privateKey': priv_key}
            cert = self.nsxv_plugin.nsx_v.vcns.upload_edge_certificate(
                edge_id, request)[1]
            cert_id = cert.get('certificates')[0]['objectId']
        return cert_id

    def _setup_metadata_lb(self, rtr_id, vip, v_port, s_port, member_ips,
                           proxy_lb=False, context=None):

        if context is None:
            context = neutron_context.get_admin_context()

        edge_id = self._get_edge_id_by_rtr_id(context, rtr_id)
        LOG.debug('Setting up Edge device %s', edge_id)

        lb_obj = nsxv_lb.NsxvLoadbalancer()

        protocol = 'HTTP'
        ssl_pass_through = False
        cert_id = None
        # Set protocol to HTTPS with default port of 443 if metadata_insecure
        # is set to False.
        if not cfg.CONF.nsxv.metadata_insecure:
            protocol = 'HTTPS'
            if proxy_lb:
                v_port = METADATA_HTTPS_VIP_PORT
            else:
                v_port = METADATA_HTTPS_PORT
                # Create the certificate on the backend
                cert_id = self._create_ssl_cert(edge_id)
            ssl_pass_through = proxy_lb
        mon_type = protocol if proxy_lb else 'tcp'
        # Create virtual server
        virt_srvr = nsxv_lb.NsxvLBVirtualServer(
            name=METADATA_VSE_NAME,
            ip_address=vip,
            protocol=protocol,
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
            template=protocol,
            server_ssl_enabled=not cfg.CONF.nsxv.metadata_insecure,
            ssl_pass_through=ssl_pass_through,
            insert_xff=not proxy_lb,
            client_ssl_cert=cert_id)

        virt_srvr.set_app_profile(app_profile)

        # Create pool, members and monitor
        pool = nsxv_lb.NsxvLBPool(
            name=METADATA_POOL_NAME)

        monitor = nsxv_lb.NsxvLBMonitor(name='MDSrvMon',
                                        mon_type=mon_type.lower())
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

        lb_obj.submit_to_backend(self.nsxv_plugin.nsx_v.vcns, edge_id)

    def configure_router_edge(self, context, rtr_id):
        ctx = context.elevated()
        # Connect router interface to inter-edge network
        port_data = {
            'port': {
                'network_id': self.internal_net,
                'name': None,
                'admin_state_up': True,
                'device_id': rtr_id,
                'device_owner': constants.DEVICE_OWNER_ROUTER_GW,
                'fixed_ips': constants.ATTR_NOT_SPECIFIED,
                'mac_address': constants.ATTR_NOT_SPECIFIED,
                'port_security_enabled': False,
                'tenant_id': nsxv_constants.INTERNAL_TENANT_ID}}

        self.nsxv_plugin.base_create_port(ctx, port_data)

        address_groups = self._get_address_groups(
            ctx,
            self.internal_net,
            rtr_id,
            is_proxy=False)

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

    def cleanup_router_edge(self, context, rtr_id, warn=False):
        filters = {
            'network_id': [self.internal_net],
            'device_id': [rtr_id]}
        ctx = context.elevated()
        ports = self.nsxv_plugin.get_ports(ctx, filters=filters)

        if ports:
            if warn:
                LOG.warning("cleanup_router_edge found port %(port)s for "
                            "router %(router)s - deleting it now.",
                            {'port': ports[0]['id'], 'router': rtr_id})
            try:
                self.nsxv_plugin.delete_port(
                    ctx, ports[0]['id'],
                    l3_port_check=False)
            except Exception as e:
                LOG.error("Failed to delete md_proxy port %(port)s: "
                          "%(e)s", {'port': ports[0]['id'], 'e': e})

    def is_md_subnet(self, subnet_id):
        return self.internal_subnet == subnet_id
