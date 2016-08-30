# Copyright 2015 VMware, Inc.
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

import xml.etree.ElementTree as et

import netaddr
from oslo_log import log as logging
from oslo_utils import excutils

from neutron.common import exceptions as n_exc
from neutron.i18n import _LE
from neutron import manager
from neutron.plugins.common import constants
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import (
    exceptions as nsxv_exc)
from vmware_nsx.plugins.nsx_v.vshield import vcns as nsxv_api


LOG = logging.getLogger(__name__)

LB_METHOD_ROUND_ROBIN = 'ROUND_ROBIN'
LB_METHOD_LEAST_CONNECTIONS = 'LEAST_CONNECTIONS'
LB_METHOD_SOURCE_IP = 'SOURCE_IP'

LB_PROTOCOL_TCP = 'TCP'
LB_PROTOCOL_HTTP = 'HTTP'
LB_PROTOCOL_HTTPS = 'HTTPS'

LB_HEALTH_MONITOR_PING = 'PING'
LB_HEALTH_MONITOR_TCP = 'TCP'
LB_HEALTH_MONITOR_HTTP = 'HTTP'
LB_HEALTH_MONITOR_HTTPS = 'HTTPS'

LB_SESSION_PERSISTENCE_SOURCE_IP = 'SOURCE_IP'
LB_SESSION_PERSISTENCE_HTTP_COOKIE = 'HTTP_COOKIE'
LB_SESSION_PERSISTENCE_APP_COOKIE = 'APP_COOKIE'

BALANCE_MAP = {
    LB_METHOD_ROUND_ROBIN: 'round-robin',
    LB_METHOD_LEAST_CONNECTIONS: 'leastconn',
    LB_METHOD_SOURCE_IP: 'ip-hash'}

PROTOCOL_MAP = {
    LB_PROTOCOL_TCP: 'tcp',
    LB_PROTOCOL_HTTP: 'http',
    LB_PROTOCOL_HTTPS: 'tcp'}

HEALTH_MONITOR_MAP = {
    LB_HEALTH_MONITOR_PING: 'icmp',
    LB_HEALTH_MONITOR_TCP: 'tcp',
    LB_HEALTH_MONITOR_HTTP: 'http',
    LB_HEALTH_MONITOR_HTTPS: 'tcp'}

SESSION_PERSISTENCE_METHOD_MAP = {
    LB_SESSION_PERSISTENCE_SOURCE_IP: 'sourceip',
    LB_SESSION_PERSISTENCE_APP_COOKIE: 'cookie',
    LB_SESSION_PERSISTENCE_HTTP_COOKIE: 'cookie'}

SESSION_PERSISTENCE_COOKIE_MAP = {
    LB_SESSION_PERSISTENCE_APP_COOKIE: 'app',
    LB_SESSION_PERSISTENCE_HTTP_COOKIE: 'insert'}

LBAAS_FW_SECTION_NAME = 'LBaaS FW Rules'

MEMBER_ID_PFX = 'member-'


def convert_lbaas_pool(lbaas_pool):
    """
    Transform OpenStack pool dict to NSXv pool dict.
    """
    edge_pool = {
        'name': 'pool_' + lbaas_pool['id'],
        'description': lbaas_pool.get('description',
                                      lbaas_pool.get('name')),
        'algorithm': BALANCE_MAP.get(
            lbaas_pool.get('lb_method'), 'round-robin'),
        'transparent': False
    }
    return edge_pool


def convert_lbaas_app_profile(name, sess_persist, protocol):
    """
    Create app profile dict for lbaas VIP.

    Neutron-lbaas VIP objects breaks into an application profile object, and
    a virtual server object in NSXv.
    """
    vcns_app_profile = {
        'insertXForwardedFor': False,
        'name': name,
        'serverSslEnabled': False,
        'sslPassthrough': False,
        'template': protocol,
    }
    # Since SSL Termination is not supported right now, so just use
    # sslPassthrough method if the protocol is HTTPS.
    if protocol == LB_PROTOCOL_HTTPS:
        vcns_app_profile['sslPassthrough'] = True

    if sess_persist:
        persist_type = sess_persist.get('type')
        if persist_type:
            # If protocol is not HTTP, only source_ip is supported
            if (protocol != LB_PROTOCOL_HTTP and
                    persist_type != LB_SESSION_PERSISTENCE_SOURCE_IP):
                msg = (_('Invalid %(protocol)s persistence method: %(type)s') %
                       {'protocol': protocol,
                        'type': persist_type})
                raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
            persistence = {
                'method': SESSION_PERSISTENCE_METHOD_MAP.get(persist_type)}
            if persist_type in SESSION_PERSISTENCE_COOKIE_MAP:
                persistence.update({
                    'cookieName': sess_persist.get('cookie_name',
                                                   'default_cookie_name'),
                    'cookieMode': SESSION_PERSISTENCE_COOKIE_MAP[persist_type]}
                )

            vcns_app_profile['persistence'] = persistence
    return vcns_app_profile


def convert_lbaas_vip(vip, app_profile_id, pool_mapping):
    """
    Transform OpenStack VIP dict to NSXv virtual server dict.
    """
    pool_id = pool_mapping['edge_pool_id']
    return {
        'name': 'vip_' + vip['id'],
        'description': vip['description'],
        'ipAddress': vip['address'],
        'protocol': vip.get('protocol'),
        'port': vip['protocol_port'],
        'connectionLimit': max(0, vip.get('connection_limit')),
        'defaultPoolId': pool_id,
        'applicationProfileId': app_profile_id}


def convert_lbaas_member(member):
    """
    Transform OpenStack pool member dict to NSXv pool member dict.
    """
    return {
        'ipAddress': member['address'],
        'weight': member['weight'],
        'port': member['protocol_port'],
        'monitorPort': member['protocol_port'],
        'name': get_member_id(member['id']),
        'condition': 'enabled' if member['admin_state_up'] else 'disabled'}


def convert_lbaas_monitor(monitor):
    """
    Transform OpenStack health monitor dict to NSXv health monitor dict.
    """
    mon = {
        'type': HEALTH_MONITOR_MAP.get(
            monitor['type'], 'icmp'),
        'interval': monitor['delay'],
        'timeout': monitor['timeout'],
        'maxRetries': monitor['max_retries'],
        'name': monitor['id']}

    if monitor.get('http_method'):
        mon['method'] = monitor['http_method']

    if monitor.get('url_path'):
        mon['url'] = monitor['url_path']
    return mon


def extract_resource_id(location_uri):
    """
    Edge assigns an ID for each resource that is being created:
    it is postfixes the uri specified in the Location header.
    This ID should be used while updating/deleting this resource.
    """
    uri_elements = location_uri.split('/')
    return uri_elements[-1]


def get_subnet_primary_ip(ip_addr, address_groups):
    """
    Retrieve the primary IP of an interface that's attached to the same subnet.
    """
    addr_group = find_address_in_same_subnet(ip_addr, address_groups)
    return addr_group['primaryAddress'] if addr_group else None


def find_address_in_same_subnet(ip_addr, address_groups):
    """
    Lookup an address group with a matching subnet to ip_addr.
    If found, return address_group.
    """
    for address_group in address_groups['addressGroups']:
        net_addr = '%(primaryAddress)s/%(subnetPrefixLength)s' % address_group
        if netaddr.IPAddress(ip_addr) in netaddr.IPNetwork(net_addr):
            return address_group


def add_address_to_address_groups(ip_addr, address_groups):
    """
    Add ip_addr as a secondary IP address to an address group which belongs to
    the same subnet.
    """
    address_group = find_address_in_same_subnet(
        ip_addr, address_groups)
    if address_group:
        sec_addr = address_group.get('secondaryAddresses')
        if not sec_addr:
            sec_addr = {
                'type': 'secondary_addresses',
                'ipAddress': [ip_addr]}
        else:
            sec_addr['ipAddress'].append(ip_addr)
        address_group['secondaryAddresses'] = sec_addr
        return True
    return False


def del_address_from_address_groups(ip_addr, address_groups):
    """
    Delete ip_addr from secondary address list in address groups.
    """
    address_group = find_address_in_same_subnet(ip_addr, address_groups)
    if address_group:
        sec_addr = address_group.get('secondaryAddresses')
        if sec_addr and ip_addr in sec_addr['ipAddress']:
            sec_addr['ipAddress'].remove(ip_addr)
            return True
    return False


def get_member_id(member_id):
    return MEMBER_ID_PFX + member_id


class EdgeLbDriver(object):
    def __init__(self):
        super(EdgeLbDriver, self).__init__()
        LOG.debug('Initializing Edge loadbalancer')
        # self.vcns is initialized by subclass
        self.vcns = None
        self._fw_section_id = None
        self._lb_plugin = None
        self._lb_driver_prop = None

    def _get_lb_plugin(self):
        if not self._lb_plugin:
            loaded_plugins = manager.NeutronManager.get_service_plugins()
            self._lb_plugin = loaded_plugins.get(constants.LOADBALANCER)
        return self._lb_plugin

    @property
    def _lb_driver(self):
        if not self._lb_driver_prop:
            plugin = self._get_lb_plugin()
            self._lb_driver_prop = plugin.drivers['vmwareedge']

        return self._lb_driver_prop

    def _get_lbaas_fw_section_id(self):
        if not self._fw_section_id:
            # Avoid concurrent creation of section by multiple neutron
            # instances
            with locking.LockManager.get_lock('lbaas-section-creation'):
                fw_section_id = self.vcns.get_section_id(LBAAS_FW_SECTION_NAME)
                if not fw_section_id:
                    section = et.Element('section')
                    section.attrib['name'] = LBAAS_FW_SECTION_NAME
                    sect = self.vcns.create_section('ip',
                                                    et.tostring(section))[1]
                    fw_section_id = et.fromstring(sect).attrib['id']
                self._fw_section_id = fw_section_id
        return self._fw_section_id

    def _get_lb_edge_id(self, context, subnet_id):
        """
        Grab the id of an Edge appliance that is connected to subnet_id.
        """
        subnet = self.callbacks.plugin.get_subnet(context, subnet_id)
        net_id = subnet.get('network_id')
        filters = {'network_id': [net_id],
                   'device_owner': ['network:router_interface']}
        attached_routers = self.callbacks.plugin.get_ports(
            context.elevated(), filters=filters,
            fields=['device_id'])

        for attached_router in attached_routers:
            router = self.callbacks.plugin.get_router(
                context, attached_router['device_id'])
            if router['router_type'] == 'exclusive':
                rtr_bindings = nsxv_db.get_nsxv_router_binding(
                    context.session, router['id'])
                return rtr_bindings['edge_id']

    def _vip_as_secondary_ip(self, edge_id, vip, handler):
        with locking.LockManager.get_lock(edge_id):
            r = self.vcns.get_interfaces(edge_id)[1]
            vnics = r.get('vnics', [])
            for vnic in vnics:
                if vnic['type'] == 'trunk':
                    for sub_interface in vnic.get('subInterfaces').get(
                            'subInterfaces'):
                        address_groups = sub_interface.get('addressGroups')
                        if handler(vip, address_groups):
                            self.vcns.update_interface(edge_id, vnic)
                            return True
                else:
                    address_groups = vnic.get('addressGroups')
                    if handler(vip, address_groups):
                        self.vcns.update_interface(edge_id, vnic)
                        return True
        return False

    def _add_vip_as_secondary_ip(self, edge_id, vip):
        """
        Edge appliance requires that a VIP will be configured as a primary
        or a secondary IP address on an interface.
        To do so, we locate an interface which is connected to the same subnet
        that vip belongs to.
        This can be a regular interface, on a sub-interface on a trunk.
        """
        if not self._vip_as_secondary_ip(
                edge_id, vip, add_address_to_address_groups):

            msg = _('Failed to add VIP %(vip)s as secondary IP on '
                    'Edge %(edge_id)s') % {'vip': vip, 'edge_id': edge_id}
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

    def _del_vip_as_secondary_ip(self, edge_id, vip):
        """
        While removing vip, delete the secondary interface from Edge config.
        """
        if not self._vip_as_secondary_ip(
                edge_id, vip, del_address_from_address_groups):

            msg = _('Failed to delete VIP %(vip)s as secondary IP on '
                    'Edge %(edge_id)s') % {'vip': vip, 'edge_id': edge_id}
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

    def _get_edge_ips(self, edge_id):
        edge_ips = []
        r = self.vcns.get_interfaces(edge_id)[1]
        vnics = r.get('vnics', [])
        for vnic in vnics:
            if vnic['type'] == 'trunk':
                for sub_interface in vnic.get('subInterfaces').get(
                        'subInterfaces'):
                    address_groups = sub_interface.get('addressGroups')
                    for address_group in address_groups['addressGroups']:
                        edge_ips.append(address_group['primaryAddress'])

            else:
                address_groups = vnic.get('addressGroups')
                for address_group in address_groups['addressGroups']:
                    edge_ips.append(address_group['primaryAddress'])
        return edge_ips

    def _update_pool_fw_rule(self, context, pool_id, edge_id,
                             operation=None, address=None):
        edge_ips = self._get_edge_ips(edge_id)

        plugin = self._get_lb_plugin()
        with locking.LockManager.get_lock('lbaas-fw-section'):
            members = plugin.get_members(
                context,
                filters={'pool_id': [pool_id]},
                fields=['address'])
            member_ips = [member['address'] for member in members]
            if operation == 'add' and address not in member_ips:
                member_ips.append(address)
            elif operation == 'del' and address in member_ips:
                member_ips.remove(address)

            section_uri = '%s/%s/%s' % (nsxv_api.FIREWALL_PREFIX,
                                        'layer3sections',
                                        self._get_lbaas_fw_section_id())
            xml_section = self.vcns.get_section(section_uri)[1]
            section = et.fromstring(xml_section)
            pool_rule = None
            for rule in section.iter('rule'):
                if rule.find('name').text == pool_id:
                    pool_rule = rule
                    if member_ips:
                        pool_rule.find('sources').find('source').find(
                            'value').text = (','.join(edge_ips))
                        pool_rule.find('destinations').find(
                            'destination').find('value').text = ','.join(
                            member_ips)
                    else:
                        section.remove(pool_rule)
                    break

            if member_ips and pool_rule is None:
                pool_rule = et.SubElement(section, 'rule')
                et.SubElement(pool_rule, 'name').text = pool_id
                et.SubElement(pool_rule, 'action').text = 'allow'
                sources = et.SubElement(pool_rule, 'sources')
                sources.attrib['excluded'] = 'false'
                source = et.SubElement(sources, 'source')
                et.SubElement(source, 'type').text = 'Ipv4Address'
                et.SubElement(source, 'value').text = ','.join(edge_ips)

                destinations = et.SubElement(pool_rule, 'destinations')
                destinations.attrib['excluded'] = 'false'
                destination = et.SubElement(destinations, 'destination')
                et.SubElement(destination, 'type').text = 'Ipv4Address'
                et.SubElement(destination, 'value').text = ','.join(member_ips)

            self.vcns.update_section(section_uri,
                                     et.tostring(section, encoding="us-ascii"),
                                     None)

    def _add_vip_fw_rule(self, edge_id, vip_id, ip_address):
        fw_rule = {
            'firewallRules': [
                {'action': 'accept', 'destination': {
                    'ipAddress': [ip_address]},
                 'enabled': True,
                 'name': vip_id}]}

        with locking.LockManager.get_lock(edge_id):
            h = self.vcns.add_firewall_rule(edge_id, fw_rule)[0]
        fw_rule_id = extract_resource_id(h['location'])

        return fw_rule_id

    def _del_vip_fw_rule(self, edge_id, vip_fw_rule_id):
        with locking.LockManager.get_lock(edge_id):
            self.vcns.delete_firewall_rule(edge_id, vip_fw_rule_id)

    def create_pool(self, context, pool):
        LOG.debug('Creating pool %s', pool)
        edge_id = self._get_lb_edge_id(context, pool['subnet_id'])

        if edge_id is None:
            self._lb_driver.pool_failed(context, pool)
            msg = _(
                'No suitable Edge found for subnet %s') % pool['subnet_id']
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

        edge_pool = convert_lbaas_pool(pool)
        try:
            with locking.LockManager.get_lock(edge_id):
                h = self.vcns.create_pool(edge_id, edge_pool)[0]
            edge_pool_id = extract_resource_id(h['location'])
            self._lb_driver.create_pool_successful(
                context, pool, edge_id, edge_pool_id)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self._lb_driver.pool_failed(context, pool)
                LOG.error(_LE('Failed to create pool %s'), pool['id'])

    def update_pool(self, context, old_pool, pool, pool_mapping):
        LOG.debug('Updating pool %s to %s', old_pool, pool)
        edge_pool = convert_lbaas_pool(pool)
        try:
            with locking.LockManager.get_lock(pool_mapping['edge_id'],
                                              external=True):
                curr_pool = self.vcns.get_pool(pool_mapping['edge_id'],
                                               pool_mapping['edge_pool_id'])[1]
                curr_pool.update(edge_pool)
                self.vcns.update_pool(pool_mapping['edge_id'],
                                      pool_mapping['edge_pool_id'],
                                      curr_pool)
                self._lb_driver.pool_successful(context, pool)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self._lb_driver.pool_failed(context, pool)
                LOG.error(_LE('Failed to update pool %s'), pool['id'])

    def delete_pool(self, context, pool, pool_mapping):
        LOG.debug('Deleting pool %s', pool)

        if pool_mapping:
            try:
                with locking.LockManager.get_lock(pool_mapping['edge_id']):
                    self.vcns.delete_pool(pool_mapping['edge_id'],
                                          pool_mapping['edge_pool_id'])
            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self._lb_driver.pool_failed(context, pool)
                    LOG.error(_LE('Failed to delete pool %s'), pool['id'])
        else:
            LOG.error(_LE('No mapping found for pool %s'), pool['id'])

        self._lb_driver.delete_pool_successful(context, pool)

    def create_vip(self, context, vip, pool_mapping):
        LOG.debug('Create VIP %s', vip)

        app_profile = convert_lbaas_app_profile(
            vip['id'], vip.get('session_persistence') or {},
            vip.get('protocol'))

        if not pool_mapping:
            msg = _('Pool %s in not mapped to any Edge appliance') % (
                vip['pool_id'])
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
        edge_id = pool_mapping['edge_id']

        app_profile_id = None
        try:
            with locking.LockManager.get_lock(edge_id):
                h = (self.vcns.create_app_profile(edge_id, app_profile))[0]
            app_profile_id = extract_resource_id(h['location'])
        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self._lb_driver.vip_failed(context, vip)
                LOG.error(_LE('Failed to create app profile on edge: %s'),
                          edge_id)

        edge_vip = convert_lbaas_vip(vip, app_profile_id, pool_mapping)
        try:
            self._add_vip_as_secondary_ip(edge_id, vip['address'])
            with locking.LockManager.get_lock(edge_id):
                h = self.vcns.create_vip(edge_id, edge_vip)[0]
            edge_vip_id = extract_resource_id(h['location'])
            edge_fw_rule_id = self._add_vip_fw_rule(edge_id, vip['id'],
                                                    vip['address'])
            self._lb_driver.create_vip_successful(
                context, vip, edge_id, app_profile_id, edge_vip_id,
                edge_fw_rule_id)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self._lb_driver.vip_failed(context, vip)
                LOG.error(_LE('Failed to create vip on Edge: %s'), edge_id)
                with locking.LockManager.get_lock(edge_id):
                    self.vcns.delete_app_profile(edge_id, app_profile_id)

    def update_vip(self, context, old_vip, vip, pool_mapping, vip_mapping):
        LOG.debug('Updating VIP %s to %s', old_vip, vip)

        edge_id = vip_mapping['edge_id']
        edge_vip_id = vip_mapping['edge_vse_id']
        app_profile_id = vip_mapping['edge_app_profile_id']
        app_profile = convert_lbaas_app_profile(
            vip['name'], vip.get('session_persistence') or {},
            vip.get('protocol'))
        try:
            with locking.LockManager.get_lock(edge_id):
                self.vcns.update_app_profile(edge_id, app_profile_id,
                                             app_profile)
        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self._lb_driver.vip_failed(context, vip)
                LOG.error(_LE('Failed to update app profile on edge: %s'),
                          edge_id)

        edge_vip = convert_lbaas_vip(vip, app_profile_id, pool_mapping)
        try:
            with locking.LockManager.get_lock(edge_id):
                self.vcns.update_vip(edge_id, edge_vip_id, edge_vip)
            self._lb_driver.vip_successful(context, vip)
        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self._lb_driver.vip_failed(context, vip)
                LOG.error(_LE('Failed to update vip on edge: %s'), edge_id)

    def delete_vip(self, context, vip, vip_mapping):
        LOG.debug('Deleting VIP %s', vip)

        if not vip_mapping:
            LOG.error(_LE('No mapping found for vip %s'), vip['id'])
        else:
            edge_id = vip_mapping['edge_id']
            edge_vse_id = vip_mapping['edge_vse_id']
            app_profile_id = vip_mapping['edge_app_profile_id']

            try:
                with locking.LockManager.get_lock(edge_id):
                    self.vcns.delete_vip(edge_id, edge_vse_id)
                self._del_vip_as_secondary_ip(edge_id, vip['address'])
                self._del_vip_fw_rule(edge_id, vip_mapping['edge_fw_rule_id'])
            except nsxv_exc.ResourceNotFound:
                LOG.error(_LE('vip not found on edge: %s'), edge_id)
            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self._lb_driver.vip_failed(context, vip)
                    LOG.error(
                        _LE('Failed to delete vip on edge: %s'), edge_id)

            try:
                with locking.LockManager.get_lock(edge_id):
                    self.vcns.delete_app_profile(edge_id, app_profile_id)
            except nsxv_exc.ResourceNotFound:
                LOG.error(_LE('app profile not found on edge: %s'), edge_id)
            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self._lb_driver.vip_failed(context, vip)
                    LOG.error(
                        _LE('Failed to delete app profile on Edge: %s'),
                        edge_id)

        self._lb_driver.delete_vip_successful(context, vip)

    def create_member(self, context, member, pool_mapping):
        LOG.debug('Creating member %s', member)

        with locking.LockManager.get_lock(pool_mapping['edge_id']):
            edge_pool = self.vcns.get_pool(pool_mapping['edge_id'],
                                           pool_mapping['edge_pool_id'])[1]
            edge_member = convert_lbaas_member(member)

            if edge_pool['member']:
                edge_pool['member'].append(edge_member)
            else:
                edge_pool['member'] = [edge_member]

            try:
                self.vcns.update_pool(
                    pool_mapping['edge_id'],
                    pool_mapping['edge_pool_id'],
                    edge_pool)

                self._update_pool_fw_rule(context, member['pool_id'],
                                          pool_mapping['edge_id'],
                                          'add',
                                          member['address'])
                self._lb_driver.member_successful(context, member)

            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self._lb_driver.member_failed(context, member)
                    LOG.error(_LE('Failed to create member on edge: %s'),
                              pool_mapping['edge_id'])

    def update_member(self, context, old_member, member, pool_mapping):
        LOG.debug('Updating member %s to %s', old_member, member)

        with locking.LockManager.get_lock(pool_mapping['edge_id']):
            edge_pool = self.vcns.get_pool(pool_mapping['edge_id'],
                                           pool_mapping['edge_pool_id'])[1]

            edge_member = convert_lbaas_member(member)
            for i, m in enumerate(edge_pool['member']):
                if m['name'] == get_member_id(member['id']):
                    edge_pool['member'][i] = edge_member
                    break

            try:
                self.vcns.update_pool(pool_mapping['edge_id'],
                                      pool_mapping['edge_pool_id'],
                                      edge_pool)
                self._lb_driver.member_successful(context, member)
            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self._lb_driver.member_failed(context, member)
                    LOG.error(_LE('Failed to update member on edge: %s'),
                              pool_mapping['edge_id'])

    def delete_member(self, context, member, pool_mapping):
        LOG.debug('Deleting member %s', member)

        if pool_mapping:
            with locking.LockManager.get_lock(pool_mapping['edge_id']):
                edge_pool = self.vcns.get_pool(
                    pool_mapping['edge_id'],
                    pool_mapping['edge_pool_id'])[1]

                for i, m in enumerate(edge_pool['member']):
                    if m['name'] == get_member_id(member['id']):
                        edge_pool['member'].pop(i)
                        break

                try:
                    self.vcns.update_pool(pool_mapping['edge_id'],
                                          pool_mapping['edge_pool_id'],
                                          edge_pool)
                    self._update_pool_fw_rule(context, member['pool_id'],
                                              pool_mapping['edge_id'],
                                              'del',
                                              member['address'])
                except nsxv_exc.VcnsApiException:
                    with excutils.save_and_reraise_exception():
                        self._lb_driver.member_failed(context, member)
                        LOG.error(_LE('Failed to update member on edge: %s'),
                                  pool_mapping['edge_id'])

        lb_plugin = self._get_lb_plugin()
        lb_plugin._delete_db_member(context, member['id'])

    def create_pool_health_monitor(self, context, health_monitor, pool_id,
                                   pool_mapping, mon_mappings):
        LOG.debug('Create HM %s', health_monitor)

        edge_mon_id = None
        with locking.LockManager.get_lock(pool_mapping['edge_id']):
            # 1st, we find if we already have a pool with the same monitor, on
            # the same Edge appliance.
            # If there is no pool on this Edge which is already associated with
            # this monitor, create this monitor on Edge
            if mon_mappings:
                edge_mon_id = mon_mappings['edge_monitor_id']
            else:
                edge_monitor = convert_lbaas_monitor(health_monitor)
                try:
                    h = self.vcns.create_health_monitor(
                        pool_mapping['edge_id'], edge_monitor)[0]
                    edge_mon_id = extract_resource_id(h['location'])

                except nsxv_exc.VcnsApiException:
                    self._lb_driver.pool_health_monitor_failed(context,
                                                               health_monitor,
                                                               pool_id)
                    with excutils.save_and_reraise_exception():
                        LOG.error(
                            _LE('Failed to associate monitor on edge: %s'),
                            pool_mapping['edge_id'])

            try:
                # Associate monitor with Edge pool
                edge_pool = self.vcns.get_pool(pool_mapping['edge_id'],
                                               pool_mapping['edge_pool_id'])[1]
                if edge_pool['monitorId']:
                    edge_pool['monitorId'].append(edge_mon_id)
                else:
                    edge_pool['monitorId'] = [edge_mon_id]

                self.vcns.update_pool(pool_mapping['edge_id'],
                                      pool_mapping['edge_pool_id'],
                                      edge_pool)

            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self._lb_driver.pool_health_monitor_failed(context,
                                                               health_monitor,
                                                               pool_id)
                    LOG.error(
                        _LE('Failed to associate monitor on edge: %s'),
                        pool_mapping['edge_id'])

        self._lb_driver.create_pool_health_monitor_successful(
            context, health_monitor, pool_id, pool_mapping['edge_id'],
            edge_mon_id)

    def update_pool_health_monitor(self, context, old_health_monitor,
                                   health_monitor, pool_id, mon_mapping):
        LOG.debug('Update HM %s to %s', old_health_monitor, health_monitor)

        edge_monitor = convert_lbaas_monitor(health_monitor)

        try:
            with locking.LockManager.get_lock(mon_mapping['edge_id']):
                self.vcns.update_health_monitor(
                    mon_mapping['edge_id'],
                    mon_mapping['edge_monitor_id'],
                    edge_monitor)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self._lb_driver.pool_health_monitor_failed(context,
                                                           health_monitor,
                                                           pool_id)
                LOG.error(
                    _LE('Failed to update monitor on edge: %s'),
                    mon_mapping['edge_id'])

        self._lb_driver.pool_health_monitor_successful(context,
                                                       health_monitor,
                                                       pool_id)

    def delete_pool_health_monitor(self, context, health_monitor, pool_id,
                                   pool_mapping, mon_mapping):
        LOG.debug('Deleting HM %s', health_monitor)

        edge_id = pool_mapping['edge_id']
        if not mon_mapping:
            return

        with locking.LockManager.get_lock(pool_mapping['edge_id']):
            edge_pool = self.vcns.get_pool(edge_id,
                                           pool_mapping['edge_pool_id'])[1]
            edge_pool['monitorId'].remove(mon_mapping['edge_monitor_id'])

            try:
                self.vcns.update_pool(edge_id,
                                      pool_mapping['edge_pool_id'],
                                      edge_pool)
            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self._lb_driver.pool_health_monitor_failed(context,
                                                               health_monitor,
                                                               pool_id)
                    LOG.error(
                        _LE('Failed to delete monitor mapping on edge: %s'),
                        mon_mapping['edge_id'])

            # If this monitor is not used on this edge anymore, delete it
            if not edge_pool['monitorId']:
                try:
                    self.vcns.delete_health_monitor(
                        mon_mapping['edge_id'],
                        mon_mapping['edge_monitor_id'])
                except nsxv_exc.VcnsApiException:
                    with excutils.save_and_reraise_exception():
                        self._lb_driver.pool_health_monitor_failed(
                            context, health_monitor, pool_id)
                        LOG.error(
                            _LE('Failed to delete monitor on edge: %s'),
                            mon_mapping['edge_id'])

        self._lb_driver.delete_pool_health_monitor_successful(
            context, health_monitor, pool_id, mon_mapping)

    def stats(self, context, pool_id, pool_mapping):
        LOG.debug('Retrieving stats for pool %s', pool_id)

        try:
            lb_stats = self.vcns.get_loadbalancer_statistics(
                pool_mapping['edge_id'])

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.error(
                    _LE('Failed to read load balancer statistics, edge: %s'),
                    pool_mapping['edge_id'])

        pools_stats = lb_stats[1].get('pool', [])
        plugin = self._get_lb_plugin()
        members = plugin.get_members(
            context,
            filters={'pool_id': [pool_id]},
            fields=['id', 'status'])
        member_map = {m['id']: m['status'] for m in members}

        for pool_stats in pools_stats:
            if pool_stats['poolId'] == pool_mapping['edge_pool_id']:
                stats = {'bytes_in': pool_stats.get('bytesIn', 0),
                         'bytes_out': pool_stats.get('bytesOut', 0),
                         'active_connections':
                             pool_stats.get('curSessions', 0),
                         'total_connections':
                             pool_stats.get('totalSessions', 0)}

                member_stats = {}
                for member in pool_stats.get('member', []):
                    member_id = member['name'][len(MEMBER_ID_PFX):]
                    if member_map[member_id] != 'ERROR':
                        member_stats[member_id] = {
                            'status': ('INACTIVE'
                                       if member['status'] == 'DOWN'
                                       else 'ACTIVE')}

                stats['members'] = member_stats
                return stats

        return {'bytes_in': 0,
                'bytes_out': 0,
                'active_connections': 0,
                'total_connections': 0}

    def is_edge_in_use(self, edge_id):
        return self._lb_driver.is_edge_in_use(edge_id)

    def is_subnet_in_use(self, context, subnet_id):
        plugin = self._get_lb_plugin()
        if plugin:
            pools = plugin.get_pools(context,
                                     filters={'subnet_id': [subnet_id]})
            if pools:
                return True
