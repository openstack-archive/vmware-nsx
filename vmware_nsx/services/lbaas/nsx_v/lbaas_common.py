# Copyright 2015 VMware, Inc.
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

from oslo_log import log as logging

from neutron_lib import constants
from neutron_lib import exceptions as n_exc

from vmware_nsx._i18n import _
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield import edge_utils

LOG = logging.getLogger(__name__)

MEMBER_ID_PFX = 'member-'
RESOURCE_ID_PFX = 'lbaas-'


def get_member_id(member_id):
    return MEMBER_ID_PFX + member_id


def get_lb_resource_id(lb_id):
    return (RESOURCE_ID_PFX + lb_id)[:36]


def get_lb_edge_name(context, lb_id):
    """Look for the resource name of the edge hosting the LB.

    For older loadbalancers this may be a router edge
    """
    binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
        context.session, lb_id)
    if binding:
        edge_binding = nsxv_db.get_nsxv_router_binding_by_edge(
            context.session, binding['edge_id'])
        if edge_binding:
            return edge_binding['router_id']
    # fallback
    return get_lb_resource_id(lb_id)


def get_lb_interface(context, plugin, lb_id, subnet_id):
    filters = {'fixed_ips': {'subnet_id': [subnet_id]},
               'device_id': [lb_id],
               'device_owner': [constants.DEVICE_OWNER_NEUTRON_PREFIX + 'LB']}

    lb_ports = plugin.get_ports(context.elevated(), filters=filters)
    return lb_ports


def create_lb_interface(context, plugin, lb_id, subnet_id, tenant_id,
                        vip_addr=None, subnet=None):
    if not subnet:
        subnet = plugin.get_subnet(context, subnet_id)
    network_id = subnet.get('network_id')

    port_dict = {'name': 'lb_if-' + lb_id,
                 'admin_state_up': True,
                 'network_id': network_id,
                 'tenant_id': tenant_id,
                 'fixed_ips': [{'subnet_id': subnet['id']}],
                 'device_owner': constants.DEVICE_OWNER_NEUTRON_PREFIX + 'LB',
                 'device_id': lb_id,
                 'mac_address': constants.ATTR_NOT_SPECIFIED
                 }
    port = plugin.base_create_port(context, {'port': port_dict})
    ip_addr = port['fixed_ips'][0]['ip_address']
    net = netaddr.IPNetwork(subnet['cidr'])
    resource_id = get_lb_edge_name(context, lb_id)

    address_groups = [{'primaryAddress': ip_addr,
                       'subnetPrefixLength': str(net.prefixlen),
                       'subnetMask': str(net.netmask)}]

    if vip_addr:
        address_groups[0]['secondaryAddresses'] = {
            'type': 'secondary_addresses', 'ipAddress': [vip_addr]}

    edge_utils.update_internal_interface(
        plugin.nsx_v, context, resource_id,
        network_id, address_groups)


def delete_lb_interface(context, plugin, lb_id, subnet_id):
    resource_id = get_lb_edge_name(context, lb_id)
    subnet = plugin.get_subnet(context, subnet_id)
    network_id = subnet.get('network_id')
    lb_ports = get_lb_interface(context, plugin, lb_id, subnet_id)
    for lb_port in lb_ports:
        plugin.delete_port(context, lb_port['id'])

    edge_utils.delete_interface(plugin.nsx_v, context, resource_id, network_id,
                                dist=False)


def get_lbaas_edge_id(context, plugin, lb_id, vip_addr, subnet_id, tenant_id):
    subnet = plugin.get_subnet(context, subnet_id)
    network_id = subnet.get('network_id')
    availability_zone = plugin.get_network_az_by_net_id(context, network_id)

    resource_id = get_lb_resource_id(lb_id)

    edge_id = plugin.edge_manager.allocate_lb_edge_appliance(
        context, resource_id, availability_zone=availability_zone)

    create_lb_interface(context, plugin, lb_id, subnet_id, tenant_id,
                        vip_addr=vip_addr, subnet=subnet)

    gw_ip = subnet.get('gateway_ip')
    if gw_ip:
        plugin.nsx_v.update_routes(edge_id, gw_ip, [])

    return edge_id


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


def vip_as_secondary_ip(vcns, edge_id, vip, handler):
    with locking.LockManager.get_lock(edge_id):
        r = vcns.get_interfaces(edge_id)[1]
        vnics = r.get('vnics', [])
        for vnic in vnics:
            if vnic['type'] == 'trunk':
                for sub_interface in vnic.get('subInterfaces', {}).get(
                        'subInterfaces', []):
                    address_groups = sub_interface.get('addressGroups')
                    if handler(vip, address_groups):
                        vcns.update_interface(edge_id, vnic)
                        return True
            else:
                address_groups = vnic.get('addressGroups')
                if handler(vip, address_groups):
                    vcns.update_interface(edge_id, vnic)
                    return True
        return False


def add_vip_as_secondary_ip(vcns, edge_id, vip):
    """
    Edge appliance requires that a VIP will be configured as a primary
    or a secondary IP address on an interface.
    To do so, we locate an interface which is connected to the same subnet
    that vip belongs to.
    This can be a regular interface, on a sub-interface on a trunk.
    """
    if not vip_as_secondary_ip(vcns, edge_id, vip,
                               add_address_to_address_groups):

        msg = _('Failed to add VIP %(vip)s as secondary IP on '
                'Edge %(edge_id)s') % {'vip': vip, 'edge_id': edge_id}
        raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)


def del_vip_as_secondary_ip(vcns, edge_id, vip):
    """
    While removing vip, delete the secondary interface from Edge config.
    """
    if not vip_as_secondary_ip(vcns, edge_id, vip,
                               del_address_from_address_groups):

        msg = _('Failed to delete VIP %(vip)s as secondary IP on '
                'Edge %(edge_id)s') % {'vip': vip, 'edge_id': edge_id}
        raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)


def extract_resource_id(location_uri):
    """
    Edge assigns an ID for each resource that is being created:
    it is postfixes the uri specified in the Location header.
    This ID should be used while updating/deleting this resource.
    """
    uri_elements = location_uri.split('/')
    return uri_elements[-1]


def set_lb_firewall_default_rule(vcns, edge_id, action):
    with locking.LockManager.get_lock(edge_id):
        vcns.update_firewall_default_policy(edge_id, {'action': action})


def add_vip_fw_rule(vcns, edge_id, vip_id, ip_address):
    fw_rule = {
        'firewallRules': [
            {'action': 'accept', 'destination': {
                'ipAddress': [ip_address]},
             'enabled': True,
             'name': vip_id}]}

    with locking.LockManager.get_lock(edge_id):
        h = vcns.add_firewall_rule(edge_id, fw_rule)[0]
    fw_rule_id = extract_resource_id(h['location'])

    return fw_rule_id


def del_vip_fw_rule(vcns, edge_id, vip_fw_rule_id):
    with locking.LockManager.get_lock(edge_id):
        vcns.delete_firewall_rule(edge_id, vip_fw_rule_id)


def get_edge_ip_addresses(vcns, edge_id):
    edge_ips = []
    r = vcns.get_interfaces(edge_id)[1]
    vnics = r.get('vnics', [])
    for vnic in vnics:
        if vnic['type'] == 'trunk':
            for sub_interface in vnic.get('subInterfaces', {}).get(
                    'subInterfaces', []):
                address_groups = sub_interface.get('addressGroups')
                for address_group in address_groups['addressGroups']:
                    edge_ips.append(address_group['primaryAddress'])

        else:
            address_groups = vnic.get('addressGroups')
            for address_group in address_groups['addressGroups']:
                edge_ips.append(address_group['primaryAddress'])
    return edge_ips


def enable_edge_acceleration(vcns, edge_id):
    with locking.LockManager.get_lock(edge_id):
        # Query the existing load balancer config in case metadata lb is set
        _, config = vcns.get_loadbalancer_config(edge_id)
        config['accelerationEnabled'] = True
        config['enabled'] = True
        config['featureType'] = 'loadbalancer_4.0'
        vcns.enable_service_loadbalancer(edge_id, config)


def is_lb_on_router_edge(context, core_plugin, edge_id):
    binding = nsxv_db.get_nsxv_router_binding_by_edge(
        context.session, edge_id)
    router_id = binding['router_id']
    if router_id.startswith(RESOURCE_ID_PFX):
        # New lbaas edge
        return False

    # verify that this is a router (and an exclusive one)
    try:
        router = core_plugin.get_router(context, router_id)
        if router.get('router_type') == 'exclusive':
            return True
    except Exception:
        pass
    LOG.error("Edge %(edge)s router %(rtr)s is not an lbaas edge, but also "
              "not an exclusive router",
              {'edge': edge_id, 'rtr': router_id})
    return False
