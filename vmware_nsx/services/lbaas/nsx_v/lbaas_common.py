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
import xml.etree.ElementTree as et

from neutron_lib import exceptions as n_exc

from vmware_nsx._i18n import _
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield import vcns as nsxv_api

MEMBER_ID_PFX = 'member-'
LBAAS_FW_SECTION_NAME = 'LBaaS FW Rules'


def get_member_id(member_id):
    return MEMBER_ID_PFX + member_id


def get_lbaas_edge_id_for_subnet(context, plugin, subnet_id, tenant_id):
    """
    Grab the id of an Edge appliance that is connected to subnet_id.
    """
    subnet = plugin.get_subnet(context, subnet_id)
    net_id = subnet.get('network_id')
    filters = {'network_id': [net_id],
               'device_owner': ['network:router_interface'],
               'tenant_id': [tenant_id]}
    attached_routers = plugin.get_ports(context.elevated(),
                                        filters=filters,
                                        fields=['device_id'])

    for attached_router in attached_routers:
        router = plugin.get_router(context, attached_router['device_id'])
        if router.get('router_type') == 'exclusive':
            rtr_bindings = nsxv_db.get_nsxv_router_binding(context.session,
                                                           router['id'])
            return rtr_bindings['edge_id']


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


def update_pool_fw_rule(vcns, pool_id, edge_id, section_id, member_ips):
    edge_ips = get_edge_ip_addresses(vcns, edge_id)

    with locking.LockManager.get_lock('lbaas-fw-section'):
        section_uri = '%s/%s/%s' % (nsxv_api.FIREWALL_PREFIX,
                                    'layer3sections',
                                    section_id)
        xml_section = vcns.get_section(section_uri)[1]
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

        vcns.update_section(section_uri,
                            et.tostring(section, encoding="us-ascii"),
                            None)


def get_lbaas_fw_section_id(vcns):
    # Avoid concurrent creation of section by multiple neutron
    # instances
    with locking.LockManager.get_lock('lbaas-fw-section'):
        fw_section_id = vcns.get_section_id(LBAAS_FW_SECTION_NAME)
        if not fw_section_id:
            section = et.Element('section')
            section.attrib['name'] = LBAAS_FW_SECTION_NAME
            sect = vcns.create_section('ip', et.tostring(section))[1]
            fw_section_id = et.fromstring(sect).attrib['id']

        return fw_section_id


def enable_edge_acceleration(vcns, edge_id):
    with locking.LockManager.get_lock(edge_id):
        # Query the existing load balancer config in case metadata lb is set
        _, config = vcns.get_loadbalancer_config(edge_id)
        config['accelerationEnabled'] = True
        config['enabled'] = True
        config['featureType'] = 'loadbalancer_4.0'
        vcns.enable_service_loadbalancer(edge_id, config)
