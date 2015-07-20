# Copyright 2015 OpenStack Foundation
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


"""
NSX-V3 Distributed Firewall
"""

from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.common import utils
from vmware_nsx.neutron.plugins.vmware.nsxlib.v3 import client as nsclient


# firewall section types
LAYER3 = 'LAYER3'

# firewall rule actions
ALLOW = 'ALLOW'
DROP = 'DROP'
REJECT = 'REJECT'

# filtering operators
EQUALS = 'EQUALS'

NSGROUP = 'NSGroup'
LOGICAL_SWITCH = 'LogicalSwitch'
LOGICAL_PORT = 'LogicalPort'
IPV4ADDRESS = 'IPv4Address'
IPV6ADDRESS = 'IPv6Address'

IN = 'IN'
OUT = 'OUT'

# NSServices resource types
L4_PORT_SET_NSSERVICE = 'L4PortSetNSService'
ICMP_TYPE_NSSERVICE = 'ICMPTypeNSService'
IP_PROTOCOL_NSSERVICE = 'IPProtocolNSService'

TCP = 'TCP'
UDP = 'UDP'
ICMPV4 = 'ICMPv4'
ICMPV6 = 'ICMPv6'

IPV4 = 'IPV4'
IPV6 = 'IPV6'


def get_nsservice(resource_type, **properties):
    service = {'resource_type': resource_type}
    service.update(properties)
    return {'service': service}


def create_nsgroup(display_name, description, tags):
    body = {'display_name': display_name,
            'description': description,
            'tags': tags}
    return nsclient.create_resource('ns-groups', body)


def list_nsgroups():
    return nsclient.get_resource('ns-groups')


@utils.retry_upon_exception_nsxv3(nsx_exc.StaleRevision)
def update_nsgroup(nsgroup_id, display_name, description):
    nsgroup = read_nsgroup(nsgroup_id)
    nsgroup.update({'display_name': display_name,
                    'description': description})
    return nsclient.update_resource('ns-groups/%s' % nsgroup_id, nsgroup)


@utils.retry_upon_exception_nsxv3(nsx_exc.StaleRevision)
def add_nsgroup_member(nsgroup_id, target_type, target_id):
    nsgroup = read_nsgroup(nsgroup_id)
    if 'members' not in nsgroup:
        nsgroup['members'] = []
    nsgroup['members'].append({'target_property': 'id',
                               'target_type': target_type,
                               'op': EQUALS,
                               'value': target_id})
    return nsclient.update_resource('ns-groups/%s' % nsgroup_id, nsgroup)


@utils.retry_upon_exception_nsxv3(nsx_exc.StaleRevision)
def remove_nsgroup_member(nsgroup_id, target_id):
    nsgroup = read_nsgroup(nsgroup_id)
    for i, member in enumerate(nsgroup.get('members', [])):
        if target_id == member['value']:
            break
    else:
        return
    del nsgroup['members'][i]
    return nsclient.update_resource('ns-groups/%s' % nsgroup_id, nsgroup)


def read_nsgroup(nsgroup_id):
    return nsclient.get_resource('ns-groups/%s' % nsgroup_id)


def delete_nsgroup(nsgroup_id):
    return nsclient.delete_resource('ns-groups/%s' % nsgroup_id)


def _build_section(display_name, description, applied_tos, tags):
    return {'display_name': display_name,
            'description': description,
            'stateful': True,
            'section_type': LAYER3,
            'applied_tos': [get_nsgroup_reference(t_id)
                            for t_id in applied_tos],
            'tags': tags}


def create_empty_section(display_name, description, applied_tos, tags):
    resource = 'firewall/sections'
    body = _build_section(display_name, description, applied_tos, tags)
    return nsclient.create_resource(resource, body)


@utils.retry_upon_exception_nsxv3(nsx_exc.StaleRevision)
def update_section(section_id, display_name, description, applied_tos=None):
    resource = 'firewall/sections/%s' % section_id
    section = read_section(section_id)
    section.update({'display_name': display_name,
                    'description': description})
    if applied_tos is not None:
        section['applied_tos'] = applied_tos
    return nsclient.update_resource(resource, section)


def read_section(section_id):
    resource = 'firewall/sections/%s' % section_id
    return nsclient.get_resource(resource)


def list_sections():
    resource = 'firewall/sections'
    return nsclient.get_resource(resource)


def delete_section(section_id):
    resource = 'firewall/sections/%s?cascade=true' % section_id
    return nsclient.delete_resource(resource)


def get_nsgroup_reference(nsgroup_id):
    return {'target_id': nsgroup_id,
            'target_type': NSGROUP}


def get_ip_cidr_reference(ip_cidr_block, ip_protocol):
    target_type = IPV4ADDRESS if ip_protocol == IPV4 else IPV6ADDRESS
    return {'target_id': ip_cidr_block,
            'target_type': target_type}


def get_firewall_rule_dict(display_name, source, destination, direction,
                           ip_protocol, service, action):
    return {'display_name': display_name,
            'sources': [source] if source else [],
            'destinations': [destination] if destination else [],
            'direction': direction,
            'ip_protocol': ip_protocol,
            'services': [service] if service else [],
            'action': action}


def add_rule_in_section(rule, section_id):
    resource = 'firewall/sections/%s/rules' % section_id
    return nsclient.create_resource(resource, rule)


def add_rules_in_section(rules, section_id):
    resource = 'firewall/sections/%s/rules?action=create_multiple' % section_id
    return nsclient.create_resource(resource, {'rules': rules})


def delete_rule(section_id, rule_id):
    resource = 'firewall/sections/%s/rules/%s' % (section_id, rule_id)
    return nsclient.delete_resource(resource)
