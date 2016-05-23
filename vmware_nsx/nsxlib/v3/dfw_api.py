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
from oslo_log import log

from vmware_nsx._i18n import _, _LW
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import utils
from vmware_nsx.nsxlib.v3 import client as nsxclient

LOG = log.getLogger(__name__)

# firewall section types
LAYER3 = 'LAYER3'

INSERT_BEFORE = 'insert_before'
INSERT_BOTTOM = 'insert_bottom'

# firewall rule actions
ALLOW = 'ALLOW'
DROP = 'DROP'
REJECT = 'REJECT'

# filtering operators and expressions
EQUALS = 'EQUALS'
NSGROUP_SIMPLE_EXPRESSION = 'NSGroupSimpleExpression'
NSGROUP_TAG_EXPRESSION = 'NSGroupTagExpression'

# nsgroup members update actions
ADD_MEMBERS = 'ADD_MEMBERS'
REMOVE_MEMBERS = 'REMOVE_MEMBERS'

NSGROUP = 'NSGroup'
LOGICAL_SWITCH = 'LogicalSwitch'
LOGICAL_PORT = 'LogicalPort'
IPV4ADDRESS = 'IPv4Address'
IPV6ADDRESS = 'IPv6Address'

IN = 'IN'
OUT = 'OUT'
IN_OUT = 'IN_OUT'

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
IPV4_IPV6 = 'IPV4_IPV6'


class NSGroupMemberNotFound(nsx_exc.NsxPluginException):
    message = _("Could not find NSGroup %(nsgroup_id)s member %(member_id)s "
                "for removal.")


class NSGroupIsFull(nsx_exc.NsxPluginException):
    message = _("NSGroup %(nsgroup_id)s contains has reached its maximum "
                "capacity, unable to add additional members.")


def get_nsservice(resource_type, **properties):
    service = {'resource_type': resource_type}
    service.update(properties)
    return {'service': service}


def get_nsgroup_port_tag_expression(scope, tag):
    return {'resource_type': NSGROUP_TAG_EXPRESSION,
            'target_type': LOGICAL_PORT,
            'scope': scope,
            'tag': tag}


def create_nsgroup(display_name, description, tags, membership_criteria=None):
    body = {'display_name': display_name,
            'description': description,
            'tags': tags,
            'members': []}
    if membership_criteria:
        body.update({'membership_criteria': [membership_criteria]})
    return nsxclient.create_resource('ns-groups', body)


def list_nsgroups():
    return nsxclient.get_resource(
        'ns-groups?populate_references=false').get('results', [])


@utils.retry_upon_exception_nsxv3(nsx_exc.StaleRevision)
def update_nsgroup(nsgroup_id, display_name=None, description=None,
                   membership_criteria=None, members=None):
    nsgroup = read_nsgroup(nsgroup_id)
    if display_name is not None:
        nsgroup['display_name'] = display_name
    if description is not None:
        nsgroup['description'] = description
    if members is not None:
        nsgroup['members'] = members
    if membership_criteria is not None:
        nsgroup['membership_criteria'] = [membership_criteria]
    return nsxclient.update_resource('ns-groups/%s' % nsgroup_id, nsgroup)


def get_nsgroup_member_expression(target_type, target_id):
    return {'resource_type': NSGROUP_SIMPLE_EXPRESSION,
            'target_property': 'id',
            'target_type': target_type,
            'op': EQUALS,
            'value': target_id}


@utils.retry_upon_exception_nsxv3(nsx_exc.StaleRevision)
def _update_nsgroup_with_members(nsgroup_id, members, action):
    members_update = 'ns-groups/%s?action=%s' % (nsgroup_id, action)
    return nsxclient.create_resource(members_update, members)


def add_nsgroup_member(nsgroup_id, target_type, target_id):
    member_expr = get_nsgroup_member_expression(target_type, target_id)
    members = {'members': [member_expr]}
    try:
        return _update_nsgroup_with_members(nsgroup_id, members, ADD_MEMBERS)
    except (nsx_exc.StaleRevision, nsx_exc.ResourceNotFound):
        raise
    except nsx_exc.ManagerError:
        # REVISIT(roeyc): A ManagerError might have been raised for a
        # different reason, e.g - NSGroup does not exists.
        LOG.warning(_LW("Failed to add %(target_type)s %(target_id)s to "
                        "NSGroup %(nsgroup_id)s"),
                    {'target_type': target_type,
                     'target_id': target_id,
                     'nsgroup_id': nsgroup_id})
        raise NSGroupIsFull(nsgroup_id=nsgroup_id)


def remove_nsgroup_member(nsgroup_id, target_type, target_id, verify=False):
    member_expr = get_nsgroup_member_expression(target_type, target_id)
    members = {'members': [member_expr]}
    try:
        return _update_nsgroup_with_members(
            nsgroup_id, members, REMOVE_MEMBERS)
    except nsx_exc.ManagerError:
        if verify:
            raise NSGroupMemberNotFound(member_id=target_id,
                                        nsgroup_id=nsgroup_id)


def read_nsgroup(nsgroup_id):
    return nsxclient.get_resource(
        'ns-groups/%s?populate_references=true' % nsgroup_id)


def delete_nsgroup(nsgroup_id):
    return nsxclient.delete_resource('ns-groups/%s?force=true' % nsgroup_id)


def _build_section(display_name, description, applied_tos, tags):
    return {'display_name': display_name,
            'description': description,
            'stateful': True,
            'section_type': LAYER3,
            'applied_tos': [get_nsgroup_reference(t_id)
                            for t_id in applied_tos],
            'tags': tags}


def create_empty_section(display_name, description, applied_tos, tags,
                         operation=INSERT_BOTTOM, other_section=None):
    resource = 'firewall/sections?operation=%s' % operation
    body = _build_section(display_name, description, applied_tos, tags)
    if other_section:
        resource += '&id=%s' % other_section
    return nsxclient.create_resource(resource, body)


@utils.retry_upon_exception_nsxv3(nsx_exc.StaleRevision)
def update_section(section_id, display_name, description, applied_tos=None):
    resource = 'firewall/sections/%s' % section_id
    section = read_section(section_id)
    section.update({'display_name': display_name,
                    'description': description})
    if applied_tos is not None:
        section['applied_tos'] = [get_nsgroup_reference(nsg_id)
                                  for nsg_id in applied_tos]
    return nsxclient.update_resource(resource, section)


def read_section(section_id):
    resource = 'firewall/sections/%s' % section_id
    return nsxclient.get_resource(resource)


def list_sections():
    resource = 'firewall/sections'
    return nsxclient.get_resource(resource).get('results', [])


def delete_section(section_id):
    resource = 'firewall/sections/%s?cascade=true' % section_id
    return nsxclient.delete_resource(resource)


def get_nsgroup_reference(nsgroup_id):
    return {'target_id': nsgroup_id,
            'target_type': NSGROUP}


def get_ip_cidr_reference(ip_cidr_block, ip_protocol):
    target_type = IPV4ADDRESS if ip_protocol == IPV4 else IPV6ADDRESS
    return {'target_id': ip_cidr_block,
            'target_type': target_type}


def get_firewall_rule_dict(display_name, source=None, destination=None,
                           direction=IN_OUT, ip_protocol=IPV4_IPV6,
                           service=None, action=ALLOW):
    return {'display_name': display_name,
            'sources': [source] if source else [],
            'destinations': [destination] if destination else [],
            'direction': direction,
            'ip_protocol': ip_protocol,
            'services': [service] if service else [],
            'action': action}


def add_rule_in_section(rule, section_id):
    resource = 'firewall/sections/%s/rules' % section_id
    params = '?operation=insert_bottom'
    return nsxclient.create_resource(resource + params, rule)


def add_rules_in_section(rules, section_id):
    resource = 'firewall/sections/%s/rules' % section_id
    params = '?action=create_multiple&operation=insert_bottom'
    return nsxclient.create_resource(resource + params, {'rules': rules})


def delete_rule(section_id, rule_id):
    resource = 'firewall/sections/%s/rules/%s' % (section_id, rule_id)
    return nsxclient.delete_resource(resource)
