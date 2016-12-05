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

from vmware_nsx._i18n import _LW
from vmware_nsx.common import utils
from vmware_nsx.nsxlib.v3 import client as nsxclient
from vmware_nsx.nsxlib.v3 import exceptions

LOG = log.getLogger(__name__)

# firewall section types
LAYER3 = 'LAYER3'

INSERT_BEFORE = 'insert_before'
INSERT_BOTTOM = 'insert_bottom'
INSERT_TOP = 'insert_top'

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

EXCLUDE_PORT = 'Exclude-Port'

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


class DfwApi(object):

    def get_nsservice(self, resource_type, **properties):
        service = {'resource_type': resource_type}
        service.update(properties)
        return {'service': service}

    def get_nsgroup_port_tag_expression(self, scope, tag):
        return {'resource_type': NSGROUP_TAG_EXPRESSION,
                'target_type': LOGICAL_PORT,
                'scope': scope,
                'tag': tag}

    def create_nsgroup(self, display_name, description, tags,
                       membership_criteria=None):
        body = {'display_name': display_name,
                'description': description,
                'tags': tags,
                'members': []}
        if membership_criteria:
            body.update({'membership_criteria': [membership_criteria]})
        return self.client.create('ns-groups', body)

    def list_nsgroups(self):
        return self.client.list(
            'ns-groups?populate_references=false').get('results', [])

    def find_nsgroups_by_display_name(self, display_name):
        found = []
        for resource in self.list_nsgroups():
            if resource['display_name'] == display_name:
                found.append(resource)
        return found

    @utils.retry_upon_exception_nsxv3(exceptions.StaleRevision)
    def update_nsgroup(self, nsgroup_id, display_name=None, description=None,
                       membership_criteria=None, members=None):
        nsgroup = self.read_nsgroup(nsgroup_id)
        if display_name is not None:
            nsgroup['display_name'] = display_name
        if description is not None:
            nsgroup['description'] = description
        if members is not None:
            nsgroup['members'] = members
        if membership_criteria is not None:
            nsgroup['membership_criteria'] = [membership_criteria]
        return self.client.update(
            'ns-groups/%s' % nsgroup_id, nsgroup)

    def get_nsgroup_member_expression(self, target_type, target_id):
        return {'resource_type': NSGROUP_SIMPLE_EXPRESSION,
                'target_property': 'id',
                'target_type': target_type,
                'op': EQUALS,
                'value': target_id}

    @utils.retry_upon_exception_nsxv3(exceptions.ManagerError)
    def _update_nsgroup_with_members(self, nsgroup_id, members, action):
        members_update = 'ns-groups/%s?action=%s' % (nsgroup_id, action)
        return self.client.create(members_update, members)

    def add_nsgroup_members(self, nsgroup_id, target_type, target_ids):
        members = []
        for target_id in target_ids:
            member_expr = self.get_nsgroup_member_expression(
                target_type, target_id)
            members.append(member_expr)
        members = {'members': members}
        try:
            return self._update_nsgroup_with_members(
                nsgroup_id, members, ADD_MEMBERS)
        except (exceptions.StaleRevision, exceptions.ResourceNotFound):
            raise
        except exceptions.ManagerError:
            # REVISIT(roeyc): A ManagerError might have been raised for a
            # different reason, e.g - NSGroup does not exists.
            LOG.warning(_LW("Failed to add %(target_type)s resources "
                            "(%(target_ids)s) to NSGroup %(nsgroup_id)s"),
                        {'target_type': target_type,
                         'target_ids': target_ids,
                         'nsgroup_id': nsgroup_id})

            raise exceptions.NSGroupIsFull(nsgroup_id=nsgroup_id)

    def remove_nsgroup_member(self, nsgroup_id, target_type,
                              target_id, verify=False):
        member_expr = self.get_nsgroup_member_expression(
            target_type, target_id)
        members = {'members': [member_expr]}
        try:
            return self._update_nsgroup_with_members(
                nsgroup_id, members, REMOVE_MEMBERS)
        except exceptions.ManagerError:
            if verify:
                raise exceptions.NSGroupMemberNotFound(member_id=target_id,
                                                       nsgroup_id=nsgroup_id)

    def read_nsgroup(self, nsgroup_id):
        return self.client.get(
            'ns-groups/%s?populate_references=true' % nsgroup_id)

    def delete_nsgroup(self, nsgroup_id):
        try:
            return self.client.delete(
                'ns-groups/%s?force=true' % nsgroup_id)
        # FIXME(roeyc): Should only except NotFound error.
        except Exception:
            LOG.debug("NSGroup %s does not exists for delete request.",
                      nsgroup_id)

    def _build_section(self, display_name, description, applied_tos, tags):
        return {'display_name': display_name,
                'description': description,
                'stateful': True,
                'section_type': LAYER3,
                'applied_tos': [self.get_nsgroup_reference(t_id)
                                for t_id in applied_tos],
                'tags': tags}

    def create_empty_section(self, display_name, description, applied_tos,
                             tags, operation=INSERT_BOTTOM,
                             other_section=None):
        resource = 'firewall/sections?operation=%s' % operation
        body = self._build_section(display_name, description,
                                   applied_tos, tags)
        if other_section:
            resource += '&id=%s' % other_section
        return self.client.create(resource, body)

    @utils.retry_upon_exception_nsxv3(exceptions.StaleRevision)
    def update_section(self, section_id, display_name=None, description=None,
                       applied_tos=None, rules=None):
        resource = 'firewall/sections/%s' % section_id
        section = self.read_section(section_id)

        if rules is not None:
            resource += '?action=update_with_rules'
            section.update({'rules': rules})
        if display_name is not None:
            section['display_name'] = display_name
        if description is not None:
            section['description'] = description
        if applied_tos is not None:
            section['applied_tos'] = [self.get_nsgroup_reference(nsg_id)
                                      for nsg_id in applied_tos]
        if rules is not None:
            return nsxclient.create_resource(resource, section)
        elif any(p is not None for p in (display_name, description,
                                         applied_tos)):
            return self.client.update(resource, section)

    def read_section(self, section_id):
        resource = 'firewall/sections/%s' % section_id
        return self.client.get(resource)

    def list_sections(self):
        resource = 'firewall/sections'
        return self.client.list(resource).get('results', [])

    def delete_section(self, section_id):
        resource = 'firewall/sections/%s?cascade=true' % section_id
        return self.client.delete(resource)

    def get_nsgroup_reference(self, nsgroup_id):
        return {'target_id': nsgroup_id,
                'target_type': NSGROUP}

    def get_ip_cidr_reference(self, ip_cidr_block, ip_protocol):
        target_type = IPV4ADDRESS if ip_protocol == IPV4 else IPV6ADDRESS
        return {'target_id': ip_cidr_block,
                'target_type': target_type}

    def get_firewall_rule_dict(self, display_name, source=None,
                               destination=None,
                               direction=IN_OUT, ip_protocol=IPV4_IPV6,
                               service=None, action=ALLOW, logged=False):
        return {'display_name': display_name,
                'sources': [source] if source else [],
                'destinations': [destination] if destination else [],
                'direction': direction,
                'ip_protocol': ip_protocol,
                'services': [service] if service else [],
                'action': action,
                'logged': logged}

    def add_rule_in_section(self, rule, section_id):
        resource = 'firewall/sections/%s/rules' % section_id
        params = '?operation=insert_bottom'
        return self.client.create(resource + params, rule)

    def add_rules_in_section(self, rules, section_id):
        resource = 'firewall/sections/%s/rules' % section_id
        params = '?action=create_multiple&operation=insert_bottom'
        return self.client.create(resource + params, {'rules': rules})

    def delete_rule(self, section_id, rule_id):
        resource = 'firewall/sections/%s/rules/%s' % (section_id, rule_id)
        return self.client.delete(resource)

    def get_section_rules(self, section_id):
        resource = 'firewall/sections/%s/rules' % section_id
        return self.client.get(resource)

    def add_member_to_fw_exclude_list(self, target_id, target_type):
        resource = 'firewall/excludelist?action=add_member'
        return nsxclient.create_resource(
            resource, {'target_id': target_id, 'target_type': target_type})

    def remove_member_from_exclude_list(self, target_id):
        resource = 'firewall/excludelist'
        params = '?action=remove_member&object_id=%s' % target_id
        return nsxclient.create_resource(resource + params, {})
