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
NSX-V3 Plugin security & Distributed Firewall integration module
"""

from neutron_lib import constants
from oslo_log import log
from oslo_utils import excutils

from vmware_nsx._i18n import _LE, _LW
from vmware_nsx.nsxlib.v3 import exceptions
from vmware_nsx.nsxlib.v3 import nsx_constants as consts
from vmware_nsx.nsxlib.v3 import utils


LOG = log.getLogger(__name__)

PORT_SG_SCOPE = 'os-security-group'
MAX_NSGROUPS_CRITERIA_TAGS = 10


class NsxLibNsGroup(utils.NsxLibApiBase):

    def __init__(self, client, max_attempts, firewall_section_handler):
        self.firewall_section = firewall_section_handler
        super(NsxLibNsGroup, self).__init__(client, max_attempts)

    def update_on_backend(self, context, security_group,
                          nsgroup_id, section_id,
                          log_sg_allowed_traffic):
        name = self.get_name(security_group)
        description = security_group['description']
        logging = (log_sg_allowed_traffic or
                   security_group[consts.LOGGING])
        rules = self.firewall_section._process_rules_logging_for_update(
            section_id, logging)
        self.update(nsgroup_id, name, description)
        self.firewall_section.update(section_id, name, description,
                                     rules=rules)

    def get_name(self, security_group):
        # NOTE(roeyc): We add the security-group id to the NSGroup name,
        # for usability purposes.
        return '%(name)s - %(id)s' % security_group

    def get_lport_tags(self, secgroups):
        if len(secgroups) > MAX_NSGROUPS_CRITERIA_TAGS:
            raise exceptions.NumberOfNsgroupCriteriaTagsReached(
                max_num=MAX_NSGROUPS_CRITERIA_TAGS)
        tags = []
        for sg in secgroups:
            tags = utils.add_v3_tag(tags, PORT_SG_SCOPE, sg)
        if not tags:
            # This port shouldn't be associated with any security-group
            tags = [{'scope': PORT_SG_SCOPE, 'tag': None}]
        return tags

    def update_lport(self, context, lport_id, original, updated):
        added = set(updated) - set(original)
        removed = set(original) - set(updated)
        for nsgroup_id in added:
            try:
                self.add_members(
                    nsgroup_id, consts.TARGET_TYPE_LOGICAL_PORT,
                    [lport_id])
            except exceptions.NSGroupIsFull:
                for nsgroup_id in added:
                    # NOTE(roeyc): If the port was not added to the nsgroup
                    # yet, then this request will silently fail.
                    self.remove_member(
                        nsgroup_id, consts.TARGET_TYPE_LOGICAL_PORT,
                        lport_id)
                raise exceptions.SecurityGroupMaximumCapacityReached(
                    sg_id=nsgroup_id)
            except exceptions.ResourceNotFound:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("NSGroup %s doesn't exists"), nsgroup_id)
        for nsgroup_id in removed:
            self.remove_member(
                nsgroup_id, consts.TARGET_TYPE_LOGICAL_PORT, lport_id)

    def init_default_section(self, name, description, nested_groups,
                             log_sg_blocked_traffic):
        fw_sections = self.list_sections()
        for section in fw_sections:
            if section['display_name'] == name:
                break
        else:
            tags = utils.build_v3_api_version_tag()
            section = self.create_empty_section(
                name, description, nested_groups, tags)

        block_rule = self.get_firewall_rule_dict(
            'Block All', action=consts.FW_ACTION_DROP,
            logged=log_sg_blocked_traffic)
        # TODO(roeyc): Add additional rules to allow IPV6 NDP.
        dhcp_client = self.get_nsservice(
            consts.L4_PORT_SET_NSSERVICE,
            l4_protocol=consts.UDP,
            source_ports=[67],
            destination_ports=[68])
        dhcp_client_rule_in = self.get_firewall_rule_dict(
            'DHCP Reply',
            direction=consts.IN,
            service=dhcp_client)

        dhcp_server = (
            self.get_nsservice(consts.L4_PORT_SET_NSSERVICE,
                               l4_protocol=consts.UDP,
                               source_ports=[68],
                               destination_ports=[67]))
        dhcp_client_rule_out = self.get_firewall_rule_dict(
            'DHCP Request',
            direction=consts.OUT,
            service=dhcp_server)

        self.update_section(section['id'],
                            name, section['description'],
                            applied_tos=nested_groups,
                            rules=[dhcp_client_rule_out,
                                   dhcp_client_rule_in,
                                   block_rule])
        return section['id']

    def get_nsservice(self, resource_type, **properties):
        service = {'resource_type': resource_type}
        service.update(properties)
        return {'service': service}

    def get_port_tag_expression(self, scope, tag):
        return {'resource_type': consts.NSGROUP_TAG_EXP,
                'target_type': consts.TARGET_TYPE_LOGICAL_PORT,
                'scope': scope,
                'tag': tag}

    def create(self, display_name, description, tags,
               membership_criteria=None):
        body = {'display_name': display_name,
                'description': description,
                'tags': tags,
                'members': []}
        if membership_criteria:
            body.update({'membership_criteria': [membership_criteria]})
        return self.client.create('ns-groups', body)

    def list(self):
        return self.client.get(
            'ns-groups?populate_references=false').get('results', [])

    def update(self, nsgroup_id, display_name=None, description=None,
               membership_criteria=None, members=None):
        #Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self.nsxlib_config.max_attempts)
        def _do_update():
            nsgroup = self.read(nsgroup_id)
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

        return _do_update()

    def get_member_expression(self, target_type, target_id):
        return {
            'resource_type': consts.NSGROUP_SIMPLE_EXP,
            'target_property': 'id',
            'target_type': target_type,
            'op': consts.EQUALS,
            'value': target_id}

    def _update_with_members(self, nsgroup_id, members, action):
        #Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self.nsxlib_config.max_attempts)
        def _do_update():
            members_update = 'ns-groups/%s?action=%s' % (nsgroup_id, action)
            return self.client.create(members_update, members)

        return _do_update()

    def add_members(self, nsgroup_id, target_type, target_ids):
        members = []
        for target_id in target_ids:
            member_expr = self.get_member_expression(
                target_type, target_id)
            members.append(member_expr)
        members = {'members': members}
        try:
            return self._update_with_members(
                nsgroup_id, members, consts.NSGROUP_ADD_MEMBERS)
        except (exceptions.StaleRevision, exceptions.ResourceNotFound):
            raise
        except exceptions.ManagerError:
            # REVISIT(roeyc): A ManagerError might have been raised for a
            # different reason, e.g - NSGroup does not exists.
            LOG.warning(_LW("Failed to add %(target_type)s resources "
                            "(%(target_ids))s to NSGroup %(nsgroup_id)s"),
                        {'target_type': target_type,
                         'target_ids': target_ids,
                         'nsgroup_id': nsgroup_id})

            raise exceptions.NSGroupIsFull(nsgroup_id=nsgroup_id)

    def remove_member(self, nsgroup_id, target_type,
                      target_id, verify=False):
        member_expr = self.get_member_expression(
            target_type, target_id)
        members = {'members': [member_expr]}
        try:
            return self._update_with_members(
                nsgroup_id, members, consts.NSGROUP_REMOVE_MEMBERS)
        except exceptions.ManagerError:
            if verify:
                raise exceptions.NSGroupMemberNotFound(member_id=target_id,
                                                       nsgroup_id=nsgroup_id)

    def read(self, nsgroup_id):
        return self.client.get(
            'ns-groups/%s?populate_references=true' % nsgroup_id)

    def delete(self, nsgroup_id):
        try:
            return self.client.delete(
                'ns-groups/%s?force=true' % nsgroup_id)
        # FIXME(roeyc): Should only except NotFound error.
        except Exception:
            LOG.debug("NSGroup %s does not exists for delete request.",
                      nsgroup_id)


class NsxLibFirewallSection(utils.NsxLibApiBase):

    def _get_direction(self, sg_rule):
        return (
            consts.IN if sg_rule['direction'] == 'ingress'
            else consts.OUT
        )

    def _get_l4_protocol_name(self, protocol_number):
        if protocol_number is None:
            return
        protocol_number = constants.IP_PROTOCOL_MAP.get(protocol_number,
                                                        protocol_number)
        protocol_number = int(protocol_number)
        if protocol_number == 6:
            return consts.TCP
        elif protocol_number == 17:
            return consts.UDP
        elif protocol_number == 1:
            return consts.ICMPV4
        else:
            return protocol_number

    def get_nsservice(self, resource_type, **properties):
        service = {'resource_type': resource_type}
        service.update(properties)
        return {'service': service}

    def _decide_service(self, sg_rule):
        l4_protocol = self._get_l4_protocol_name(sg_rule['protocol'])
        direction = self._get_direction(sg_rule)

        if l4_protocol in [consts.TCP, consts.UDP]:
            # If port_range_min is not specified then we assume all ports are
            # matched, relying on neutron to perform validation.
            source_ports = []
            if sg_rule['port_range_min'] is None:
                destination_ports = []
            elif sg_rule['port_range_min'] != sg_rule['port_range_max']:
                # NSX API requires a non-empty range (e.g - '22-23')
                destination_ports = ['%(port_range_min)s-%(port_range_max)s'
                                     % sg_rule]
            else:
                destination_ports = ['%(port_range_min)s' % sg_rule]

            if direction == consts.OUT:
                source_ports, destination_ports = destination_ports, []

            return self.get_nsservice(
                consts.L4_PORT_SET_NSSERVICE,
                l4_protocol=l4_protocol,
                source_ports=source_ports,
                destination_ports=destination_ports)
        elif l4_protocol == consts.ICMPV4:
            return self.get_nsservice(
                consts.ICMP_TYPE_NSSERVICE,
                protocol=l4_protocol,
                icmp_type=sg_rule['port_range_min'],
                icmp_code=sg_rule['port_range_max'])
        elif l4_protocol is not None:
            return self.get_nsservice(
                consts.IP_PROTOCOL_NSSERVICE,
                protocol_number=l4_protocol)

    def _build(self, display_name, description, applied_tos, tags):
        return {'display_name': display_name,
                'description': description,
                'stateful': True,
                'section_type': consts.FW_SECTION_LAYER3,
                'applied_tos': [self.get_nsgroup_reference(t_id)
                                for t_id in applied_tos],
                'tags': tags}

    def create_empty(self, display_name, description,
                     applied_tos, tags,
                     operation=consts.FW_INSERT_BOTTOM,
                     other_section=None):
        resource = 'firewall/sections?operation=%s' % operation
        body = self._build(display_name, description,
                           applied_tos, tags)
        if other_section:
            resource += '&id=%s' % other_section
        return self.client.create(resource, body)

    def update(self, section_id, display_name=None, description=None,
               applied_tos=None, rules=None):
        #Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self.nsxlib_config.max_attempts)
        def _do_update():
            resource = 'firewall/sections/%s' % section_id
            section = self.read(section_id)

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
                return self.client.create(resource, section)
            elif any(p is not None for p in (display_name, description,
                                             applied_tos)):
                return self.client.update(resource, section)

        return _do_update()

    def read(self, section_id):
        resource = 'firewall/sections/%s' % section_id
        return self.client.get(resource)

    def list(self):
        resource = 'firewall/sections'
        return self.client.get(resource).get('results', [])

    def delete(self, section_id):
        resource = 'firewall/sections/%s?cascade=true' % section_id
        return self.client.delete(resource)

    def get_nsgroup_reference(self, nsgroup_id):
        return {'target_id': nsgroup_id,
                'target_type': consts.NSGROUP}

    def get_ip_cidr_reference(self, ip_cidr_block, ip_protocol):
        target_type = (consts.TARGET_TYPE_IPV4ADDRESS
                       if ip_protocol == consts.IPV4
                       else consts.TARGET_TYPE_IPV6ADDRESS)
        return {'target_id': ip_cidr_block,
                'target_type': target_type}

    def get_rule_dict(
        self, display_name, source=None,
        destination=None,
        direction=consts.IN_OUT,
        ip_protocol=consts.IPV4_IPV6,
        service=None, action=consts.FW_ACTION_ALLOW,
        logged=False):
        return {'display_name': display_name,
                'sources': [source] if source else [],
                'destinations': [destination] if destination else [],
                'direction': direction,
                'ip_protocol': ip_protocol,
                'services': [service] if service else [],
                'action': action,
                'logged': logged}

    def add_rule(self, rule, section_id):
        resource = 'firewall/sections/%s/rules' % section_id
        params = '?operation=insert_bottom'
        return self.client.create(resource + params, rule)

    def add_rules(self, rules, section_id):
        resource = 'firewall/sections/%s/rules' % section_id
        params = '?action=create_multiple&operation=insert_bottom'
        return self.client.create(resource + params, {'rules': rules})

    def delete_rule(self, section_id, rule_id):
        resource = 'firewall/sections/%s/rules/%s' % (section_id, rule_id)
        return self.client.delete(resource)

    def get_rules(self, section_id):
        resource = 'firewall/sections/%s/rules' % section_id
        return self.client.get(resource)

    def _get_fw_rule_from_sg_rule(self, sg_rule, nsgroup_id, rmt_nsgroup_id,
                                  logged, action):
        # IPV4 or IPV6
        ip_protocol = sg_rule['ethertype'].upper()
        direction = self._get_direction(sg_rule)

        if sg_rule.get(consts.LOCAL_IP_PREFIX):
            local_ip_prefix = self.get_ip_cidr_reference(
                sg_rule[consts.LOCAL_IP_PREFIX],
                ip_protocol)
        else:
            local_ip_prefix = None

        source = None
        local_group = self.get_nsgroup_reference(nsgroup_id)
        if sg_rule['remote_ip_prefix'] is not None:
            source = self.get_ip_cidr_reference(
                sg_rule['remote_ip_prefix'], ip_protocol)
            destination = local_ip_prefix or local_group
        else:
            if rmt_nsgroup_id:
                source = self.get_nsgroup_reference(rmt_nsgroup_id)
            destination = local_ip_prefix or local_group
        if direction == consts.OUT:
            source, destination = destination, source

        service = self._decide_service(sg_rule)
        name = sg_rule['id']

        return self.get_rule_dict(name, source,
                                  destination, direction,
                                  ip_protocol, service,
                                  action, logged)

    def create_rules(self, context, section_id, nsgroup_id,
                     logging_enabled, action, security_group_rules,
                     ruleid_2_remote_nsgroup_map):
        # 1. translate rules
        # 2. insert in section
        # 3. return the rules
        firewall_rules = []
        for sg_rule in security_group_rules:
            remote_nsgroup_id = ruleid_2_remote_nsgroup_map[sg_rule['id']]
            fw_rule = self._get_fw_rule_from_sg_rule(
                sg_rule, nsgroup_id, remote_nsgroup_id,
                logging_enabled, action)

            firewall_rules.append(fw_rule)

        return self.add_rules(firewall_rules, section_id)

    def set_rule_logging(self, section_id, logging):
        rules = self._process_rules_logging_for_update(
            section_id, logging)
        self.update(section_id, rules=rules)

    def _process_rules_logging_for_update(self, section_id, logging_enabled):
        rules = self.get_rules(section_id).get('results', [])
        update_rules = False
        for rule in rules:
            if rule['logged'] != logging_enabled:
                rule['logged'] = logging_enabled
                update_rules = True
        return rules if update_rules else None

    def init_default(self, name, description, nested_groups,
                     log_sg_blocked_traffic):
        fw_sections = self.list()
        for section in fw_sections:
            if section['display_name'] == name:
                break
        else:
            tags = self.build_v3_api_version_tag()
            section = self.create_empty(
                name, description, nested_groups, tags)

        block_rule = self.get_rule_dict(
            'Block All', action=consts.FW_ACTION_DROP,
            logged=log_sg_blocked_traffic)
        # TODO(roeyc): Add additional rules to allow IPV6 NDP.
        dhcp_client = self.get_nsservice(
            consts.L4_PORT_SET_NSSERVICE,
            l4_protocol=consts.UDP,
            source_ports=[67],
            destination_ports=[68])
        dhcp_client_rule_in = self.get_rule_dict(
            'DHCP Reply', direction=consts.IN,
            service=dhcp_client)

        dhcp_server = (
            self.get_nsservice(
                consts.L4_PORT_SET_NSSERVICE,
                l4_protocol=consts.UDP,
                source_ports=[68],
                destination_ports=[67]))
        dhcp_client_rule_out = self.get_rule_dict(
            'DHCP Request', direction=consts.OUT,
            service=dhcp_server)

        self.update(section['id'],
                    name, section['description'],
                    applied_tos=nested_groups,
                    rules=[dhcp_client_rule_out,
                           dhcp_client_rule_in,
                           block_rule])
        return section['id']
