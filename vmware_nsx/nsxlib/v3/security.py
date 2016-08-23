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
NSX-V3 Plugin security integration module
"""

from neutron_lib import constants
from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils

from vmware_nsx._i18n import _LE
from vmware_nsx.common import utils
from vmware_nsx.db import nsx_models
from vmware_nsx.extensions import secgroup_rule_local_ip_prefix
from vmware_nsx.extensions import securitygrouplogging as sg_logging
from vmware_nsx.nsxlib.v3 import dfw_api as firewall
from vmware_nsx.nsxlib.v3 import exceptions


LOG = log.getLogger(__name__)

DEFAULT_SECTION = 'OS Default Section for Neutron Security-Groups'
DEFAULT_SECTION_TAG_NAME = 'neutron_default_dfw_section'
PORT_SG_SCOPE = 'os-security-group'

MAX_NSGROUPS_CRITERIA_TAGS = 10


# XXX this method should be refactored to pull the common stuff out to
# a security_group utils file.
class Security(object):

    def _get_l4_protocol_name(self, protocol_number):
        if protocol_number is None:
            return
        protocol_number = constants.IP_PROTOCOL_MAP.get(protocol_number,
                                                        protocol_number)
        protocol_number = int(protocol_number)
        if protocol_number == 6:
            return firewall.TCP
        elif protocol_number == 17:
            return firewall.UDP
        elif protocol_number == 1:
            return firewall.ICMPV4
        else:
            return protocol_number

    def _get_direction(self, sg_rule):
        return (
            firewall.IN if sg_rule['direction'] == 'ingress' else firewall.OUT
        )

    def _decide_service(self, sg_rule):
        l4_protocol = self._get_l4_protocol_name(sg_rule['protocol'])
        direction = self._get_direction(sg_rule)

        if l4_protocol in [firewall.TCP, firewall.UDP]:
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

            if direction == firewall.OUT:
                source_ports, destination_ports = destination_ports, []

            return self.get_nsservice(firewall.L4_PORT_SET_NSSERVICE,
                                      l4_protocol=l4_protocol,
                                      source_ports=source_ports,
                                      destination_ports=destination_ports)
        elif l4_protocol == firewall.ICMPV4:
            return self.get_nsservice(firewall.ICMP_TYPE_NSSERVICE,
                                      protocol=l4_protocol,
                                      icmp_type=sg_rule['port_range_min'],
                                      icmp_code=sg_rule['port_range_max'])
        elif l4_protocol is not None:
            return self.get_nsservice(firewall.IP_PROTOCOL_NSSERVICE,
                                      protocol_number=l4_protocol)

    def _get_fw_rule_from_sg_rule(self, sg_rule, nsgroup_id, rmt_nsgroup_id,
                                  logged, action):
        # IPV4 or IPV6
        ip_protocol = sg_rule['ethertype'].upper()
        direction = self._get_direction(sg_rule)

        if sg_rule.get(secgroup_rule_local_ip_prefix.LOCAL_IP_PREFIX):
            local_ip_prefix = self.get_ip_cidr_reference(
                sg_rule[secgroup_rule_local_ip_prefix.LOCAL_IP_PREFIX],
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
        if direction == firewall.OUT:
            source, destination = destination, source

        service = self._decide_service(sg_rule)
        name = sg_rule['id']

        return self.get_firewall_rule_dict(name, source,
                                           destination, direction,
                                           ip_protocol, service,
                                           action, logged)

    def create_firewall_rules(self, context, section_id, nsgroup_id,
                              logging_enabled, action, security_group_rules):

        # 1. translate rules
        # 2. insert in section
        # 3. save mappings

        firewall_rules = []
        for sg_rule in security_group_rules:
            remote_nsgroup_id = self._get_remote_nsg_mapping(
                context, sg_rule, nsgroup_id)

            fw_rule = self._get_fw_rule_from_sg_rule(
                sg_rule, nsgroup_id, remote_nsgroup_id,
                logging_enabled, action)

            firewall_rules.append(fw_rule)

        return self.add_rules_in_section(firewall_rules, section_id)

    def _process_firewall_section_rules_logging_for_update(self, section_id,
                                                           logging_enabled):
        rules = self.get_section_rules(section_id).get('results', [])
        update_rules = False
        for rule in rules:
            if rule['logged'] != logging_enabled:
                rule['logged'] = logging_enabled
                update_rules = True
        return rules if update_rules else None

    def set_firewall_rule_logging_for_section(self, section_id, logging):
        rules = self._process_firewall_section_rules_logging_for_update(
            section_id, logging)
        self.update_section(section_id, rules=rules)

    def update_security_group_on_backend(self, context, security_group):
        nsgroup_id, section_id = self.get_sg_mappings(context.session,
                                                      security_group['id'])
        name = self.get_nsgroup_name(security_group)
        description = security_group['description']
        logging = (cfg.CONF.nsx_v3.log_security_groups_allowed_traffic or
                   security_group[sg_logging.LOGGING])
        rules = self._process_firewall_section_rules_logging_for_update(
            section_id, logging)
        self.update_nsgroup(nsgroup_id, name, description)
        self.update_section(section_id, name, description, rules=rules)

    def get_nsgroup_name(self, security_group):
        # NOTE(roeyc): We add the security-group id to the NSGroup name,
        # for usability purposes.
        return '%(name)s - %(id)s' % security_group

    # XXX remove db calls from nsxlib
    def save_sg_rule_mappings(self, session, firewall_rules):
        # REVISIT(roeyc): This method should take care db access only.
        rules = [(rule['display_name'], rule['id']) for rule in firewall_rules]
        with session.begin(subtransactions=True):
            for neutron_id, nsx_id in rules:
                mapping = nsx_models.NeutronNsxRuleMapping(
                    neutron_id=neutron_id, nsx_id=nsx_id)
                session.add(mapping)
        return mapping

    # XXX db calls should not be here...
    def get_sg_mappings(self, session, sg_id):
        nsgroup_mapping = session.query(
            nsx_models.NeutronNsxSecurityGroupMapping
        ).filter_by(neutron_id=sg_id).one()
        section_mapping = session.query(
            nsx_models.NeutronNsxFirewallSectionMapping
        ).filter_by(neutron_id=sg_id).one()
        return nsgroup_mapping.nsx_id, section_mapping.nsx_id

    def _get_remote_nsg_mapping(self, context, sg_rule, nsgroup_id):
        remote_nsgroup_id = None
        remote_group_id = sg_rule.get('remote_group_id')
        # skip unnecessary db access when possible
        if remote_group_id == sg_rule['security_group_id']:
            remote_nsgroup_id = nsgroup_id
        elif remote_group_id:
            remote_nsgroup_id, s = self.get_sg_mappings(context.session,
                                                        remote_group_id)
        return remote_nsgroup_id

    def get_lport_tags_for_security_groups(self, secgroups):
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

    def update_lport_with_security_groups(self, context, lport_id,
                                          original, updated):
        added = set(updated) - set(original)
        removed = set(original) - set(updated)
        for sg_id in added:
            nsgroup_id, s = self.get_sg_mappings(context.session, sg_id)
            try:
                self.add_nsgroup_members(
                    nsgroup_id, firewall.LOGICAL_PORT, [lport_id])
            except exceptions.NSGroupIsFull:
                for sg_id in added:
                    nsgroup_id, s = self.get_sg_mappings(
                        context.session, sg_id)
                    # NOTE(roeyc): If the port was not added to the nsgroup
                    # yet, then this request will silently fail.
                    self.remove_nsgroup_member(
                        nsgroup_id, firewall.LOGICAL_PORT, lport_id)
                raise exceptions.SecurityGroupMaximumCapacityReached(
                    sg_id=sg_id)
            except exceptions.ResourceNotFound:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("NSGroup %s doesn't exists"), nsgroup_id)
        for sg_id in removed:
            nsgroup_id, s = self.get_sg_mappings(context.session, sg_id)
            self.remove_nsgroup_member(
                nsgroup_id, firewall.LOGICAL_PORT, lport_id)

    def _init_default_section(self, name, description, nested_groups):
        fw_sections = self.list_sections()
        for section in fw_sections:
            if section['display_name'] == name:
                break
        else:
            tags = utils.build_v3_api_version_tag()
            section = self.create_empty_section(
                name, description, nested_groups, tags)

        block_rule = self.get_firewall_rule_dict(
            'Block All', action=firewall.DROP,
            logged=cfg.CONF.nsx_v3.log_security_groups_blocked_traffic)
        # TODO(roeyc): Add additional rules to allow IPV6 NDP.
        dhcp_client = self.get_nsservice(firewall.L4_PORT_SET_NSSERVICE,
                                         l4_protocol=firewall.UDP,
                                         source_ports=[67],
                                         destination_ports=[68])
        dhcp_client_rule_in = self.get_firewall_rule_dict(
            'DHCP Reply', direction=firewall.IN, service=dhcp_client)

        dhcp_server = (
            self.get_nsservice(firewall.L4_PORT_SET_NSSERVICE,
                               l4_protocol=firewall.UDP,
                               source_ports=[68],
                               destination_ports=[67]))
        dhcp_client_rule_out = self.get_firewall_rule_dict(
            'DHCP Request', direction=firewall.OUT, service=dhcp_server)

        self.update_section(section['id'],
                            name, section['description'],
                            applied_tos=nested_groups,
                            rules=[dhcp_client_rule_out,
                                   dhcp_client_rule_in,
                                   block_rule])
        return section['id']
