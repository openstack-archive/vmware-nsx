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

from neutron.db import securitygroups_db

from vmware_nsx.common import utils
from vmware_nsx.db import nsx_models
from vmware_nsx.nsxlib.v3 import dfw_api as firewall


NSGROUP_CONTAINER = 'NSGroup Container'
DEFAULT_SECTION = 'OS default section for security-groups'
DEFAULT_SECTION_TAG_NAME = 'neutron_default_dfw_section'


def _get_l4_protocol_name(protocol_number):
    if protocol_number is None:
        return
    protocol_number = securitygroups_db.IP_PROTOCOL_MAP.get(protocol_number,
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


def _get_direction(sg_rule):
    return firewall.IN if sg_rule['direction'] == 'ingress' else firewall.OUT


def _decide_service(sg_rule):
    l4_protocol = _get_l4_protocol_name(sg_rule['protocol'])
    direction = _get_direction(sg_rule)

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

        return firewall.get_nsservice(firewall.L4_PORT_SET_NSSERVICE,
                                      l4_protocol=l4_protocol,
                                      source_ports=source_ports,
                                      destination_ports=destination_ports)
    elif l4_protocol == firewall.ICMPV4:
        return firewall.get_nsservice(firewall.ICMP_TYPE_NSSERVICE,
                                      protocol=l4_protocol,
                                      icmp_type=sg_rule['port_range_min'],
                                      icmp_code=sg_rule['port_range_max'])
    elif l4_protocol is not None:
        return firewall.get_nsservice(firewall.IP_PROTOCOL_NSSERVICE,
                                      protocol_number=l4_protocol)


def _get_fw_rule_from_sg_rule(sg_rule, nsgroup_id, rmt_nsgroup_id):
    # IPV4 or IPV6
    ip_protocol = sg_rule['ethertype'].upper()
    direction = _get_direction(sg_rule)

    source = None
    local_group = firewall.get_nsgroup_reference(nsgroup_id)
    if sg_rule['remote_ip_prefix'] is not None:
        source = firewall.get_ip_cidr_reference(sg_rule['remote_ip_prefix'],
                                                ip_protocol)
        destination = local_group
    else:
        if rmt_nsgroup_id:
            source = firewall.get_nsgroup_reference(rmt_nsgroup_id)
        destination = local_group
    if direction == firewall.OUT:
        source, destination = destination, source

    service = _decide_service(sg_rule)
    name = sg_rule['id']

    return firewall.get_firewall_rule_dict(name, source,
                                           destination, direction,
                                           ip_protocol, service,
                                           firewall.ALLOW)


def create_firewall_rules(context, section_id, nsgroup_id,
                          security_group_rules):

    # 1. translate rules
    # 2. insert in section
    # 3. save mappings

    firewall_rules = []
    for sg_rule in security_group_rules:
        remote_nsgroup_id = _get_remote_nsg_mapping(
            context, sg_rule, nsgroup_id)

        fw_rule = _get_fw_rule_from_sg_rule(
            sg_rule, nsgroup_id, remote_nsgroup_id)

        firewall_rules.append(fw_rule)

    return firewall.add_rules_in_section(firewall_rules, section_id)


def get_nsgroup_name(security_group):
    # NOTE(roeyc): We add the security-group id to the NSGroup name,
    # for usability purposes.
    return '%(name)s - %(id)s' % security_group


def save_sg_rule_mappings(session, firewall_rules):
    # REVISIT(roeyc): This method should take care db access only.
    rules = [(rule['display_name'], rule['id']) for rule in firewall_rules]
    with session.begin(subtransactions=True):
        for neutron_id, nsx_id in rules:
            mapping = nsx_models.NeutronNsxRuleMapping(
                neutron_id=neutron_id, nsx_id=nsx_id)
            session.add(mapping)
    return mapping


def save_sg_mappings(session, sg_id, nsgroup_id, section_id):
    with session.begin(subtransactions=True):
        session.add(
            nsx_models.NeutronNsxFirewallSectionMapping(neutron_id=sg_id,
                                                        nsx_id=section_id))
        session.add(
            nsx_models.NeutronNsxSecurityGroupMapping(neutron_id=sg_id,
                                                      nsx_id=nsgroup_id))


def get_sg_rule_mapping(session, rule_id):
    rule_mapping = session.query(nsx_models.NeutronNsxRuleMapping).filter_by(
        neutron_id=rule_id).one()
    return rule_mapping.nsx_id


def get_sg_mappings(session, sg_id):
    nsgroup_mapping = session.query(nsx_models.NeutronNsxSecurityGroupMapping
                                    ).filter_by(neutron_id=sg_id).one()
    section_mapping = session.query(nsx_models.NeutronNsxFirewallSectionMapping
                                    ).filter_by(neutron_id=sg_id).one()
    return nsgroup_mapping.nsx_id, section_mapping.nsx_id


def _get_remote_nsg_mapping(context, sg_rule, nsgroup_id):
    remote_nsgroup_id = None
    remote_group_id = sg_rule.get('remote_group_id')
    # skip unnecessary db access when possible
    if remote_group_id == sg_rule['security_group_id']:
        remote_nsgroup_id = nsgroup_id
    elif remote_group_id:
        remote_nsgroup_id, _ = get_sg_mappings(context.session,
                                               remote_group_id)
    return remote_nsgroup_id


def update_lport_with_security_groups(context, lport_id, original, updated):
    added = set(updated) - set(original)
    removed = set(original) - set(updated)
    for sg_id in added:
        nsgroup_id, _ = get_sg_mappings(context.session, sg_id)
        firewall.add_nsgroup_member(
            nsgroup_id, firewall.LOGICAL_PORT, lport_id)
    for sg_id in removed:
        nsgroup_id, _ = get_sg_mappings(context.session, sg_id)
        firewall.remove_nsgroup_member(
            nsgroup_id, lport_id)


def init_nsgroup_container_and_default_section_rules():
    # REVISIT(roeyc): Should handle Neutron active-active
    # deployment scenario.
    nsgroup_description = ('This NSGroup is necessary for OpenStack '
                           'integration, do not delete.')
    section_description = ("This section is handled by OpenStack to contain "
                           "default rules on security-groups.")

    nsgroup_id = _init_nsgroup_container(NSGROUP_CONTAINER,
                                         nsgroup_description)
    section_id = _init_default_section(
        DEFAULT_SECTION, section_description, nsgroup_id)
    return nsgroup_id, section_id


def _init_nsgroup_container(name, description):
    nsgroups = firewall.list_nsgroups()
    for nsg in nsgroups:
        if nsg['display_name'] == name:
            # NSGroup container exists.
            break
    else:
        # Need to create the nsgroup container and the OS default
        # security-groups section.
        nsg = firewall.create_nsgroup(name, description, [])
    return nsg['id']


def _init_default_section(name, description, nsgroup_id):
    fw_sections = firewall.list_sections()
    for section in fw_sections:
        if section.get('display_name') == name:
            break
    else:
        section = firewall.create_empty_section(
            name, description, [nsgroup_id],
            utils.build_v3_api_version_tag())
        block_rule = firewall.get_firewall_rule_dict(
            'Block All', action=firewall.DROP)
        # TODO(roeyc): Add additional rules to allow IPV6 NDP.
        dhcp_client = firewall.get_nsservice(firewall.L4_PORT_SET_NSSERVICE,
                                             l4_protocol=firewall.UDP,
                                             source_ports=[67],
                                             destination_ports=[68])
        dhcp_client_rule_in = firewall.get_firewall_rule_dict(
            'DHCP Reply', direction=firewall.IN, service=dhcp_client)

        dhcp_server = (
            firewall.get_nsservice(firewall.L4_PORT_SET_NSSERVICE,
                                   l4_protocol=firewall.UDP,
                                   source_ports=[68],
                                   destination_ports=[67]))
        dhcp_client_rule_out = firewall.get_firewall_rule_dict(
            'DHCP Request', direction=firewall.OUT, service=dhcp_server)

        firewall.add_rules_in_section([dhcp_client_rule_out,
                                       dhcp_client_rule_in,
                                       block_rule],
                                      section['id'])
    return section['id']
