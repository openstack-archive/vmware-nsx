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

import xml.etree.ElementTree as et

from oslo_log import log as logging

from vmware_nsx.common import utils

WAIT_INTERVAL = 2000
MAX_ATTEMPTS = 5

LOG = logging.getLogger(__name__)


class NsxSecurityGroupUtils(object):

    def __init__(self, nsxv_manager):
        LOG.debug("Start Security Group Utils initialization")
        self.nsxv_manager = nsxv_manager

    def to_xml_string(self, element):
        return et.tostring(element)

    def get_section_with_rules(self, name, rules, section_id=None):
        """Helper method to create section dict with rules."""

        section = et.Element('section')
        section.attrib['name'] = name
        if section_id:
            section.attrib['id'] = section_id
        for rule in rules:
            section.append(rule)
        return section

    def get_container(self, nsx_sg_id):
        container = {'type': 'SecurityGroup', 'value': nsx_sg_id}
        return container

    def get_remote_container(self, remote_group_id, remote_ip_mac):
        container = None
        if remote_group_id is not None:
            return self.get_container(remote_group_id)
        if remote_ip_mac is not None:
            container = {'type': 'Ipv4Address', 'value': remote_ip_mac}
        return container

    def get_rule_config(self, applied_to_ids, name, action='allow',
                        applied_to='SecurityGroup',
                        source=None, destination=None, services=None,
                        flags=None, logged=False):
        """Helper method to create a nsx rule dict."""
        ruleTag = et.Element('rule')
        ruleTag.attrib['logged'] = 'true' if logged else 'false'
        nameTag = et.SubElement(ruleTag, 'name')
        nameTag.text = name
        actionTag = et.SubElement(ruleTag, 'action')
        actionTag.text = action

        apList = et.SubElement(ruleTag, 'appliedToList')
        for applied_to_id in applied_to_ids:
            apTag = et.SubElement(apList, 'appliedTo')
            apTypeTag = et.SubElement(apTag, 'type')
            apTypeTag.text = applied_to
            apValueTag = et.SubElement(apTag, 'value')
            apValueTag.text = applied_to_id

        if source is not None:
            sources = et.SubElement(ruleTag, 'sources')
            sources.attrib['excluded'] = 'false'
            srcTag = et.SubElement(sources, 'source')
            srcTypeTag = et.SubElement(srcTag, 'type')
            srcTypeTag.text = source['type']
            srcValueTag = et.SubElement(srcTag, 'value')
            srcValueTag.text = source['value']

        if destination is not None:
            dests = et.SubElement(ruleTag, 'destinations')
            dests.attrib['excluded'] = 'false'
            destTag = et.SubElement(dests, 'destination')
            destTypeTag = et.SubElement(destTag, 'type')
            destTypeTag.text = destination['type']
            destValueTag = et.SubElement(destTag, 'value')
            destValueTag.text = destination['value']

        if services:
            s = et.SubElement(ruleTag, 'services')
            for protocol, port, icmptype, icmpcode in services:
                svcTag = et.SubElement(s, 'service')
                try:
                    int(protocol)
                    svcProtocolTag = et.SubElement(svcTag, 'protocol')
                    svcProtocolTag.text = str(protocol)
                except ValueError:
                    svcProtocolTag = et.SubElement(svcTag, 'protocolName')
                    svcProtocolTag.text = protocol
                if port is not None:
                    svcPortTag = et.SubElement(svcTag, 'destinationPort')
                    svcPortTag.text = str(port)
                if icmptype is not None:
                    svcPortTag = et.SubElement(svcTag, 'subProtocol')
                    svcPortTag.text = str(icmptype)
                if icmpcode is not None:
                    svcPortTag = et.SubElement(svcTag, 'icmpCode')
                    svcPortTag.text = str(icmpcode)

        if flags:
            if flags.get('ethertype') is not None:
                pktTag = et.SubElement(ruleTag, 'packetType')
                pktTag.text = flags.get('ethertype')
            if flags.get('direction') is not None:
                dirTag = et.SubElement(ruleTag, 'direction')
                dirTag.text = flags.get('direction')
        return ruleTag

    def get_rule_id_pair_from_section(self, resp):
        root = et.fromstring(resp)
        pairs = []
        for rule in root.findall('rule'):
            pair = {'nsx_id': rule.attrib.get('id'),
                    'neutron_id': rule.find('name').text}
            pairs.append(pair)
        return pairs

    def extend_section_with_rules(self, section, nsx_rules):
        section.extend(nsx_rules)

    def parse_section(self, xml_string):
        return et.fromstring(xml_string)

    def get_nsx_sg_name(self, sg_data):
        return '%(name)s (%(id)s)' % sg_data

    def get_nsx_section_name(self, sg_data):
        return 'SG Section: %s' % self.get_nsx_sg_name(sg_data)

    def parse_and_get_section_id(self, section_xml):
        section = et.fromstring(section_xml)
        return section.attrib['id']

    def is_section_logged(self, section):
        # Determine if this section rules are being logged by the first rule
        # 'logged' value.
        rule = section.find('rule')
        if rule is not None:
            return rule.attrib.get('logged') == 'true'
        return False

    def set_rules_logged_option(self, section, logged):
        value = 'true' if logged else 'false'
        rules = section.findall('rule')
        updated = False
        for rule in rules:
            if rule.attrib['logged'] != value:
                rule.attrib['logged'] = value
                updated = True
        return updated

    def del_nsx_security_group_from_policy(self, policy_id, sg_id):
        if not policy_id:
            return
        policy = self.nsxv_manager.vcns.get_security_policy(policy_id)
        policy = utils.normalize_xml(policy)

        # check if the security group is already bounded to the policy
        for binding in policy.iter('securityGroupBinding'):
            if binding.find('objectId').text == sg_id:
                # delete this entry
                policy.remove(binding)

                return self.nsxv_manager.vcns.update_security_policy(
                    policy_id, et.tostring(policy))

    def add_nsx_security_group_to_policy(self, policy_id, sg_id):
        if not policy_id:
            return
        # Get the policy configuration
        policy = self.nsxv_manager.vcns.get_security_policy(policy_id)
        policy = utils.normalize_xml(policy)

        # check if the security group is already bounded to the policy
        for binding in policy.iter('securityGroupBinding'):
            if binding.find('objectId').text == sg_id:
                # Already there
                return

        # Add a new binding entry
        new_binding = et.SubElement(policy, 'securityGroupBinding')
        et.SubElement(new_binding, 'objectId').text = sg_id

        return self.nsxv_manager.vcns.update_security_policy(
            policy_id, et.tostring(policy))
