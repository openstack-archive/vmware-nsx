# Copyright 2019 VMware, Inc.
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

from oslo_log import log as logging

from neutron_lib.api.definitions import constants as fwaas_consts

from vmware_nsxlib.v3 import nsx_constants

LOG = logging.getLogger(__name__)


def translate_fw_rule_action(fwaas_action, fwaas_rule_id):
    """Translate FWaaS action to NSX action"""
    if fwaas_action == fwaas_consts.FWAAS_ALLOW:
        return nsx_constants.FW_ACTION_ALLOW
    if fwaas_action == fwaas_consts.FWAAS_DENY:
        return nsx_constants.FW_ACTION_DROP
    if fwaas_action == fwaas_consts.FWAAS_REJECT:
        # reject is not supported by the NSX edge firewall
        LOG.warning("Reject action is not supported by the NSX backend "
                    "for edge firewall. Using %(action)s instead for "
                    "rule %(id)s",
              {'action': nsx_constants.FW_ACTION_DROP,
               'id': fwaas_rule_id})
        return nsx_constants.FW_ACTION_DROP
    # Unexpected action
    LOG.error("Unsupported FWAAS action %(action)s for rule %(id)s", {
        'action': fwaas_action, 'id': fwaas_rule_id})


def translate_fw_rule_protocol(fwaas_protocol):
    """Translate FWaaS L4 protocol to NSX protocol"""
    if fwaas_protocol.lower() == 'tcp':
        return nsx_constants.TCP
    if fwaas_protocol.lower() == 'udp':
        return nsx_constants.UDP
    if fwaas_protocol.lower() == 'icmp':
        # This will cover icmpv6 too, when adding  the rule.
        return nsx_constants.ICMPV4


def translate_fw_rule_ports(ports):
    return [ports.replace(':', '-')]
