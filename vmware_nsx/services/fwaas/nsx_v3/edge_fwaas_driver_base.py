# Copyright 2017 VMware, Inc.
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

from neutron_fwaas.services.firewall.drivers import fwaas_base
from neutron_lib.api.definitions import constants as fwaas_consts
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.plugins import directory
from oslo_log import log as logging

from vmware_nsx.extensions import projectpluginmap
from vmware_nsxlib.v3 import nsx_constants as consts

LOG = logging.getLogger(__name__)
RULE_NAME_PREFIX = 'Fwaas-'
DEFAULT_RULE_NAME = 'Default LR Layer3 Rule'


class CommonEdgeFwaasV3Driver(fwaas_base.FwaasDriverBase):
    """Base class for NSX-V3 driver for Firewall As A Service - V1 & V2."""

    def __init__(self, driver_exception, driver_name):
        super(CommonEdgeFwaasV3Driver, self).__init__()
        self.driver_name = driver_name
        self.backend_support = True
        self.driver_exception = driver_exception
        registry.subscribe(
            self.check_backend_version,
            resources.PROCESS, events.BEFORE_SPAWN)
        self._core_plugin = None

    @property
    def core_plugin(self):
        """Get the NSX-V3 core plugin"""
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
            if self._core_plugin.is_tvd_plugin():
                self._core_plugin = self._core_plugin.get_plugin_by_type(
                    projectpluginmap.NsxPlugins.NSX_T)
                if not self._core_plugin:
                    # The nsx-t plugin was not initialized
                    return
            # make sure plugin init was completed
            if not self._core_plugin.init_is_complete:
                self._core_plugin.init_complete(None, None, {})
        return self._core_plugin

    @property
    def nsxlib(self):
        return self.core_plugin.nsxlib

    @property
    def nsx_firewall(self):
        return self.nsxlib.firewall_section

    @property
    def nsx_router(self):
        return self.nsxlib.logical_router

    def check_backend_version(self, resource, event, trigger, payload=None):
        if (self.core_plugin and
            not self.nsxlib.feature_supported(consts.FEATURE_ROUTER_FIREWALL)):
            # router firewall is not supported
            LOG.warning("FWaaS is not supported by the NSX backend (version "
                        "%s): Router firewall is not supported",
                        self.nsxlib.get_version())
            self.backend_support = False

    def should_apply_firewall_to_router(self, router_data):
        """Return True if the firewall rules should be added the router

        Right now the driver supports for all routers.
        """
        return True

    def _translate_action(self, fwaas_action, fwaas_rule_id):
        """Translate FWaaS action to NSX action"""
        if fwaas_action == fwaas_consts.FWAAS_ALLOW:
            return consts.FW_ACTION_ALLOW
        if fwaas_action == fwaas_consts.FWAAS_DENY:
            return consts.FW_ACTION_DROP
        if fwaas_action == fwaas_consts.FWAAS_REJECT:
            # reject is not supported by the nsx router firewall
            LOG.warning("Reject action is not supported by the NSX backend "
                        "for router firewall. Using %(action)s instead for "
                        "rule %(id)s",
                  {'action': consts.FW_ACTION_DROP,
                   'id': fwaas_rule_id})
            return consts.FW_ACTION_DROP
        # Unexpected action
        LOG.error("Unsupported FWAAS action %(action)s for rule %(id)s", {
            'action': fwaas_action, 'id': fwaas_rule_id})
        raise self.driver_exception(driver=self.driver_name)

    def _translate_cidr(self, cidr):
        return self.nsx_firewall.get_ip_cidr_reference(
            cidr,
            consts.IPV6 if netaddr.valid_ipv6(cidr) else consts.IPV4)

    def translate_addresses_to_target(self, cidrs):
        return [self._translate_cidr(ip) for ip in cidrs]

    @staticmethod
    def _translate_protocol(fwaas_protocol):
        """Translate FWaaS L4 protocol to NSX protocol"""
        if fwaas_protocol.lower() == 'tcp':
            return consts.TCP
        if fwaas_protocol.lower() == 'udp':
            return consts.UDP
        if fwaas_protocol.lower() == 'icmp':
            # This will cover icmpv6 too, when adding  the rule.
            return consts.ICMPV4

    @staticmethod
    def _translate_ports(ports):
        return [ports.replace(':', '-')]

    def _translate_services(self, fwaas_rule):
        l4_protocol = self._translate_protocol(fwaas_rule['protocol'])
        if l4_protocol in [consts.TCP, consts.UDP]:
            source_ports = []
            destination_ports = []
            if fwaas_rule.get('source_port'):
                source_ports = self._translate_ports(
                    fwaas_rule['source_port'])
            if fwaas_rule.get('destination_port'):
                destination_ports = self._translate_ports(
                    fwaas_rule['destination_port'])

            return [self.nsx_firewall.get_nsservice(
                consts.L4_PORT_SET_NSSERVICE,
                l4_protocol=l4_protocol,
                source_ports=source_ports,
                destination_ports=destination_ports)]
        elif l4_protocol == consts.ICMPV4:
            # Add both icmp v4 & v6 services
            return [
                self.nsx_firewall.get_nsservice(
                    consts.ICMP_TYPE_NSSERVICE,
                    protocol=consts.ICMPV4),
                self.nsx_firewall.get_nsservice(
                    consts.ICMP_TYPE_NSSERVICE,
                    protocol=consts.ICMPV6),
            ]

    def _translate_rules(self, fwaas_rules, replace_src=None,
                         replace_dest=None, logged=False):
        translated_rules = []
        for rule in fwaas_rules:
            nsx_rule = {}
            if not rule['enabled']:
                # skip disabled rules
                continue
            # Make sure the rule has a name, and it starts with the prefix
            # (backend max name length is 255)
            if rule.get('name'):
                name = RULE_NAME_PREFIX + rule['name']
            else:
                name = RULE_NAME_PREFIX + rule['id']
            nsx_rule['display_name'] = name[:255]
            if rule.get('description'):
                nsx_rule['notes'] = rule['description']
            nsx_rule['action'] = self._translate_action(
                rule['action'], rule['id'])
            if replace_dest:
                # set this value as the destination logical switch,
                # and set the rule to ingress
                nsx_rule['destinations'] = [{'target_type': 'LogicalSwitch',
                                             'target_id': replace_dest}]
                nsx_rule['direction'] = 'IN'
            elif rule.get('destination_ip_address'):
                nsx_rule['destinations'] = self.translate_addresses_to_target(
                    [rule['destination_ip_address']])
            if replace_src:
                # set this value as the source logical switch,
                # and set the rule to egress
                nsx_rule['sources'] = [{'target_type': 'LogicalSwitch',
                                        'target_id': replace_src}]
                nsx_rule['direction'] = 'OUT'
            elif rule.get('source_ip_address'):
                nsx_rule['sources'] = self.translate_addresses_to_target(
                    [rule['source_ip_address']])
            if rule.get('protocol'):
                nsx_rule['services'] = self._translate_services(rule)
            if logged:
                nsx_rule['logged'] = logged
            translated_rules.append(nsx_rule)

        return translated_rules

    def validate_backend_version(self):
        # prevent firewall actions if the backend does not support it
        if not self.backend_support:
            LOG.error("The NSX backend does not support router firewall")
            raise self.driver_exception(driver=self.driver_name)

    def get_default_backend_rule(self, section_id, allow_all=True):
        # Add default allow all rule
        old_default_rule = self.nsx_firewall.get_default_rule(
            section_id)
        return {
            'display_name': DEFAULT_RULE_NAME,
            'action': (consts.FW_ACTION_ALLOW if allow_all
                       else consts.FW_ACTION_DROP),
            'is_default': True,
            'id': old_default_rule['id'] if old_default_rule else 0}
