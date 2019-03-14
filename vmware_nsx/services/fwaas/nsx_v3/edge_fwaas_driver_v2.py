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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.plugins import directory
from oslo_log import log as logging

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.services.fwaas.common import v3_utils
from vmware_nsx.services.fwaas.nsx_v3 import edge_fwaas_driver_base \
    as base_driver
from vmware_nsxlib.v3 import nsx_constants as consts

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas V2 NSX-V3 driver'
RULE_NAME_PREFIX = 'Fwaas-'
DEFAULT_RULE_NAME = 'Default LR Layer3 Rule'


class EdgeFwaasV3DriverV2(base_driver.CommonEdgeFwaasV3Driver):
    """NSX-V3 driver for Firewall As A Service - V2."""

    def __init__(self):
        super(EdgeFwaasV3DriverV2, self).__init__(FWAAS_DRIVER_NAME)
        registry.subscribe(
            self.check_backend_version,
            resources.PROCESS, events.BEFORE_SPAWN)

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

    def _translate_cidr(self, cidr, fwaas_rule_id):
        # Validate that this is a legal & supported ipv4 / ipv6 cidr
        error_msg = (_("Unsupported FWAAS cidr %(cidr)s for rule %(id)s") % {
                     'cidr': cidr, 'id': fwaas_rule_id})
        net = netaddr.IPNetwork(cidr)
        if net.version == 4:
            if cidr.startswith('0.0.0.0/'):
                # Treat as ANY and just log warning
                LOG.warning(error_msg)
                return
            if net.prefixlen == 0:
                LOG.error(error_msg)
                raise self.driver_exception(driver=self.driver_name)
        elif net.version == 6:
            if str(net.ip) == "::" or net.prefixlen == 0:
                LOG.error(error_msg)
                raise self.driver_exception(driver=self.driver_name)
        else:
            LOG.error(error_msg)
            raise self.driver_exception(driver=self.driver_name)

        return self.nsx_firewall.get_ip_cidr_reference(
            cidr,
            consts.IPV6 if net.version == 6 else consts.IPV4)

    def translate_addresses_to_target(self, cidrs, plugin_type,
                                      fwaas_rule_id=None):
        translated_cidrs = []
        for ip in cidrs:
            res = self._translate_cidr(ip, fwaas_rule_id)
            if res:
                translated_cidrs.append(res)
        return translated_cidrs

    def _translate_services(self, fwaas_rule):
        l4_protocol = v3_utils.translate_fw_rule_protocol(
            fwaas_rule['protocol'])
        if l4_protocol in [consts.TCP, consts.UDP]:
            source_ports = []
            destination_ports = []
            if fwaas_rule.get('source_port'):
                source_ports = v3_utils.translate_fw_rule_ports(
                    fwaas_rule['source_port'])
            if fwaas_rule.get('destination_port'):
                destination_ports = v3_utils.translate_fw_rule_ports(
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
            nsx_rule['action'] = v3_utils.translate_fw_rule_action(
                rule['action'], rule['id'])
            if not nsx_rule['action']:
                raise self.driver_exception(driver=self.driver_name)

            if (rule.get('destination_ip_address') and
                not rule['destination_ip_address'].startswith('0.0.0.0/')):
                nsx_rule['destinations'] = self.translate_addresses_to_target(
                    [rule['destination_ip_address']], rule['id'])
            elif replace_dest:
                # set this value as the destination logical switch
                # (only if no dest IP)
                nsx_rule['destinations'] = [{'target_type': 'LogicalSwitch',
                                             'target_id': replace_dest}]
            if (rule.get('source_ip_address') and
                not rule['source_ip_address'].startswith('0.0.0.0/')):
                nsx_rule['sources'] = self.translate_addresses_to_target(
                    [rule['source_ip_address']], rule['id'])
            elif replace_src:
                # set this value as the source logical switch,
                # (only if no source IP)
                nsx_rule['sources'] = [{'target_type': 'LogicalSwitch',
                                        'target_id': replace_src}]
            if rule.get('protocol'):
                nsx_rule['services'] = self._translate_services(rule)
            if logged:
                nsx_rule['logged'] = logged
            # Set rule direction
            if replace_src:
                nsx_rule['direction'] = 'OUT'
            elif replace_dest:
                nsx_rule['direction'] = 'IN'
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

    def get_port_translated_rules(self, nsx_ls_id, firewall_group,
                                  plugin_rules):
        """Return the list of translated rules per port"""
        port_rules = []
        # TODO(asarfaty): get this value from the firewall group extensions
        logged = False
        # Add the firewall group ingress/egress rules only if the fw is up
        if firewall_group['admin_state_up']:
            port_rules.extend(self._translate_rules(
                firewall_group['ingress_rule_list'],
                replace_dest=nsx_ls_id,
                logged=logged))
            port_rules.extend(self._translate_rules(
                firewall_group['egress_rule_list'],
                replace_src=nsx_ls_id,
                logged=logged))

        # Add the per-port plugin rules
        if plugin_rules and isinstance(plugin_rules, list):
            port_rules.extend(plugin_rules)

        # Add ingress/egress block rules for this port
        port_rules.extend([
            {'display_name': "Block port ingress",
             'action': consts.FW_ACTION_DROP,
             'destinations': [{'target_type': 'LogicalSwitch',
                               'target_id': nsx_ls_id}],
             'direction': 'IN'},
            {'display_name': "Block port egress",
             'action': consts.FW_ACTION_DROP,
             'sources': [{'target_type': 'LogicalSwitch',
                          'target_id': nsx_ls_id}],
             'direction': 'OUT'}])

        return port_rules
