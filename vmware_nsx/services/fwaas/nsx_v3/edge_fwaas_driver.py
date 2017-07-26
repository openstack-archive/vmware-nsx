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
from neutron_lib import context as n_context
from neutron_lib.exceptions import firewall_v1 as exceptions
from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from vmware_nsx.db import db as nsx_db
from vmware_nsxlib.v3 import nsx_constants as consts

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas NSX-V3 driver'
RULE_NAME_PREFIX = 'Fwaas-'
DEFAULT_RULE_NAME = 'Default LR Layer3 Rule'
NSX_FW_TAG = 'os-neutron-fw-id'


class EdgeFwaasV3Driver(fwaas_base.FwaasDriverBase):
    """NSX-V3 driver for Firewall As A Service - V1."""

    def __init__(self):
        LOG.debug("Loading FWaaS NsxV3Driver.")
        super(EdgeFwaasV3Driver, self).__init__()
        self.driver_name = FWAAS_DRIVER_NAME

        self.backend_support = True
        registry.subscribe(
            self.check_backend_version,
            resources.PROCESS, events.BEFORE_SPAWN)

    @property
    def nsxlib(self):
        return directory.get_plugin().nsxlib

    @property
    def nsx_firewall(self):
        return self.nsxlib.firewall_section

    @property
    def nsx_router(self):
        return self.nsxlib.logical_router

    def check_backend_version(self, resource, event, trigger, **kwargs):
        if not self.nsxlib.feature_supported(consts.FEATURE_ROUTER_FIREWALL):
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

    @staticmethod
    def _translate_action(fwaas_action, fwaas_rule_id):
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
        raise exceptions.FirewallInternalDriverError(
            driver=FWAAS_DRIVER_NAME)

    def _translate_cidr(self, cidr):
        return self.nsx_firewall.get_ip_cidr_reference(
            cidr,
            consts.IPV6 if netaddr.valid_ipv6(cidr) else consts.IPV4)

    def _translate_addresses(self, cidrs):
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

    def _translate_rules(self, fwaas_rules):
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
            if rule.get('destination_ip_address'):
                nsx_rule['destinations'] = self._translate_addresses(
                    [rule['destination_ip_address']])
            if rule.get('source_ip_address'):
                nsx_rule['sources'] = self._translate_addresses(
                    [rule['source_ip_address']])
            if rule.get('protocol'):
                nsx_rule['services'] = self._translate_services(rule)

            translated_rules.append(nsx_rule)

        return translated_rules

    def _create_or_update_firewall(self, agent_mode, apply_list, firewall):
        # admin state down means default block rule firewall
        if not firewall['admin_state_up']:
            self.apply_default_policy(agent_mode, apply_list, firewall)
            return
        context = n_context.get_admin_context()
        rules = self._translate_rules(firewall['firewall_rule_list'])
        # update each router on the backend
        self._update_backend_routers(context, apply_list, firewall['id'],
                                     rules=rules)

    def validate_backend_version(self):
        # prevent firewall actions if the backend does not support it
        if not self.backend_support:
            LOG.error("The NSX backend does not support router firewall")
            raise exceptions.FirewallInternalDriverError(
                driver=self.driver_name)

    @log_helpers.log_method_call
    def create_firewall(self, agent_mode, apply_list, firewall):
        """Create the Firewall with a given policy. """
        self.validate_backend_version()
        self._create_or_update_firewall(agent_mode, apply_list, firewall)

    @log_helpers.log_method_call
    def update_firewall(self, agent_mode, apply_list, firewall):
        """Remove previous policy and apply the new policy."""
        self.validate_backend_version()
        self._create_or_update_firewall(agent_mode, apply_list, firewall)

    @log_helpers.log_method_call
    def delete_firewall(self, agent_mode, apply_list, firewall):
        """Delete firewall.

        Removes rules created by this instance from the backend firewall
        And add the default allow rule.
        """
        self.validate_backend_version()
        context = n_context.get_admin_context()
        self._update_backend_routers(context, apply_list, firewall['id'],
                                     delete_fw=True)

    @log_helpers.log_method_call
    def apply_default_policy(self, agent_mode, apply_list, firewall):
        """Apply the default policy (deny all).

        The backend firewall always has this policy (=deny all) as default,
        so we only need to delete the current rules.
        """
        self.validate_backend_version()
        context = n_context.get_admin_context()
        self._update_backend_routers(context, apply_list, firewall['id'],
                                     rules=[])

    def _update_backend_routers(self, context, apply_list, fw_id, rules=None,
                                delete_fw=False):
        # update each router on the backend
        for router_info in apply_list:

            # Skip unsupported routers
            if not self.should_apply_firewall_to_router(router_info.router):
                continue

            router_id = router_info.router_id

            # update the routers firewall
            if delete_fw:
                self._delete_nsx_router_firewall(context, router_id)
            else:
                self._update_nsx_router_firewall(context, router_id, fw_id,
                                                 rules)

    def _get_backend_router_and_fw_section(self, context, router_id):
        # find the backend router id in the DB
        nsx_router_id = nsx_db.get_nsx_router_id(context.session, router_id)
        if nsx_router_id is None:
            LOG.error("Didn't find nsx router for router %s", router_id)
            raise exceptions.FirewallInternalDriverError(
                driver=self.driver_name)

        # get the FW section id of the backend router
        try:
            section_id = self.nsx_router.get_firewall_section_id(
                nsx_router_id)
        except Exception as e:
            LOG.error("Failed to find router firewall section for router "
                      "%(id)s: %(e)s", {'id': router_id, 'e': e})
            raise exceptions.FirewallInternalDriverError(
                driver=self.driver_name)
        if section_id is None:
            LOG.error("Failed to find router firewall section for router "
                      "%(id)s.", {'id': router_id})
            raise exceptions.FirewallInternalDriverError(
                driver=self.driver_name)

        return nsx_router_id, section_id

    def _update_nsx_router_tags(self, nsx_router_id, fw_id=None):
        """Get the updated tags to put on the nsx-router

        With/without the firewall id
        """
        # Get the current tags
        nsx_router = self.nsx_router.get(nsx_router_id)
        if 'tags' not in nsx_router:
            nsx_router['tags'] = []
        tags = nsx_router['tags']

        # Look for the firewall tag and update/remove it
        update_tags = False
        found_tag = False
        for tag in tags:
            if tag.get('scope') == NSX_FW_TAG:
                found_tag = True
                if not fw_id:
                    tags.remove(tag)
                    update_tags = True
                    break
                if fw_id != tag.get('tag'):
                    tag['tag'] = fw_id
                    update_tags = True
                    break
        # Add the tag if not found
        if fw_id and not found_tag:
            tags.append({'scope': NSX_FW_TAG,
                         'tag': fw_id})
            update_tags = True

        # update tags on the backend router
        if update_tags:
            self.nsx_router.update(nsx_router_id, tags=tags)

    def _delete_nsx_router_firewall(self, context, router_id):
        """Reset the router firewall back to it's default"""

        # find the backend router and its firewall section
        nsx_router_id, section_id = self._get_backend_router_and_fw_section(
            context, router_id)

        # Add default allow all rule
        old_default_rule = self.nsx_firewall.get_default_rule(
            section_id)
        allow_all = {
            'display_name': DEFAULT_RULE_NAME,
            'action': consts.FW_ACTION_ALLOW,
            'is_default': True,
            'id': old_default_rule['id'] if old_default_rule else 0}

        # Update the backend firewall section with the rules
        self.nsx_firewall.update(section_id, rules=[allow_all])

        # Also update the router tags
        self._update_nsx_router_tags(nsx_router_id)

    def _update_nsx_router_firewall(self, context, router_id, fw_id, rules):
        """Update the backend router firewall section

        Adding all relevant north-south rules from the FWaaS firewall
        and the default drop all rule

        Since those rules do no depend on the router gateway/interfaces/ips
        there is no need to call this method on each router update.
        Just when the firewall changes.
        """
        # find the backend router and its firewall section
        nsx_router_id, section_id = self._get_backend_router_and_fw_section(
            context, router_id)

        # Add default drop all rule at the end
        old_default_rule = self.nsx_firewall.get_default_rule(
            section_id)
        drop_all = {
            'display_name': DEFAULT_RULE_NAME,
            'action': consts.FW_ACTION_DROP,
            'is_default': True,
            'id': old_default_rule['id'] if old_default_rule else 0}

        # Update the backend firewall section with the rules
        self.nsx_firewall.update(section_id, rules=rules + [drop_all])

        # Also update the router tags
        self._update_nsx_router_tags(nsx_router_id, fw_id=fw_id)
