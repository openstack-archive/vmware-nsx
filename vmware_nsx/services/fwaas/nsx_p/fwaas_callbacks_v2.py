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

import random

import netaddr
from oslo_log import log as logging

from neutron_lib.exceptions import firewall_v2 as exceptions

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.services.fwaas.common import fwaas_callbacks_v2 as \
    com_callbacks
from vmware_nsx.services.fwaas.common import v3_utils
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3.policy import constants as policy_constants
from vmware_nsxlib.v3 import utils as nsxlib_utils

LOG = logging.getLogger(__name__)
GATEWAY_POLICY_NAME = 'Tier1 %s gateway policy'
DEFAULT_RULE_NAME = 'Default LR Layer3 Rule'
DEFAULT_RULE_ID = 'default_rule'
RULE_NAME_PREFIX = 'Fwaas-'
ROUTER_FW_TAG = 'os-router-firewall'


class NsxpFwaasCallbacksV2(com_callbacks.NsxCommonv3FwaasCallbacksV2):
    """NSX-P RPC callbacks for Firewall As A Service V2."""

    def __init__(self, with_rpc):
        super(NsxpFwaasCallbacksV2, self).__init__(with_rpc)
        self.internal_driver = None
        if self.fwaas_enabled:
            self.internal_driver = self.fwaas_driver

    @property
    def plugin_type(self):
        return projectpluginmap.NsxPlugins.NSX_P

    @property
    def nsxpolicy(self):
        return self.core_plugin.nsxpolicy

    def _get_default_backend_rule(self, domain_id, router_id):
        """Return the default allow-all rule entry

        This rule enrty will be added to the end of the rules list
        """
        return self.nsxpolicy.gateway_policy.build_entry(
            DEFAULT_RULE_NAME, domain_id, router_id,
            self._get_random_rule_id(DEFAULT_RULE_ID),
            description=DEFAULT_RULE_NAME,
            sequence_number=None,
            action=nsx_constants.FW_ACTION_ALLOW,
            scope=[self.nsxpolicy.tier1.get_path(router_id)],
            source_groups=None, dest_groups=None,
            direction=nsx_constants.IN_OUT)

    def _translate_service(self, domain_id, router_id, rule):
        """Return the NSX Policy service id matching the FW rule service.

        L4 protocol service will be created per router-id & rule-id
        and the service id will reflect both, as will as the L4 protocol.
        This will allow the cleanup of the service by tags when the router is
        detached.
        """
        ip_version = rule.get('ip_version', 4)
        if rule.get('protocol'):
            tags = self.nsxpolicy.build_v3_tags_payload(
                rule, resource_type='os-neutron-fwrule-id',
                project_name=domain_id)
            tags = nsxlib_utils.add_v3_tag(tags, ROUTER_FW_TAG, router_id)
            l4_protocol = v3_utils.translate_fw_rule_protocol(
                rule.get('protocol'))
            # The L4 protocol must be a part of the service ID to allow
            # changing the protocol of a rule
            srv_id = '%s-%s-%s' % (rule['protocol'], router_id, rule['id'])
            srv_name = 'FW_rule_%s_%s_service' % (rule['id'], rule['protocol'])
            description = '%s service for FW rule %s of Tier1 %s' % (
                rule['protocol'], rule['id'], router_id)
            if l4_protocol in [nsx_constants.TCP, nsx_constants.UDP]:
                if rule.get('destination_port') is None:
                    destination_ports = []
                else:
                    destination_ports = v3_utils.translate_fw_rule_ports(
                        rule['destination_port'])

                if rule.get('source_port') is None:
                    source_ports = []
                else:
                    source_ports = v3_utils.translate_fw_rule_ports(
                        rule['source_port'])

                self.nsxpolicy.service.create_or_overwrite(
                    srv_name, service_id=srv_id,
                    description=description,
                    protocol=l4_protocol,
                    dest_ports=destination_ports,
                    source_ports=source_ports,
                    tags=tags)
            elif l4_protocol == nsx_constants.ICMPV4:
                #TODO(asarfaty): Can use predefined service for ICMP
                self.nsxpolicy.icmp_service.create_or_overwrite(
                    srv_name, service_id=srv_id,
                    version=ip_version,
                    tags=tags)
            return srv_id

    def _get_random_rule_id(self, rule_id):
        """Return a rule ID with random suffix to be used on the NSX
        Random sequence needs to be added to rule IDs, so that PUT command
        will replace all existing rules.
        Keeping the same rule id will require updating the rule revision as
        well.
        """
        return '%s-%s' % (rule_id, str(random.randint(1, 10000000)))

    def _get_rule_ips_group_id(self, rule_id, direction):
        return '%s-%s' % (direction, rule_id)

    def _is_empty_cidr(self, cidr, fwaas_rule_id):
        net = netaddr.IPNetwork(cidr)
        if ((net.version == 4 and cidr.startswith('0.0.0.0/')) or
            (net.version == 6 and str(net.ip) == "::")):
            LOG.warning("Unsupported FWaaS cidr %(cidr)s for rule %(id)s",
                        {'cidr': cidr, 'id': fwaas_rule_id})
            return True

    def _validate_cidr(self, cidr, fwaas_rule_id):
        error_msg = (_("Illegal FWaaS cidr %(cidr)s for rule %(id)s") %
                     {'cidr': cidr, 'id': fwaas_rule_id})
        # Validate that this is a legal & supported ipv4 / ipv6 cidr
        net = netaddr.IPNetwork(cidr)
        if net.version == 4:
            if net.prefixlen == 0:
                LOG.error(error_msg)
                raise self.driver_exception(driver=self.driver_name)
        elif net.version == 6:
            if net.prefixlen == 0:
                LOG.error(error_msg)
                raise self.driver_exception(driver=self.driver_name)
        else:
            LOG.error(error_msg)
            raise self.driver_exception(driver=self.driver_name)

    def _get_rule_cidr_group(self, domain_id, router_id, rule, is_source,
                             is_ingress):
        field = 'source_ip_address' if is_source else 'destination_ip_address'
        direction_text = 'source' if is_source else 'destination'
        if (rule.get(field) and
            not self._is_empty_cidr(rule[field], rule['id'])):
            # Create a group for ips
            group_ips = rule[field]
            group_id = self._get_rule_ips_group_id(rule['id'], direction_text)
            self._validate_cidr(group_ips, rule['id'])
            expr = self.nsxpolicy.group.build_ip_address_expression(
                [group_ips])
            tags = self.nsxpolicy.build_v3_tags_payload(
                rule, resource_type='os-neutron-fwrule-id',
                project_name=domain_id)
            tags = nsxlib_utils.add_v3_tag(tags, ROUTER_FW_TAG, router_id)
            self.nsxpolicy.group.create_or_overwrite_with_conditions(
                "FW_rule_%s_%s" % (rule['id'], direction_text),
                domain_id, group_id=group_id,
                description='%s: %s' % (direction_text, group_ips),
                conditions=[expr], tags=tags)
            return group_id

    def _create_network_group(self, domain_id, router_id, neutron_net_id):
        scope_and_tag = "%s|%s" % ('os-neutron-net-id', neutron_net_id)
        tags = []
        tags = nsxlib_utils.add_v3_tag(tags, ROUTER_FW_TAG, router_id)
        expr = self.nsxpolicy.group.build_condition(
            cond_val=scope_and_tag,
            cond_key=policy_constants.CONDITION_KEY_TAG,
            cond_member_type=nsx_constants.TARGET_TYPE_LOGICAL_SWITCH)
        group_id = '%s-%s' % (router_id, neutron_net_id)
        self.nsxpolicy.group.create_or_overwrite_with_conditions(
            "Segment_%s" % neutron_net_id,
            domain_id,
            group_id=group_id,
            description='Group for segment %s' % neutron_net_id,
            conditions=[expr],
            tags=tags)
        return group_id

    def _translate_rules(self, domain_id, router_id, segment_group,
                         fwaas_rules, is_ingress, logged=False):
        """Translate a list of FWaaS rules to NSX rule structure"""
        translated_rules = []
        for rule in fwaas_rules:
            if not rule['enabled']:
                # skip disabled rules
                continue

            # Make sure the rule has a name, and it starts with the prefix
            # (backend max name length is 255)
            if rule.get('name'):
                rule_name = RULE_NAME_PREFIX + rule['name']
            else:
                rule_name = RULE_NAME_PREFIX + rule['id']
            rule_name = rule_name[:255]

            # Set rule ID with a random suffix
            rule_id = self._get_random_rule_id(rule['id'])

            action = v3_utils.translate_fw_rule_action(
                rule['action'], rule['id'])
            if not action:
                raise exceptions.FirewallInternalDriverError(
                    driver=self.internal_driver.driver_name)

            src_group = self._get_rule_cidr_group(
                domain_id, router_id, rule, is_source=True,
                is_ingress=is_ingress)
            if not is_ingress and not src_group:
                src_group = segment_group
            dest_group = self._get_rule_cidr_group(
                domain_id, router_id, rule, is_source=False,
                is_ingress=is_ingress)
            if is_ingress and not dest_group:
                dest_group = segment_group

            srv_id = self._translate_service(domain_id, router_id, rule)
            direction = nsx_constants.IN if is_ingress else nsx_constants.OUT
            ip_protocol = (nsx_constants.IPV4 if rule.get('ip_version', 4) == 4
                           else nsx_constants.IPV6)
            rule_entry = self.nsxpolicy.gateway_policy.build_entry(
                rule_name, domain_id, router_id, rule_id,
                description=rule.get('description'),
                action=action,
                source_groups=[src_group] if src_group else None,
                dest_groups=[dest_group] if dest_group else None,
                service_ids=[srv_id] if srv_id else None,
                ip_protocol=ip_protocol,
                logged=logged,
                scope=[self.nsxpolicy.tier1.get_path(router_id)],
                direction=direction)
            translated_rules.append(rule_entry)
        return translated_rules

    def _get_port_translated_rules(self, domain_id, router_id, neutron_net_id,
                                   firewall_group):
        """Return the list of translated FWaaS rules per port
        Add the egress/ingress rules of this port +
        default drop rules in each direction for this port.
        """
        net_group_id = self._create_network_group(
            domain_id, router_id, neutron_net_id)
        port_rules = []
        # Add the firewall group ingress/egress rules only if the fw is up
        if firewall_group['admin_state_up']:
            port_rules.extend(self._translate_rules(
                domain_id, router_id, net_group_id,
                firewall_group['ingress_rule_list'], is_ingress=True))
            port_rules.extend(self._translate_rules(
                domain_id, router_id, net_group_id,
                firewall_group['egress_rule_list'], is_ingress=False))

        # Add ingress/egress block rules for this port
        port_rules.extend([
            self.nsxpolicy.gateway_policy.build_entry(
                "Block port ingress", domain_id, router_id,
                self._get_random_rule_id(
                    DEFAULT_RULE_ID + neutron_net_id + 'ingress'),
                action=nsx_constants.FW_ACTION_DROP,
                dest_groups=[net_group_id],
                scope=[self.nsxpolicy.tier1.get_path(router_id)],
                direction=nsx_constants.IN),
            self.nsxpolicy.gateway_policy.build_entry(
                "Block port egress", domain_id, router_id,
                self._get_random_rule_id(
                    DEFAULT_RULE_ID + neutron_net_id + 'egress'),
                action=nsx_constants.FW_ACTION_DROP,
                scope=[self.nsxpolicy.tier1.get_path(router_id)],
                source_groups=[net_group_id],
                direction=nsx_constants.OUT)])

        return port_rules

    def _set_rules_order(self, fw_rules):
        # TODO(asarfaty): Consider adding vmware-nsxlib api for this
        # add sequence numbers to keep rules in order
        seq_num = 0
        for rule in fw_rules:
            rule.attrs['sequence_number'] = seq_num
            seq_num += 1

    def update_router_firewall(self, context, router_id, router,
                               router_interfaces, called_from_fw=False):
        """Rewrite all the FWaaS v2 rules in the router edge firewall

        This method should be called on FWaaS updates, and on router
        interfaces changes.
        The purpose of called_from_fw is to differ between fw calls and other
        router calls, and if it is True - add the service router accordingly.
        """
        plugin = self.core_plugin
        domain_id = router['project_id']
        fw_rules = []
        router_with_fw = False
        # Add firewall rules per port attached to a firewall group
        for port in router_interfaces:

            # Check if this port has a firewall
            fwg = self.get_port_fwg(context, port['id'])
            if fwg:
                router_with_fw = True
                # Add the FWaaS rules for this port:ingress/egress firewall
                # rules + default ingress/egress drop rule for this port
                fw_rules.extend(self._get_port_translated_rules(
                    domain_id, router_id, port['network_id'], fwg))

        # Add a default allow-all rule to all other traffic & ports
        fw_rules.append(self._get_default_backend_rule(domain_id, router_id))
        self._set_rules_order(fw_rules)

        # Update the backend router firewall
        sr_exists_on_backend = plugin.verify_sr_at_backend(router_id)
        if called_from_fw:
            # FW action required
            if router_with_fw:
                # Firewall needed and no NSX service router: create it.
                if not sr_exists_on_backend:
                    plugin.create_service_router(
                        context, router_id, update_firewall=False)
                    sr_exists_on_backend = True
            else:
                # First, check if other services exist and use the sr
                router_with_services = plugin.service_router_has_services(
                    context, router_id, router=router)
                if not router_with_services and sr_exists_on_backend:
                    # No other services that require service router: delete it
                    # This also deleted the gateway policy.
                    self.core_plugin.delete_service_router(
                        context, domain_id, router_id)
                    sr_exists_on_backend = False

        if sr_exists_on_backend:
            # update the edge firewall
            self.create_router_gateway_policy(context, domain_id, router_id,
                                              router, fw_rules)

        if not router_with_fw:
            # Do all the cleanup once the router has no more FW rules
            self.delete_router_gateway_policy(domain_id, router_id)
            self.cleanup_router_fw_resources(domain_id, router_id)

    def create_router_gateway_policy(self, context, domain_id, router_id,
                                     router, fw_rules):
        """Create/Overwrite gateway policy for a router with firewall rules"""
        # Check if the gateway policy already exists
        try:
            self.nsxpolicy.gateway_policy.get(domain_id, map_id=router_id)
        except nsx_lib_exc.ResourceNotFound:
            LOG.info("Going to create gateway policy for router %s", router_id)
        else:
            # only update the rules of this policy
            self.nsxpolicy.gateway_policy.update_entries(
                domain_id, router_id, fw_rules)
            return

        tags = self.nsxpolicy.build_v3_tags_payload(
            router, resource_type='os-neutron-router-id',
            project_name=context.tenant_name)
        policy_name = GATEWAY_POLICY_NAME % router_id
        self.nsxpolicy.gateway_policy.create_with_entries(
            policy_name, domain_id, map_id=router_id,
            description=policy_name,
            tags=tags,
            entries=fw_rules,
            category=policy_constants.CATEGORY_LOCAL_GW)

    def delete_router_gateway_policy(self, domain_id, router_id):
        """Delete the gateway policy associated with a router, it it exists.
        Should be called when the router is deleted / FW removed from it
        """
        try:
            self.nsxpolicy.gateway_policy.get(domain_id, map_id=router_id)
        except nsx_lib_exc.ResourceNotFound:
            return
        self.nsxpolicy.gateway_policy.delete(domain_id, map_id=router_id)

        # Also delete all groups & services
        self.cleanup_router_fw_resources(domain_id, router_id)

    def cleanup_router_fw_resources(self, domain_id, router_id):
        tags_to_search = [{'scope': ROUTER_FW_TAG, 'tag': router_id}]
        # Delete per rule & per network groups
        groups = self.nsxpolicy.search_by_tags(
            tags_to_search,
            self.nsxpolicy.group.entry_def.resource_type())['results']
        for group in groups:
            self.nsxpolicy.group.delete(domain_id, group['id'])

        services = self.nsxpolicy.search_by_tags(
            tags_to_search,
            self.nsxpolicy.service.parent_entry_def.resource_type())['results']
        for srv in services:
            self.nsxpolicy.service.delete(srv['id'])
