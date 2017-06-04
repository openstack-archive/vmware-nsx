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

from neutron_lib import context as n_context
from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron_fwaas.extensions import firewall as fw_ext
from neutron_fwaas.services.firewall.drivers import fwaas_base

from vmware_nsx.common import locking
from vmware_nsx.plugins.nsx_v.vshield.common import (
    exceptions as vcns_exc)
from vmware_nsx.plugins.nsx_v.vshield import edge_firewall_driver
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.plugins.nsx_v.vshield import vcns_driver

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas NSX-V driver'
RULE_NAME_PREFIX = 'Fwaas-'


class EdgeFwaasDriver(fwaas_base.FwaasDriverBase):
    """NSX-V driver for Firewall As A Service - V1."""

    @property
    def edge_manager(self):
        return directory.get_plugin().edge_manager

    def __init__(self):
        LOG.debug("Loading FWaaS NsxVDriver.")
        super(EdgeFwaasDriver, self).__init__()
        self._nsxv = vcns_driver.VcnsDriver(None)

    def should_apply_firewall_to_router(self, router_data):
        """Return True if the firewall rules should be added the router

        Return False in those cases:
        - router without an external gateway (rule may be added later when
                                              there is a gateway)

        Raise an exception if the router is unsupported:
        - shared router (not supported)
        - md proxy router (not supported)

        """
        if (not router_data.get('distributed') and
            router_data.get('router_type') == 'shared'):
            LOG.error("Cannot apply firewall to shared router %s",
                      router_data['id'])
            raise fw_ext.FirewallInternalDriverError(driver=FWAAS_DRIVER_NAME)

        if router_data.get('name', '').startswith('metadata_proxy_router'):
            LOG.error("Cannot apply firewall to the metadata proxy router %s",
                      router_data['id'])
            raise fw_ext.FirewallInternalDriverError(driver=FWAAS_DRIVER_NAME)

        if not router_data.get('external_gateway_info'):
            LOG.info("Cannot apply firewall to router %s with no gateway",
                     router_data['id'])
            return False

        return True

    def _get_routers_edges(self, context, apply_list):
        # Get edges for all the routers in the apply list.
        # note that shared routers are currently not supported
        edge_manager = self.edge_manager
        edges = []
        for router_info in apply_list:

            # No FWaaS rules needed if there is no external gateway
            if not self.should_apply_firewall_to_router(router_info.router):
                continue

            lookup_id = None
            router_id = router_info.router_id
            if router_info.router.get('distributed'):
                # Distributed router
                # we need the plr edge id
                lookup_id = edge_manager.get_plr_by_tlr_id(
                    context, router_id)
            else:
                # Exclusive router
                lookup_id = router_id
            if lookup_id:
                # look for the edge id in the DB
                edge_id = edge_utils.get_router_edge_id(context, lookup_id)
                if edge_id:
                    edges.append(edge_id)
        return edges

    def _translate_rules(self, fwaas_rules):
        translated_rules = []
        for rule in fwaas_rules:
            if not rule['enabled']:
                # skip disabled rules
                continue
            # Make sure the rule has a name, and it starts with the prefix
            # (backend max name length is 30)
            if rule.get('name'):
                rule['name'] = RULE_NAME_PREFIX + rule['name']
            else:
                rule['name'] = RULE_NAME_PREFIX + rule['id']
            rule['name'] = rule['name'][:30]
            # source & destination should be lists
            if rule.get('destination_ip_address'):
                rule['destination_ip_address'] = [
                    rule['destination_ip_address']]
            if rule.get('source_ip_address'):
                rule['source_ip_address'] = [rule['source_ip_address']]
            translated_rules.append(rule)

        return translated_rules

    def _is_allow_external_rule(self, rule):
        rule_name = rule.get('name', '')
        if rule_name == edge_firewall_driver.FWAAS_ALLOW_EXT_RULE_NAME:
            return True
        # For older routers, the allow-external rule didn't have a name
        # TODO(asarfaty): delete this in the future
        if (not rule_name and
            rule.get('action') == edge_firewall_driver.FWAAS_ALLOW and
            rule.get('destination_vnic_groups', []) == ['external']):
            return True
        return False

    def _get_other_backend_rules(self, context, edge_id):
        """Get a list of current backend rules from other applications

        Those rules should stay on the backend firewall, when updating the
        FWaaS rules.

        Return it as 2 separate lists of rules, which should go before/after
        the fwaas rules.
        """
        try:
            backend_fw = self._nsxv.get_firewall(context, edge_id)
            backend_rules = backend_fw['firewall_rule_list']
        except vcns_exc.VcnsApiException:
            # Need to create a new one
            backend_rules = []
        # remove old FWaaS rules from the rules list.
        # also delete the allow-external rule, if it is there.
        # If necessary - we will add it again later
        before_rules = []
        after_rules = []
        go_after = False
        for rule_item in backend_rules:
            rule = rule_item['firewall_rule']
            rule_name = rule.get('name', '')
            fwaas_rule = rule_name.startswith(RULE_NAME_PREFIX)
            if fwaas_rule:
                # reached the fwaas part, the rest of the rules should be
                # in the 'after' list
                go_after = True
            if (rule_name == edge_firewall_driver.DNAT_RULE_NAME or
                rule_name == edge_firewall_driver.NO_SNAT_RULE_NAME):
                # passed the fwaas part, the rest of the rules should be
                # in the 'after' list
                go_after = True
            if (not fwaas_rule and
                not self._is_allow_external_rule(rule)):
                if go_after:
                    after_rules.append(rule)
                else:
                    before_rules.append(rule)

        return before_rules, after_rules

    def _set_rules_on_edge(self, context, edge_id, fw_id, translated_rules,
                           allow_external=False):
        """delete old FWaaS rules from the Edge, and add new ones

        Note that the edge might have other FW rules like NAT or LBaas
        that should remain there.

        allow_external is usually False because it shouldn't exist with a
        firewall. It should only be True when the firewall is being deleted.
        """
        # Get the existing backend rules which do not belong to FWaaS
        backend_rules, after_rules = self._get_other_backend_rules(
            context, edge_id)

        # add new FWaaS rules at the correct location by their original order
        backend_rules.extend(translated_rules)
        backend_rules.extend(after_rules)

        # update the backend
        try:
            with locking.LockManager.get_lock(str(edge_id)):
                self._nsxv.update_firewall(
                    edge_id,
                    {'firewall_rule_list': backend_rules},
                    context,
                    allow_external=allow_external)
        except Exception as e:
            # catch known library exceptions and raise Fwaas generic exception
            LOG.error("Failed to update backend firewall %(fw)s: "
                      "%(e)s", {'e': e, 'fw': fw_id})
            raise fw_ext.FirewallInternalDriverError(driver=FWAAS_DRIVER_NAME)

    def _create_or_update_firewall(self, agent_mode, apply_list, firewall):
        # admin state down means default block rule firewall
        if not firewall['admin_state_up']:
            self.apply_default_policy(agent_mode, apply_list, firewall)
            return

        context = n_context.get_admin_context()

        # Find out the relevant edges
        router_edges = self._get_routers_edges(context, apply_list)
        if not router_edges:
            LOG.warning("Cannot apply the firewall to any of the routers %s",
                        apply_list)
            return

        rules = self._translate_rules(firewall['firewall_rule_list'])
        # update each edge
        for edge_id in router_edges:
            self._set_rules_on_edge(
                context, edge_id, firewall['id'], rules)

    @log_helpers.log_method_call
    def create_firewall(self, agent_mode, apply_list, firewall):
        """Create the Firewall with a given policy. """
        self._create_or_update_firewall(agent_mode, apply_list, firewall)

    @log_helpers.log_method_call
    def update_firewall(self, agent_mode, apply_list, firewall):
        """Remove previous policy and apply the new policy."""
        self._create_or_update_firewall(agent_mode, apply_list, firewall)

    def _delete_firewall_or_set_default_policy(self, apply_list, firewall,
                                               allow_external):
        context = n_context.get_admin_context()
        router_edges = self._get_routers_edges(context, apply_list)
        if router_edges:
            for edge_id in router_edges:
                self._set_rules_on_edge(context, edge_id, firewall['id'], [],
                                        allow_external=allow_external)

    @log_helpers.log_method_call
    def delete_firewall(self, agent_mode, apply_list, firewall):
        """Delete firewall.

        Removes rules created by this instance from the backend firewall
        And add the default allow-external rule.
        """
        self._delete_firewall_or_set_default_policy(apply_list, firewall,
                                                    allow_external=True)

    @log_helpers.log_method_call
    def apply_default_policy(self, agent_mode, apply_list, firewall):
        """Apply the default policy (deny all).

        The backend firewall always has this policy (=deny all) as default,
        so we only need to delete the current rules.
        """
        self._delete_firewall_or_set_default_policy(apply_list, firewall,
                                                    allow_external=False)

    def get_firewall_translated_rules(self, firewall):
        if firewall['admin_state_up']:
            return self._translate_rules(firewall['firewall_rule_list'])
        return []
