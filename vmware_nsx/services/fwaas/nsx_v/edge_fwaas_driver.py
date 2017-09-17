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
from neutron_lib.exceptions import firewall_v1 as exceptions
from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron_fwaas.services.firewall.drivers import fwaas_base

from vmware_nsx.common import locking
from vmware_nsx.plugins.nsx_v.vshield import edge_utils

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas NSX-V driver'
RULE_NAME_PREFIX = 'Fwaas-'


class EdgeFwaasDriver(fwaas_base.FwaasDriverBase):
    """NSX-V driver for Firewall As A Service - V1."""

    @property
    def core_plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
            if not self._core_plugin.init_is_complete:
                self._core_plugin.init_complete(None, None, {})
        return self._core_plugin

    @property
    def edge_manager(self):
        return self.core_plugin.edge_manager

    def __init__(self):
        LOG.debug("Loading FWaaS NsxVDriver.")
        super(EdgeFwaasDriver, self).__init__()
        self.driver_name = FWAAS_DRIVER_NAME
        self._core_plugin = None

    def should_apply_firewall_to_router(self, router_data,
                                        raise_exception=True):
        """Return True if the firewall rules should be added the router

        Return False in those cases:
        - router without an external gateway (rule may be added later when
                                              there is a gateway)

        Raise an exception if the router is unsupported
        (and raise_exception is True):
        - shared router (not supported)
        - md proxy router (not supported)

        """
        if (not router_data.get('distributed') and
            router_data.get('router_type') == 'shared'):
            LOG.error("Cannot apply firewall to shared router %s",
                      router_data['id'])
            if raise_exception:
                raise exceptions.FirewallInternalDriverError(
                    driver=self.driver_name)
            return False

        if router_data.get('name', '').startswith('metadata_proxy_router'):
            LOG.error("Cannot apply firewall to the metadata proxy router %s",
                      router_data['id'])
            if raise_exception:
                raise exceptions.FirewallInternalDriverError(
                    driver=self.driver_name)
            return False

        if not router_data.get('external_gateway_info'):
            LOG.info("Cannot apply firewall to router %s with no gateway",
                     router_data['id'])
            return False

        return True

    def _get_routers_edges(self, context, apply_list):
        # Get edges for all the routers in the apply list.
        # note that shared routers are currently not supported
        edge_manager = self.edge_manager
        edges_map = {}
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
                    edges_map[router_id] = {'edge_id': edge_id,
                                            'lookup_id': lookup_id}
        return edges_map

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

    def _set_rules_on_router_edge(self, context, router_id, neutron_id,
                                  edge_id, fw_id, translated_rules,
                                  delete_fw=False):
        """Recreate router edge firewall rules

        Using the plugin code to recreate all the rules with the additional
        FWaaS rules.

        router_id is the is of the router about to be updated
            (in case of distributed router - the plr)
        neutron_id is the neutron router id
        """
        # update the backend
        router_db = self.core_plugin._get_router(context, neutron_id)
        try:
            with locking.LockManager.get_lock(str(edge_id)):
                self.core_plugin.update_router_firewall(
                    context, router_id, router_db,
                    fwaas_rules=translated_rules)
        except Exception as e:
            # catch known library exceptions and raise Fwaas generic exception
            LOG.error("Failed to update firewall %(fw)s on edge %(edge_id)s: "
                      "%(e)s", {'e': e, 'fw': fw_id, 'edge_id': edge_id})
            raise exceptions.FirewallInternalDriverError(
                driver=self.driver_name)

    def _create_or_update_firewall(self, agent_mode, apply_list, firewall):
        # admin state down means default block rule firewall
        if not firewall['admin_state_up']:
            self.apply_default_policy(agent_mode, apply_list, firewall)
            return

        # get router-edge mapping
        context = n_context.get_admin_context()
        edges_map = self._get_routers_edges(context, apply_list)
        if not edges_map:
            routers = [r.router_id for r in apply_list]
            LOG.warning("Cannot apply the firewall %(fw)s to any of the "
                        "routers %(rtrs)s",
                        {'fw': firewall['id'], 'rtrs': routers})
            return

        # Translate the FWaaS rules
        rules = self._translate_rules(firewall['firewall_rule_list'])

        # update each relevant edge with the new rules
        for router_info in apply_list:
            neutron_id = router_info.router_id
            info = edges_map.get(neutron_id)
            if info:
                self._set_rules_on_router_edge(
                    context, info['lookup_id'], neutron_id, info['edge_id'],
                    firewall['id'], rules)

    @log_helpers.log_method_call
    def create_firewall(self, agent_mode, apply_list, firewall):
        """Create the Firewall with a given policy. """
        self._create_or_update_firewall(agent_mode, apply_list, firewall)

    @log_helpers.log_method_call
    def update_firewall(self, agent_mode, apply_list, firewall):
        """Remove previous policy and apply the new policy."""
        self._create_or_update_firewall(agent_mode, apply_list, firewall)

    def _delete_firewall_or_set_default_policy(self, apply_list, firewall,
                                               delete_fw=False):
        # get router-edge mapping
        context = n_context.get_admin_context()
        edges_map = self._get_routers_edges(context, apply_list)

        # if the firewall is deleted, rules should be None
        rules = None if delete_fw else []

        # Go over all routers and update them on backend
        for router_info in apply_list:
            neutron_id = router_info.router_id
            info = edges_map.get(neutron_id)
            if info:
                self._set_rules_on_router_edge(
                    context, info['lookup_id'], neutron_id, info['edge_id'],
                    firewall['id'], rules, delete_fw=delete_fw)

    @log_helpers.log_method_call
    def delete_firewall(self, agent_mode, apply_list, firewall):
        """Delete firewall.

        Removes rules created by this instance from the backend firewall
        And add the default allow-external rule.
        """
        self._delete_firewall_or_set_default_policy(apply_list, firewall,
                                                    delete_fw=True)

    @log_helpers.log_method_call
    def apply_default_policy(self, agent_mode, apply_list, firewall):
        """Apply the default policy (deny all).

        The backend firewall always has this policy (=deny all) as default,
        so we only need to delete the current rules.
        """
        self._delete_firewall_or_set_default_policy(apply_list, firewall,
                                                    delete_fw=False)

    def get_firewall_translated_rules(self, firewall):
        if firewall['admin_state_up']:
            return self._translate_rules(firewall['firewall_rule_list'])
        return []
