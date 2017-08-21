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
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron_lib.exceptions import firewall_v1 as exceptions

from vmware_nsx.services.fwaas.nsx_v3 import edge_fwaas_driver_base as \
    base_driver

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas V1 NSX-V3 driver'
NSX_FW_TAG = 'os-neutron-fw-id'


class EdgeFwaasV3Driver(base_driver.CommonEdgeFwaasV3Driver):
    """NSX-V3 driver for Firewall As A Service - V1."""

    def __init__(self):
        exception_cls = exceptions.FirewallInternalDriverError
        super(EdgeFwaasV3Driver, self).__init__(exception_cls,
                                                FWAAS_DRIVER_NAME)

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
        nsx_router_id, section_id = self.get_backend_router_and_fw_section(
            context, router_id)

        # Add default allow all rule
        allow_all = self.get_default_backend_rule(section_id, allow_all=True)

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
        nsx_router_id, section_id = self.get_backend_router_and_fw_section(
            context, router_id)

        #TODO(asarfaty) add dhcp relay allow rules here
        # Add default drop all rule at the end
        drop_all = self.get_default_backend_rule(section_id, allow_all=False)

        # Update the backend firewall section with the rules
        self.nsx_firewall.update(section_id, rules=rules + [drop_all])

        # Also update the router tags
        self._update_nsx_router_tags(nsx_router_id, fw_id=fw_id)
