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


class EdgeFwaasV3DriverV1(base_driver.CommonEdgeFwaasV3Driver):
    """NSX-V3 driver for Firewall As A Service - V1."""

    def __init__(self):
        exception_cls = exceptions.FirewallInternalDriverError
        super(EdgeFwaasV3DriverV1, self).__init__(exception_cls,
                                                  FWAAS_DRIVER_NAME)

    @log_helpers.log_method_call
    def create_firewall(self, agent_mode, apply_list, firewall):
        """Create the Firewall with a given policy. """
        self._update_backend_routers(apply_list, firewall['id'])

    @log_helpers.log_method_call
    def update_firewall(self, agent_mode, apply_list, firewall):
        """Remove previous policy and apply the new policy."""
        self._update_backend_routers(apply_list, firewall['id'])

    @log_helpers.log_method_call
    def delete_firewall(self, agent_mode, apply_list, firewall):
        """Delete firewall.

        Removes rules created by this instance from the backend firewall
        And add the default allow rule.
        """
        self._update_backend_routers(apply_list, firewall['id'])

    @log_helpers.log_method_call
    def apply_default_policy(self, agent_mode, apply_list, firewall):
        """Apply the default policy (deny all).

        The backend firewall always has this policy (=deny all) as default,
        so we only need to delete the current rules.
        """
        self._update_backend_routers(apply_list, firewall['id'])

    def _update_backend_routers(self, apply_list, fw_id):
        """"Update each router on the backend using the core plugin code"""
        self.validate_backend_version()
        context = n_context.get_admin_context()
        for router_info in apply_list:
            # Skip unsupported routers
            if not self.should_apply_firewall_to_router(router_info.router):
                continue

            self.core_plugin.update_router_firewall(
                context, router_info.router_id)

    def update_nsx_router_tags(self, nsx_router_id, fw_id=None):
        """Update the backend router with tags marking the attached fw id"""
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

    def get_router_translated_rules(self, router_id, firewall):
        """Return the list of translated rules

        The default drop all will be added later
        """
        # Return the firewall rules only if the fw is up
        if firewall['admin_state_up']:
            # TODO(asarfaty): get this value from the firewall extensions
            logged = False
            return self._translate_rules(firewall['firewall_rule_list'],
                                         logged=logged)

        return []
