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

from oslo_log import log as logging

from vmware_nsx.services.fwaas.common import fwaas_callbacks_v1 as com_clbcks

LOG = logging.getLogger(__name__)


class Nsxv3FwaasCallbacksV1(com_clbcks.NsxFwaasCallbacks):
    """NSX-V3 RPC callbacks for Firewall As A Service - V1."""

    def __init__(self, nsxlib):
        super(Nsxv3FwaasCallbacksV1, self).__init__()

    def should_apply_firewall_to_router(self, context, router_id):
        """Return True if the FWaaS rules should be added to this router."""
        if not super(Nsxv3FwaasCallbacksV1,
                     self).should_apply_firewall_to_router(context,
                                                           router_id):
            return False

        # get all the relevant router info
        ctx_elevated = context.elevated()
        router_data = self.core_plugin.get_router(ctx_elevated, router_id)
        if not router_data:
            LOG.error("Couldn't read router %s data", router_id)
            return False

        # Check if the FWaaS driver supports this router
        if not self.fwaas_driver.should_apply_firewall_to_router(router_data):
            return False

        return True

    def update_router_firewall(self, context, nsxlib, router_id,
                               router_interfaces):
        """Rewrite all the FWaaS v1 rules in the router edge firewall

        This method should be called on FWaaS updates, and on router
        interfaces changes.
        """

        # find the backend router and its firewall section
        nsx_id, sect_id = self.fwaas_driver.get_backend_router_and_fw_section(
            context, router_id)
        fw_rules = []
        fw_id = None
        if self.should_apply_firewall_to_router(context, router_id):
            # Find the firewall attached to this router
            # (must have one since should_apply returned true)
            firewall = self.get_router_firewall(context, router_id)
            fw_id = firewall['id']

            # Add the FW rules
            fw_rules.extend(self.fwaas_driver.get_router_translated_rules(
                router_id, firewall))

            # Add plugin additional allow rules
            fw_rules.extend(self.core_plugin.get_extra_fw_rules(
                context, router_id))

            # Add the default drop all rule
            fw_rules.append(self.fwaas_driver.get_default_backend_rule(
                sect_id, allow_all=False))
        else:
            # default allow all rule
            fw_rules.append(self.fwaas_driver.get_default_backend_rule(
                sect_id, allow_all=True))

        # update the backend
        nsxlib.firewall_section.update(sect_id, rules=fw_rules)

        # Also update the router tags
        self.fwaas_driver.update_nsx_router_tags(nsx_id, fw_id=fw_id)
