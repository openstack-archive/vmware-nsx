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

from vmware_nsx.services.fwaas.common import fwaas_callbacks_v2 as \
    com_callbacks

LOG = logging.getLogger(__name__)


class Nsxv3FwaasCallbacksV2(com_callbacks.NsxFwaasCallbacksV2):
    """NSX-V3 RPC callbacks for Firewall As A Service - V2."""

    def __init__(self, nsxlib):
        super(Nsxv3FwaasCallbacksV2, self).__init__()

    def should_apply_firewall_to_router(self, context, router_id):
        """Return True if the FWaaS rules should be added to this router."""
        if not super(Nsxv3FwaasCallbacksV2,
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

    def get_port_rules(self, nsx_port_id, fwg):
        return self.fwaas_driver.get_port_translated_rules(nsx_port_id, fwg)

    def get_backend_router_and_fw_section(self, context, router_id):
        """Find the backend router and its firewall section"""
        return self.fwaas_driver.get_backend_router_and_fw_section(
            context, router_id)

    def get_default_allow_all_rule(self, section_id):
        return self.fwaas_driver.get_default_backend_rule(
            section_id, allow_all=True)
