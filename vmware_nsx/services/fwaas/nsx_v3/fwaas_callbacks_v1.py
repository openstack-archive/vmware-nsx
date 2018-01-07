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

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.services.fwaas.common import fwaas_callbacks_v1 as com_clbcks
from vmware_nsx.services.fwaas.nsx_tv import edge_fwaas_driver_v1 as tv_driver

LOG = logging.getLogger(__name__)


class Nsxv3FwaasCallbacksV1(com_clbcks.NsxFwaasCallbacks):
    """NSX-V3 RPC callbacks for Firewall As A Service - V1."""

    def __init__(self):
        super(Nsxv3FwaasCallbacksV1, self).__init__()
        # update the fwaas driver in case of TV plugin
        if self.fwaas_enabled:
            if self.fwaas_driver.driver_name == tv_driver.FWAAS_DRIVER_NAME:
                self.internal_driver = self.fwaas_driver.get_T_driver()
            else:
                self.internal_driver = self.fwaas_driver

    @property
    def plugin_type(self):
        return projectpluginmap.NsxPlugins.NSX_T

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
        if not self.internal_driver.should_apply_firewall_to_router(
            router_data):
            return False

        return True

    def update_router_firewall(self, context, nsxlib, router_id,
                               router_interfaces, nsx_router_id, section_id):
        """Rewrite all the FWaaS v1 rules in the router edge firewall

        This method should be called on FWaaS updates, and on router
        interfaces changes.
        """
        fw_rules = []
        fw_id = None
        if self.should_apply_firewall_to_router(context, router_id):
            # Find the firewall attached to this router
            # (must have one since should_apply returned true)
            firewall = self.get_router_firewall(context, router_id)
            fw_id = firewall['id']

            # Add the FW rules
            fw_rules.extend(self.internal_driver.get_router_translated_rules(
                router_id, firewall))

            # Add plugin additional allow rules
            fw_rules.extend(self.core_plugin.get_extra_fw_rules(
                context, router_id))

            # Add the default drop all rule
            fw_rules.append(self.internal_driver.get_default_backend_rule(
                section_id, allow_all=False))
        else:
            # default allow all rule
            fw_rules.append(self.internal_driver.get_default_backend_rule(
                section_id, allow_all=True))

        # update the backend
        nsxlib.firewall_section.update(section_id, rules=fw_rules)

        # Also update the router tags
        self.internal_driver.update_nsx_router_tags(nsx_router_id, fw_id=fw_id)

    def delete_port(self, context, port_id):
        # nothing to do in FWaaS v1
        pass
