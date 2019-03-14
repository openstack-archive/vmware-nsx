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

from vmware_nsx.db import db as nsx_db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.services.fwaas.common import fwaas_callbacks_v2 as \
    com_callbacks
from vmware_nsx.services.fwaas.nsx_tv import edge_fwaas_driver_v2 as tv_driver

LOG = logging.getLogger(__name__)


class Nsxv3FwaasCallbacksV2(com_callbacks.NsxCommonv3FwaasCallbacksV2):
    """NSX-V3 RPC callbacks for Firewall As A Service - V2."""

    def __init__(self, with_rpc):
        super(Nsxv3FwaasCallbacksV2, self).__init__(with_rpc)
        # update the fwaas driver in case of TV plugin
        self.internal_driver = None
        if self.fwaas_enabled:
            if self.fwaas_driver.driver_name == tv_driver.FWAAS_DRIVER_NAME:
                self.internal_driver = self.fwaas_driver.get_T_driver()
            else:
                self.internal_driver = self.fwaas_driver

    @property
    def plugin_type(self):
        return projectpluginmap.NsxPlugins.NSX_T

    def get_port_rules(self, nsx_ls_id, fwg, plugin_rules):
        return self.internal_driver.get_port_translated_rules(
            nsx_ls_id, fwg, plugin_rules)

    def update_router_firewall(self, context, nsxlib, router_id,
                               router_interfaces, nsx_router_id, section_id,
                               from_fw=False):
        """Rewrite all the FWaaS v2 rules in the router edge firewall

        This method should be called on FWaaS updates, and on router
        interfaces changes.
        The purpose of from_fw is to differ between fw calls and other router
        calls, and if it is True - add the service router accordingly.
        """
        fw_rules = []
        with_fw = False
        # Add firewall rules per port attached to a firewall group
        for port in router_interfaces:
            nsx_ls_id, _nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port['id'])

            # Check if this port has a firewall
            fwg = self.get_port_fwg(context, port['id'])
            if fwg:
                with_fw = True
                # Add plugin additional allow rules
                plugin_rules = self.core_plugin.get_extra_fw_rules(
                    context, router_id, port['id'])

                # add the FWaaS rules for this port
                # ingress/egress firewall rules + default ingress/egress drop
                # rule for this port
                fw_rules.extend(self.get_port_rules(nsx_ls_id, fwg,
                                                    plugin_rules))

        # add a default allow-all rule to all other traffic & ports
        fw_rules.append(self.internal_driver.get_default_backend_rule(
            section_id, allow_all=True))

        # update the backend router firewall
        exists_on_backend = self.core_plugin.verify_sr_at_backend(context,
                                                                  router_id)
        if from_fw:
            # fw action required
            if with_fw:
                # firewall exists in Neutron and not on backend - create
                if not exists_on_backend:
                    self.core_plugin.create_service_router(
                        context, router_id, update_firewall=False)
            else:
                # First, check if other services exist and use the sr
                sr_exists = self.core_plugin.service_router_has_services(
                    context, router_id)
                if not sr_exists and exists_on_backend:
                    # No other services that require service router - delete
                    self.core_plugin.delete_service_router(context, router_id)
                    exists_on_backend = False
        if exists_on_backend:
            nsxlib.firewall_section.update(section_id, rules=fw_rules)
