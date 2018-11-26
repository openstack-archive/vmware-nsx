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

from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron_lib.exceptions import firewall_v2 as exceptions

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.nsx import utils as tvd_utils
from vmware_nsx.services.fwaas.nsx_v import edge_fwaas_driver_v2 as v_driver
from vmware_nsx.services.fwaas.nsx_v3 import edge_fwaas_driver_v2 as t_driver

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'FwaaS V2 NSX-TV driver'

try:
    from neutron_fwaas.services.firewall.service_drivers.agents.drivers \
        import fwaas_base_v2
except ImportError:
    # FWaaS project no found
    from vmware_nsx.services.fwaas.common import fwaas_mocks \
        as fwaas_base_v2


class EdgeFwaasTVDriverV2(fwaas_base_v2.FwaasDriverBase):
    """NSX-TV driver for Firewall As A Service - V2.
    """

    def __init__(self):
        super(EdgeFwaasTVDriverV2, self).__init__()
        self.driver_name = FWAAS_DRIVER_NAME

        # supported drivers:
        self.drivers = {}
        try:
            self.drivers[projectpluginmap.NsxPlugins.NSX_T] = (
                t_driver.EdgeFwaasV3DriverV2())
        except Exception:
            LOG.warning("EdgeFwaasTVDriverV2 failed to initialize the NSX-T "
                        "driver")
            self.drivers[projectpluginmap.NsxPlugins.NSX_T] = None
        try:
            self.drivers[projectpluginmap.NsxPlugins.NSX_V] = (
                v_driver.EdgeFwaasVDriverV2())
        except Exception:
            LOG.warning("EdgeFwaasTVDriverV2 failed to initialize the NSX-V "
                        "driver")
            self.drivers[projectpluginmap.NsxPlugins.NSX_V] = None

    def get_T_driver(self):
        return self.drivers[projectpluginmap.NsxPlugins.NSX_T]

    def get_V_driver(self):
        return self.drivers[projectpluginmap.NsxPlugins.NSX_V]

    def _get_driver_for_project(self, project):
        plugin_type = tvd_utils.get_tvd_plugin_type_for_project(project)
        if not self.drivers.get(plugin_type):
            LOG.error("Project %(project)s with plugin %(plugin)s has no "
                      "support for FWaaS V2", {'project': project,
                                               'plugin': plugin_type})
            raise exceptions.FirewallInternalDriverError(
                driver=self.driver_name)
        return self.drivers[plugin_type]

    @log_helpers.log_method_call
    def create_firewall_group(self, agent_mode, apply_list, firewall_group):
        d = self._get_driver_for_project(firewall_group['tenant_id'])
        return d.create_firewall_group(agent_mode, apply_list, firewall_group)

    @log_helpers.log_method_call
    def update_firewall_group(self, agent_mode, apply_list, firewall_group):
        d = self._get_driver_for_project(firewall_group['tenant_id'])
        return d.update_firewall_group(agent_mode, apply_list, firewall_group)

    @log_helpers.log_method_call
    def delete_firewall_group(self, agent_mode, apply_list, firewall_group):
        d = self._get_driver_for_project(firewall_group['tenant_id'])
        return d.delete_firewall_group(agent_mode, apply_list, firewall_group)

    @log_helpers.log_method_call
    def apply_default_policy(self, agent_mode, apply_list, firewall_group):
        d = self._get_driver_for_project(firewall_group['tenant_id'])
        return d.apply_default_policy(agent_mode, apply_list, firewall_group)

    def translate_addresses_to_target(self, cidrs, plugin_type,
                                      fwaas_rule_id=None):
        # This api is called directly from the core plugin
        if not self.drivers.get(plugin_type):
            LOG.error("%s has no support for plugin %s",
                      self.driver_name, plugin_type)
        else:
            return self.drivers[plugin_type].translate_addresses_to_target(
                cidrs, fwaas_rule_id=fwaas_rule_id)
