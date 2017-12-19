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

from neutron_fwaas.services.firewall.drivers import fwaas_base
from neutron_lib import context as n_context
from neutron_lib.exceptions import firewall_v1 as exceptions

from vmware_nsx.db import db as nsx_db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.services.fwaas.nsx_v import edge_fwaas_driver as v_driver
from vmware_nsx.services.fwaas.nsx_v3 import edge_fwaas_driver_v1 as t_driver

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'FwaaS V1 NSX-TV driver'


class EdgeFwaasTVDriverV1(fwaas_base.FwaasDriverBase):
    """NSX-TV driver for Firewall As A Service - V1.

    This driver is just a wrapper calling the relevant nsx-v/t driver
    """

    def __init__(self):
        super(EdgeFwaasTVDriverV1, self).__init__()
        self.driver_name = FWAAS_DRIVER_NAME

        # supported drivers:
        self.drivers = {}
        self.drivers[projectpluginmap.NsxPlugins.NSX_T] = (
            t_driver.EdgeFwaasV3DriverV1())
        self.drivers[projectpluginmap.NsxPlugins.NSX_V] = (
            v_driver.EdgeFwaasDriver())

    def get_T_driver(self):
        return self.drivers[projectpluginmap.NsxPlugins.NSX_T]

    def get_V_driver(self):
        return self.drivers[projectpluginmap.NsxPlugins.NSX_V]

    def _get_driver_for_project(self, project):
        context = n_context.get_admin_context()
        mapping = nsx_db.get_project_plugin_mapping(
            context.session, project)
        if mapping:
            plugin_type = mapping['plugin']
        else:
            LOG.error("Didn't find the plugin project %s is using", project)
            raise exceptions.FirewallInternalDriverError(
                driver=self.driver_name)

        if plugin_type not in self.drivers:
            LOG.error("Project %(project)s with plugin %(plugin)s has no "
                      "support for FWaaS V1", {'project': project,
                                               'plugin': plugin_type})
            raise exceptions.FirewallInternalDriverError(
                driver=self.driver_name)
        return self.drivers[plugin_type]

    @log_helpers.log_method_call
    def create_firewall(self, agent_mode, apply_list, firewall):
        d = self._get_driver_for_project(firewall['tenant_id'])
        return d.create_firewall(agent_mode, apply_list, firewall)

    @log_helpers.log_method_call
    def update_firewall(self, agent_mode, apply_list, firewall):
        d = self._get_driver_for_project(firewall['tenant_id'])
        return d.update_firewall(agent_mode, apply_list, firewall)

    @log_helpers.log_method_call
    def delete_firewall(self, agent_mode, apply_list, firewall):
        d = self._get_driver_for_project(firewall['tenant_id'])
        return d.delete_firewall(agent_mode, apply_list, firewall)

    @log_helpers.log_method_call
    def apply_default_policy(self, agent_mode, apply_list, firewall):
        d = self._get_driver_for_project(firewall['tenant_id'])
        return d.apply_default_policy(agent_mode, apply_list, firewall)
