# Copyright 2016 VMware, Inc.
#
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

from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import subnet_alloc

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.nsx import utils as tvd_utils
from vmware_nsx.services.ipam.common import driver as common_driver
from vmware_nsx.services.ipam.nsx_v import driver as v_driver
from vmware_nsx.services.ipam.nsx_v3 import driver as t_driver

LOG = logging.getLogger(__name__)


class NsxTvdIpamDriver(subnet_alloc.SubnetAllocator,
                       common_driver.NsxIpamBase):
    """IPAM Driver For NSX-TVD plugin."""

    def __init__(self, subnetpool, context):
        super(NsxTvdIpamDriver, self).__init__(subnetpool, context)
        # initialize the different drivers
        self.drivers = {}
        try:
            self.drivers[projectpluginmap.NsxPlugins.NSX_T] = (
                t_driver.Nsxv3IpamDriver(subnetpool, context))
        except Exception as e:
            LOG.warning("NsxTvdIpamDriver failed to initialize the NSX-T "
                        "driver %s", e)
            self.drivers[projectpluginmap.NsxPlugins.NSX_T] = None
        try:
            self.drivers[projectpluginmap.NsxPlugins.NSX_V] = (
                v_driver.NsxvIpamDriver(subnetpool, context))
        except Exception as e:
            LOG.warning("NsxTvdIpamDriver failed to initialize the NSX-V "
                        "driver %s", e)
            self.drivers[projectpluginmap.NsxPlugins.NSX_V] = None

    def get_T_driver(self):
        return self.drivers[projectpluginmap.NsxPlugins.NSX_T]

    def get_V_driver(self):
        return self.drivers[projectpluginmap.NsxPlugins.NSX_V]

    def _get_driver_for_project(self, project):
        plugin_type = tvd_utils.get_tvd_plugin_type_for_project(project)
        if not self.drivers.get(plugin_type):
            LOG.error("Project %(project)s with plugin %(plugin)s has no "
                      "support for IPAM", {'project': project,
                                           'plugin': plugin_type})
            raise ipam_exc.IpamValueInvalid(
                message="IPAM driver not found")
        return self.drivers[plugin_type]

    def allocate_subnet(self, subnet_request):
        d = self._get_driver_for_project(subnet_request.tenant_id)
        return d.allocate_subnet(subnet_request)

    def update_subnet(self, subnet_request):
        d = self._get_driver_for_project(subnet_request.tenant_id)
        return d.update_subnet(subnet_request)

    def remove_subnet(self, subnet_id):
        d = self._get_driver_for_project(self._context.tenant_id)
        return d.remove_subnet(subnet_id)

    def get_subnet(self, subnet_id):
        d = self._get_driver_for_project(self._context.tenant_id)
        return d.get_subnet(subnet_id)

    def get_subnet_request_factory(self):
        d = self._get_driver_for_project(self._context.tenant_id)
        return d.get_subnet_request_factory()
