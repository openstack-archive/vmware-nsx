# Copyright 2018 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
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

from neutron_lib.plugins import directory
from neutron_vpnaas.services.vpn import service_drivers

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.nsx import utils as tvd_utils
from vmware_nsx.services.vpnaas.nsx_tvd import ipsec_validator
from vmware_nsx.services.vpnaas.nsxv import ipsec_driver as v_driver
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_driver as t_driver

LOG = logging.getLogger(__name__)
IPSEC = 'ipsec'


class NSXIPsecVpnDriver(service_drivers.VpnDriver):
    """Wrapper driver to select the relevant driver for each VPNaaS request"""
    def __init__(self, service_plugin):
        self.vpn_plugin = service_plugin
        self._core_plugin = directory.get_plugin()
        validator = ipsec_validator.IPsecValidator(service_plugin)
        super(NSXIPsecVpnDriver, self).__init__(service_plugin, validator)

        # supported drivers:
        self.drivers = {}
        try:
            self.drivers[projectpluginmap.NsxPlugins.NSX_T] = (
                t_driver.NSXv3IPsecVpnDriver(service_plugin))
        except Exception as e:
            LOG.error("NSXIPsecVpnDriver failed to initialize the NSX-T "
                      "driver: %s", e)
            self.drivers[projectpluginmap.NsxPlugins.NSX_T] = None
        try:
            self.drivers[projectpluginmap.NsxPlugins.NSX_V] = (
                v_driver.NSXvIPsecVpnDriver(service_plugin))
        except Exception as e:
            LOG.error("NSXIPsecVpnDriver failed to initialize the NSX-V "
                      "driver: %s", e)
            self.drivers[projectpluginmap.NsxPlugins.NSX_V] = None

    @property
    def service_type(self):
        return IPSEC

    def _get_driver_for_project(self, project):
        plugin_type = tvd_utils.get_tvd_plugin_type_for_project(project)
        if not self.drivers.get(plugin_type):
            msg = (_("Project %(project)s with plugin %(plugin)s has no "
                     "support for VPNaaS"), {'project': project,
                                             'plugin': plugin_type})
            raise nsx_exc.NsxPluginException(err_msg=msg)
        return self.drivers[plugin_type]

    def create_ipsec_site_connection(self, context, ipsec_site_conn):
        d = self._get_driver_for_project(ipsec_site_conn['tenant_id'])
        return d.create_ipsec_site_connection(context, ipsec_site_conn)

    def delete_ipsec_site_connection(self, context, ipsec_site_conn):
        d = self._get_driver_for_project(ipsec_site_conn['tenant_id'])
        return d.delete_ipsec_site_connection(context, ipsec_site_conn)

    def update_ipsec_site_connection(self, context, old_ipsec_conn,
                                     ipsec_site_conn):
        d = self._get_driver_for_project(old_ipsec_conn['tenant_id'])
        return d.update_ipsec_site_connection(context, old_ipsec_conn,
                                              ipsec_site_conn)

    def create_vpnservice(self, context, vpnservice):
        d = self._get_driver_for_project(vpnservice['tenant_id'])
        return d.create_vpnservice(context, vpnservice)

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        pass

    def delete_vpnservice(self, context, vpnservice):
        pass

    def _generate_ipsecvpn_firewall_rules(self, plugin_type, context,
                                          **kargs):
        d = self.drivers.get(plugin_type)
        if d:
            return d._generate_ipsecvpn_firewall_rules(
                plugin_type, context, **kargs)
        return []

    def get_ipsec_site_connection_status(self, context, ipsec_site_conn_id):
        # Currently only NSX-T supports it. In the future we will need to
        # decide on the driver by the tenant
        driver = self.drivers.get(projectpluginmap.NsxPlugins.NSX_T)
        if driver and hasattr(driver, 'get_ipsec_site_connection_status'):
            return driver.get_ipsec_site_connection_status(
                context, ipsec_site_conn_id)

    def validate_router_gw_info(self, context, router_id, gw_info):
        # Currently only NSX-T supports it. In the future we will need to
        # decide on the driver by the tenant
        driver = self.drivers.get(projectpluginmap.NsxPlugins.NSX_T)
        if driver and hasattr(driver, 'validate_router_gw_info'):
            return driver.validate_router_gw_info(
                context, router_id, gw_info)
