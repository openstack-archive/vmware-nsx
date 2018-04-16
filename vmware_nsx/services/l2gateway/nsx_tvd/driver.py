# Copyright 2015 VMware, Inc.
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

from networking_l2gw.db.l2gateway import l2gateway_db
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_log import log as logging

from vmware_nsx.db import db as nsx_db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.services.l2gateway.nsx_v import driver as v_driver
from vmware_nsx.services.l2gateway.nsx_v3 import driver as t_driver

LOG = logging.getLogger(__name__)


class NsxTvdL2GatewayDriver(l2gateway_db.L2GatewayMixin):
    """Class to handle API calls for L2 gateway and NSX-TVD plugin wrapper."""

    def __init__(self, plugin):
        super(NsxTvdL2GatewayDriver, self).__init__()
        self._plugin = plugin

        # supported drivers:
        self.drivers = {}
        try:
            self.drivers[projectpluginmap.NsxPlugins.NSX_T] = (
                t_driver.NsxV3Driver(plugin))
        except Exception:
            LOG.warning("NsxTvdL2GatewayDriver failed to initialize the NSX-T "
                        "driver")
            self.drivers[projectpluginmap.NsxPlugins.NSX_T] = None
        try:
            self.drivers[projectpluginmap.NsxPlugins.NSX_V] = (
                v_driver.NsxvL2GatewayDriver(plugin))
        except Exception:
            LOG.warning("NsxTvdL2GatewayDriver failed to initialize the NSX-V "
                        "driver")
            self.drivers[projectpluginmap.NsxPlugins.NSX_V] = None

    def _get_driver_for_project(self, context, project):
        """Get the l2gw driver by the plugin of the project"""
        mapping = nsx_db.get_project_plugin_mapping(
            context.session, project)
        if mapping:
            plugin_type = mapping['plugin']
        else:
            msg = _("Couldn't find the plugin project %s is using") % project
            raise n_exc.InvalidInput(error_message=msg)

        if plugin_type not in self.drivers:
            msg = (_("Project %(project)s with plugin %(plugin)s has no "
                     "support for L2GW") % {'project': project,
                                            'plugin': plugin_type})
            raise n_exc.InvalidInput(error_message=msg)

        # make sure the core plugin is supported
        core_plugin = directory.get_plugin()
        if not core_plugin.get_plugin_by_type(plugin_type):
            msg = (_("Plugin %(plugin)s for project %(project)s is not "
                     "supported by the core plugin") % {'project': project,
                                                        'plugin': plugin_type})
            raise n_exc.InvalidInput(error_message=msg)

        return self.drivers[plugin_type]

    def create_l2_gateway(self, context, l2_gateway):
        d = self._get_driver_for_project(
            context, l2_gateway['l2_gateway']['tenant_id'])
        return d.create_l2_gateway(context, l2_gateway)

    def create_l2_gateway_precommit(self, context, l2_gateway):
        # Not implemented by any of the plugins
        pass

    def create_l2_gateway_postcommit(self, context, l2_gateway):
        # Not implemented by any of the plugins
        pass

    def update_l2_gateway(self, context, l2_gateway):
        # Not implemented by any of the plugins
        pass

    def update_l2_gateway_precommit(self, context, l2_gateway):
        # Not implemented by any of the plugins
        pass

    def update_l2_gateway_postcommit(self, context, l2_gateway):
        # Not implemented by any of the plugins
        pass

    def create_l2_gateway_connection(self, context, l2_gateway_connection):
        d = self._get_driver_for_project(
            context,
            l2_gateway_connection['l2_gateway_connection']['tenant_id'])
        return d.create_l2_gateway_connection(context, l2_gateway_connection)

    def create_l2_gateway_connection_precommit(self, contex, gw_connection):
        # Not implemented by any of the plugins
        pass

    def create_l2_gateway_connection_postcommit(self, context, gw_connection):
        d = self._get_driver_for_project(context, gw_connection['tenant_id'])
        return d.create_l2_gateway_connection_postcommit(
            context, gw_connection)

    def _get_gw_connection_driver(self, context, l2gw_connection_id):
        l2gw_conn = self._plugin._get_l2_gateway_connection(
            context, l2gw_connection_id)
        return self._get_driver_for_project(context, l2gw_conn.tenant_id)

    def delete_l2_gateway_connection(self, context, l2_gateway_connection_id):
        d = self._get_gw_connection_driver(context, l2_gateway_connection_id)
        return d.delete_l2_gateway_connection(
            context, l2_gateway_connection_id)

    def delete_l2_gateway_connection_precommit(self, context,
                                               l2_gateway_connection):
        # Not implemented by any of the plugins
        pass

    def delete_l2_gateway_connection_postcommit(self, context,
                                                l2_gateway_connection_id):
        # Not implemented by any of the plugins
        #Note(asarfaty): in postcommit the l2_gateway_connection was already
        # deleted so we cannot decide on the plugin by the project of the
        # connection.
        pass

    def delete_l2_gateway(self, context, l2_gateway_id):
        l2gw = self._plugin._get_l2_gateway(context, l2_gateway_id)
        d = self._get_driver_for_project(
            context, l2gw['tenant_id'])
        return d.delete_l2_gateway(context, l2_gateway_id)

    def delete_l2_gateway_precommit(self, context, l2_gateway):
        # Not implemented by any of the plugins
        pass

    def delete_l2_gateway_postcommit(self, context, l2_gateway):
        # Not implemented by any of the plugins
        #Note(asarfaty): in postcommit the l2_gateway was already deleted
        # so we cannot decide on the plugin by the project of the gw.
        pass

    def add_port_mac(self, context, port_dict):
        """Process a created Neutron port."""
        pass

    def delete_port_mac(self, context, port):
        """Process a deleted Neutron port."""
        pass
