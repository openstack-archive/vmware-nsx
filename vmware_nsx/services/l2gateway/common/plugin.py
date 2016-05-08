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
from networking_l2gw.services.l2gateway.common import constants as l2gw_const

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from vmware_nsx.common import config  # noqa

LOG = logging.getLogger(__name__)


class NsxL2GatewayPlugin(l2gateway_db.L2GatewayMixin):

    """Service plugin for VMware NSX to implement Neutron's L2 gateway API."""

    supported_extension_aliases = ["l2-gateway", "l2-gateway-connection"]
    _methods_to_delegate = ["create_l2_gateway", "get_l2_gateway",
                            "delete_l2_gateway", "get_l2_gateways",
                            "update_l2_gateway",
                            "create_l2_gateway_precommit",
                            "create_l2_gateway_postcommit",
                            "delete_l2_gateway_precommit",
                            "delete_l2_gateway_postcommit",
                            "create_l2_gateway_connection",
                            "create_l2_gateway_connection_precommit",
                            "create_l2_gateway_connection_postcommit",
                            "get_l2_gateway_connection",
                            "get_l2_gateway_connections",
                            "update_l2_gateway_connection",
                            "delete_l2_gateway_connection_precommit",
                            "delete_l2_gateway_connection_postcommit",
                            "delete_l2_gateway_connection"]

    def __init__(self, plugin):
        """Initialize service plugin and load backend driver."""
        super(NsxL2GatewayPlugin, self).__init__()
        self._plugin = plugin
        LOG.debug("Starting service plugin for NSX L2Gateway")
        self._nsx_l2gw_driver = cfg.CONF.nsx_l2gw_driver
        if not getattr(self, "_nsx_l2gw_driver"):
            raise cfg.RequiredOptError("nsx_l2gw_driver")
        self._driver = importutils.import_object(self._nsx_l2gw_driver)

    @staticmethod
    def get_plugin_type():
        """Get type of the plugin."""
        return l2gw_const.L2GW

    @staticmethod
    def get_plugin_description():
        """Get description of the plugin."""
        return l2gw_const.L2_GATEWAY_SERVICE_PLUGIN

    def __getattribute__(self, name):
        """Delegate L2GW API calls to the driver class."""
        methods = object.__getattribute__(self, "_methods_to_delegate")
        if name in methods:
            # If method is delegated, return the driver class method.
            return getattr(object.__getattribute__(self, "_driver"), name)
        else:
            # Else return our own method.
            return object.__getattribute__(self, name)
