# Copyright 2015 VMware, Inc.
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

from neutron import manager
from neutron.plugins.common import constants


class EdgeLoadbalancerBaseManager(object):
    _lbv2_driver = None
    _core_plugin = None

    def __init__(self, vcns_driver):
        super(EdgeLoadbalancerBaseManager, self).__init__()
        self.vcns_driver = vcns_driver

    def _get_plugin(self, plugin_type):
        loaded_plugins = manager.NeutronManager.get_service_plugins()
        return loaded_plugins[plugin_type]

    @property
    def lbv2_driver(self):
        if not EdgeLoadbalancerBaseManager._lbv2_driver:
            plugin = self._get_plugin(
                constants.LOADBALANCERV2)
            EdgeLoadbalancerBaseManager._lbv2_driver = (
                plugin.drivers['vmwareedge'])

        return EdgeLoadbalancerBaseManager._lbv2_driver

    @property
    def core_plugin(self):
        if not EdgeLoadbalancerBaseManager._core_plugin:
            EdgeLoadbalancerBaseManager._core_plugin = (
                self._get_plugin(constants.CORE))

        return EdgeLoadbalancerBaseManager._core_plugin

    @property
    def vcns(self):
        return self.vcns_driver.vcns
