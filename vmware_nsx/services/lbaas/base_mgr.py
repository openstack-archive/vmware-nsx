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

from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class LoadbalancerBaseManager(object):
    _lbv2_driver = None
    _core_plugin = None
    _flavor_plugin = None

    def __init__(self):
        super(LoadbalancerBaseManager, self).__init__()

    def _get_plugin(self, plugin_type):
        return directory.get_plugin(plugin_type)

    @property
    def lbv2_driver(self):
        if not self._lbv2_driver:
            plugin = self._get_plugin(
                plugin_const.LOADBALANCERV2)
            self._lbv2_driver = (
                plugin.drivers['vmwareedge'])

        return self._lbv2_driver

    @property
    def core_plugin(self):
        if not self._core_plugin:
            self._core_plugin = (
                self._get_plugin(plugin_const.CORE))

        return self._core_plugin

    @property
    def flavor_plugin(self):
        if not self._flavor_plugin:
            self._flavor_plugin = (
                self._get_plugin(plugin_const.FLAVORS))

        return self._flavor_plugin


class EdgeLoadbalancerBaseManager(LoadbalancerBaseManager):

    def __init__(self, vcns_driver):
        super(EdgeLoadbalancerBaseManager, self).__init__()
        self.vcns_driver = vcns_driver

    @property
    def vcns(self):
        return self.vcns_driver.vcns


class Nsxv3LoadbalancerBaseManager(LoadbalancerBaseManager):

    def __init__(self):
        super(Nsxv3LoadbalancerBaseManager, self).__init__()
