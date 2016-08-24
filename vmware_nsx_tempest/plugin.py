# Copyright 2015 VMware, Inc.
#
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os

from tempest import config
from tempest.test_discover import plugins

from vmware_nsx_tempest import config as config_nsx


class VMwareNsxTempestPlugin(plugins.TempestPlugin):

    """Our addon configuration is defined at vmware_nsx_tempest/config.py

       1. register_opts() to register group/opts to Tempest
       2. get_opt_lists() to pass config to Tempest

       The official plugin is defined at
       http://docs.openstack.org/developer/tempest/plugin.html
    """

    def load_tests(self):
        mydir = os.path.dirname(os.path.abspath(__file__))
        base_path = os.path.split(mydir)[0]
        test_dir = "vmware_nsx_tempest/tests"
        test_fullpath = os.path.join(base_path, test_dir)
        return (test_fullpath, base_path)

    def register_opts(self, conf):
        config.register_opt_group(
            conf,
            config_nsx.service_available_group,
            config_nsx.ServiceAvailableGroup)
        config.register_opt_group(
            conf,
            config_nsx.scenario_group, config_nsx.ScenarioGroup)
        config.register_opt_group(
            conf,
            config_nsx.network_group, config_nsx.NetworkGroup)
        config.register_opt_group(
            conf,
            config_nsx.nsxv_group, config_nsx.NSXvGroup)
        config.register_opt_group(
            conf,
            config_nsx.l2gw_group, config_nsx.L2gwGroup)
        config.register_opt_group(
            conf,
            config_nsx.nsxv3_group, config_nsx.NSXv3Group)

    def get_opt_lists(self):
        return [
            (config_nsx.scenario_group.name, config_nsx.scenario_group),
            ('service_available', config_nsx.ServiceAvailableGroup)
        ]
