# Copyright (c) 2015 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
from oslo_config import cfg

import neutron.tests.unit.db.test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_extra_dhcp_opt as test_dhcpopts
import neutron.tests.unit.extensions.test_securitygroup as ext_sg
from vmware_nsx.neutron.plugins.vmware.nsxlib import v3 as nsxlib
from vmware_nsx.neutron.plugins.vmware.nsxlib.v3 import dfw_api as firewall
from vmware_nsx.neutron.tests.unit.vmware import nsx_v3_mocks

PLUGIN_NAME = ('vmware_nsx.neutron.plugins.vmware.'
               'plugins.nsx_v3_plugin.NsxV3Plugin')


class NsxPluginV3TestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        cfg.CONF.set_override('nsx_manager', '1.2.3.4', 'nsx_v3')
        # Mock entire nsxlib methods as this is the best approach to perform
        # white-box testing on the plugin class
        # TODO(salv-orlando): supply unit tests for nsxlib.v3
        nsxlib.create_logical_switch = nsx_v3_mocks.create_logical_switch
        nsxlib.delete_logical_switch = mock.Mock()
        nsxlib.get_logical_switch = nsx_v3_mocks.get_logical_switch
        nsxlib.update_logical_switch = nsx_v3_mocks.update_logical_switch
        nsxlib.create_logical_port = nsx_v3_mocks.create_logical_port
        nsxlib.delete_logical_port = mock.Mock()
        nsxlib.get_logical_port = nsx_v3_mocks.get_logical_port
        nsxlib.update_logical_port = nsx_v3_mocks.update_logical_port
        # TODO(berlin): fill valid data
        nsxlib.get_edge_cluster = nsx_v3_mocks.get_edge_cluster
        nsxlib.get_logical_router = nsx_v3_mocks.get_logical_router
        firewall.add_rules_in_section = nsx_v3_mocks.add_rules_in_section
        firewall.nsclient.create_resource = nsx_v3_mocks.create_resource
        firewall.nsclient.update_resource = nsx_v3_mocks.update_resource
        firewall.nsclient.get_resource = nsx_v3_mocks.get_resource
        firewall.nsclient.delete_resource = nsx_v3_mocks.delete_resource

        super(NsxPluginV3TestCase, self).setUp(plugin=plugin,
                                               ext_mgr=ext_mgr)


class TestNetworksV2(test_plugin.TestNetworksV2, NsxPluginV3TestCase):
    pass


class TestPortsV2(test_plugin.TestPortsV2, NsxPluginV3TestCase):
    pass


class SecurityGroupsTestCase(ext_sg.SecurityGroupDBTestCase):

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None):
        nsxlib.create_logical_switch = nsx_v3_mocks.create_logical_switch
        nsxlib.create_logical_port = nsx_v3_mocks.create_logical_port
        nsxlib.update_logical_port = nsx_v3_mocks.update_logical_port
        nsxlib.delete_logical_port = mock.Mock()
        nsxlib.delete_logical_switch = mock.Mock()
        nsxlib.get_logical_port = nsx_v3_mocks.get_logical_port
        nsxlib.update_logical_port = nsx_v3_mocks.update_logical_port
        firewall.add_rules_in_section = nsx_v3_mocks.add_rules_in_section
        firewall.nsclient.create_resource = nsx_v3_mocks.create_resource
        firewall.nsclient.update_resource = nsx_v3_mocks.update_resource
        firewall.nsclient.get_resource = nsx_v3_mocks.get_resource
        firewall.nsclient.delete_resource = nsx_v3_mocks.delete_resource

        super(SecurityGroupsTestCase, self).setUp(plugin=PLUGIN_NAME,
                                                  ext_mgr=ext_mgr)


class TestSecurityGroups(ext_sg.TestSecurityGroups, SecurityGroupsTestCase):
    pass


class DHCPOptsTestCase(test_dhcpopts.TestExtraDhcpOpt, NsxPluginV3TestCase):

    def setUp(self, plugin=None):
        super(test_dhcpopts.ExtraDhcpOptDBTestCase, self).setUp(
            plugin=PLUGIN_NAME)
