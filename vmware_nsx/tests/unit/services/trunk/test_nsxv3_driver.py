# Copyright (c) 2016 VMware, Inc.
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

from neutron.tests import base

from neutron_lib import context
from oslo_config import cfg
from oslo_utils import importutils

from vmware_nsx.common import nsx_constants
from vmware_nsx.services.trunk.nsx_v3 import driver as trunk_driver
from vmware_nsx.tests.unit.nsx_v3 import test_constants as test_consts
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_nsx_v3_plugin


class TestNsxV3TrunkHandler(test_nsx_v3_plugin.NsxV3PluginTestCaseMixin,
                            base.BaseTestCase):
    def setUp(self):
        super(TestNsxV3TrunkHandler, self).setUp()
        self.context = context.get_admin_context()
        self.core_plugin = importutils.import_object(test_consts.PLUGIN_NAME)
        self.handler = trunk_driver.NsxV3TrunkHandler(self.core_plugin)
        self.handler._update_port_at_backend = mock.Mock()
        self.trunk_1 = mock.Mock()
        self.trunk_1.port_id = "parent_port_1"

        self.trunk_2 = mock.Mock()
        self.trunk_2.port_id = "parent_port_2"

        self.sub_port_1 = mock.Mock()
        self.sub_port_1.segmentation_id = 40
        self.sub_port_1.trunk_id = "trunk-1"
        self.sub_port_1.port_id = "sub_port_1"

        self.sub_port_2 = mock.Mock()
        self.sub_port_2.segmentation_id = 41
        self.sub_port_2.trunk_id = "trunk-2"
        self.sub_port_2.port_id = "sub_port_2"

        self.sub_port_3 = mock.Mock()
        self.sub_port_3.segmentation_id = 43
        self.sub_port_3.trunk_id = "trunk-2"
        self.sub_port_3.port_id = "sub_port_3"

    def test_trunk_created(self):
        # Create trunk with no subport
        self.trunk_1.sub_ports = []
        self.handler.trunk_created(self.context, self.trunk_1)
        self.handler._update_port_at_backend.assert_not_called()

        # Create trunk with 1 subport
        self.trunk_1.sub_ports = [self.sub_port_1]
        self.handler.trunk_created(self.context, self.trunk_1)
        self.handler._update_port_at_backend.assert_called_with(
            self.context,
            self.trunk_1.port_id,
            self.sub_port_1)

        # Create trunk with multiple subports
        self.trunk_2.sub_ports = [self.sub_port_2, self.sub_port_3]
        self.handler.trunk_created(self.context, self.trunk_2)
        calls = [mock.call._update_port_at_backend(
                     self.context,
                     self.trunk_2.port_id,
                     self.sub_port_2),
                 mock.call._update_port_at_backend(
                     self.context,
                     self.trunk_2.port_id,
                     self.sub_port_3)]
        self.handler._update_port_at_backend.assert_has_calls(
            calls, any_order=True)

    def test_trunk_deleted(self):
        # Delete trunk with no subport
        self.trunk_1.sub_ports = []
        self.handler.trunk_deleted(self.context, self.trunk_1)
        self.handler._update_port_at_backend.assert_not_called()

        # Delete trunk with 1 subport
        self.trunk_1.sub_ports = [self.sub_port_1]
        self.handler.trunk_deleted(self.context, self.trunk_1)
        self.handler._update_port_at_backend.assert_called_with(
            context=self.context,
            parent_port_id=None,
            subport=self.sub_port_1)

        # Delete trunk with multiple subports
        self.trunk_2.sub_ports = [self.sub_port_2, self.sub_port_3]
        self.handler.trunk_deleted(self.context, self.trunk_2)
        calls = [mock.call._update_port_at_backend(
                     context=self.context,
                     parent_port_id=None,
                     subport=self.sub_port_2),
                 mock.call._update_port_at_backend(
                     context=self.context,
                     parent_port_id=None,
                     subport=self.sub_port_3)]
        self.handler._update_port_at_backend.assert_has_calls(
            calls, any_order=True)

    def test_subports_added(self):
        # Update trunk with no subport
        sub_ports = []
        self.handler.subports_added(self.context, self.trunk_1, sub_ports)
        self.handler._update_port_at_backend.assert_not_called()

        # Update trunk with 1 subport
        sub_ports = [self.sub_port_1]
        self.handler.subports_added(self.context, self.trunk_1, sub_ports)
        self.handler._update_port_at_backend.assert_called_with(
            self.context,
            self.trunk_1.port_id,
            self.sub_port_1)

        # Update trunk with multiple subports
        sub_ports = [self.sub_port_2, self.sub_port_3]
        self.handler.subports_added(self.context, self.trunk_2, sub_ports)
        calls = [mock.call._update_port_at_backend(
                     self.context,
                     self.trunk_2.port_id,
                     self.sub_port_2),
                 mock.call._update_port_at_backend(
                     self.context,
                     self.trunk_2.port_id,
                     self.sub_port_3)]
        self.handler._update_port_at_backend.assert_has_calls(
            calls, any_order=True)

    def test_subports_deleted(self):
        # Update trunk to remove no subport
        sub_ports = []
        self.handler.subports_deleted(self.context, self.trunk_1, sub_ports)
        self.handler._update_port_at_backend.assert_not_called()

        # Update trunk to remove 1 subport
        sub_ports = [self.sub_port_1]
        self.handler.subports_deleted(self.context, self.trunk_1, sub_ports)
        self.handler._update_port_at_backend.assert_called_with(
            context=self.context,
            parent_port_id=None,
            subport=self.sub_port_1)

        # Update trunk to remove multiple subports
        sub_ports = [self.sub_port_2, self.sub_port_3]
        self.handler.subports_deleted(self.context, self.trunk_2, sub_ports)
        calls = [mock.call._update_port_at_backend(
                     context=self.context,
                     parent_port_id=None,
                     subport=self.sub_port_2),
                 mock.call._update_port_at_backend(
                     context=self.context,
                     parent_port_id=None,
                     subport=self.sub_port_3)]
        self.handler._update_port_at_backend.assert_has_calls(
            calls, any_order=True)


class TestNsxV3TrunkDriver(base.BaseTestCase):
    def setUp(self):
        super(TestNsxV3TrunkDriver, self).setUp()

    def test_is_loaded(self):
        driver = trunk_driver.NsxV3TrunkDriver.create(mock.Mock())
        cfg.CONF.set_override('core_plugin',
                              nsx_constants.VMWARE_NSX_V3_PLUGIN_NAME)
        self.assertTrue(driver.is_loaded)

        cfg.CONF.set_override('core_plugin', 'not_vmware_nsx_plugin')
        self.assertFalse(driver.is_loaded)
