# Copyright (c) 2015 VMware, Inc.
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

from neutron import context
from neutron.tests import base

from networking_l2gw.tests.unit.db import test_l2gw_db

from vmware_nsx.services.l2gateway import nsx_v3_driver
from vmware_nsx.services.l2gateway import plugin as l2gw_plugin

from oslo_config import cfg
from oslo_utils import uuidutils


NSX_V3_DRIVER_CLASS_PATH = ('vmware_nsx.services.l2gateway.'
                            'nsx_v3_driver.NsxV3Driver')


class TestNsxV3L2GatewayDriver(test_l2gw_db.L2GWTestCase,
                               base.BaseTestCase):

    def setUp(self):
        super(TestNsxV3L2GatewayDriver, self).setUp()
        cfg.CONF.set_override("nsx_l2gw_driver",
                              NSX_V3_DRIVER_CLASS_PATH, 'NSX')
        self.l2gw_plugin = l2gw_plugin.NsxL2GatewayPlugin()
        self.driver = nsx_v3_driver.NsxV3Driver()
        self.context = context.get_admin_context()

    def test_nsxl2gw_driver_init(self):
        with mock.patch.object(nsx_v3_driver.NsxV3Driver,
                               '_ensure_default_l2_gateway') as def_gw:
            with mock.patch.object(nsx_v3_driver.NsxV3Driver,
                                   'subscribe_callback_notifications') as sub:
                with mock.patch.object(nsx_v3_driver.LOG,
                                       'debug') as debug:
                    l2gw_plugin.NsxL2GatewayPlugin()
                    self.assertTrue(def_gw.called)
                    self.assertTrue(sub.called)
                    self.assertTrue(debug.called)

    def test_create_default_l2_gateway(self):
        def_bridge_cluster_id = uuidutils.generate_uuid()
        with mock.patch.object(nsx_v3_driver.NsxV3Driver,
                               'subscribe_callback_notifications'):
            cfg.CONF.set_override("default_bridge_cluster_uuid",
                                  def_bridge_cluster_id,
                                  "nsx_v3")
            l2gw_plugin.NsxL2GatewayPlugin()
            l2gws = self.driver._get_l2_gateways(self.context)
            def_l2gw = None
            for l2gw in l2gws:
                for device in l2gw['devices']:
                    if device['device_name'] == def_bridge_cluster_id:
                        def_l2gw = l2gw
            self.assertIsNotNone(def_l2gw)
            self.assertTrue(def_l2gw.devices[0].device_name,
                            def_bridge_cluster_id)
            self.assertTrue(def_l2gw.devices[0].interfaces[0].interface_name,
                            'default-bridge-cluster')
