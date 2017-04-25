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

from networking_l2gw.db.l2gateway import l2gateway_db
from networking_l2gw.services.l2gateway.common import config
from networking_l2gw.services.l2gateway.common import constants
from networking_l2gw.services.l2gateway import exceptions as l2gw_exc
from networking_l2gw.services.l2gateway import plugin as core_l2gw_plugin
from networking_l2gw.tests.unit.db import test_l2gw_db
from oslo_config import cfg
from oslo_utils import importutils
from oslo_utils import uuidutils

from neutron.tests import base
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context
from neutron_lib import exceptions as n_exc

from vmware_nsx.services.l2gateway.nsx_v3 import driver as nsx_v3_driver
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_nsx_v3_plugin
from vmware_nsxlib.tests.unit.v3 import mocks as nsx_v3_mocks
from vmware_nsxlib.v3 import nsx_constants


NSX_V3_PLUGIN_CLASS = ('vmware_nsx.plugins.nsx_v3.plugin.NsxV3Plugin')
NSX_V3_L2GW_DRIVER_CLASS_PATH = ('vmware_nsx.services.l2gateway.'
                                 'nsx_v3.driver.NsxV3Driver')


class TestNsxV3L2GatewayDriver(test_l2gw_db.L2GWTestCase,
                               test_nsx_v3_plugin.NsxV3PluginTestCaseMixin,
                               base.BaseTestCase):

    def setUp(self):
        super(TestNsxV3L2GatewayDriver, self).setUp()
        self.core_plugin = importutils.import_object(NSX_V3_PLUGIN_CLASS)
        self.driver = nsx_v3_driver.NsxV3Driver(mock.MagicMock())
        mock.patch.object(config, 'register_l2gw_opts_helper')
        mock.patch('neutron.services.service_base.load_drivers',
                   return_value=({'dummyprovider': self.driver},
                                 'dummyprovider')).start()
        mock.patch.object(l2gateway_db.L2GatewayMixin, '__init__'),
        mock.patch.object(l2gateway_db, 'subscribe')
        mock.patch('neutron.db.servicetype_db.ServiceTypeManager.get_instance',
                   return_value=mock.MagicMock()).start()
        self.l2gw_plugin = core_l2gw_plugin.L2GatewayPlugin()
        self.context = context.get_admin_context()

    def _get_nw_data(self):
        net_data = super(TestNsxV3L2GatewayDriver, self)._get_nw_data()
        net_data['network']['port_security_enabled'] = True
        return net_data

    def test_nsxl2gw_driver_init(self):
        with mock.patch.object(nsx_v3_driver.NsxV3Driver,
                               'subscribe_callback_notifications') as sub:
            with mock.patch.object(nsx_v3_driver.LOG,
                                   'debug') as debug:
                nsx_v3_driver.NsxV3Driver(mock.MagicMock())
                self.assertTrue(sub.called)
                self.assertTrue(debug.called)

    def test_create_default_l2_gateway(self):
        def_bridge_cluster_name = nsx_v3_mocks.NSX_BRIDGE_CLUSTER_NAME
        cfg.CONF.set_override("default_bridge_cluster",
                              def_bridge_cluster_name,
                              "nsx_v3")
        nsx_v3_driver.NsxV3Driver(mock.MagicMock())
        # fake the callback invoked after init
        registry.notify(resources.PROCESS, events.BEFORE_SPAWN,
                        mock.MagicMock())
        l2gws = self.driver._get_l2_gateways(self.context)
        def_bridge_cluster_id = (
            self.nsxlib.bridge_cluster.get_id_by_name_or_id(
                def_bridge_cluster_name))
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

    def test_create_duplicate_default_l2_gateway_noop(self):
        def_bridge_cluster_name = nsx_v3_mocks.NSX_BRIDGE_CLUSTER_NAME
        cfg.CONF.set_override("default_bridge_cluster",
                              def_bridge_cluster_name,
                              "nsx_v3")
        for i in range(0, 2):
            nsx_v3_driver.NsxV3Driver(mock.MagicMock())
            # fake the callback invoked after init
            registry.notify(resources.PROCESS, events.BEFORE_SPAWN,
                            mock.MagicMock())
        l2gws = self.driver._get_l2_gateways(self.context)
        # Verify whether only one default L2 gateway is created
        self.assertEqual(1, len(l2gws))

    def test_create_default_l2_gateway_no_bc_uuid_noop(self):
        with mock.patch.object(nsx_v3_driver.NsxV3Driver,
                               'subscribe_callback_notifications'):
            nsx_v3_driver.NsxV3Driver(mock.MagicMock())
            l2gws = self.driver._get_l2_gateways(self.context)
            # Verify no default L2 gateway is created if bridge cluster id is
            # not configured in nsx.ini
            self.assertEqual([], l2gws)

    def test_create_l2_gateway_multiple_devices_fail(self):
        invalid_l2gw_dict = {
            "l2_gateway": {
                "tenant_id": "fake_tenant_id",
                "name": "invalid_l2gw",
                "devices": [{"interfaces":
                            [{"name": "interface1"}],
                            "device_name": "device1"},
                            {"interfaces":
                            [{"name": "interface_2"}],
                            "device_name": "device2"}]}}
        self.assertRaises(n_exc.InvalidInput,
                          self.l2gw_plugin.create_l2_gateway,
                          self.context, invalid_l2gw_dict)

    def test_create_l2_gateway_multiple_interfaces_fail(self):
        invalid_l2gw_dict = {
            "l2_gateway": {
                "tenant_id": "fake_tenant_id",
                "name": "invalid_l2gw",
                "devices": [{"interfaces":
                            [{"name": "interface1"},
                             {"name": "interface2"}],
                            "device_name": "device1"}]}}
        self.assertRaises(n_exc.InvalidInput,
                          self.l2gw_plugin.create_l2_gateway,
                          self.context, invalid_l2gw_dict)

    def test_create_l2_gateway_invalid_device_name_fail(self):
        invalid_l2gw_dict = {
            "l2_gateway": {
                "tenant_id": "fake_tenant_id",
                "name": "invalid_l2gw",
                "devices": [{"interfaces":
                            [{"name": "interface_1"}],
                            "device_name": "device-1"}]}}
        self.assertRaises(n_exc.InvalidInput,
                          self.l2gw_plugin.create_l2_gateway,
                          self.context, invalid_l2gw_dict)

    def test_create_l2_gateway_valid(self):
        bc_uuid = uuidutils.generate_uuid()
        l2gw_data = self._get_l2_gateway_data(name='gw1',
                                              device_name=bc_uuid)
        l2gw = self.l2gw_plugin.create_l2_gateway(self.context, l2gw_data)
        self.assertIsNotNone(l2gw)
        self.assertEqual("gw1", l2gw["name"])
        self.assertEqual("port1",
                         l2gw["devices"][0]["interfaces"][0]["name"])
        self.assertEqual(bc_uuid, l2gw["devices"][0]["device_name"])

    def test_create_l2_gateway_connection(self):
        type(self.driver)._core_plugin = self.core_plugin
        bc_uuid = uuidutils.generate_uuid()
        l2gw_data = self._get_l2_gateway_data(name='def-l2gw',
                                              device_name=bc_uuid)
        l2gw = self._create_l2gateway(l2gw_data)
        net_data = self._get_nw_data()
        net = self.core_plugin.create_network(self.context, net_data)
        l2gw_conn_data = {constants.CONNECTION_RESOURCE_NAME: {
            'l2_gateway_id': l2gw['id'],
            'tenant_id': 'fake_tenant_id',
            'network_id': net['id']}}
        l2gw_conn = self.l2gw_plugin.create_l2_gateway_connection(
            self.context, l2gw_conn_data)
        self.assertIsNotNone(l2gw_conn)
        self.assertEqual(net['id'], l2gw_conn['network_id'])
        self.assertEqual(l2gw['id'], l2gw_conn['l2_gateway_id'])

    def test_delete_l2_gateway_connection(self):
        type(self.driver)._core_plugin = self.core_plugin
        bc_uuid = uuidutils.generate_uuid()
        l2gw_data = self._get_l2_gateway_data(name='def-l2gw',
                                              device_name=bc_uuid)
        l2gw = self._create_l2gateway(l2gw_data)
        net_data = self._get_nw_data()
        net = self.core_plugin.create_network(self.context, net_data)
        l2gw_conn_data = {constants.CONNECTION_RESOURCE_NAME: {
            'l2_gateway_id': l2gw['id'],
            'tenant_id': 'fake_tenant_id',
            'network_id': net['id']}}
        l2gw_conn = self.l2gw_plugin.create_l2_gateway_connection(
            self.context,
            l2gw_conn_data)
        self.l2gw_plugin.delete_l2_gateway_connection(self.context,
                                                      l2gw_conn['id'])
        # Verify that the L2 gateway connection was deleted
        self.assertRaises(l2gw_exc.L2GatewayConnectionNotFound,
                          self.l2gw_plugin.get_l2_gateway_connection,
                          self.context, l2gw_conn['id'])
        ports = self.core_plugin.get_ports(self.context)
        # Verify that the L2 gateway connection port was cleaned up
        self.assertEqual(0, len(ports))

    def test_create_l2_gateway_connection_creates_port(self):
        type(self.driver)._core_plugin = self.core_plugin
        bc_uuid = uuidutils.generate_uuid()
        l2gw_data = self._get_l2_gateway_data(name='def-l2gw',
                                              device_name=bc_uuid)
        l2gw = self._create_l2gateway(l2gw_data)
        net_data = self._get_nw_data()
        net = self.core_plugin.create_network(self.context, net_data)
        l2gw_conn_data = {
            'id': uuidutils.generate_uuid(),
            'l2_gateway_id': l2gw['id'],
            'tenant_id': 'fake_tenant_id',
            'network_id': net['id']}
        self.driver.create_l2_gateway_connection_postcommit(self.context,
                                                            l2gw_conn_data)
        ports = self.core_plugin.get_ports(self.context)
        # Verify that the L2 gateway connection port was created with device
        # owner BRIDGEENDPOINT
        self.assertEqual(1, len(ports))
        port = ports[0]
        self.assertEqual(nsx_constants.BRIDGE_ENDPOINT, port['device_owner'])
        # Verify that the L2 gateway connection port was created with no
        # fixed ips
        self.assertEqual(0, len(port.get('fixed_ips')))

    def test_core_plugin_delete_l2_gateway_connection_port_fail(self):
        type(self.driver)._core_plugin = self.core_plugin
        bc_uuid = uuidutils.generate_uuid()
        l2gw_data = self._get_l2_gateway_data(name='def-l2gw',
                                              device_name=bc_uuid)
        l2gw = self._create_l2gateway(l2gw_data)
        net_data = self._get_nw_data()
        net = self.core_plugin.create_network(self.context, net_data)
        l2gw_conn_data = {
            'id': uuidutils.generate_uuid(),
            'l2_gateway_id': l2gw['id'],
            'tenant_id': 'fake_tenant_id',
            'network_id': net['id']}
        self.driver.create_l2_gateway_connection_postcommit(self.context,
                                                            l2gw_conn_data)
        port = self.core_plugin.get_ports(self.context)[0]
        self.assertRaises(n_exc.ServicePortInUse,
                          self.core_plugin.delete_port,
                          self.context, port['id'])
