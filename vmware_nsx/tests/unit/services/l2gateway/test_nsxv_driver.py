# Copyright 2015 VMware, Inc.
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
import mock

from neutron.tests import base

from networking_l2gw.db.l2gateway import l2gateway_db
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import nsxv_db
from vmware_nsx.dvs import dvs_utils
from vmware_nsx.services.l2gateway.nsx_v import driver as nsx_v_driver
from vmware_nsx.tests.unit.nsx_v import test_plugin

CORE_PLUGIN = "vmware_nsx.plugins.nsx_v.plugin.NsxVPluginV2"


class TestL2gatewayDriver(base.BaseTestCase):

    def setUp(self):
        super(TestL2gatewayDriver, self).setUp()
        self.context = context.get_admin_context()
        self.plugin = nsx_v_driver.NsxvL2GatewayDriver(mock.MagicMock())

    def test_validate_device_with_multi_devices(self):
        fake_l2gw_dict = {"l2_gateway":
                          {"tenant_id": "fake__tenant_id",
                           "name": "fake_l2gw",
                           "devices": [{"interfaces":
                                        [{"name": "fake_inter"}],
                                        "device_name": "fake_dev"},
                                       {"interfaces":
                                        [{"name": "fake_inter_1"}],
                                        "device_name": "fake_dev_1"}]}}
        with mock.patch.object(l2gateway_db.L2GatewayMixin, '_admin_check'):
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.create_l2_gateway,
                              self.context, fake_l2gw_dict)

    def test_validate_interface_with_multi_interfaces(self):
        fake_l2gw_dict = {"l2_gateway":
                          {"tenant_id": "fake_tenant_id",
                           "name": "fake_l2gw",
                           "devices": [{"interfaces":
                                        [{"name": "fake_inter_1"},
                                         {"name": "fake_inter_2"}],
                                        "device_name": "fake_dev"}]}}
        with mock.patch.object(l2gateway_db.L2GatewayMixin, '_admin_check'):
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.create_l2_gateway,
                              self.context, fake_l2gw_dict)

    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._nsxv')
    def test_validate_interface_with_invalid_interfaces(self, _nsxv):
        fake_interfaces = [{"name": "fake_inter"}]
        _nsxv.vcns.validate_network.return_value = False
        self.assertRaises(n_exc.InvalidInput,
                          self.plugin._validate_interface_list,
                          self.context,
                          fake_interfaces)

    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._edge_manager')
    def test_create_gw_edge_failure(self, edge_manager):
        with mock.patch.object(nsxv_db,
                               'get_nsxv_router_binding',
                               return_value=None):
            self.assertRaises(nsx_exc.NsxL2GWDeviceNotFound,
                             self.plugin._create_l2_gateway_edge,
                             self.context)

    @mock.patch('networking_l2gw.db.l2gateway.l2gateway_db.'
                'L2GatewayMixin._admin_check')
    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._validate_device_list')
    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._validate_interface_list')
    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._create_l2_gateway_edge')
    @mock.patch('networking_l2gw.db.l2gateway.l2gateway_db.'
                'L2GatewayMixin.create_l2_gateway')
    def test_create_l2_gateway_failure(self, create_l2gw, _create_l2gw_edge,
                               val_inter, val_dev, _admin_check):
        fake_l2gw_dict = {"l2_gateway":
                          {"tenant_id": "fake_teannt_id",
                           "name": "fake_l2gw",
                           "devices": [{"interfaces":
                                        [{"name": "fake_inter"}],
                                        "device_name": "fake_dev"}]}}
        _create_l2gw_edge.side_effect = nsx_exc.NsxL2GWDeviceNotFound
        self.assertRaises(nsx_exc.NsxL2GWDeviceNotFound,
                         self.plugin.create_l2_gateway,
                         self.context, fake_l2gw_dict)

    @mock.patch('networking_l2gw.db.l2gateway.l2gateway_db.'
                'L2GatewayMixin._admin_check')
    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._validate_device_list')
    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._validate_interface_list')
    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._create_l2_gateway_edge')
    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._edge_manager')
    def test_create_l2_gateway(self, edge_manager, _create_l2gw_edge,
                               val_inter, val_dev, _admin_check):
        fake_l2gw_dict = {"l2_gateway":
                          {"tenant_id": "fake_teannt_id",
                           "name": "fake_l2gw",
                           "devices": [{"interfaces":
                                        [{"name": "fake_inter"}],
                                        "device_name": "fake_dev"}]}}
        fake_devices = [{"interfaces": [{"name": "fake_inter"}],
                         "device_name": "fake_dev"}]
        fake_interfaces = [{"name": "fake_inter"}]
        _create_l2gw_edge.return_value = 'fake_dev'
        self.plugin.create_l2_gateway(self.context, fake_l2gw_dict)
        _admin_check.assert_called_with(self.context, 'CREATE')
        val_dev.assert_called_with(fake_devices)
        val_inter.assert_called_with(self.context, fake_interfaces)

    @mock.patch('networking_l2gw.db.l2gateway.l2gateway_db.'
                'L2GatewayMixin._admin_check')
    @mock.patch('networking_l2gw.db.l2gateway.l2gateway_db.'
                'L2GatewayMixin.get_l2_gateway_connection')
    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._get_device')
    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._nsxv')
    def test_delete_l2_gateway_connection(self, nsxv, get_devices,
                                          get_conn, admin_check):
        fake_conn_dict = {'l2_gateway_id': 'fake_l2gw_id'}
        fake_device_dict = {'id': 'fake_dev_id',
                            'device_name': 'fake_dev_name'}
        get_conn.return_value = fake_conn_dict
        get_devices.return_value = fake_device_dict
        self.plugin.delete_l2_gateway_connection(self.context, fake_conn_dict)
        admin_check.assert_called_with(self.context, 'DELETE')
        get_conn.assert_called_with(self.context, fake_conn_dict)
        get_devices.assert_called_with(self.context, 'fake_l2gw_id')
        self.plugin._nsxv().del_bridge.asert_called_with('fake_dev_name')

    @mock.patch('networking_l2gw.db.l2gateway.l2gateway_db.'
                'L2GatewayMixin._admin_check')
    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._get_device')
    @mock.patch('vmware_nsx.db.'
                'nsxv_db.get_nsxv_router_binding_by_edge')
    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._edge_manager')
    def test_delete_l2_gateway(self, edge_manager, get_nsxv_router,
                               get_devices, admin_check):
        fake_device_dict = {"id": "fake_dev_id",
                            "device_name": "fake_edge_name",
                            "l2_gateway_id": "fake_l2gw_id"}
        fake_rtr_binding = {"router_id": 'fake_router_id'}
        get_devices.return_value = fake_device_dict
        get_nsxv_router.return_value = fake_rtr_binding
        self.plugin.delete_l2_gateway(self.context, 'fake_l2gw_id')
        admin_check.assert_called_with(self.context, 'DELETE')
        get_devices.assert_called_with(self.context, 'fake_l2gw_id')
        get_nsxv_router.assert_called_with(self.context.session,
                                           "fake_edge_name")


class TestL2GatewayDriverRouter(test_plugin.NsxVPluginV2TestCase):

    @mock.patch.object(dvs_utils, 'dvs_create_session')
    def setUp(self, *mocks):
        # init the nsxv plugin, edge manager and fake vcns
        super(TestL2GatewayDriverRouter, self).setUp(plugin=CORE_PLUGIN,
                                                     ext_mgr=None)
        self.context = context.get_admin_context()
        # init the L2 gateway driver
        self.driver = nsx_v_driver.NsxvL2GatewayDriver(mock.MagicMock())

    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._validate_device_list')
    @mock.patch('vmware_nsx.services.l2gateway.'
                'nsx_v.driver.NsxvL2GatewayDriver._validate_interface_list')
    def test_create_l2_gateway_router(self, val_inter, val_dev):
        # Verify that creating the router doesn't fail
        fake_l2gw_dict = {"l2_gateway":
                          {"tenant_id": "fake_teannt_id",
                           "name": "fake_l2gw",
                           "devices": [{"interfaces":
                                        [{"name": "fake_inter"}],
                                        "device_name": "fake_dev"}]}}
        self.driver.create_l2_gateway(self.context, fake_l2gw_dict)

    def test_create_l2_gateway_router_edge(self):
        # Verify that the router edge is really created
        edge_id = self.driver._create_l2_gateway_edge(self.context)
        self.assertEqual('edge-1', edge_id)
