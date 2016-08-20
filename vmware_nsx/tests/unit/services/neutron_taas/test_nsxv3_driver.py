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

from neutron import context
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin

from neutron_taas.extensions import taas
from neutron_taas.services.taas import taas_plugin
from neutron_taas.tests.unit.db import test_taas_db

from oslo_utils import importutils
from oslo_utils import uuidutils

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.services.neutron_taas.nsx_v3 import driver as nsx_v3_driver
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_nsx_v3_plugin

_uuid = uuidutils.generate_uuid
NSX_V3_PLUGIN_CLASS = ('vmware_nsx.plugins.nsx_v3.plugin.NsxV3Plugin')


class TestNsxV3TaaSDriver(test_taas_db.TaaSDbTestCase,
                          test_nsx_v3_plugin.NsxV3PluginTestCaseMixin,
                          test_plugin.NeutronDbPluginV2TestCase):
    def setUp(self):
        super(TestNsxV3TaaSDriver, self).setUp()
        self.driver = nsx_v3_driver.NsxV3Driver(mock.MagicMock())
        mock.patch('neutron.services.service_base.load_drivers',
                   return_value=({'dummyprovider': self.driver},
                                 'dummyprovider')).start()
        mock.patch('neutron.db.servicetype_db.ServiceTypeManager.get_instance',
                   return_value=mock.MagicMock()).start()
        self.taas_plugin = taas_plugin.TaasPlugin()
        self.core_plugin = importutils.import_object(NSX_V3_PLUGIN_CLASS)
        mock.patch(
            'vmware_nsx.plugins.nsx_v3.plugin.NsxV3Plugin.get_floatingips',
            return_value=([{'floating_ip_address': '172.10.10.10'}])).start()
        self.ctx = context.get_admin_context()

    def test_validate_tap_flow_same_network_same_port_fail(self):
        with self.port() as src_port:
            self.assertRaises(nsx_exc.NsxTaaSDriverException,
                              self.driver._validate_tap_flow,
                              src_port['port'], src_port['port'])

    def test_validate_tap_flow_same_network_different_port(self):
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                with self.port(subnet=subnet) as src_port:
                    with self.port(subnet=subnet) as dest_port:
                        result = self.driver._validate_tap_flow(
                            src_port['port'],
                            dest_port['port'])
                        # result = None signifies that the method returned
                        # with no exceptions.
                        self.assertIsNone(result)

    def test_convert_to_backend_direction(self):
        direction = 'BOTH'
        nsx_direction = self.driver._convert_to_backend_direction(direction)
        self.assertEqual('BIDIRECTIONAL', nsx_direction)

        direction = 'IN'
        nsx_direction = self.driver._convert_to_backend_direction(direction)
        self.assertEqual('INGRESS', nsx_direction)

        direction = 'OUT'
        nsx_direction = self.driver._convert_to_backend_direction(direction)
        self.assertEqual('EGRESS', nsx_direction)

    def test_convert_to_backend_source_port(self):
        nsx_id = _uuid()
        with mock.patch('vmware_nsx.db.db.get_nsx_switch_and_port_id',
                        return_value=(_uuid(), nsx_id)):
            result = self.driver._convert_to_backend_source_port(
                self.ctx.session, _uuid())
            self.assertEqual(1, len(result))
            self.assertEqual('LogicalPortMirrorSource',
                             result[0].get('resource_type'))
            self.assertEqual(1, len(result[0].get('port_ids')))
            self.assertEqual(nsx_id, result[0].get('port_ids')[0])

    def test_convert_to_backend_dest_port(self):
        nsx_id = _uuid()
        with mock.patch('vmware_nsx.db.db.get_nsx_switch_and_port_id',
                        return_value=(_uuid(), nsx_id)):
            result = self.driver._convert_to_backend_dest_port(
                self.ctx.session, _uuid())
            self.assertEqual('LogicalPortMirrorDestination',
                             result.get('resource_type'))
            self.assertEqual(1, len(result.get('port_ids')))
            self.assertEqual(nsx_id, result.get('port_ids')[0])

    def test_create_tap_service(self):
        ts_name = 'test-tap-service'
        with self.port(tenant_id=self.tenant_id) as port:
            ts_data = self._get_tap_service_data(
                name=ts_name, port_id=port['port']['id'])
            ts = self.taas_plugin.create_tap_service(self.ctx, ts_data)
            self.assertIsNotNone(ts)
            self.assertEqual(ts_name, ts['name'])
            self.assertEqual(port['port']['id'], ts['port_id'])

    def test_delete_tap_service(self):
        with self.port(tenant_id=self.tenant_id) as port:
            ts_data = self._get_tap_service_data(port_id=port['port']['id'])
            ts = self.taas_plugin.create_tap_service(self.ctx, ts_data)
            self.assertIsNotNone(ts)
            self.taas_plugin.delete_tap_service(self.ctx, ts['id'])
            self.assertRaises(taas.TapServiceNotFound,
                              self._get_tap_service, ts['id'])

    def test_create_tap_flow(self):
        tf_name = 'test-tap-flow'
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                with self.port(tenant_id=self.tenant_id,
                               subnet=subnet) as dest_port:
                    with self.port(tenant_id=self.tenant_id,
                                   subnet=subnet) as src_port:
                        ts_data = self._get_tap_service_data(
                            port_id=dest_port['port']['id'])
                        ts = self.taas_plugin.create_tap_service(
                            self.ctx, ts_data)
                        tf_data = self._get_tap_flow_data(
                            tap_service_id=ts['id'],
                            source_port=src_port['port']['id'],
                            name=tf_name)
                        tf = self.taas_plugin.create_tap_flow(self.ctx,
                                                              tf_data)
                        self.assertIsNotNone(tf)
                        self.assertEqual(tf_name, tf['name'])
                        self.assertEqual(src_port['port']['id'],
                                         tf['source_port'])

    def test_create_tap_flow_same_network_same_port_fail(self):
        tf_name = 'test-tap-flow'
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                with self.port(tenant_id=self.tenant_id,
                               subnet=subnet) as port:
                        ts_data = self._get_tap_service_data(
                            port_id=port['port']['id'])
                        ts = self.taas_plugin.create_tap_service(
                            self.ctx, ts_data)
                        tf_data = self._get_tap_flow_data(
                            tap_service_id=ts['id'],
                            source_port=port['port']['id'],
                            name=tf_name)
                        self.assertRaises(nsx_exc.NsxTaaSDriverException,
                                          self.taas_plugin.create_tap_flow,
                                          self.ctx,
                                          tf_data)

    def test_delete_tap_flow(self):
        tf_name = 'test-tap-flow'
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                with self.port(tenant_id=self.tenant_id,
                               subnet=subnet) as dest_port:
                    with self.port(tenant_id=self.tenant_id,
                                   subnet=subnet) as src_port:
                        ts_data = self._get_tap_service_data(
                            port_id=dest_port['port']['id'])
                        ts = self.taas_plugin.create_tap_service(
                            self.ctx, ts_data)
                        tf_data = self._get_tap_flow_data(
                            tap_service_id=ts['id'],
                            source_port=src_port['port']['id'],
                            name=tf_name)
                        tf = self.taas_plugin.create_tap_flow(self.ctx,
                                                              tf_data)
                        self.assertIsNotNone(tf)
                        self.taas_plugin.delete_tap_flow(self.ctx, tf['id'])
                        self.assertRaises(taas.TapFlowNotFound,
                                          self._get_tap_flow, tf['id'])
