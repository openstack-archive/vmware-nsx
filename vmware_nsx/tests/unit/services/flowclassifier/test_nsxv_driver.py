# Copyright 2016 VMware, Inc.
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
from oslo_config import cfg
from oslo_utils import importutils

from vmware_nsx.services.flowclassifier.nsx_v import driver as nsx_v_driver
from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.nsx_v.vshield import fake_vcns

from neutron.api import extensions as api_ext
from neutron.common import config
from neutron_lib.api.definitions import portbindings
from neutron_lib import context
from neutron_lib.plugins import directory

from networking_sfc.db import flowclassifier_db as fdb
from networking_sfc.extensions import flowclassifier
from networking_sfc.services.flowclassifier.common import context as fc_ctx
from networking_sfc.services.flowclassifier.common import exceptions as fc_exc
from networking_sfc.tests import base
from networking_sfc.tests.unit.db import test_flowclassifier_db


class TestNsxvFlowClassifierDriver(
    test_flowclassifier_db.FlowClassifierDbPluginTestCaseBase,
    base.NeutronDbPluginV2TestCase):

    resource_prefix_map = dict([
        (k, flowclassifier.FLOW_CLASSIFIER_PREFIX)
        for k in flowclassifier.RESOURCE_ATTRIBUTE_MAP.keys()
    ])

    def setUp(self):
        # init the flow classifier plugin
        flowclassifier_plugin = (
            test_flowclassifier_db.DB_FLOWCLASSIFIER_PLUGIN_CLASS)

        service_plugins = {
            flowclassifier.FLOW_CLASSIFIER_EXT: flowclassifier_plugin
        }
        fdb.FlowClassifierDbPlugin.supported_extension_aliases = [
            flowclassifier.FLOW_CLASSIFIER_EXT]
        fdb.FlowClassifierDbPlugin.path_prefix = (
            flowclassifier.FLOW_CLASSIFIER_PREFIX
        )

        super(TestNsxvFlowClassifierDriver, self).setUp(
            ext_mgr=None,
            plugin=None,
            service_plugins=service_plugins
        )

        self.flowclassifier_plugin = importutils.import_object(
            flowclassifier_plugin)
        ext_mgr = api_ext.PluginAwareExtensionManager(
            test_flowclassifier_db.extensions_path,
            {
                flowclassifier.FLOW_CLASSIFIER_EXT: self.flowclassifier_plugin
            }
        )
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = api_ext.ExtensionMiddleware(app, ext_mgr=ext_mgr)
        self.ctx = context.get_admin_context()

        # use the fake vcns
        mock_vcns = mock.patch(vmware.VCNS_NAME, autospec=True)
        mock_vcns_instance = mock_vcns.start()
        self.fc2 = fake_vcns.FakeVcns()
        mock_vcns_instance.return_value = self.fc2

        # use the nsxv flow classifier driver
        self._profile_id = 'serviceprofile-1'
        cfg.CONF.set_override('service_insertion_profile_id',
                              self._profile_id, 'nsxv')
        cfg.CONF.set_override('service_insertion_redirect_all',
                              True, 'nsxv')

        self.driver = nsx_v_driver.NsxvFlowClassifierDriver()
        self.driver.initialize()

        self._fc_name = 'test1'
        self._fc_description = 'test 1'
        self._fc_source = '10.10.0.0/24'
        self._fc_dest = '20.10.0.0/24'
        self._fc_prot = 'TCP'
        self._fc_source_ports = range(100, 115)
        self._fc_dest_ports = range(80, 81)
        self._fc = {'name': self._fc_name,
                    'description': self._fc_description,
                    'logical_source_port': None,
                    'logical_destination_port': None,
                    'source_ip_prefix': self._fc_source,
                    'destination_ip_prefix': self._fc_dest,
                    'protocol': self._fc_prot,
                    'source_port_range_min': self._fc_source_ports[0],
                    'source_port_range_max': self._fc_source_ports[-1],
                    'destination_port_range_min': self._fc_dest_ports[0],
                    'destination_port_range_max': self._fc_dest_ports[-1]}

    def tearDown(self):
        super(TestNsxvFlowClassifierDriver, self).tearDown()

    def test_driver_init(self):
        self.assertEqual(self._profile_id, self.driver._profile_id)
        self.assertEqual(self.driver._security_group_id, '0')

        orig_get_plugin = directory.get_plugin

        def mocked_get_plugin(plugin=None):
            # mock only the core plugin
            if plugin:
                return orig_get_plugin(plugin)
            return mock_nsxv_plugin

        mock_nsxv_plugin = mock.Mock()
        fc_plugin = directory.get_plugin(flowclassifier.FLOW_CLASSIFIER_EXT)
        with mock.patch.object(directory, 'get_plugin',
                               new=mocked_get_plugin):
            with mock.patch.object(
                mock_nsxv_plugin,
                'add_vms_to_service_insertion') as fake_add:
                with mock.patch.object(
                    fc_plugin,
                    'create_flow_classifier') as fake_create:
                    self.driver.init_complete(None, None, {})
                    # check that the plugin was called to add vms to the
                    # security group
                    self.assertTrue(fake_add.called)
                    # check that redirect_all flow classifier entry
                    # was created
                    self.assertTrue(fake_create.called)

    def test_create_flow_classifier_precommit(self):
        with self.flow_classifier(flow_classifier=self._fc) as fc:
            fc_context = fc_ctx.FlowClassifierContext(
                self.flowclassifier_plugin, self.ctx,
                fc['flow_classifier']
            )
            # just make sure it does not raise an exception
            self.driver.create_flow_classifier_precommit(fc_context)

    def test_create_flow_classifier_precommit_logical_source_port(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port:
            with self.flow_classifier(flow_classifier={
                'name': 'test1',
                'logical_source_port': src_port['port']['id']
            }) as fc:
                fc_context = fc_ctx.FlowClassifierContext(
                    self.flowclassifier_plugin, self.ctx,
                    fc['flow_classifier']
                )
                self.assertRaises(
                    fc_exc.FlowClassifierBadRequest,
                    self.driver.create_flow_classifier_precommit,
                    fc_context)

    def test_create_flow_classifier_precommit_logical_dest_port(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as dst_port:
            with self.flow_classifier(flow_classifier={
                'name': 'test1',
                'logical_destination_port': dst_port['port']['id']
            }) as fc:
                fc_context = fc_ctx.FlowClassifierContext(
                    self.flowclassifier_plugin, self.ctx,
                    fc['flow_classifier']
                )
                self.assertRaises(
                    fc_exc.FlowClassifierBadRequest,
                    self.driver.create_flow_classifier_precommit,
                    fc_context)

    def _validate_rule_structure(self, rule):
        self.assertEqual(self._fc_description, rule.find('notes').text)
        self.assertEqual('ipv4', rule.find('packetType').text)
        self.assertEqual(
            self._fc_source,
            rule.find('sources').find('source').find('value').text)
        self.assertEqual(
            self._fc_dest,
            rule.find('destinations').find('destination').find('value').text)
        ports = "%s-%s" % (self._fc_source_ports[0], self._fc_source_ports[-1])
        if self._fc_source_ports[0] == self._fc_source_ports[-1]:
            ports = str(self._fc_source_ports[0])
        self.assertEqual(
            ports,
            rule.find('services').find('service').find('sourcePort').text)
        ports = "%s-%s" % (self._fc_dest_ports[0], self._fc_dest_ports[-1])
        if self._fc_dest_ports[0] == self._fc_dest_ports[-1]:
            ports = str(self._fc_dest_ports[0])
        self.assertEqual(
            ports,
            rule.find('services').find('service').find('destinationPort').text)
        self.assertEqual(
            self._fc_prot,
            rule.find('services').find('service').find('protocolName').text)
        self.assertTrue(rule.find('name').text.startswith(self._fc_name))

    def test_create_flow_classifier(self):
        with self.flow_classifier(flow_classifier=self._fc) as fc:
            fc_context = fc_ctx.FlowClassifierContext(
                self.flowclassifier_plugin, self.ctx,
                fc['flow_classifier']
            )
            with mock.patch.object(
                self.driver,
                'update_redirect_section_in_backed') as mock_update_section:
                self.driver.create_flow_classifier(fc_context)
                self.assertTrue(mock_update_section.called)
                section = mock_update_section.call_args[0][0]
                self._validate_rule_structure(section.find('rule'))

    def test_update_flow_classifier(self):
        with self.flow_classifier(flow_classifier=self._fc) as fc:
            fc_context = fc_ctx.FlowClassifierContext(
                self.flowclassifier_plugin, self.ctx,
                fc['flow_classifier']
            )
            self.driver.create_flow_classifier(fc_context)
            with mock.patch.object(
                self.driver,
                'update_redirect_section_in_backed') as mock_update_section:
                self.driver.update_flow_classifier(fc_context)
                self.assertTrue(mock_update_section.called)
                section = mock_update_section.call_args[0][0]
                self._validate_rule_structure(section.find('rule'))

    def test_delete_flow_classifier(self):
        with self.flow_classifier(flow_classifier=self._fc) as fc:
            fc_context = fc_ctx.FlowClassifierContext(
                self.flowclassifier_plugin, self.ctx,
                fc['flow_classifier']
            )
            self.driver.create_flow_classifier(fc_context)
            with mock.patch.object(
                self.driver,
                'update_redirect_section_in_backed') as mock_update_section:
                self.driver.delete_flow_classifier(fc_context)
                self.assertTrue(mock_update_section.called)
                section = mock_update_section.call_args[0][0]
                # make sure the rule is not there
                self.assertIsNone(section.find('rule'))
