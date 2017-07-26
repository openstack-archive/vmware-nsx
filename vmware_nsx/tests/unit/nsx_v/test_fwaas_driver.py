# Copyright 2017 VMware, Inc.
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

import copy

import mock
from neutron_lib.exceptions import firewall_v1 as exceptions
from oslo_utils import uuidutils

from vmware_nsx.services.fwaas.nsx_v import edge_fwaas_driver
from vmware_nsx.tests.unit.nsx_v import test_plugin as test_v_plugin

FAKE_FW_ID = 'fake_fw_uuid'


class NsxvFwaasTestCase(test_v_plugin.NsxVPluginV2TestCase):
    def setUp(self):
        super(NsxvFwaasTestCase, self).setUp()
        self.firewall = edge_fwaas_driver.EdgeFwaasDriver()

    def _fake_rules_v4(self):
        rule1 = {'enabled': True,
                 'action': 'allow',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '80',
                 'source_port': '1-65535',
                 'source_ip_address': '10.24.4.2',
                 'id': 'fake-fw-rule1'}
        rule2 = {'enabled': True,
                 'action': 'deny',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '22',
                 'id': 'fake-fw-rule2'}
        rule3 = {'enabled': True,
                 'action': 'reject',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '23',
                 'id': 'fake-fw-rule3'}
        return [rule1, rule2, rule3]

    def _fake_backend_rules_v4(self):
        rule1 = {'enabled': True,
                 'action': 'allow',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '80',
                 'source_port': '1-65535',
                 'source_ip_address': ['10.24.4.2'],
                 'position': '0',
                 'id': 'fake-fw-rule1',
                 'name': 'Fwaas-fake-fw-rule1'}
        rule2 = {'enabled': True,
                 'action': 'deny',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '22',
                 'id': 'fake-fw-rule2',
                 'position': '1',
                 'name': 'Fwaas-fake-fw-rule2'}
        rule3 = {'enabled': True,
                 'action': 'reject',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '23',
                 'position': '2',
                 'id': 'fake-fw-rule3',
                 'name': 'Fwaas-fake-fw-rule3'}

        return [rule1, rule2, rule3]

    def _fake_firewall_no_rule(self):
        rule_list = []
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': True,
                   'tenant_id': 'tenant-uuid',
                   'firewall_rule_list': rule_list}
        return fw_inst

    def _fake_firewall(self, rule_list):
        _rule_list = copy.deepcopy(rule_list)
        for rule in _rule_list:
            rule['position'] = str(_rule_list.index(rule))
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': True,
                   'tenant_id': 'tenant-uuid',
                   'firewall_rule_list': _rule_list}
        return fw_inst

    def _fake_firewall_with_admin_down(self, rule_list):
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': False,
                   'tenant_id': 'tenant-uuid',
                   'firewall_rule_list': rule_list}
        return fw_inst

    def _fake_apply_list(self, router_count=1):
        apply_list = []
        while router_count > 0:
            rtr_id = uuidutils.generate_uuid()
            router_inst = {'id': rtr_id}
            router_info_inst = mock.Mock()
            router_info_inst.router = router_inst
            router_info_inst.router_id = rtr_id
            apply_list.append(router_info_inst)
            router_count -= 1
        return apply_list

    def _get_fake_mapping(self, apply_list):
        router_edge_map = {}
        for router_info in apply_list:
            router_edge_map[router_info.router_id] = {
                'edge_id': 'edge-1',
                'lookup_id': router_info.router_id}
        return router_edge_map

    def _setup_firewall_with_rules(self, func, router_count=1):
        apply_list = self._fake_apply_list(router_count=router_count)
        rule_list = self._fake_rules_v4()
        firewall = self._fake_firewall(rule_list)
        edges = self._get_fake_mapping(apply_list)

        with mock.patch("vmware_nsx.plugins.nsx_v.plugin.NsxVPluginV2."
                        "update_router_firewall") as update_fw,\
            mock.patch("vmware_nsx.plugins.nsx_v.plugin.NsxVPluginV2."
                       "_get_router"),\
            mock.patch.object(self.firewall,
                              "_get_routers_edges", return_value=edges):
            func('nsx', apply_list, firewall)
            self.assertEqual(router_count, update_fw.call_count)
            # Validate the args of the last call
            self.assertEqual(apply_list[-1].router_id,
                             update_fw.call_args[0][1])
            backend_rules = update_fw.call_args[1]['fwaas_rules']
            self.assertEqual(len(rule_list), len(backend_rules))
            self.assertEqual(self._fake_backend_rules_v4(), backend_rules)

    def test_create_firewall_no_rules(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_firewall_no_rule()
        edges = self._get_fake_mapping(apply_list)
        with mock.patch("vmware_nsx.plugins.nsx_v.plugin.NsxVPluginV2."
                        "update_router_firewall") as update_fw,\
            mock.patch("vmware_nsx.plugins.nsx_v.plugin.NsxVPluginV2."
                       "_get_router"),\
            mock.patch.object(self.firewall,
                              "_get_routers_edges", return_value=edges):
            self.firewall.create_firewall('nsx', apply_list, firewall)
            self.assertEqual(1, update_fw.call_count)
            # Validate the args of the last call
            self.assertEqual(apply_list[0].router_id,
                             update_fw.call_args[0][1])
            backend_rules = update_fw.call_args[1]['fwaas_rules']
            self.assertEqual([], backend_rules)

    def test_create_firewall_with_rules(self):
        self._setup_firewall_with_rules(self.firewall.create_firewall)

    def test_create_firewall_with_rules_two_routers(self):
        self._setup_firewall_with_rules(self.firewall.create_firewall,
                                        router_count=2)

    def test_update_firewall_with_rules(self):
        self._setup_firewall_with_rules(self.firewall.update_firewall)

    def test_delete_firewall(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_firewall_no_rule()
        edges = self._get_fake_mapping(apply_list)
        with mock.patch("vmware_nsx.plugins.nsx_v.plugin.NsxVPluginV2."
                        "update_router_firewall") as update_fw,\
            mock.patch("vmware_nsx.plugins.nsx_v.plugin.NsxVPluginV2."
                       "_get_router"),\
            mock.patch.object(self.firewall,
                              "_get_routers_edges", return_value=edges):
            self.firewall.delete_firewall('nsx', apply_list, firewall)
            self.assertEqual(1, update_fw.call_count)
            # Validate the args of the last call
            self.assertEqual(apply_list[0].router_id,
                             update_fw.call_args[0][1])
            backend_rules = update_fw.call_args[1]['fwaas_rules']
            self.assertIsNone(backend_rules)

    def test_create_firewall_with_admin_down(self):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4()
        firewall = self._fake_firewall_with_admin_down(rule_list)
        edges = self._get_fake_mapping(apply_list)
        with mock.patch("vmware_nsx.plugins.nsx_v.plugin.NsxVPluginV2."
                        "update_router_firewall") as update_fw,\
            mock.patch("vmware_nsx.plugins.nsx_v.plugin.NsxVPluginV2."
                       "_get_router"),\
            mock.patch.object(self.firewall,
                              "_get_routers_edges", return_value=edges):
            self.firewall.create_firewall('nsx', apply_list, firewall)
            self.assertEqual(1, update_fw.call_count)
            # Validate the args of the last call
            self.assertEqual(apply_list[0].router_id,
                             update_fw.call_args[0][1])
            backend_rules = update_fw.call_args[1]['fwaas_rules']
            self.assertEqual([], backend_rules)

    def test_should_apply_firewall_to_router(self):
        router = {'id': 'fake_id',
                  'external_gateway_info': 'fake_data',
                  'router_type': 'exclusive',
                  'distributed': False}
        self.assertTrue(self.firewall.should_apply_firewall_to_router(router))

        # no external gateway:
        router['external_gateway_info'] = None
        self.assertFalse(self.firewall.should_apply_firewall_to_router(router))
        router['external_gateway_info'] = 'Dummy'

        # not for shared router:
        router['router_type'] = 'shared'
        router['distributed'] = False
        self.assertRaises(exceptions.FirewallInternalDriverError,
                          self.firewall.should_apply_firewall_to_router,
                          router)

        # should work for distributed router
        router['router_type'] = 'exclusive'
        router['distributed'] = True
        self.assertTrue(self.firewall.should_apply_firewall_to_router(router))

        # not for mdproxy router:
        router['name'] = 'metadata_proxy_router'
        self.assertRaises(exceptions.FirewallInternalDriverError,
                          self.firewall.should_apply_firewall_to_router,
                          router)
