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

from vmware_nsx.services.fwaas.nsx_v import edge_fwaas_driver
from vmware_nsx.tests.unit.nsx_v import test_plugin as test_v_plugin

FAKE_FW_ID = 'fake_fw_uuid'


class NsxvFwaasTestCase(test_v_plugin.NsxVPluginV2TestCase):
    def setUp(self):
        super(NsxvFwaasTestCase, self).setUp()
        self.firewall = edge_fwaas_driver.EdgeFwaasDriver()
        self.firewall._get_routers_edges = mock.Mock()
        self.firewall._get_routers_edges.return_value = ['edge-1']

    def _fake_rules_v4(self):
        rule1 = {'enabled': True,
                 'action': 'allow',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '80',
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
            router_inst = {}
            router_info_inst = mock.Mock()
            router_info_inst.router = router_inst
            apply_list.append(router_info_inst)
            router_count -= 1
        return apply_list

    def _setup_firewall_with_rules(self, func, router_count=1):
        apply_list = self._fake_apply_list(router_count=router_count)
        rule_list = self._fake_rules_v4()
        firewall = self._fake_firewall(rule_list)
        edges = ['edge-1'] * router_count
        with mock.patch.object(self.firewall._nsxv,
                               "update_firewall") as update_fw,\
            mock.patch.object(self.firewall,
                              "_get_routers_edges", return_value=edges):
            func('nsx', apply_list, firewall)
            self.assertEqual(router_count, update_fw.call_count)
            bakend_rules = update_fw.call_args[0][1]['firewall_rule_list']
            self.assertEqual(len(rule_list), len(bakend_rules))

    def test_create_firewall_no_rules(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_firewall_no_rule()
        with mock.patch.object(self.firewall._nsxv,
                               "update_firewall") as update_fw:
            self.firewall.create_firewall('nsx', apply_list, firewall)
            self.assertEqual(1, update_fw.call_count)
            bakend_rules = update_fw.call_args[0][1]['firewall_rule_list']
            self.assertEqual(0, len(bakend_rules))

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
        with mock.patch.object(self.firewall._nsxv,
                               "update_firewall") as update_fw:
            self.firewall.delete_firewall('nsx', apply_list, firewall)
            self.assertEqual(1, update_fw.call_count)
            bakend_rules = update_fw.call_args[0][1]['firewall_rule_list']
            self.assertEqual(0, len(bakend_rules))

    def test_create_firewall_with_admin_down(self):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4()
        firewall = self._fake_firewall_with_admin_down(rule_list)
        with mock.patch.object(self.firewall._nsxv,
                               "update_firewall") as update_fw:
            self.firewall.create_firewall('nsx', apply_list, firewall)
            self.assertEqual(1, update_fw.call_count)
            bakend_rules = update_fw.call_args[0][1]['firewall_rule_list']
            self.assertEqual(0, len(bakend_rules))
