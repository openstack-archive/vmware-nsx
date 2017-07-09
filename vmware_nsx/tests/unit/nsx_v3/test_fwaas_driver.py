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
from vmware_nsxlib.v3 import nsx_constants as consts

from vmware_nsx.services.fwaas.nsx_v3 import edge_fwaas_driver
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_v3_plugin

FAKE_FW_ID = 'fake_fw_uuid'
FAKE_ROUTER_ID = 'fake_rtr_uuid'
MOCK_NSX_ID = 'nsx_router_id'
MOCK_DEFAULT_RULE_ID = 'nsx_default_rule_id'
MOCK_SECTION_ID = 'sec_id'
DEFAULT_RULE = {'is_default': True,
                'display_name': edge_fwaas_driver.DEFAULT_RULE_NAME,
                'id': MOCK_DEFAULT_RULE_ID,
                'action': consts.FW_ACTION_DROP}


class Nsxv3FwaasTestCase(test_v3_plugin.NsxV3PluginTestCaseMixin):
    def setUp(self):
        super(Nsxv3FwaasTestCase, self).setUp()
        self.firewall = edge_fwaas_driver.EdgeFwaasV3Driver()

        # Start some nsxlib/DB mocks
        mock.patch(
            "vmware_nsxlib.v3.core_resources.NsxLibLogicalRouter."
            "get_firewall_section_id",
            return_value=MOCK_SECTION_ID).start()

        mock.patch(
            "vmware_nsxlib.v3.security.NsxLibFirewallSection."
            "get_default_rule",
            return_value={'id': MOCK_DEFAULT_RULE_ID}).start()

        mock.patch(
            "vmware_nsx.db.db.get_nsx_router_id",
            return_value=MOCK_NSX_ID).start()

    def _default_rule(self, drop=True):
        rule = DEFAULT_RULE
        if drop:
            rule['action'] = consts.FW_ACTION_DROP
        else:
            rule['action'] = consts.FW_ACTION_ALLOW
        return rule

    def _fake_rules_v4(self):
        rule1 = {'enabled': True,
                 'action': 'allow',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '80',
                 'source_ip_address': '10.24.4.2',
                 'id': 'fake-fw-rule1',
                 'description': 'first rule'}
        rule2 = {'enabled': True,
                 'action': 'reject',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '22:24',
                 'source_port': '1:65535',
                 'id': 'fake-fw-rule2'}
        rule3 = {'enabled': True,
                 'action': 'deny',
                 'ip_version': 4,
                 'protocol': 'icmp',
                 'id': 'fake-fw-rule3'}
        rule4 = {'enabled': True,
                 'action': 'deny',
                 'ip_version': 4,
                 'source_ip_address': '10.25.5.2',
                 'id': 'fake-fw-rule4'}
        return [rule1, rule2, rule3, rule4]

    def _fake_translated_rules(self):
        # The expected translation of the rules in _fake_rules_v4
        service1 = {'l4_protocol': 'TCP',
                    'resource_type': 'L4PortSetNSService',
                    'destination_ports': ['80'],
                    'source_ports': []}
        rule1 = {'action': 'ALLOW',
                 'services': [{'service': service1}],
                 'sources': [{'target_id': '10.24.4.2',
                              'target_type': 'IPv4Address'}],
                 'display_name': 'Fwaas-fake-fw-rule1',
                 'notes': 'first rule'}
        service2 = {'l4_protocol': 'TCP',
                    'resource_type': 'L4PortSetNSService',
                    'destination_ports': ['22-24'],
                    'source_ports': ['1-65535']}
        rule2 = {'action': 'DROP',  # Reject is replaced with deny
                 'services': [{'service': service2}],
                 'display_name': 'Fwaas-fake-fw-rule2'}
        service3_1 = {'resource_type': 'ICMPTypeNSService',
                      'protocol': 'ICMPv4'}
        service3_2 = {'resource_type': 'ICMPTypeNSService',
                      'protocol': 'ICMPv6'}
        rule3 = {'action': 'DROP',
                 # icmp is translated to icmp v4 & v6
                 'services': [{'service': service3_1},
                              {'service': service3_2}],
                 'display_name': 'Fwaas-fake-fw-rule3'}
        rule4 = {'action': 'DROP',
                 'sources': [{'target_id': '10.25.5.2',
                              'target_type': 'IPv4Address'}],
                 'display_name': 'Fwaas-fake-fw-rule4'}

        return [rule1, rule2, rule3, rule4]

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
            router_inst = {'id': FAKE_ROUTER_ID}
            router_info_inst = mock.Mock()
            router_info_inst.router = router_inst
            apply_list.append(router_info_inst)
            router_count -= 1
        return apply_list

    def _setup_firewall_with_rules(self, func, router_count=1):
        apply_list = self._fake_apply_list(router_count=router_count)
        rule_list = self._fake_rules_v4()
        firewall = self._fake_firewall(rule_list)
        with mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection."
                        "update") as update_fw:
            func('nsx', apply_list, firewall)
            self.assertEqual(router_count, update_fw.call_count)
            update_fw.assert_called_with(
                MOCK_SECTION_ID,
                rules=self._fake_translated_rules() + [self._default_rule()])

    def test_create_firewall_no_rules(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_firewall_no_rule()
        initial_tags = [{'scope': 'xxx', 'tag': 'yyy'}]
        with mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection."
                        "update") as update_fw,\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibLogicalRouter."
                       "update") as update_rtr,\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibLogicalRouter."
                       "get", return_value={'tags': initial_tags}) as get_rtr:
            self.firewall.create_firewall('nsx', apply_list, firewall)
            update_fw.assert_called_once_with(
                MOCK_SECTION_ID,
                rules=[self._default_rule()])
            get_rtr.assert_called_once_with(MOCK_NSX_ID)
            expected_tags = initial_tags
            expected_tags.append({'scope': edge_fwaas_driver.NSX_FW_TAG,
                                  'tag': firewall['id']})
            update_rtr.assert_called_once_with(MOCK_NSX_ID, tags=expected_tags)

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
        initial_tags = [{'scope': 'xxx', 'tag': 'yyy'},
                        {'scope': edge_fwaas_driver.NSX_FW_TAG,
                         'tag': firewall['id']}]
        with mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection."
                        "update") as update_fw,\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibLogicalRouter."
                       "update") as update_rtr,\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibLogicalRouter."
                       "get", return_value={'tags': initial_tags}) as get_rtr:
            self.firewall.delete_firewall('nsx', apply_list, firewall)
            update_fw.assert_called_once_with(
                MOCK_SECTION_ID,
                rules=[self._default_rule(drop=False)])
            get_rtr.assert_called_once_with(MOCK_NSX_ID)
            expected_tags = initial_tags
            expected_tags.pop()
            expected_tags.append({'scope': edge_fwaas_driver.NSX_FW_TAG,
                                  'tag': firewall['id']})
            update_rtr.assert_called_once_with(MOCK_NSX_ID, tags=expected_tags)

    def test_create_firewall_with_admin_down(self):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4()
        firewall = self._fake_firewall_with_admin_down(rule_list)
        with mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection."
                        "update") as update_fw:
            self.firewall.create_firewall('nsx', apply_list, firewall)
            update_fw.assert_called_once_with(
                MOCK_SECTION_ID,
                rules=[self._default_rule()])
