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

from neutron_lib.plugins import directory

from vmware_nsx.services.fwaas.nsx_v3 import edge_fwaas_driver_v2
from vmware_nsx.services.fwaas.nsx_v3 import fwaas_callbacks_v2
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_v3_plugin
from vmware_nsxlib.v3 import nsx_constants as consts

FAKE_FW_ID = 'fake_fw_uuid'
FAKE_ROUTER_ID = 'fake_rtr_uuid'
FAKE_PORT_ID = 'fake_port_uuid'
FAKE_NET_ID = 'fake_net_uuid'
FAKE_NSX_LS_ID = 'fake_nsx_ls_uuid'
MOCK_NSX_ID = 'nsx_nsx_router_id'
MOCK_DEFAULT_RULE_ID = 'nsx_default_rule_id'
MOCK_SECTION_ID = 'sec_id'
DEFAULT_RULE = {'is_default': True,
                'display_name': edge_fwaas_driver_v2.DEFAULT_RULE_NAME,
                'id': MOCK_DEFAULT_RULE_ID,
                'action': consts.FW_ACTION_DROP}


class Nsxv3FwaasTestCase(test_v3_plugin.NsxV3PluginTestCaseMixin):
    def setUp(self):
        super(Nsxv3FwaasTestCase, self).setUp()
        self.firewall = edge_fwaas_driver_v2.EdgeFwaasV3DriverV2()

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

        self.plugin = directory.get_plugin()
        self.plugin.fwaas_callbacks = fwaas_callbacks_v2.\
            Nsxv3FwaasCallbacksV2(False)
        self.plugin.fwaas_callbacks.fwaas_enabled = True
        self.plugin.fwaas_callbacks.fwaas_driver = self.firewall
        self.plugin.fwaas_callbacks.internal_driver = self.firewall
        self.plugin.init_is_complete = True

    def _default_rule(self):
        rule = DEFAULT_RULE
        rule['action'] = consts.FW_ACTION_ALLOW
        return rule

    def _fake_rules_v4(self, is_ingress=True, cidr='10.24.4.0/24',
                       is_conflict=False):
        rule1 = {'enabled': True,
                 'action': 'allow',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '80',
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
                 'id': 'fake-fw-rule4'}
        if is_ingress:
            if not is_conflict:
                rule1['source_ip_address'] = cidr
            else:
                rule1['destination_ip_address'] = cidr
        else:
            if not is_conflict:
                rule1['destination_ip_address'] = cidr
            else:
                rule1['source_ip_address'] = cidr

        return [rule1, rule2, rule3, rule4]

    def _translated_cidr(self, cidr):
        if cidr is None:
            return []
        else:
            return [{'target_id': cidr,
                     'target_type': 'IPv4Address'}]

    def _fake_translated_rules(self, nsx_port_id, cidr='10.24.4.0/24',
                               is_ingress=True, is_conflict=False,
                               logged=False):
        # The expected translation of the rules in _fake_rules_v4
        service1 = {'l4_protocol': 'TCP',
                    'resource_type': 'L4PortSetNSService',
                    'destination_ports': ['80'],
                    'source_ports': []}
        rule1 = {'action': 'ALLOW',
                 'services': [{'service': service1}],
                 'sources': self._translated_cidr(cidr),
                 'display_name': 'Fwaas-fake-fw-rule1',
                 'notes': 'first rule'}
        if ((is_ingress and is_conflict) or
            (not is_ingress and not is_conflict)):
            # Swap ips
            rule1['destinations'] = rule1['sources']
            del rule1['sources']
        if 'sources' in rule1 and not rule1['sources']:
            del rule1['sources']
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
                 'display_name': 'Fwaas-fake-fw-rule4'}

        if nsx_port_id:
            if is_ingress:
                field = 'destinations'
                direction = 'IN'
            else:
                field = 'sources'
                direction = 'OUT'
            new_val = [{'target_id': nsx_port_id,
                        'target_type': 'LogicalSwitch'}]
            for rule in (rule1, rule2, rule3, rule4):
                if not rule.get(field):
                    rule[field] = new_val
                rule['direction'] = direction
        if logged:
            for rule in (rule1, rule2, rule3, rule4):
                rule['logged'] = logged
        return [rule1, rule2, rule3, rule4]

    def _fake_empty_firewall_group(self):
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': True,
                   'tenant_id': 'tenant-uuid',
                   'ingress_rule_list': [],
                   'egress_rule_list': []}
        return fw_inst

    def _fake_firewall_group(self, rule_list, is_ingress=True,
                             admin_state_up=True):
        _rule_list = copy.deepcopy(rule_list)
        for rule in _rule_list:
            rule['position'] = str(_rule_list.index(rule))
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': admin_state_up,
                   'tenant_id': 'tenant-uuid',
                   'ingress_rule_list': [],
                   'egress_rule_list': []}
        if is_ingress:
            fw_inst['ingress_rule_list'] = _rule_list
        else:
            fw_inst['egress_rule_list'] = _rule_list
        return fw_inst

    def _fake_firewall_group_with_admin_down(self, rule_list,
                                             is_ingress=True):
        return self._fake_firewall_group(
            rule_list, is_ingress=is_ingress, admin_state_up=False)

    def _fake_apply_list(self):
        router_inst = {'id': FAKE_ROUTER_ID, 'external_gateway_info': 'dummy'}
        router_info_inst = mock.Mock()
        router_info_inst.router = router_inst
        router_info_inst.router_id = FAKE_ROUTER_ID
        apply_list = [(router_info_inst, FAKE_PORT_ID)]
        return apply_list

    def test_create_firewall_no_rules(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_empty_firewall_group()
        port = {'id': FAKE_PORT_ID, 'network_id': FAKE_NET_ID}
        with mock.patch.object(self.plugin, '_get_router_interfaces',
                               return_value=[port]),\
            mock.patch.object(self.plugin, 'get_port',
                              return_value=port),\
            mock.patch.object(self.plugin.fwaas_callbacks, 'get_port_fwg',
                              return_value=firewall),\
            mock.patch.object(self.plugin, 'service_router_has_services',
                              return_value=True),\
            mock.patch("vmware_nsx.db.db.get_nsx_switch_and_port_id",
                       return_value=(FAKE_NSX_LS_ID, 0)),\
            mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection."
                       "update") as update_fw:
            self.firewall.create_firewall_group('nsx', apply_list, firewall)
            # expecting 2 block rules for the logical port (egress & ingress)
            # and last default allow all rule
            expected_rules = [
                {'display_name': "Block port ingress",
                 'action': consts.FW_ACTION_DROP,
                 'destinations': [{'target_type': 'LogicalSwitch',
                                   'target_id': FAKE_NSX_LS_ID}],
                 'direction': 'IN'},
                {'display_name': "Block port egress",
                 'action': consts.FW_ACTION_DROP,
                 'sources': [{'target_type': 'LogicalSwitch',
                              'target_id': FAKE_NSX_LS_ID}],
                 'direction': 'OUT'},
                self._default_rule()
            ]
            update_fw.assert_called_once_with(
                MOCK_SECTION_ID,
                rules=expected_rules)

    def _setup_firewall_with_rules(self, func, is_ingress=True,
                                   is_conflict=False):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4(is_ingress=is_ingress,
                                        is_conflict=is_conflict)
        firewall = self._fake_firewall_group(rule_list, is_ingress=is_ingress)
        port = {'id': FAKE_PORT_ID, 'network_id': FAKE_NET_ID}
        with mock.patch.object(self.plugin, '_get_router_interfaces',
                               return_value=[port]),\
            mock.patch.object(self.plugin, 'get_port',
                              return_value=port),\
            mock.patch.object(self.plugin.fwaas_callbacks, 'get_port_fwg',
                              return_value=firewall), \
            mock.patch.object(self.plugin, 'service_router_has_services',
                              return_value=True), \
            mock.patch("vmware_nsx.db.db.get_nsx_switch_and_port_id",
                       return_value=(FAKE_NSX_LS_ID, 0)),\
            mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection."
                       "update") as update_fw:
            func('nsx', apply_list, firewall)
            expected_rules = self._fake_translated_rules(
                FAKE_NSX_LS_ID, is_ingress=is_ingress,
                is_conflict=is_conflict) + [
                {'display_name': "Block port ingress",
                 'action': consts.FW_ACTION_DROP,
                 'destinations': [{'target_type': 'LogicalSwitch',
                                   'target_id': FAKE_NSX_LS_ID}],
                 'direction': 'IN'},
                {'display_name': "Block port egress",
                 'action': consts.FW_ACTION_DROP,
                 'sources': [{'target_type': 'LogicalSwitch',
                              'target_id': FAKE_NSX_LS_ID}],
                 'direction': 'OUT'},
                self._default_rule()
            ]
            update_fw.assert_called_once_with(
                MOCK_SECTION_ID,
                rules=expected_rules)

    def test_create_firewall_with_ingress_rules(self):
        self._setup_firewall_with_rules(self.firewall.create_firewall_group)

    def test_update_firewall_with_ingress_rules(self):
        self._setup_firewall_with_rules(self.firewall.update_firewall_group)

    def test_create_firewall_with_egress_rules(self):
        self._setup_firewall_with_rules(self.firewall.create_firewall_group,
                                        is_ingress=False)

    def test_update_firewall_with_egress_rules(self):
        self._setup_firewall_with_rules(self.firewall.update_firewall_group,
                                        is_ingress=False)

    def test_create_firewall_with_egress_conflicting_rules(self):
        self._setup_firewall_with_rules(self.firewall.update_firewall_group,
                                        is_ingress=False, is_conflict=True)

    def test_create_firewall_with_ingress_conflicting_rules(self):
        self._setup_firewall_with_rules(self.firewall.update_firewall_group,
                                        is_ingress=True, is_conflict=True)

    def test_create_firewall_with_illegal_cidr(self):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4(cidr='0.0.0.0/24')
        firewall = self._fake_firewall_group(rule_list)
        port = {'id': FAKE_PORT_ID, 'network_id': FAKE_NET_ID}
        with mock.patch.object(self.plugin, '_get_router_interfaces',
                               return_value=[port]),\
            mock.patch.object(self.plugin, 'get_port',
                              return_value=port), \
            mock.patch.object(self.plugin, 'service_router_has_services',
                              return_value=True), \
            mock.patch.object(self.plugin.fwaas_callbacks, 'get_port_fwg',
                              return_value=firewall),\
            mock.patch("vmware_nsx.db.db.get_nsx_switch_and_port_id",
                       return_value=(FAKE_NSX_LS_ID, 0)),\
            mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection."
                       "update") as update_fw:
            self.firewall.create_firewall_group('nsx', apply_list, firewall)
            expected_rules = self._fake_translated_rules(
                FAKE_NSX_LS_ID, cidr=None) + [
                {'display_name': "Block port ingress",
                 'action': consts.FW_ACTION_DROP,
                 'destinations': [{'target_type': 'LogicalSwitch',
                                   'target_id': FAKE_NSX_LS_ID}],
                 'direction': 'IN'},
                {'display_name': "Block port egress",
                 'action': consts.FW_ACTION_DROP,
                 'sources': [{'target_type': 'LogicalSwitch',
                              'target_id': FAKE_NSX_LS_ID}],
                 'direction': 'OUT'},
                self._default_rule()
            ]
            update_fw.assert_called_once_with(
                MOCK_SECTION_ID,
                rules=expected_rules)

    def test_delete_firewall(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_empty_firewall_group()
        port = {'id': FAKE_PORT_ID}
        with mock.patch.object(self.plugin, '_get_router_interfaces',
                               return_value=[port]),\
            mock.patch.object(self.plugin.fwaas_callbacks, 'get_port_fwg',
                              return_value=None), \
            mock.patch.object(self.plugin, 'service_router_has_services',
                              return_value=True), \
            mock.patch("vmware_nsx.db.db.get_nsx_switch_and_port_id",
                       return_value=(FAKE_NSX_LS_ID, 0)),\
            mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection."
                       "update") as update_fw:
            self.firewall.delete_firewall_group('nsx', apply_list, firewall)
            update_fw.assert_called_once_with(
                MOCK_SECTION_ID,
                rules=[self._default_rule()])

    def test_create_firewall_with_admin_down(self):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4()
        firewall = self._fake_firewall_group_with_admin_down(rule_list)
        with mock.patch.object(self.plugin, 'service_router_has_services',
                               return_value=True), \
                mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection"
                           ".update") as update_fw:
            self.firewall.create_firewall_group('nsx', apply_list, firewall)
            update_fw.assert_called_once_with(
                MOCK_SECTION_ID,
                rules=[self._default_rule()])

    def test_create_firewall_with_dhcp_relay(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_empty_firewall_group()
        port = {'id': FAKE_PORT_ID, 'network_id': FAKE_NET_ID}
        relay_server = '1.1.1.1'
        with mock.patch.object(self.plugin, '_get_router_interfaces',
                               return_value=[port]),\
            mock.patch.object(self.plugin, 'get_port',
                              return_value=port),\
            mock.patch.object(self.plugin, '_get_port_relay_servers',
                              return_value=[relay_server]),\
            mock.patch.object(self.plugin.fwaas_callbacks, 'get_port_fwg',
                              return_value=firewall), \
            mock.patch.object(self.plugin, 'service_router_has_services',
                              return_value=True), \
            mock.patch("vmware_nsx.db.db.get_nsx_switch_and_port_id",
                       return_value=(FAKE_NSX_LS_ID, 0)),\
            mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection."
                       "update") as update_fw:
            self.firewall.create_firewall_group('nsx', apply_list, firewall)
            # expecting 2 allow rules for the relay servers,
            # 2 block rules for the logical port (egress & ingress)
            # and last default allow all rule
            expected_rules = [
                {'display_name': "DHCP Relay ingress traffic",
                 'action': consts.FW_ACTION_ALLOW,
                 'destinations': [{'target_type': 'LogicalSwitch',
                                   'target_id': FAKE_NSX_LS_ID}],
                 'sources': [{'target_id': relay_server,
                              'target_type': 'IPv4Address'}],
                 'services': self.plugin._get_port_relay_services(),
                 'direction': 'IN'},
                {'display_name': "DHCP Relay egress traffic",
                 'action': consts.FW_ACTION_ALLOW,
                 'sources': [{'target_type': 'LogicalSwitch',
                              'target_id': FAKE_NSX_LS_ID}],
                 'destinations': [{'target_id': relay_server,
                                   'target_type': 'IPv4Address'}],
                 'services': self.plugin._get_port_relay_services(),
                 'direction': 'OUT'},
                {'display_name': "Block port ingress",
                 'action': consts.FW_ACTION_DROP,
                 'destinations': [{'target_type': 'LogicalSwitch',
                                   'target_id': FAKE_NSX_LS_ID}],
                 'direction': 'IN'},
                {'display_name': "Block port egress",
                 'action': consts.FW_ACTION_DROP,
                 'sources': [{'target_type': 'LogicalSwitch',
                              'target_id': FAKE_NSX_LS_ID}],
                 'direction': 'OUT'},
                self._default_rule()
            ]
            update_fw.assert_called_once_with(
                MOCK_SECTION_ID,
                rules=expected_rules)
