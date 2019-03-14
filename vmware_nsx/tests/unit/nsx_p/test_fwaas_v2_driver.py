# Copyright 2019 VMware, Inc.
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

from neutron_lib.api.definitions import constants as fwaas_consts
from neutron_lib.plugins import directory
from oslo_utils import uuidutils

from vmware_nsx.services.fwaas.nsx_p import edge_fwaas_driver_v2
from vmware_nsx.services.fwaas.nsx_p import fwaas_callbacks_v2
from vmware_nsx.tests.unit.nsx_p import test_plugin as test_p_plugin
from vmware_nsxlib.v3 import nsx_constants as consts

FAKE_FW_ID = 'fake_fw_uuid'
FAKE_ROUTER_ID = 'fake_rtr_uuid'
FAKE_PORT_ID = 'fake_port_uuid'
FAKE_NET_ID = 'fake_net_uuid'
GW_POLICY_PATH = ("vmware_nsxlib.v3.policy.core_resources."
                  "NsxPolicyGatewayPolicyApi")


class NsxpFwaasTestCase(test_p_plugin.NsxPPluginTestCaseMixin):
    def setUp(self):
        super(NsxpFwaasTestCase, self).setUp()
        self.firewall = edge_fwaas_driver_v2.EdgeFwaasPDriverV2()

        self.project_id = uuidutils.generate_uuid()
        self.plugin = directory.get_plugin()
        self.plugin.fwaas_callbacks = fwaas_callbacks_v2.NsxpFwaasCallbacksV2(
            False)
        self.plugin.fwaas_callbacks.fwaas_enabled = True
        self.plugin.fwaas_callbacks.fwaas_driver = self.firewall
        self.plugin.fwaas_callbacks.internal_driver = self.firewall
        self.plugin.init_is_complete = True

        def mock_get_random_rule_id(rid):
            return rid

        mock.patch.object(self.plugin.fwaas_callbacks, '_get_random_rule_id',
                          side_effect=mock_get_random_rule_id).start()

        mock.patch.object(self.plugin.nsxpolicy, 'search_by_tags',
                          return_value={'results': []}).start()

    def _default_rule(self, seq_num):
        return self.plugin.nsxpolicy.gateway_policy.build_entry(
                fwaas_callbacks_v2.DEFAULT_RULE_NAME,
                self.project_id, FAKE_ROUTER_ID,
                fwaas_callbacks_v2.DEFAULT_RULE_ID,
                description=fwaas_callbacks_v2.DEFAULT_RULE_NAME,
                action=consts.FW_ACTION_ALLOW,
                scope=[self.plugin.nsxpolicy.tier1.get_path(FAKE_ROUTER_ID)],
                sequence_number=seq_num,
                direction=consts.IN_OUT).get_obj_dict()

    def _block_interface_rules(self, seq_num):
        net_group_id = '%s-%s' % (FAKE_ROUTER_ID, FAKE_NET_ID)
        ingress_rule = self.plugin.nsxpolicy.gateway_policy.build_entry(
                "Block port ingress",
                self.project_id, FAKE_ROUTER_ID,
                fwaas_callbacks_v2.DEFAULT_RULE_ID + FAKE_NET_ID + 'ingress',
                action=consts.FW_ACTION_DROP,
                dest_groups=[net_group_id],
                scope=[self.plugin.nsxpolicy.tier1.get_path(FAKE_ROUTER_ID)],
                sequence_number=seq_num,
                direction=consts.IN)

        egress_rule = self.plugin.nsxpolicy.gateway_policy.build_entry(
                "Block port egress",
                self.project_id, FAKE_ROUTER_ID,
                fwaas_callbacks_v2.DEFAULT_RULE_ID + FAKE_NET_ID + 'egress',
                action=consts.FW_ACTION_DROP,
                source_groups=[net_group_id],
                scope=[self.plugin.nsxpolicy.tier1.get_path(FAKE_ROUTER_ID)],
                sequence_number=seq_num + 1,
                direction=consts.OUT)

        return [ingress_rule.get_obj_dict(), egress_rule.get_obj_dict()]

    def _fake_rules_v4(self, is_ingress=True, cidr='10.24.4.0/24',
                       is_conflict=False):
        rule1 = {'enabled': True,
                 'action': 'allow',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '80',
                 'id': 'fake-fw-rule1',
                 'description': 'first rule'}
        rule2 = {'name': 'rule 2',
                 'enabled': True,
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

    def _validate_rules_translation(self, actual_rules, rule_list, is_ingress):
        for index in range(len(rule_list)):
            self._validate_rule_translation(
                actual_rules[index].get_obj_dict(),
                rule_list[index],
                is_ingress)

    def _validate_rule_translation(self, nsx_rule, fw_rule, is_ingress):
        self.assertEqual(fw_rule['id'], nsx_rule['id'])
        self.assertEqual(fwaas_callbacks_v2.RULE_NAME_PREFIX +
                         (fw_rule.get('name') or fw_rule['id']),
                         nsx_rule['display_name'])
        self.assertEqual(fw_rule.get('description'), nsx_rule['description'])
        self.assertEqual(consts.IN if is_ingress else consts.OUT,
                         nsx_rule['direction'])
        self.assertEqual(self.plugin.nsxpolicy.tier1.get_path(FAKE_ROUTER_ID),
                         nsx_rule['scope'][0])

        # Action
        if (fw_rule['action'] == fwaas_consts.FWAAS_REJECT or
            fw_rule['action'] == fwaas_consts.FWAAS_DENY):
            self.assertEqual(consts.FW_ACTION_DROP, nsx_rule['action'])
        else:
            self.assertEqual(consts.FW_ACTION_ALLOW, nsx_rule['action'])

        # Service
        if fw_rule.get('protocol') in ['tcp', 'udp', 'icmp']:
            self.assertEqual(['/infra/services/%s-%s-%s' % (
                                fw_rule['protocol'], FAKE_ROUTER_ID,
                                fw_rule['id'])],
                             nsx_rule['services'])
        # Source & destination
        if (fw_rule.get('source_ip_address') and
            not fw_rule['source_ip_address'].startswith('0.0.0.0')):
            self.assertEqual(['/infra/domains/%s/groups/source-%s' % (
                                self.project_id, fw_rule['id'])],
                             nsx_rule['source_groups'])
        elif not is_ingress:
            self.assertEqual(['/infra/domains/%s/groups/%s-%s' % (
                                self.project_id, FAKE_ROUTER_ID, FAKE_NET_ID)],
                             nsx_rule['source_groups'])

        if (fw_rule.get('destination_ip_address') and
            not fw_rule['destination_ip_address'].startswith('0.0.0.0')):
            self.assertEqual(['/infra/domains/%s/groups/destination-%s' % (
                                self.project_id, fw_rule['id'])],
                             nsx_rule['destination_groups'])
        elif is_ingress:
            self.assertEqual(['/infra/domains/%s/groups/%s-%s' % (
                                self.project_id, FAKE_ROUTER_ID, FAKE_NET_ID)],
                             nsx_rule['destination_groups'])

    def _fake_empty_firewall_group(self):
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': True,
                   'tenant_id': self.project_id,
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
                   'tenant_id': self.project_id,
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
            mock.patch.object(self.plugin.fwaas_callbacks, 'get_port_fwg',
                              return_value=firewall),\
            mock.patch.object(self.plugin, '_get_router',
                              return_value={'project_id': self.project_id}),\
            mock.patch.object(self.plugin, 'service_router_has_services',
                              return_value=True),\
            mock.patch(GW_POLICY_PATH + ".update_entries") as update_fw:
            self.firewall.create_firewall_group('nsx', apply_list, firewall)
            # expecting 2 block rules for the logical switch (egress & ingress)
            # and last default allow all rule
            expected_rules = (self._block_interface_rules(0) +
                              [self._default_rule(2)])
            update_fw.assert_called_once_with(
                self.project_id, FAKE_ROUTER_ID, mock.ANY)
            # compare rules one by one
            actual_rules = update_fw.call_args[0][2]
            self.assertEqual(len(expected_rules), len(actual_rules))
            for index in range(len(actual_rules)):
                self.assertEqual(expected_rules[index],
                                 actual_rules[index].get_obj_dict())

    def _setup_firewall_with_rules(self, func, is_ingress=True,
                                   is_conflict=False, cidr='10.24.4.0/24'):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4(is_ingress=is_ingress,
                                        is_conflict=is_conflict,
                                        cidr=cidr)
        firewall = self._fake_firewall_group(rule_list, is_ingress=is_ingress)
        port = {'id': FAKE_PORT_ID, 'network_id': FAKE_NET_ID}
        with mock.patch.object(self.plugin, '_get_router_interfaces',
                               return_value=[port]),\
            mock.patch.object(self.plugin.fwaas_callbacks, 'get_port_fwg',
                              return_value=firewall), \
            mock.patch.object(self.plugin, '_get_router',
                              return_value={'project_id': self.project_id}),\
            mock.patch.object(self.plugin, 'service_router_has_services',
                              return_value=True), \
            mock.patch(GW_POLICY_PATH + ".update_entries") as update_fw:
            func('nsx', apply_list, firewall)
            expected_default_rules = self._block_interface_rules(
                len(rule_list)) + [self._default_rule(len(rule_list) + 2)]
            update_fw.assert_called_once_with(
                self.project_id, FAKE_ROUTER_ID, mock.ANY)

            # compare rules one by one
            actual_rules = update_fw.call_args[0][2]
            self.assertEqual(len(rule_list) + 3, len(actual_rules))
            self._validate_rules_translation(
                actual_rules,
                rule_list,
                is_ingress)
            # compare the last 3 rules (default interface rules +
            # default allow rule)
            self.assertEqual(actual_rules[-3].get_obj_dict(),
                             expected_default_rules[0])
            self.assertEqual(actual_rules[-2].get_obj_dict(),
                             expected_default_rules[1])
            self.assertEqual(actual_rules[-1].get_obj_dict(),
                             expected_default_rules[2])

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
        self._setup_firewall_with_rules(self.firewall.create_firewall_group,
                                        cidr='0.0.0.0/24')

    def test_delete_firewall(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_empty_firewall_group()
        port = {'id': FAKE_PORT_ID}
        with mock.patch.object(self.plugin, '_get_router_interfaces',
                               return_value=[port]),\
            mock.patch.object(self.plugin.fwaas_callbacks, 'get_port_fwg',
                              return_value=None), \
            mock.patch.object(self.plugin, '_get_router',
                              return_value={'project_id': self.project_id}),\
            mock.patch.object(self.plugin, 'service_router_has_services',
                              return_value=True), \
            mock.patch(GW_POLICY_PATH + ".update_entries") as update_fw:
            self.firewall.delete_firewall_group('nsx', apply_list, firewall)

            # expecting only the default allow-all rule
            expected_rules = [self._default_rule(0)]
            update_fw.assert_called_once_with(
                self.project_id, FAKE_ROUTER_ID, mock.ANY)
            # compare rules one by one
            actual_rules = update_fw.call_args[0][2]
            self.assertEqual(len(expected_rules), len(actual_rules))
            for index in range(len(actual_rules)):
                self.assertEqual(expected_rules[index],
                                 actual_rules[index].get_obj_dict())

    def test_create_firewall_with_admin_down(self):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4()
        firewall = self._fake_firewall_group_with_admin_down(rule_list)
        with mock.patch.object(self.plugin, 'service_router_has_services',
                               return_value=True), \
            mock.patch.object(self.plugin, '_get_router',
                              return_value={'project_id': self.project_id}),\
            mock.patch(GW_POLICY_PATH + ".update_entries") as update_fw:
            self.firewall.create_firewall_group('nsx', apply_list, firewall)

            # expecting only the default allow-all rule
            expected_rules = [self._default_rule(0)]
            update_fw.assert_called_once_with(
                self.project_id, FAKE_ROUTER_ID, mock.ANY)
            # compare rules one by one
            actual_rules = update_fw.call_args[0][2]
            self.assertEqual(len(expected_rules), len(actual_rules))
            for index in range(len(actual_rules)):
                self.assertEqual(expected_rules[index],
                                 actual_rules[index].get_obj_dict())
