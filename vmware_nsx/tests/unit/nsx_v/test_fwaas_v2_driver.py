# Copyright 2018 VMware, Inc.
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

from vmware_nsx.db import nsxv_models
from vmware_nsx.plugins.nsx_v.vshield import edge_firewall_driver
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.services.fwaas.nsx_v import edge_fwaas_driver_v2
from vmware_nsx.services.fwaas.nsx_v import fwaas_callbacks_v2
from vmware_nsx.tests.unit.nsx_v import test_plugin as test_v_plugin

FAKE_FW_ID = 'fake_fw_uuid'
FAKE_ROUTER_ID = 'fake_rtr_uuid'
FAKE_PORT_ID = 'fake_port_uuid'
FAKE_NET_ID = 'fake_net_uuid'
FAKE_DB_OBJ = nsxv_models.NsxvEdgeVnicBinding(vnic_index='1')


class NsxvFwaasTestCase(test_v_plugin.NsxVPluginV2TestCase):
    def setUp(self):
        super(NsxvFwaasTestCase, self).setUp()
        self.firewall = edge_fwaas_driver_v2.EdgeFwaasVDriverV2()

        self.plugin = directory.get_plugin()
        self.plugin.fwaas_callbacks = fwaas_callbacks_v2.\
            NsxvFwaasCallbacksV2(False)
        self.plugin.fwaas_callbacks.fwaas_enabled = True
        self.plugin.fwaas_callbacks.fwaas_driver = self.firewall
        self.plugin.fwaas_callbacks.internal_driver = self.firewall
        self.plugin.init_is_complete = True
        self.plugin.metadata_proxy_handler = None

        # Start some mocks
        self.router = {'id': FAKE_ROUTER_ID,
                       'external_gateway_info': {'network_id': 'external'}}
        mock.patch.object(self.plugin, '_get_router',
                          return_value=self.router).start()
        mock.patch.object(self.plugin, 'get_router',
                          return_value=self.router).start()
        self.port = {'id': FAKE_PORT_ID, 'network_id': FAKE_NET_ID}
        mock.patch.object(self.plugin, '_get_router_interfaces',
                          return_value=[self.port]).start()
        mock.patch.object(self.plugin, 'get_port',
                          return_value=self.port).start()
        mock.patch.object(self.plugin, '_get_subnet_fw_rules',
                          return_value=[]).start()
        mock.patch.object(self.plugin, '_get_dnat_fw_rule',
                          return_value=[]).start()
        mock.patch.object(self.plugin, '_get_allocation_pools_fw_rule',
                          return_value=[]).start()
        mock.patch.object(self.plugin, '_get_nosnat_subnets_fw_rules',
                          return_value=[]).start()

    def _fake_rules_v4(self, is_ingress=True, is_conflict=False,
                       cidr='10.24.4.0/24'):
        rule1 = {'enabled': True,
                 'action': 'allow',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '80',
                 'id': 'fake-fw-rule1',
                 'description': 'first rule',
                 'position': '0'}
        rule2 = {'enabled': True,
                 'action': 'reject',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '22:24',
                 'source_port': '1:65535',
                 'id': 'fake-fw-rule2',
                 'position': '1'}
        rule3 = {'enabled': True,
                 'action': 'deny',
                 'ip_version': 4,
                 'protocol': 'icmp',
                 'id': 'fake-fw-rule3',
                 'position': '2'}
        rule4 = {'enabled': True,
                 'action': 'deny',
                 'ip_version': 4,
                 'id': 'fake-fw-rule4',
                 'position': '3'}
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

    def _fake_translated_rules(self, rules_list,
                               nsx_port_id,
                               is_ingress=True,
                               logged=False):
        translated_rules = copy.copy(rules_list)
        for rule in translated_rules:
            if logged:
                rule['logged'] = True
            if is_ingress:
                if not rule.get('destination_ip_address'):
                    rule['destination_vnic_groups'] = ['vnic-index-1']
            else:
                if not rule.get('source_ip_address'):
                    rule['source_vnic_groups'] = ['vnic-index-1']
            if rule.get('destination_ip_address'):
                rule['destination_ip_address'] = [
                    rule['destination_ip_address']]
            if rule.get('source_ip_address'):
                rule['source_ip_address'] = [
                    rule['source_ip_address']]
            rule['name'] = (fwaas_callbacks_v2.RULE_NAME_PREFIX +
                            (rule.get('name') or rule['id']))[:30]
            if rule.get('id'):
                if is_ingress:
                    rule['id'] = ('ingress-%s' % rule['id'])[:36]
                else:
                    rule['id'] = ('egress-%s' % rule['id'])[:36]

        return translated_rules

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
        router_inst = self.router
        router_info_inst = mock.Mock()
        router_info_inst.router = router_inst
        router_info_inst.router_id = FAKE_ROUTER_ID
        apply_list = [(router_info_inst, FAKE_PORT_ID)]
        return apply_list

    def test_create_firewall_no_rules(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_empty_firewall_group()
        with mock.patch.object(self.plugin.fwaas_callbacks, 'get_port_fwg',
                              return_value=firewall),\
            mock.patch.object(self.plugin.fwaas_callbacks,
                              '_get_port_firewall_group_id',
                              return_value=FAKE_FW_ID),\
            mock.patch.object(self.plugin.fwaas_callbacks,
                              '_get_fw_group_from_plugin',
                              return_value=firewall),\
            mock.patch("vmware_nsx.db.nsxv_db.get_edge_vnic_binding",
                       return_value=FAKE_DB_OBJ),\
            mock.patch.object(edge_utils, "update_firewall") as update_fw,\
            mock.patch.object(edge_utils, 'get_router_edge_id',
                              return_value='edge-1'):
            self.firewall.create_firewall_group('nsx', apply_list, firewall)
            # expecting 2 block rules for the logical port (egress & ingress)
            # and last default allow all rule
            expected_rules = [
                {'name': "Block port ingress",
                 'action': edge_firewall_driver.FWAAS_DENY,
                 'destination_vnic_groups': ['vnic-index-1'],
                 'logged': False},
                {'name': "Block port egress",
                 'action': edge_firewall_driver.FWAAS_DENY,
                 'source_vnic_groups': ['vnic-index-1'],
                 'logged': False}]
            update_fw.assert_called_once_with(
                self.plugin.nsx_v, mock.ANY, FAKE_ROUTER_ID,
                {'firewall_rule_list': expected_rules})

    def _setup_firewall_with_rules(self, func, is_ingress=True,
                                   is_conflict=False):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4(is_ingress=is_ingress,
                                        is_conflict=is_conflict)
        firewall = self._fake_firewall_group(rule_list, is_ingress=is_ingress)
        with mock.patch.object(self.plugin.fwaas_callbacks, 'get_port_fwg',
                              return_value=firewall),\
            mock.patch.object(self.plugin.fwaas_callbacks,
                              '_get_port_firewall_group_id',
                              return_value=FAKE_FW_ID),\
            mock.patch.object(self.plugin.fwaas_callbacks,
                              '_get_fw_group_from_plugin',
                              return_value=firewall),\
            mock.patch("vmware_nsx.db.nsxv_db.get_edge_vnic_binding",
                       return_value=FAKE_DB_OBJ),\
            mock.patch.object(edge_utils, "update_firewall") as update_fw,\
            mock.patch.object(edge_utils, 'get_router_edge_id',
                              return_value='edge-1'):
            func('nsx', apply_list, firewall)
            expected_rules = self._fake_translated_rules(
                rule_list,
                'vnic-index-1', is_ingress=is_ingress) + [
                {'name': "Block port ingress",
                 'action': edge_firewall_driver.FWAAS_DENY,
                 'destination_vnic_groups': ['vnic-index-1'],
                 'logged': False},
                {'name': "Block port egress",
                 'action': edge_firewall_driver.FWAAS_DENY,
                 'source_vnic_groups': ['vnic-index-1'],
                 'logged': False}]

            update_fw.assert_called_once_with(
                self.plugin.nsx_v, mock.ANY, FAKE_ROUTER_ID,
                {'firewall_rule_list': expected_rules})

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

    def test_update_firewall_with_egress_conflicting_rules(self):
        self._setup_firewall_with_rules(self.firewall.update_firewall_group,
                                        is_ingress=False, is_conflict=True)

    def test_update_firewall_with_ingress_conflicting_rules(self):
        self._setup_firewall_with_rules(self.firewall.update_firewall_group,
                                        is_ingress=True, is_conflict=True)

    def test_delete_firewall(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_empty_firewall_group()
        with mock.patch.object(self.plugin.fwaas_callbacks, 'get_port_fwg',
                              return_value=None),\
            mock.patch("vmware_nsx.db.db.get_nsx_switch_and_port_id",
                       return_value=('vnic-index-1', 0)),\
            mock.patch.object(edge_utils, "update_firewall") as update_fw,\
            mock.patch.object(edge_utils, 'get_router_edge_id',
                              return_value='edge-1'):
            self.firewall.delete_firewall_group('nsx', apply_list, firewall)
            update_fw.assert_called_once_with(
                self.plugin.nsx_v, mock.ANY, FAKE_ROUTER_ID,
                {'firewall_rule_list': []})

    def test_create_firewall_with_admin_down(self):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4()
        firewall = self._fake_firewall_group_with_admin_down(rule_list)
        with mock.patch.object(edge_utils, "update_firewall") as update_fw,\
            mock.patch.object(edge_utils, 'get_router_edge_id',
                              return_value='edge-1'):
            self.firewall.create_firewall_group('nsx', apply_list, firewall)
            update_fw.assert_called_once_with(
                self.plugin.nsx_v, mock.ANY, FAKE_ROUTER_ID,
                {'firewall_rule_list': []})
