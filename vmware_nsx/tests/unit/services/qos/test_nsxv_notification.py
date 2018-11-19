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
import copy

import mock
from neutron.services.qos import qos_plugin
from neutron.tests.unit.services.qos import base
from neutron_lib import context
from neutron_lib.objects import registry as obj_reg
from neutron_lib.plugins import directory
from neutron_lib.services.qos import constants as qos_consts
from oslo_config import cfg
from oslo_utils import uuidutils

from vmware_nsx.dvs import dvs
from vmware_nsx.dvs import dvs_utils
from vmware_nsx.services.qos.common import utils as qos_com_utils
from vmware_nsx.services.qos.nsx_v import driver as qos_driver
from vmware_nsx.services.qos.nsx_v import utils as qos_utils
from vmware_nsx.tests.unit.nsx_v import test_plugin

CORE_PLUGIN = "vmware_nsx.plugins.nsx_v.plugin.NsxVPluginV2"
QosPolicy = obj_reg.load_class('QosPolicy')
QosPolicyDefault = obj_reg.load_class('QosPolicyDefault')
QosBandwidthLimitRule = obj_reg.load_class('QosBandwidthLimitRule')
QosDscpMarkingRule = obj_reg.load_class('QosDscpMarkingRule')


class TestQosNsxVNotification(test_plugin.NsxVPluginV2TestCase,
                              base.BaseQosTestCase):

    @mock.patch.object(dvs_utils, 'dvs_create_session')
    def setUp(self, *mocks):
        # init the nsx-v plugin for testing with DVS
        self._init_dvs_config()
        # Reset the drive to re-create it
        qos_driver.DRIVER = None
        # Skip Octavia init because of RPC conflicts
        with mock.patch("vmware_nsx.services.lbaas.octavia.octavia_listener."
                        "NSXOctaviaListener.__init__", return_value=None),\
            mock.patch("vmware_nsx.services.lbaas.octavia.octavia_listener."
                       "NSXOctaviaStatisticsCollector.__init__",
                       return_value=None):
            super(TestQosNsxVNotification, self).setUp(plugin=CORE_PLUGIN,
                                                       ext_mgr=None,
                                                       with_md_proxy=False)
        self.setup_coreplugin(CORE_PLUGIN)

        plugin_instance = directory.get_plugin()
        self._core_plugin = plugin_instance
        self._core_plugin.init_is_complete = True

        self.qos_plugin = qos_plugin.QoSPlugin()
        mock.patch.object(qos_utils.NsxVQosRule,
                          '_get_qos_plugin',
                          return_value=self.qos_plugin).start()

        # Pre defined QoS data for the tests
        self.test_tenant_id = '1d7ddf4daf1f47529b5cc93b2e843980'
        self.ctxt = context.Context('fake_user', self.test_tenant_id)

        self.policy_data = {
            'policy': {'id': uuidutils.generate_uuid(),
                       'project_id': self.test_tenant_id,
                       'name': 'test-policy',
                       'description': 'Test policy description',
                       'shared': True}}

        self.rule_data = {
            'bandwidth_limit_rule': {
                'id': uuidutils.generate_uuid(),
                'max_kbps': 100,
                'max_burst_kbps': 150,
                'type': qos_consts.RULE_TYPE_BANDWIDTH_LIMIT}}
        self.ingress_rule_data = {
            'bandwidth_limit_rule': {
                'id': uuidutils.generate_uuid(),
                'max_kbps': 200,
                'max_burst_kbps': 250,
                'direction': 'ingress',
                'type': qos_consts.RULE_TYPE_BANDWIDTH_LIMIT}}
        self.dscp_rule_data = {
            'dscp_marking_rule': {
                'id': uuidutils.generate_uuid(),
                'dscp_mark': 22,
                'type': qos_consts.RULE_TYPE_DSCP_MARKING}}

        self.policy = QosPolicy(
            self.ctxt, **self.policy_data['policy'])

        # egress bw rule
        self.rule = QosBandwidthLimitRule(
            self.ctxt, **self.rule_data['bandwidth_limit_rule'])
        # ingress bw rule
        self.ingress_rule = QosBandwidthLimitRule(
            self.ctxt, **self.ingress_rule_data['bandwidth_limit_rule'])
        # dscp marking rule
        self.dscp_rule = QosDscpMarkingRule(
            self.ctxt, **self.dscp_rule_data['dscp_marking_rule'])

        self._net_data = {'network': {
            'name': 'test-qos',
            'tenant_id': self.test_tenant_id,
            'qos_policy_id': self.policy.id,
            'port_security_enabled': False,
            'admin_state_up': False,
            'shared': False
        }}
        self._rules = [self.rule_data['bandwidth_limit_rule']]
        self._dscp_rules = [self.dscp_rule_data['dscp_marking_rule']]

        mock.patch.object(QosPolicy, 'obj_load_attr').start()

    def _init_dvs_config(self):
        # Ensure that DVS is enabled
        # and enable the DVS features for nsxv qos support
        cfg.CONF.set_override('host_ip', 'fake_ip', group='dvs')
        cfg.CONF.set_override('host_username', 'fake_user', group='dvs')
        cfg.CONF.set_override('host_password', 'fake_password', group='dvs')
        cfg.CONF.set_override('dvs_name', 'fake_dvs', group='dvs')
        cfg.CONF.set_default('use_dvs_features', True, 'nsxv')

    def _create_net(self, net_data=None):
        if net_data is None:
            net_data = self._net_data
            net_data['tenant_id'] = self.test_tenant_id
        with mock.patch('vmware_nsx.services.qos.common.utils.'
                        'get_network_policy_id',
                        return_value=self.policy.id):
            return self._core_plugin.create_network(self.ctxt, net_data)

    @mock.patch.object(qos_com_utils, 'update_network_policy_binding')
    @mock.patch.object(dvs.DvsManager, 'update_port_groups_config')
    def test_create_network_with_policy_rule(self,
                                             dvs_update_mock,
                                             update_bindings_mock):
        """Test the DVS update when a QoS rule is attached to a network"""
        # Create a policy with a rule
        _policy = QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        setattr(_policy, "rules", [self.rule, self.ingress_rule,
                                   self.dscp_rule])

        with mock.patch('neutron.services.qos.qos_plugin.QoSPlugin.'
                        'get_policy',
                        return_value=_policy) as get_rules_mock,\
            mock.patch.object(self.plugin, '_validate_qos_policy_id'):
            # create the network to use this policy
            net = self._create_net()

            # make sure the network-policy binding was updated
            update_bindings_mock.assert_called_once_with(
                self.ctxt, net['id'], self.policy.id)
            # make sure the qos rule was found
            get_rules_mock.assert_called_with(self.ctxt, self.policy.id)
            # make sure the dvs was updated
            self.assertTrue(dvs_update_mock.called)

    @mock.patch.object(qos_com_utils, 'update_network_policy_binding')
    @mock.patch.object(dvs.DvsManager, 'update_port_groups_config')
    def test_create_network_with_default_policy(self,
                                                dvs_update_mock,
                                                update_bindings_mock):
        """Test the DVS update when default policy attached to a network"""
        # Create a default policy with a rule
        policy_data = copy.deepcopy(self.policy_data['policy'])
        policy_data['is_default'] = True
        _policy = QosPolicy(self.ctxt, **policy_data)
        setattr(_policy, "rules", [self.rule, self.dscp_rule])
        default_policy = QosPolicyDefault(
            qos_policy_id=policy_data['id'])

        with mock.patch('neutron.services.qos.qos_plugin.QoSPlugin.'
                        'get_policy',
                        return_value=_policy) as get_rules_mock,\
            mock.patch.object(
                QosPolicyDefault, 'get_object', return_value=default_policy):
            # create the network (with no specific qos policy)
            net_data = copy.deepcopy(self._net_data)
            del net_data['network']['qos_policy_id']
            net = self._create_net(net_data=net_data)

            # make sure the network-policy binding was updated
            update_bindings_mock.assert_called_once_with(
                self.ctxt, net['id'], self.policy.id)
            # make sure the qos rule was found
            get_rules_mock.assert_called_with(self.ctxt, self.policy.id)
            # make sure the dvs was updated
            self.assertTrue(dvs_update_mock.called)

    @mock.patch.object(qos_com_utils, 'update_network_policy_binding')
    @mock.patch.object(dvs.DvsManager, 'update_port_groups_config')
    def _test_rule_action_notification(self, action,
                                       dvs_update_mock,
                                       update_bindings_mock):
        # Create a policy with a rule
        _policy = QosPolicy(
            self.ctxt, **self.policy_data['policy'])

        # set the rule in the policy data
        setattr(_policy, "rules", [self.rule])

        with mock.patch('neutron.services.qos.qos_plugin.QoSPlugin.'
                        'get_policy',
                        return_value=_policy) as get_rules_mock,\
            mock.patch.object(QosPolicy, 'get_object', return_value=_policy):
            # create the network to use this policy
            net = self._create_net()
            dvs_update_mock.called = False
            get_rules_mock.called = False

            with mock.patch('neutron.objects.db.api.create_object',
                    return_value=self.rule_data),\
                mock.patch('neutron.objects.db.api.update_object',
                   return_value=self.rule_data),\
                mock.patch('neutron.objects.db.api.delete_object'),\
                mock.patch.object(_policy, 'get_bound_networks',
                    return_value=[net['id']]),\
                mock.patch.object(self.ctxt.session, 'expunge'):

                # create/update/delete the rule
                if action == 'create':
                    self.qos_plugin.create_policy_bandwidth_limit_rule(
                        self.ctxt, self.policy.id, self.rule_data)
                elif action == 'update':
                    self.qos_plugin.update_policy_bandwidth_limit_rule(
                        self.ctxt, self.rule.id,
                        self.policy.id, self.rule_data)
                else:
                    self.qos_plugin.delete_policy_bandwidth_limit_rule(
                        self.ctxt, self.rule.id, self.policy.id)

                # make sure the qos rule was found
                self.assertTrue(get_rules_mock.called)
                # make sure the dvs was updated
                self.assertTrue(dvs_update_mock.called)

    def test_create_rule_notification(self):
        """Test the DVS update when a QoS rule, attached to a network,
        is created
        """
        self._test_rule_action_notification('create')

    def test_update_rule_notification(self):
        """Test the DVS update when a QoS rule, attached to a network,
        is modified
        """
        self._test_rule_action_notification('update')

    def test_delete_rule_notification(self):
        """Test the DVS update when a QoS rule, attached to a network,
        is deleted
        """
        self._test_rule_action_notification('delete')

    @mock.patch.object(qos_com_utils, 'update_network_policy_binding')
    @mock.patch.object(dvs.DvsManager, 'update_port_groups_config')
    def _test_dscp_rule_action_notification(self, action,
                                            dvs_update_mock,
                                            update_bindings_mock):
        # Create a policy with a rule
        _policy = QosPolicy(
            self.ctxt, **self.policy_data['policy'])

        # set the rule in the policy data
        setattr(_policy, "rules", [self.dscp_rule])
        plugin = self.qos_plugin
        with mock.patch('neutron.services.qos.qos_plugin.QoSPlugin.'
                        'get_policy',
                        return_value=_policy) as rules_mock,\
            mock.patch.object(QosPolicy, 'get_object',
                              return_value=_policy),\
            mock.patch.object(self.ctxt.session, 'expunge'):
            # create the network to use this policy
            net = self._create_net()
            dvs_update_mock.called = False
            rules_mock.called = False

            with mock.patch('neutron.objects.db.api.create_object',
                    return_value=self.dscp_rule_data),\
                mock.patch('neutron.objects.db.api.update_object',
                   return_value=self.dscp_rule_data),\
                mock.patch('neutron.objects.db.api.delete_object'),\
                mock.patch.object(_policy, 'get_bound_networks',
                    return_value=[net['id']]),\
                mock.patch.object(self.ctxt.session, 'expunge'):

                # create/update/delete the rule
                if action == 'create':
                    plugin.create_policy_dscp_marking_rule(
                        self.ctxt,
                        self.policy.id,
                        self.dscp_rule_data)
                elif action == 'update':
                    plugin.update_policy_dscp_marking_rule(
                        self.ctxt,
                        self.dscp_rule.id,
                        self.policy.id,
                        self.dscp_rule_data)
                else:
                    plugin.delete_policy_dscp_marking_rule(
                        self.ctxt,
                        self.dscp_rule.id,
                        self.policy.id)

                # make sure the qos rule was found
                self.assertTrue(rules_mock.called)

                # make sure the dvs was updated
                self.assertTrue(dvs_update_mock.called)

    def test_create_dscp_rule_notification(self):
        """Test the DVS update when a QoS DSCP rule, attached to a network,
        is created
        """
        self._test_dscp_rule_action_notification('create')

    def test_update_dscp_rule_notification(self):
        """Test the DVS update when a QoS DSCP rule, attached to a network,
        is modified
        """
        self._test_dscp_rule_action_notification('update')

    def test_delete_dscp_rule_notification(self):
        """Test the DVS update when a QoS DSCP rule, attached to a network,
        is deleted
        """
        self._test_dscp_rule_action_notification('delete')
