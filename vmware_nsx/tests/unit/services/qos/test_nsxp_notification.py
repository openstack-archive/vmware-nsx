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

from neutron_lib import context
from neutron_lib import exceptions
from neutron_lib.objects import registry as obj_reg
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.services.qos import qos_plugin
from neutron.tests.unit.services.qos import base

from vmware_nsx.common import utils
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils
from vmware_nsx.services.qos.nsx_v3 import driver as qos_driver
from vmware_nsx.services.qos.nsx_v3 import pol_utils as qos_utils
from vmware_nsx.tests.unit.nsx_p import test_plugin
from vmware_nsxlib.v3.policy import core_defs as policy_defs

PLUGIN_NAME = 'vmware_nsx.plugins.nsx_p.plugin.NsxPolicyPlugin'
QoSPolicy = obj_reg.load_class('QosPolicy')
QosBandwidthLimitRule = obj_reg.load_class('QosBandwidthLimitRule')
QosDscpMarkingRule = obj_reg.load_class('QosDscpMarkingRule')
QosMinimumBandwidthRule = obj_reg.load_class('QosMinimumBandwidthRule')


class TestQosNsxPNotification(base.BaseQosTestCase,
                              test_plugin.NsxPPluginTestCaseMixin):

    def setUp(self):
        # Reset the drive to re-create it
        qos_driver.DRIVER = None
        super(TestQosNsxPNotification, self).setUp()
        self.setup_coreplugin(PLUGIN_NAME)

        self.qos_plugin = qos_plugin.QoSPlugin()
        self.ctxt = context.Context('fake_user', 'fake_tenant')
        mock.patch.object(self.ctxt.session, 'refresh').start()
        mock.patch.object(self.ctxt.session, 'expunge').start()
        policy_id = uuidutils.generate_uuid()
        self.project_id = uuidutils.generate_uuid()
        self.policy_data = {
            'policy': {'id': policy_id,
                       'project_id': self.project_id,
                       'name': 'test-policy',
                       'description': 'Test policy description',
                       'shared': True}}
        self.rule_data = {
            'bandwidth_limit_rule': {'id': uuidutils.generate_uuid(),
                                     'max_kbps': 2000,
                                     'max_burst_kbps': 150}}
        self.ingress_rule_data = {
            'bandwidth_limit_rule': {'id': uuidutils.generate_uuid(),
                                     'max_kbps': 3000,
                                     'max_burst_kbps': 350,
                                     'direction': 'ingress'}}
        self.dscp_rule_data = {
            'dscp_marking_rule': {'id': uuidutils.generate_uuid(),
                                  'dscp_mark': 22}}

        self.policy = QoSPolicy(
            self.ctxt, **self.policy_data['policy'])

        # egress BW limit rule
        self.rule = QosBandwidthLimitRule(
            self.ctxt, **self.rule_data['bandwidth_limit_rule'])
        # ingress bw limit rule
        self.ingress_rule = QosBandwidthLimitRule(
            self.ctxt, **self.ingress_rule_data['bandwidth_limit_rule'])
        self.dscp_rule = QosDscpMarkingRule(
            self.ctxt, **self.dscp_rule_data['dscp_marking_rule'])

        self.fake_profile = {'id': policy_id}

        mock.patch('neutron.objects.db.api.create_object').start()
        mock.patch('neutron.objects.db.api.update_object').start()
        mock.patch('neutron.objects.db.api.delete_object').start()

        self.peak_bw_multiplier = cfg.CONF.NSX.qos_peak_bw_multiplier

        self.nsxlib = v3_utils.get_nsxlib_wrapper()

    def _get_expected_tags(self):
        policy_dict = {'id': self.policy.id, 'tenant_id': self.project_id}
        return self.nsxlib.build_v3_tags_payload(
            policy_dict, resource_type='os-neutron-qos-id',
            project_name=self.ctxt.tenant_name)

    @mock.patch.object(QoSPolicy, 'create_rbac_policy')
    def test_policy_create_profile(self, *mocks):
        # test the profile creation when a QoS policy is created
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'NsxQosProfileApi.create_or_overwrite',
                        return_value=self.fake_profile) as create_profile,\
            mock.patch.object(QoSPolicy, 'get_object',
                              return_value=self.policy),\
            mock.patch.object(QoSPolicy, 'create'):
            self.qos_plugin.create_policy(self.ctxt, self.policy_data)
            exp_name = utils.get_name_and_uuid(self.policy.name,
                                               self.policy.id)

            create_profile.assert_called_once_with(
                exp_name,
                profile_id=self.policy.id,
                description=self.policy_data["policy"]["description"],
                dscp=None,
                shaper_configurations=[],
                tags=self._get_expected_tags())

    @mock.patch.object(QoSPolicy, '_reload_rules')
    def test_bw_rule_create_profile(self, *mocks):
        # test the profile update when an egress QoS BW rule is created
        _policy = QoSPolicy(
            self.ctxt, **self.policy_data['policy'])
        # add a rule to the policy
        setattr(_policy, "rules", [self.rule])
        with mock.patch.object(QoSPolicy, 'get_object', return_value=_policy),\
            mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                       'NsxQosProfileApi.'
                       'create_or_overwrite') as create_profile,\
            mock.patch('neutron.objects.db.api.update_object',
                       return_value=self.rule_data):
            self.qos_plugin.update_policy_bandwidth_limit_rule(
                self.ctxt, self.rule.id, _policy.id, self.rule_data)

            # validate the data on the profile
            rule_dict = self.rule_data['bandwidth_limit_rule']
            expected_bw = int(round(float(
                rule_dict['max_kbps']) / 1024))
            expected_burst = rule_dict['max_burst_kbps'] * 128
            expected_peak = int(expected_bw * self.peak_bw_multiplier)
            exp_name = utils.get_name_and_uuid(self.policy.name,
                                               self.policy.id)
            # egress neutron rule -> ingress nsx args
            shaper_type = policy_defs.QoSRateLimiter.INGRESS_RATE_LIMITER_TYPE
            expected_shaper = policy_defs.QoSRateLimiter(
                resource_type=shaper_type,
                enabled=True,
                burst_size=expected_burst,
                peak_bandwidth=expected_peak,
                average_bandwidth=expected_bw)
            create_profile.assert_called_once_with(
                exp_name,
                profile_id=self.policy.id,
                description=self.policy_data["policy"]["description"],
                dscp=None,
                shaper_configurations=[mock.ANY],
                tags=self._get_expected_tags())
            # Compare the shaper
            actual_shaper = create_profile.call_args[1][
                'shaper_configurations'][0]
            self.assertEqual(expected_shaper.get_obj_dict(),
                             actual_shaper.get_obj_dict())

    @mock.patch.object(QoSPolicy, '_reload_rules')
    def test_ingress_bw_rule_create_profile(self, *mocks):
        # test the profile update when a ingress QoS BW rule is created
        _policy = QoSPolicy(
            self.ctxt, **self.policy_data['policy'])
        # add a rule to the policy
        setattr(_policy, "rules", [self.ingress_rule])
        with mock.patch.object(QoSPolicy, 'get_object', return_value=_policy),\
            mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                       'NsxQosProfileApi.'
                       'create_or_overwrite') as create_profile,\
            mock.patch('neutron.objects.db.api.update_object',
                       return_value=self.ingress_rule_data):
            self.qos_plugin.update_policy_bandwidth_limit_rule(
                self.ctxt, self.ingress_rule.id, _policy.id,
                self.ingress_rule_data)

            # validate the data on the profile
            rule_dict = self.ingress_rule_data['bandwidth_limit_rule']
            expected_bw = int(round(float(
                rule_dict['max_kbps']) / 1024))
            expected_burst = rule_dict['max_burst_kbps'] * 128
            expected_peak = int(expected_bw * self.peak_bw_multiplier)
            exp_name = utils.get_name_and_uuid(self.policy.name,
                                               self.policy.id)
            # ingress neutron rule -> egress nsx args
            shaper_type = policy_defs.QoSRateLimiter.EGRESS_RATE_LIMITER_TYPE
            expected_shaper = policy_defs.QoSRateLimiter(
                resource_type=shaper_type,
                enabled=True,
                burst_size=expected_burst,
                peak_bandwidth=expected_peak,
                average_bandwidth=expected_bw)
            create_profile.assert_called_once_with(
                exp_name,
                profile_id=self.policy.id,
                description=self.policy_data["policy"]["description"],
                dscp=None,
                shaper_configurations=[mock.ANY],
                tags=self._get_expected_tags())
            # Compare the shaper
            actual_shaper = create_profile.call_args[1][
                'shaper_configurations'][0]
            self.assertEqual(expected_shaper.get_obj_dict(),
                             actual_shaper.get_obj_dict())

    @mock.patch.object(QoSPolicy, '_reload_rules')
    def test_bw_rule_create_profile_minimal_val(self, *mocks):
        # test driver precommit with an invalid limit value
        bad_limit = qos_utils.MAX_KBPS_MIN_VALUE - 1
        rule_data = {
            'bandwidth_limit_rule': {'id': uuidutils.generate_uuid(),
                                     'max_kbps': bad_limit,
                                     'max_burst_kbps': 150}}

        rule = QosBandwidthLimitRule(
            self.ctxt, **rule_data['bandwidth_limit_rule'])

        _policy = QoSPolicy(
            self.ctxt, **self.policy_data['policy'])
        # add a rule to the policy
        setattr(_policy, "rules", [rule])
        with mock.patch.object(QoSPolicy, 'get_object',
                               return_value=_policy),\
            mock.patch('neutron.objects.db.api.update_object',
                       return_value=rule_data):
            self.assertRaises(
                exceptions.DriverCallError,
                self.qos_plugin.update_policy_bandwidth_limit_rule,
                self.ctxt, rule.id, _policy.id, rule_data)

    @mock.patch.object(QoSPolicy, '_reload_rules')
    def test_bw_rule_create_profile_maximal_val(self, *mocks):
        # test driver precommit with an invalid burst value
        bad_burst = qos_utils.MAX_BURST_MAX_VALUE + 1
        rule_data = {
            'bandwidth_limit_rule': {'id': uuidutils.generate_uuid(),
                                     'max_kbps': 1025,
                                     'max_burst_kbps': bad_burst}}

        rule = QosBandwidthLimitRule(
            self.ctxt, **rule_data['bandwidth_limit_rule'])

        _policy = QoSPolicy(
            self.ctxt, **self.policy_data['policy'])
        # add a rule to the policy
        setattr(_policy, "rules", [rule])
        with mock.patch.object(QoSPolicy, 'get_object',
                               return_value=_policy),\
            mock.patch('neutron.objects.db.api.update_object',
                       return_value=rule_data):
                self.assertRaises(
                    exceptions.DriverCallError,
                    self.qos_plugin.update_policy_bandwidth_limit_rule,
                    self.ctxt, rule.id, _policy.id, rule_data)

    @mock.patch.object(QoSPolicy, '_reload_rules')
    def test_dscp_rule_create_profile(self, *mocks):
        # test the profile update when a QoS DSCP rule is created
        _policy = QoSPolicy(
            self.ctxt, **self.policy_data['policy'])
        # add a rule to the policy
        setattr(_policy, "rules", [self.dscp_rule])
        with mock.patch.object(QoSPolicy, 'get_object', return_value=_policy),\
            mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                       'NsxQosProfileApi.'
                       'create_or_overwrite') as create_profile,\
            mock.patch('neutron.objects.db.api.update_object',
                       return_value=self.dscp_rule_data):
            self.qos_plugin.update_policy_dscp_marking_rule(
                self.ctxt, self.dscp_rule.id,
                _policy.id, self.dscp_rule_data)

            # validate the data on the profile
            rule_dict = self.dscp_rule_data['dscp_marking_rule']
            dscp_mark = rule_dict['dscp_mark']

            exp_name = utils.get_name_and_uuid(self.policy.name,
                                               self.policy.id)
            expected_dscp = policy_defs.QoSDscp(
                mode=policy_defs.QoSDscp.QOS_DSCP_UNTRUSTED,
                priority=dscp_mark)
            create_profile.assert_called_once_with(
                exp_name,
                profile_id=self.policy.id,
                description=self.policy_data["policy"]["description"],
                dscp=mock.ANY,
                shaper_configurations=[],
                tags=self._get_expected_tags())
            # Compare the dscp obj
            actual_dscp = create_profile.call_args[1]['dscp']
            self.assertEqual(expected_dscp.get_obj_dict(),
                             actual_dscp.get_obj_dict())

    @mock.patch.object(QoSPolicy, '_reload_rules')
    def test_minimum_bw_rule_create_profile(self, *mocks):
        # Minimum BW rules are not supported
        policy = QoSPolicy(
            self.ctxt, **self.policy_data['policy'])
        min_bw_rule_data = {
            'minimum_bandwidth_rule': {'id': uuidutils.generate_uuid(),
                                       'min_kbps': 10,
                                       'direction': 'egress'}}
        min_bw_rule = QosMinimumBandwidthRule(
            self.ctxt, **min_bw_rule_data['minimum_bandwidth_rule'])
        # add a rule to the policy
        setattr(policy, "rules", [min_bw_rule])
        with mock.patch.object(
                QoSPolicy, 'get_object', return_value=policy),\
            mock.patch('neutron.objects.db.api.'
                       'update_object', return_value=self.dscp_rule_data):
            self.assertRaises(
                exceptions.DriverCallError,
                self.qos_plugin.update_policy_minimum_bandwidth_rule,
                self.ctxt, min_bw_rule.id,
                policy.id, min_bw_rule_data)

    def test_rule_delete_profile(self):
        # test the profile update when a QoS rule is deleted
        _policy = QoSPolicy(
            self.ctxt, **self.policy_data['policy'])
        # The mock will return the policy without the rule,
        # as if it was deleted
        with mock.patch.object(QoSPolicy, 'get_object', return_value=_policy),\
            mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                       'NsxQosProfileApi.'
                       'create_or_overwrite') as set_profile:
            setattr(_policy, "rules", [self.rule])
            self.qos_plugin.delete_policy_bandwidth_limit_rule(
                self.ctxt, self.rule.id, self.policy.id)
            # validate the data on the profile
            exp_name = utils.get_name_and_uuid(self.policy.name,
                                               self.policy.id)

            set_profile.assert_called_once_with(
                exp_name,
                profile_id=self.policy.id,
                description=self.policy_data["policy"]["description"],
                dscp=None,
                shaper_configurations=[],
                tags=self._get_expected_tags())

    @mock.patch('neutron.objects.db.api.get_object', return_value=None)
    def test_policy_delete_profile(self, *mocks):
        # test the profile deletion when a QoS policy is deleted
        with mock.patch('vmware_nsxlib.v3.policy.core_resources.'
                        'NsxQosProfileApi.delete') as delete_profile:
            self.qos_plugin.delete_policy(self.ctxt, self.policy.id)
            delete_profile.assert_called_once_with(self.policy.id)
