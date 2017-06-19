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
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.common import exceptions
from neutron.objects import base as base_object
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import rule as rule_object
from neutron.services.qos import qos_plugin
from neutron.tests.unit.services.qos import base

from vmware_nsx.db import db as nsx_db
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils
from vmware_nsx.services.qos.nsx_v3 import driver as qos_driver
from vmware_nsx.services.qos.nsx_v3 import utils as qos_utils
from vmware_nsx.tests.unit.nsx_v3 import test_plugin

PLUGIN_NAME = 'vmware_nsx.plugins.nsx_v3.plugin.NsxV3Plugin'


class TestQosNsxV3Notification(base.BaseQosTestCase,
                               test_plugin.NsxV3PluginTestCaseMixin):

    def setUp(self):
        # Reset the drive to re-create it
        qos_driver.DRIVER = None
        super(TestQosNsxV3Notification, self).setUp()
        self.setup_coreplugin(PLUGIN_NAME)

        self.qos_plugin = qos_plugin.QoSPlugin()
        self.ctxt = context.Context('fake_user', 'fake_tenant')
        mock.patch.object(self.ctxt.session, 'refresh').start()
        mock.patch.object(self.ctxt.session, 'expunge').start()
        self.policy_data = {
            'policy': {'id': uuidutils.generate_uuid(),
                       'project_id': uuidutils.generate_uuid(),
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

        self.policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])

        # egress BW limit rule
        self.rule = rule_object.QosBandwidthLimitRule(
            self.ctxt, **self.rule_data['bandwidth_limit_rule'])
        # ingress bw limit rule
        self.ingress_rule = rule_object.QosBandwidthLimitRule(
            self.ctxt, **self.ingress_rule_data['bandwidth_limit_rule'])
        self.dscp_rule = rule_object.QosDscpMarkingRule(
            self.ctxt, **self.dscp_rule_data['dscp_marking_rule'])

        self.fake_profile_id = 'fake_profile'
        self.fake_profile = {'id': self.fake_profile_id}

        mock.patch('neutron.objects.db.api.create_object').start()
        mock.patch('neutron.objects.db.api.update_object').start()
        mock.patch('neutron.objects.db.api.delete_object').start()
        mock.patch.object(nsx_db, 'get_switch_profile_by_qos_policy',
                          return_value=self.fake_profile_id).start()

        self.peak_bw_multiplier = cfg.CONF.NSX.qos_peak_bw_multiplier

        self.nsxlib = v3_utils.get_nsxlib_wrapper()

    @mock.patch(
        'neutron.objects.rbac_db.RbacNeutronDbObjectMixin'
        '.create_rbac_policy')
    @mock.patch.object(nsx_db, 'add_qos_policy_profile_mapping')
    def test_policy_create_profile(self, fake_db_add, fake_rbac_create):
        # test the switch profile creation when a QoS policy is created
        with mock.patch(
            'vmware_nsxlib.v3.core_resources.NsxLibQosSwitchingProfile.create',
            return_value=self.fake_profile
        ) as create_profile:
            with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                return_value=self.policy):
                with mock.patch('neutron.objects.qos.policy.QosPolicy.create'):
                    policy = self.qos_plugin.create_policy(self.ctxt,
                                                           self.policy_data)
                    expected_tags = self.nsxlib.build_v3_tags_payload(
                        policy,
                        resource_type='os-neutron-qos-id',
                        project_name=self.ctxt.tenant_name)

                    create_profile.assert_called_once_with(
                        description=self.policy_data["policy"]["description"],
                        name=self.policy_data["policy"]["name"],
                        tags=expected_tags)
                    # verify that the policy->profile mapping entry was added
                    self.assertTrue(fake_db_add.called)

    @mock.patch(
        'neutron.objects.rbac_db.RbacNeutronDbObjectMixin'
        '.create_rbac_policy')
    def __test_policy_update_profile(self, *mocks):
        # test the switch profile update when a QoS policy is updated
        fields = base_object.get_updatable_fields(
            policy_object.QosPolicy, self.policy_data['policy'])
        with mock.patch(
            'vmware_nsxlib.v3.core_resources.NsxLibQosSwitchingProfile.update'
        ) as update_profile:
            with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                return_value=self.policy):
                with mock.patch('neutron.objects.qos.policy.QosPolicy.update'):
                    self.qos_plugin.update_policy(
                        self.ctxt, self.policy.id, {'policy': fields})
                    # verify that the profile was updated with the correct data
                    self.policy_data["policy"]["id"] = self.policy.id
                    expected_tags = self.nsxlib.build_v3_tags_payload(
                        self.policy_data["policy"],
                        resource_type='os-neutron-qos-id',
                        project_name=self.ctxt.tenant_name)

                    update_profile.assert_called_once_with(
                        self.fake_profile_id,
                        description=self.policy_data["policy"]["description"],
                        name=self.policy_data["policy"]["name"],
                        tags=expected_tags
                    )

    @mock.patch.object(policy_object.QosPolicy, '_reload_rules')
    def test_bw_rule_create_profile(self, *mocks):
        # test the switch profile update when a egress QoS BW rule is created
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        # add a rule to the policy
        setattr(_policy, "rules", [self.rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
            return_value=_policy):
            with mock.patch(
                'vmware_nsxlib.v3.core_resources.NsxLibQosSwitchingProfile.'
                'set_profile_shaping'
            ) as update_profile:
                with mock.patch('neutron.objects.db.api.update_object',
                    return_value=self.rule_data):
                    self.qos_plugin.update_policy_bandwidth_limit_rule(
                        self.ctxt, self.rule.id, _policy.id, self.rule_data)

                    # validate the data on the profile
                    rule_dict = self.rule_data['bandwidth_limit_rule']
                    expected_bw = int(round(float(
                        rule_dict['max_kbps']) / 1024))
                    expected_burst = rule_dict['max_burst_kbps'] * 128
                    expected_peak = int(expected_bw * self.peak_bw_multiplier)
                    # egress neutron rule -> ingress nsx args
                    update_profile.assert_called_once_with(
                        self.fake_profile_id,
                        ingress_bw_enabled=True,
                        ingress_burst_size=expected_burst,
                        ingress_peak_bandwidth=expected_peak,
                        ingress_average_bandwidth=expected_bw,
                        egress_bw_enabled=False,
                        egress_burst_size=None,
                        egress_peak_bandwidth=None,
                        egress_average_bandwidth=None,
                        dscp=0,
                        qos_marking='trusted'
                    )

    @mock.patch.object(policy_object.QosPolicy, '_reload_rules')
    def test_ingress_bw_rule_create_profile(self, *mocks):
        # test the switch profile update when a ingress QoS BW rule is created
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        # add a rule to the policy
        setattr(_policy, "rules", [self.ingress_rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
            return_value=_policy):
            with mock.patch(
                'vmware_nsxlib.v3.core_resources.NsxLibQosSwitchingProfile.'
                'set_profile_shaping'
            ) as update_profile:
                with mock.patch('neutron.objects.db.api.update_object',
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
                    # ingress neutron rule -> egress nsx args
                    update_profile.assert_called_once_with(
                        self.fake_profile_id,
                        egress_bw_enabled=True,
                        egress_burst_size=expected_burst,
                        egress_peak_bandwidth=expected_peak,
                        egress_average_bandwidth=expected_bw,
                        ingress_bw_enabled=False,
                        ingress_burst_size=None,
                        ingress_peak_bandwidth=None,
                        ingress_average_bandwidth=None,
                        dscp=0,
                        qos_marking='trusted'
                    )

    @mock.patch.object(policy_object.QosPolicy, '_reload_rules')
    def test_bw_rule_create_profile_minimal_val(self, *mocks):
        # test driver precommit with an invalid limit value
        bad_limit = qos_utils.MAX_KBPS_MIN_VALUE - 1
        rule_data = {
            'bandwidth_limit_rule': {'id': uuidutils.generate_uuid(),
                                     'max_kbps': bad_limit,
                                     'max_burst_kbps': 150}}

        rule = rule_object.QosBandwidthLimitRule(
            self.ctxt, **rule_data['bandwidth_limit_rule'])

        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        # add a rule to the policy
        setattr(_policy, "rules", [rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy),\
            mock.patch('neutron.objects.db.api.update_object',
                       return_value=rule_data):
            self.assertRaises(
                exceptions.DriverCallError,
                self.qos_plugin.update_policy_bandwidth_limit_rule,
                self.ctxt, rule.id, _policy.id, rule_data)

    @mock.patch.object(policy_object.QosPolicy, '_reload_rules')
    def test_bw_rule_create_profile_maximal_val(self, *mocks):
        # test driver precommit with an invalid burst value
        bad_burst = qos_utils.MAX_BURST_MAX_VALUE + 1
        rule_data = {
            'bandwidth_limit_rule': {'id': uuidutils.generate_uuid(),
                                     'max_kbps': 1025,
                                     'max_burst_kbps': bad_burst}}

        rule = rule_object.QosBandwidthLimitRule(
            self.ctxt, **rule_data['bandwidth_limit_rule'])

        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        # add a rule to the policy
        setattr(_policy, "rules", [rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy),\
            mock.patch('neutron.objects.db.api.update_object',
                       return_value=rule_data):
                self.assertRaises(
                    exceptions.DriverCallError,
                    self.qos_plugin.update_policy_bandwidth_limit_rule,
                    self.ctxt, rule.id, _policy.id, rule_data)

    @mock.patch.object(policy_object.QosPolicy, '_reload_rules')
    def test_dscp_rule_create_profile(self, *mocks):
        # test the switch profile update when a QoS DSCP rule is created
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        # add a rule to the policy
        setattr(_policy, "rules", [self.dscp_rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
            return_value=_policy):
            with mock.patch(
                'vmware_nsxlib.v3.core_resources.NsxLibQosSwitchingProfile.'
                'set_profile_shaping'
            ) as update_profile:
                with mock.patch('neutron.objects.db.api.'
                    'update_object', return_value=self.dscp_rule_data):
                    self.qos_plugin.update_policy_dscp_marking_rule(
                        self.ctxt, self.dscp_rule.id,
                        _policy.id, self.dscp_rule_data)

                    # validate the data on the profile
                    rule_dict = self.dscp_rule_data['dscp_marking_rule']
                    dscp_mark = rule_dict['dscp_mark']
                    update_profile.assert_called_once_with(
                        self.fake_profile_id,
                        ingress_bw_enabled=False,
                        ingress_burst_size=None,
                        ingress_peak_bandwidth=None,
                        ingress_average_bandwidth=None,
                        egress_bw_enabled=False,
                        egress_burst_size=None,
                        egress_peak_bandwidth=None,
                        egress_average_bandwidth=None,
                        dscp=dscp_mark,
                        qos_marking='untrusted'
                    )

    def test_rule_delete_profile(self):
        # test the switch profile update when a QoS rule is deleted
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        # The mock will return the policy without the rule,
        # as if it was deleted
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
            return_value=_policy):
            with mock.patch(
                'vmware_nsxlib.v3.core_resources.NsxLibQosSwitchingProfile.'
                'set_profile_shaping'
            ) as update_profile:
                setattr(_policy, "rules", [self.rule])
                self.qos_plugin.delete_policy_bandwidth_limit_rule(
                    self.ctxt, self.rule.id, self.policy.id)
                # validate the data on the profile
                update_profile.assert_called_once_with(
                    self.fake_profile_id,
                    ingress_bw_enabled=False,
                    ingress_burst_size=None,
                    ingress_peak_bandwidth=None,
                    ingress_average_bandwidth=None,
                    egress_bw_enabled=False,
                    egress_burst_size=None,
                    egress_peak_bandwidth=None,
                    egress_average_bandwidth=None,
                    dscp=0,
                    qos_marking='trusted'
                )

    @mock.patch('neutron.objects.db.api.get_object', return_value=None)
    def test_policy_delete_profile(self, *mocks):
        # test the switch profile deletion when a QoS policy is deleted
        with mock.patch(
            'vmware_nsxlib.v3.core_resources.NsxLibQosSwitchingProfile.'
            'delete',
            return_value=self.fake_profile
        ) as delete_profile:
            self.qos_plugin.delete_policy(self.ctxt, self.policy.id)
            delete_profile.assert_called_once_with(self.fake_profile_id)
