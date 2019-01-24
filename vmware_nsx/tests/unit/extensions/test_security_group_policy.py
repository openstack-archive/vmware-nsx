# Copyright 2016 VMware, Inc.
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

import mock
from oslo_config import cfg
import webob.exc

from neutron.extensions import securitygroup as ext_sg
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_securitygroup
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc

from vmware_nsx.extensions import nsxpolicy
from vmware_nsx.extensions import securitygrouplogging as ext_logging
from vmware_nsx.extensions import securitygrouppolicy as ext_policy
from vmware_nsx.tests.unit.nsx_v import test_plugin
from vmware_nsx.tests.unit.nsx_v.vshield import fake_vcns

PLUGIN_NAME = 'vmware_nsx.plugin.NsxVPlugin'


class SecGroupPolicyExtensionTestCase(
        test_plugin.NsxVPluginV2TestCase,
        test_securitygroup.SecurityGroupDBTestCase):
    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None):
        cfg.CONF.set_override('use_nsx_policies', True, group='nsxv')
        cfg.CONF.set_override('default_policy_id', 'policy-1', group='nsxv')
        # This feature is enabled only since 6.2
        with mock.patch.object(fake_vcns.FakeVcns,
                               'get_version',
                               return_value="6.2.3"):
            super(SecGroupPolicyExtensionTestCase, self).setUp(
                plugin=plugin, ext_mgr=ext_mgr)
            self._tenant_id = test_db_base_plugin_v2.TEST_TENANT_ID
            # add policy & logging security group attribute
            ext_sg.Securitygroup().update_attributes_map(
                ext_policy.RESOURCE_ATTRIBUTE_MAP)
            ext_sg.Securitygroup().update_attributes_map(
                ext_logging.RESOURCE_ATTRIBUTE_MAP)

    def _create_secgroup_with_policy(self, policy_id, description=None,
                                     logging=False):
        body = {'security_group':
            {'name': 'sg-policy',
             'tenant_id': self._tenant_id,
             'policy': policy_id,
             'description': description if description else '',
             'logging': logging}}
        return self._create_security_group_response(self.fmt, body)

    def _get_secgroup_with_policy(self):
        policy_id = 'policy-5'
        res = self._create_secgroup_with_policy(policy_id)
        return self.deserialize(self.fmt, res)

    def test_secgroup_create_with_policy(self):
        policy_id = 'policy-5'
        res = self._create_secgroup_with_policy(policy_id)
        sg = self.deserialize(self.fmt, res)
        self.assertEqual(policy_id, sg['security_group']['policy'])
        self.assertEqual('dummy', sg['security_group']['description'])

    def test_secgroup_create_with_policyand_desc(self):
        policy_id = 'policy-5'
        desc = 'test'
        res = self._create_secgroup_with_policy(policy_id, description=desc)
        sg = self.deserialize(self.fmt, res)
        self.assertEqual(policy_id, sg['security_group']['policy'])
        self.assertEqual(desc, sg['security_group']['description'])

    def test_secgroup_create_without_policy(self):
        res = self._create_secgroup_with_policy(None)
        self.assertEqual(400, res.status_int)

    def test_secgroup_create_with_illegal_policy(self):
        policy_id = 'bad-policy'
        with mock.patch(PLUGIN_NAME + '.get_nsx_policy',
                        side_effect=n_exc.ObjectNotFound(id=policy_id)):
            res = self._create_secgroup_with_policy(policy_id)
            self.assertEqual(400, res.status_int)

    def test_secgroup_create_with_policy_and_logging(self):
        # We do not support policy & logging together
        policy_id = 'policy-5'
        res = self._create_secgroup_with_policy(policy_id, logging=True)
        self.assertEqual(400, res.status_int)

    def test_secgroup_update_with_policy(self):
        # Test that updating the policy is allowed
        old_policy = 'policy-5'
        new_policy = 'policy-6'
        res = self._create_secgroup_with_policy(old_policy)
        sg = self.deserialize(self.fmt, res)
        data = {'security_group': {'policy': new_policy}}
        req = self.new_update_request('security-groups', data,
                                      sg['security_group']['id'])
        updated_sg = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(new_policy, updated_sg['security_group']['policy'])
        # Verify the same result in 'get'
        req = self.new_show_request('security-groups',
                                    sg['security_group']['id'])
        shown_sg = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(new_policy, shown_sg['security_group']['policy'])

    def test_secgroup_update_no_policy_change(self):
        # Test updating without changing the policy
        old_policy = 'policy-5'
        desc = 'abc'
        res = self._create_secgroup_with_policy(old_policy)
        sg = self.deserialize(self.fmt, res)
        data = {'security_group': {'description': desc}}
        req = self.new_update_request('security-groups', data,
                                      sg['security_group']['id'])
        updated_sg = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(old_policy, updated_sg['security_group']['policy'])
        self.assertEqual(desc, updated_sg['security_group']['description'])

    def test_secgroup_update_remove_policy(self):
        # removing the policy is not allowed
        sg = self._get_secgroup_with_policy()
        data = {'security_group': {'policy': None}}
        req = self.new_update_request('security-groups', data,
                                      sg['security_group']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(400, res.status_int)

    def test_secgroup_update_add_logging(self):
        # We do not support policy & logging together
        sg = self._get_secgroup_with_policy()
        data = {'security_group': {'logging': True}}
        req = self.new_update_request('security-groups', data,
                                      sg['security_group']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(400, res.status_int)

    def test_non_admin_cannot_delete_policy_sg_and_admin_can(self):
        sg = self._get_secgroup_with_policy()
        sg_id = sg['security_group']['id']

        # Try deleting the request as a normal user returns forbidden
        # as a tenant is not allowed to delete this.
        ctx = context.Context('', self._tenant_id)
        self._delete('security-groups', sg_id,
                     expected_code=webob.exc.HTTPForbidden.code,
                     neutron_context=ctx)
        # can be deleted though as admin
        self._delete('security-groups', sg_id,
                     expected_code=webob.exc.HTTPNoContent.code)

    def test_create_rule(self):
        sg = self._get_secgroup_with_policy()
        rule = self._build_security_group_rule(
            sg['security_group']['id'], 'ingress',
            constants.PROTO_NAME_TCP, '22', '22')
        res = self._create_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(400, res.status_int)


class SecGroupPolicyExtensionTestCaseWithRules(
    SecGroupPolicyExtensionTestCase):

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None):
        cfg.CONF.set_override('allow_tenant_rules_with_policy',
                              True, group='nsxv')
        super(SecGroupPolicyExtensionTestCaseWithRules, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr)

    def test_secgroup_create_without_policy(self):
        # in case allow_tenant_rules_with_policy is True, it is allowed to
        # create a regular sg
        desc = 'test'
        res = self._create_secgroup_with_policy(None, description=desc)
        sg = self.deserialize(self.fmt, res)
        self.assertIsNone(sg['security_group']['policy'])
        self.assertEqual(desc, sg['security_group']['description'])

    def test_secgroup_create_without_policy_update_policy(self):
        # Create a regular security group. adding the policy later should fail
        res = self._create_secgroup_with_policy(None)
        sg = self.deserialize(self.fmt, res)
        data = {'security_group': {'policy': 'policy-1'}}
        req = self.new_update_request('security-groups', data,
                                      sg['security_group']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(400, res.status_int)

    def test_secgroup_create_without_policy_and_rule(self):
        # Test that regular security groups can have rules
        res = self._create_secgroup_with_policy(None)
        sg = self.deserialize(self.fmt, res)
        self.assertIsNone(sg['security_group']['policy'])

        rule = self._build_security_group_rule(
            sg['security_group']['id'], 'ingress',
            constants.PROTO_NAME_TCP, '22', '22')
        res = self._create_security_group_rule(self.fmt, rule)
        rule_data = self.deserialize(self.fmt, res)
        self.assertEqual(
            sg['security_group']['id'],
            rule_data['security_group_rule']['security_group_id'])


class NsxPolExtensionManager(object):

    def get_resources(self):
        return nsxpolicy.Nsxpolicy.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestNsxPolicies(test_plugin.NsxVPluginV2TestCase):

    def setUp(self, plugin=None):
        super(TestNsxPolicies, self).setUp()
        ext_mgr = NsxPolExtensionManager()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def test_get_policy(self):
        id = 'policy-1'
        req = self.new_show_request('nsx-policies', id)
        res = self.deserialize(
            self.fmt, req.get_response(self.ext_api)
        )
        policy = res['nsx_policy']
        self.assertEqual(id, policy['id'])

    def test_list_policies(self):
        req = self.new_list_request('nsx-policies')
        res = self.deserialize(
            self.fmt, req.get_response(self.ext_api)
        )
        self.assertIn('nsx_policies', res)
        # the fake_vcns api returns 3 policies
        self.assertEqual(3, len(res['nsx_policies']))
