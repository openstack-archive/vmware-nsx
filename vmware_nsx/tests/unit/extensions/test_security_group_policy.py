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

from neutron.api.v2 import attributes as attr
from neutron import context
from neutron.tests.unit.extensions import test_securitygroup

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
            self._tenant_id = 'foobar'
            # add policy security group attribute
            attr.RESOURCE_ATTRIBUTE_MAP['security_groups'].update(
                ext_policy.RESOURCE_ATTRIBUTE_MAP['security_groups'])

    def tearDown(self):
        # remove policy security group attribute
        del attr.RESOURCE_ATTRIBUTE_MAP['security_groups']['policy']
        super(SecGroupPolicyExtensionTestCase, self).tearDown()

    def _create_secgroup_with_policy(self, policy_id):
        body = {'security_group': {'name': 'sg-policy',
                                   'tenant_id': self._tenant_id,
                                   'policy': policy_id}}
        security_group_req = self.new_create_request('security-groups', body)
        return security_group_req.get_response(self.ext_api)

    def test_secgroup_create_with_policy(self):
        policy_id = 'policy-5'
        res = self._create_secgroup_with_policy(policy_id)
        sg = self.deserialize(self.fmt, res)
        self.assertEqual(policy_id, sg['security_group']['policy'])

    def test_secgroup_create_without_policy(self):
        res = self._create_secgroup_with_policy(None)
        self.assertEqual(400, res.status_int)

    def test_secgroup_create_with_illegal_policy(self):
        with mock.patch.object(fake_vcns.FakeVcns,
                               'validate_inventory',
                               return_value=False):
            policy_id = 'bad-policy'
            res = self._create_secgroup_with_policy(policy_id)
            self.assertEqual(400, res.status_int)

    def test_secgroup_update_with_policy(self):
        old_policy = 'policy-5'
        new_policy = 'policy-6'
        res = self._create_secgroup_with_policy(old_policy)
        sg = self.deserialize(self.fmt, res)
        data = {'security_group': {'policy': new_policy}}
        req = self.new_update_request('security-groups', data,
                                      sg['security_group']['id'])
        updated_sg = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(new_policy, updated_sg['security_group']['policy'])

    def test_secgroup_update_no_policy_change(self):
        old_policy = 'policy-5'
        res = self._create_secgroup_with_policy(old_policy)
        sg = self.deserialize(self.fmt, res)
        data = {'security_group': {'description': 'abc'}}
        req = self.new_update_request('security-groups', data,
                                      sg['security_group']['id'])
        updated_sg = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(old_policy, updated_sg['security_group']['policy'])

    def test_secgroup_update_remove_policy(self):
        old_policy = 'policy-5'
        new_policy = None
        res = self._create_secgroup_with_policy(old_policy)
        sg = self.deserialize(self.fmt, res)
        data = {'security_group': {'policy': new_policy}}
        req = self.new_update_request('security-groups', data,
                                      sg['security_group']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(400, res.status_int)

    def test_non_admin_cannot_delete_policy_sg_and_admin_can(self):
        policy_id = 'policy-5'
        res = self._create_secgroup_with_policy(policy_id)
        sg = self.deserialize(self.fmt, res)
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
