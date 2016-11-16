# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from tempest import config
from tempest import test

from vmware_nsx_tempest.tests.nsxv.api.lbaas import base

CONF = config.CONF
PROTOCOL_PORT = 80


class TestL7Policies(base.BaseTestCase):

    @classmethod
    def skip_checks(cls):
        super(TestL7Policies, cls).skip_checks()
        if '1739510' in CONF.nsxv.bugs_to_resolve:
            msg = ("skip lbaas_l7_switching_ops because bug=1739150"
                   "  -- l7 switching is not supported")
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TestL7Policies, cls).resource_setup()
        cls.load_balancer = cls._create_load_balancer(
            tenant_id=cls.subnet.get('tenant_id'),
            vip_subnet_id=cls.subnet.get('id'),
            wait=True)
        cls.loadbalancer_id = cls.load_balancer.get('id')
        cls.listener = cls._create_listener(
            loadbalancer_id=cls.load_balancer.get('id'),
            protocol='HTTP', protocol_port=80)
        cls.listener_id = cls.listener.get('id')
        cls.pool = cls._create_pool(protocol='HTTP',
                                    tenant_id=cls.tenant_id,
                                    lb_algorithm='ROUND_ROBIN',
                                    listener_id=cls.listener_id)
        cls.pool_id = cls.pool.get('id')
        cls.pool7 = cls._create_pool(protocol='HTTP',
                                     tenant_id=cls.tenant_id,
                                     lb_algorithm='ROUND_ROBIN',
                                     loadbalancer_id=cls.loadbalancer_id)
        cls.pool7_id = cls.pool7.get('id')

    @classmethod
    def resource_cleanup(cls):
        super(TestL7Policies, cls).resource_cleanup()

    def remove_all_policies(self):
        policies = self._list_l7policies()
        for policy in policies:
            self._delete_l7policy(policy.get('id'))
        policies = self._list_l7policies()
        self.assertEmpty(policies)

    def create_to_pool_policy(self, to_position=None, name='policy-pool'):
        policy_kwargs = dict(
            action='REDIRECT_TO_POOL', name=name,
            redirect_pool_id=self.pool7_id,
            listener_id=self.listener_id)
        if to_position:
            policy_kwargs['position'] = to_position
        policy = self._create_l7policy(**policy_kwargs)
        self.assertEqual(policy.get('name'), name)
        self.assertEqual(policy.get('listener_id'), self.listener_id)
        self.assertEqual(policy.get('redirect_pool_id'), self.pool7_id)
        return policy

    def create_to_url_policy(self, redirect_url=None, to_position=None,
                             name='policy-url'):
        policy_kwargs = dict(
            action='REDIRECT_TO_URL', name=name,
            redirect_url=redirect_url,
            redirect_pool_id=self.pool7_id,
            listener_id=self.listener_id)
        if to_position:
            policy_kwargs['position'] = to_position
        policy = self._create_l7policy(**policy_kwargs)
        self.assertEqual(policy.get('name'), name)
        self.assertEqual(policy.get('listener_id'), self.listener_id)
        self.assertEqual(policy.get('redirect_pool_id'), self.pool7_id)
        return policy

    def create_reject_policy(self, to_position=1, name='policy-reject'):
        policy_kwargs = dict(
            action='REJECT', name=name,
            redirect_pool_id=self.pool7_id,
            listener_id=self.listener_id)
        if to_position:
            policy_kwargs['position'] = to_position
        policy = self._create_l7policy(**policy_kwargs)
        self.assertEqual(policy.get('name'), name)
        self.assertEqual(policy.get('listener_id'), self.listener_id)
        self.assertEqual(policy.get('redirect_pool_id'), self.pool7_id)
        return policy

    @test.idempotent_id('465c9bea-53de-4a1f-ae00-fa2ee52d250b')
    def test_l7policies_crud_ops(self):
        policy = self.create_to_pool_policy()
        # update
        new_policy_name = policy.get('name') + "-update"
        policy2 = self._update_l7policy(policy.get('id'),
                                        name=new_policy_name)
        self.assertEqual(policy2.get('name'), new_policy_name)
        # show
        s_policy = self._show_l7policy(policy.get('id'))
        self.assertEqual(policy2.get('name'), s_policy.get('name'))
        # list
        policies = self._list_l7policies()
        policy_id_list = [x.get('id') for x in policies]
        self.assertIn(policy.get('id'), policy_id_list)
        # delete
        self._delete_l7policy(policy.get('id'))
        policies = self._list_l7policies()
        policy_id_list = [x.get('id') for x in policies]
        self.assertNotIn(policy.get('id'), policy_id_list)

    @test.idempotent_id('726588f4-970a-4f32-8253-95766ddaa7b4')
    def test_policy_position(self):
        self.remove_all_policies()
        policy1 = self.create_to_pool_policy()
        self.assertEqual(policy1.get('position'), 1)
        # create reject_policy at position=1
        policy2 = self.create_reject_policy(to_position=1)
        self.assertEqual(policy2.get('position'), 1)
        policy1A = self._show_l7policy(policy1.get('id'))
        self.assertEqual(policy1A.get('position'), 2)
        # create to_url_policy at position=2
        policy3 = self.create_to_url_policy(to_position=2)
        self.assertEqual(policy3.get('position'), 2)
        policy2A = self._show_l7policy(policy2.get('id'))
        self.assertEqual(policy2A.get('position'), 1)
        policy1A = self._show_l7policy(policy1.get('id'))
        self.assertEqual(policy1A.get('position'), 3)
        # delete policy3, policy1 position==2
        self._delete_l7policy(policy3.get('id'))
        policy1A = self._show_l7policy(policy1.get('id'))
        self.assertEqual(policy1A.get('position'), 2)
        policy2A = self._show_l7policy(policy2.get('id'))
        self.assertEqual(policy2A.get('position'), 1)
        self._delete_l7policy(policy2.get('id'))
        policies = self._list_l7policies()
        self.assertEqual(len(policies), 1)
        self.assertEqual(policy1.get('id'), policies[0].get('id'))
        self._delete_l7policy(policy1.get('id'))
        policies = self._list_l7policies()
        self.assertEmpty(policies)
