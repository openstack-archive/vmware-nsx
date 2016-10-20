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


class TestL7Rules(base.BaseTestCase):

    @classmethod
    def skip_checks(cls):
        super(TestL7Rules, cls).skip_checks()
        if '1739510' in CONF.nsxv.bugs_to_resolve:
            msg = ("skip lbaas_l7_switching_ops because bug=1739150"
                   "  -- l7 switching is not supported")
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TestL7Rules, cls).resource_setup()
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
        cls.policy7 = cls._create_l7policy(action='REDIRECT_TO_POOL',
                                           name='policy1',
                                           redirect_pool_id=cls.pool7_id,
                                           listener_id=cls.listener_id)
        cls.policy7_id = cls.policy7.get('id')

    @classmethod
    def resource_cleanup(cls):
        super(TestL7Rules, cls).resource_cleanup()

    @test.idempotent_id('27e8a3a1-bd3a-40e5-902d-fe9bc79ebf1f')
    def test_l7rules_crud_ops(self):
        rule = self._create_l7rule(self.policy7_id,
                                   type='PATH',
                                   compare_type='STARTS_WITH',
                                   value='/api')
        self.assertEqual(rule.get('compare_type'), 'STARTS_WITH')
        self.assertEqual(rule.get('value'), '/api')
        self.assertEqual(rule.get('type'), 'PATH')
        # update
        new_value = '/v2/api'
        rule2 = self._update_l7rule(self.policy7_id, rule.get('id'),
                                    value=new_value)
        self.assertEqual(rule2.get('value'), new_value)
        # show
        s_rule = self._show_l7rule(self.policy7_id, rule.get('id'))
        self.assertEqual(s_rule.get('value'), new_value)
        # list
        rules = self._list_l7rules(self.policy7_id)
        rule_id_list = [x.get('id') for x in rules]
        self.assertIn(rule.get('id'), rule_id_list)
        # delete
        self._delete_l7rule(self.policy7_id, rule.get('id'))
        rules = self._list_l7rules(self.policy7_id)
        rule_id_list = [x.get('id') for x in rules]
        self.assertNotIn(rule.get('id'), rule_id_list)
