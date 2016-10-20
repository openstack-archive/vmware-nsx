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
import time

from tempest import test

from vmware_nsx_tempest.services.lbaas import l7policies_client
from vmware_nsx_tempest.services.lbaas import l7rules_client
from vmware_nsx_tempest.tests.nsxv.scenario import (
    test_lbaas_round_robin_ops as lbaas_ops)


class TestL7SwitchingOps(lbaas_ops.LBaasRoundRobinBaseTest):

    """This test validates lbaas l7 switching with round-robin opertion.

    Test leverage test_lbaas_round_robin to create the basic round-robin
    operation, and then build l7 pool and members to forwarding url path
    starts_with value specified.

    Manual operation can be found at test proc: https://goo.gl/btDMXy
    """

    @classmethod
    def resource_setup(cls):
        super(TestL7SwitchingOps, cls).resource_setup()
        cls.create_lbaas_clients(cls.manager)
        cls.l7policies_client = l7policies_client.get_client(cls.manager)
        cls.l7rules_client = l7rules_client.get_client(cls.manager)

    @classmethod
    def setup_credentials(cls):
        super(TestL7SwitchingOps, cls).setup_credentials()

    def setUp(self):
        super(TestL7SwitchingOps, self).setUp()
        self.switching_startswith_value1 = "/api"
        self.switching_startswith_value2 = "/api2"
        self.reject_startswith = "/api/v1"
        self.pool7 = None
        self.l7policy1 = None
        self.l7rule1 = None
        self.l7rule_kwargs = dict(type='PATH',
                                  compare_type='STARTS_WITH',
                                  value=self.switching_startswith_value1)
        self.l7policy_reject = None

    def tearDown(self):
        lb_id = self.loadbalancer['id']
        # teardown lbaas l7 provision
        for policy in [self.l7policy1, self.l7policy_reject]:
            if policy:
                self.l7policies_client.delete_l7policy(policy.get('id'))
                self.wait_for_load_balancer_status(lb_id)
        if self.pool7:
            self.pools_client.delete_pool(self.pool7.get('id'))
            self.wait_for_load_balancer_status(lb_id)
        super(TestL7SwitchingOps, self).tearDown()

    def create_and_start_l7_web_servers(self):
        key_name = self.keypair['name']
        network_name = self.network['name']
        security_groups = [{'name': self.security_group['id']}]
        self.server7 = self.create_server_on_network(
            self.network, name=(network_name + "-7"),
            security_groups=security_groups,
            key_name=key_name, wait_on_boot=False,
            servers_client=self.manager.servers_client)
        self.server8 = self.create_server_on_network(
            self.network, name=(network_name + "-8"),
            security_groups=security_groups,
            key_name=key_name, wait_on_boot=False,
            servers_client=self.manager.servers_client)
        self.l7_server_list = [self.server7, self.server8]
        self.wait_for_servers_become_active(self.l7_server_list)
        self.start_web_servers(self.l7_server_list)

    def build_l7_switching(self):
        subnet_id = self.subnet.get('id')
        lb_id = self.loadbalancer['id']
        l7_name = self.loadbalancer['name'] + "-7"
        redirect_to_listener_id = self.listener.get('id')
        # build_l7_pool(loadbalancer_id):
        self.pool7 = self.pools_client .create_pool(
            loadbalancer_id=lb_id,
            lb_algorithm=self.lb_algorithm, protocol=self.protocol_type,
            name=l7_name)['pool']
        self.wait_for_load_balancer_status(lb_id)
        pool_id = self.pool7['id']
        self.member7_list = []
        for server in self.l7_server_list:
            fip = server['_floating_ip']
            fixed_ip_address = fip['fixed_ip_address']
            member = self.members_client.create_member(
                pool_id, subnet_id=subnet_id,
                address=fixed_ip_address,
                protocol_port=self.protocol_port)
            self.wait_for_load_balancer_status(lb_id)
            self.member7_list.append(member)
        l7policy_kwargs = dict(action="REDIRECT_TO_POOL",
                               redirect_pool_id=pool_id,
                               listener_id=redirect_to_listener_id,
                               name='policy1')
        l7policy1 = self.l7policies_client.create_l7policy(**l7policy_kwargs)
        self.l7policy1 = l7policy1.get(u'l7policy', l7policy1)
        policy_id = self.l7policy1.get('id')
        self.l7rule1 = self.l7rules_client.create_l7rule(
            policy_id, **self.l7rule_kwargs)['rule']
        l7policy_kwargs = dict(action="REJECT", position=1,
                               redirect_pool_id=pool_id,
                               listener_id=redirect_to_listener_id,
                               name='policy-reject')
        l7policy1 = self.l7policies_client.create_l7policy(**l7policy_kwargs)
        self.l7policy_reject = l7policy1.get(u'l7policy', l7policy1)
        self.reject_policy_id = self.l7policy_reject.get('id')
        l7rule_kwargs = dict(type='PATH',
                             compare_type='STARTS_WITH',
                             value=self.reject_startswith)
        self.l7rule_reject = self.l7rules_client.create_l7rule(
            self.reject_policy_id, **l7rule_kwargs)['rule']

    def check_l7_switching(self, start_path, expected_server_list,
                           send_count=6):
        self.do_http_request(start_path, send_count)
        for sv_name, cnt in self.http_cnt.items():
            self.assertIn(sv_name, expected_server_list)
            self.assertTrue(cnt > 0)

    def validate_l7_switching(self):
        l7_sv_name_list = [s['name'] for s in self.l7_server_list]
        rr_sv_name_list = [s['name'] for s in self.rr_server_list]
        reject_name_list = ["403"]

        # URL prefix api switching to pool7
        self.check_l7_switching('api', l7_sv_name_list, 6)
        # URL prefix ap/i switching to pool1
        self.check_l7_switching('ap/i', rr_sv_name_list, 6)
        # URL prefix api2 switching to pool7
        self.check_l7_switching('api2', l7_sv_name_list, 6)

        # URL /api/v1 should be rejected, status=403
        self.check_l7_switching('api/v1', reject_name_list, 6)

        # change rule starts_with's value to /api2
        # and /api & /api/2 will be swithed to default pool
        policy_id = self.l7policy1.get('id')
        rule_id = self.l7rule1.get('id')
        self.l7rule_kwargs['value'] = self.switching_startswith_value2
        self.l7rule2 = self.l7rules_client.update_l7rule(
            policy_id, rule_id, **self.l7rule_kwargs)['rule']
        time.sleep(2.0)
        # URL prefix api switching to pool
        self.check_l7_switching('api', rr_sv_name_list, 6)
        # URL prefix api switching to pool
        self.check_l7_switching('api/2', rr_sv_name_list, 6)
        # URL prefix api2 switching to pool7
        self.check_l7_switching('api2', l7_sv_name_list, 6)
        # URL prefix api2 switching to pool
        self.check_l7_switching('xapi2', rr_sv_name_list, 6)

        # URL /api/v1 should be rejected, status=403
        self.check_l7_switching('api/v1', reject_name_list, 6)

    @test.idempotent_id('f11e19e4-16b5-41c7-878d-59b9e943e3ce')
    @test.services('compute', 'network')
    def test_lbaas_l7_switching_ops(self):
        self.create_lbaas_networks()
        self.start_web_servers()
        self.create_project_lbaas()
        self.check_project_lbaas()
        # do l7 provision and testing
        self.create_and_start_l7_web_servers()
        self.build_l7_switching()
        self.validate_l7_switching()
