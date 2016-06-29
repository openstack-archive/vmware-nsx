# Copyright 2013 OpenStack Foundation
# Copyright 2015 VMware Inc
# All Rights Reserved.
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

import six

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from tempest.api.network import base
from tempest import config
from tempest import test

from vmware_nsx_tempest.services import load_balancer_v1_client as LBV1C

CONF = config.CONF


class LoadBalancerTestJSON(base.BaseNetworkTest):
    """
    Tests the following operations in the Neutron API using the REST client
    for
    Neutron:

        create vIP, and Pool
        show vIP
        list vIP
        update vIP
        delete vIP
        update pool
        delete pool
        show pool
        list pool
        health monitoring operations
    """

    @classmethod
    def skip_checks(cls):
        super(LoadBalancerTestJSON, cls).skip_checks()
        if not test.is_extension_enabled('lbaas', 'network'):
            msg = "lbaas extension not enabled."
            raise cls.skipException(msg)
        if not test.is_extension_enabled('nsxv-router-type', 'network'):
            msg = "nsxv-router-type extension is not enabled"
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(LoadBalancerTestJSON, cls).resource_setup()
        _params = cls.manager.default_params_with_timeout_values.copy()
        for p in _params.keys():
            if p in ['service', 'region', 'endpoint_type']:
                _params.pop(p)
        cls.lbv1_client = LBV1C.get_client(cls.manager)
        cls.network = cls.create_network()
        cls.name = cls.network['name']
        cls.subnet = cls.create_subnet(cls.network)
        cls.ext_net_id = CONF.network.public_network_id
        cls.router = cls.create_router(data_utils.rand_name('router-'),
                                       admin_state_up=True,
                                       external_network_id=cls.ext_net_id,
                                       router_type='exclusive')
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        pool_name = data_utils.rand_name('pool-')
        vip_name = data_utils.rand_name('vip-')
        cls.pool = cls.lbv1_client.create_pool(
            pool_name, "ROUND_ROBIN", "HTTP", cls.subnet['id'])['pool']
        cls.vip = cls.lbv1_client.create_vip(cls.pool['id'],
                                             subnet_id=cls.subnet['id'],
                                             name=vip_name,
                                             protocol="HTTP",
                                             protocol_port=80)['vip']
        cls.member = cls.lbv1_client.create_member(
            80, cls.pool['id'], cls._ip_version)['member']
        cls.member_address = ("10.0.9.47" if cls._ip_version == 4
                              else "2015::beef")
        cls.health_monitor = cls.lbv1_client.create_health_monitor(
            delay=4, max_retries=3, type="TCP", timeout=1)['health_monitor']

    @classmethod
    def resource_cleanup(cls):
        """
        Cleanup the lb resources first and then call resource_cleanup
        in BaseNetworkTest to cleanup other network resources. NSX-v
        plugin requires the lb resources to be deleted before we can
        delete subnet or remove interface from router.
        """
        # Cleanup lb health monitors
        if cls.health_monitor:
            test_utils.call_and_ignore_notfound_exc(
                cls.lbv1_client.delete_health_monitor,
                cls.health_monitor['id'])
            cls.health_monitor = None

        # Cleanup members
        if cls.member:
            test_utils.call_and_ignore_notfound_exc(
                cls.lbv1_client.delete_member, cls.member['id'])
            cls.member = None

        # Cleanup vips
        if cls.vip:
            test_utils.call_and_ignore_notfound_exc(
                cls.lbv1_client.delete_vip, cls.vip['id'])
            cls.vip = None

        # Cleanup pool
        if cls.pool:
            test_utils.call_and_ignore_notfound_exc(
                cls.lbv1_client.delete_pool, cls.pool['id'])
            cls.pool = None

        super(LoadBalancerTestJSON, cls).resource_cleanup()

    def _check_list_with_filter(self, obj_name, attr_exceptions, **kwargs):
        create_obj = getattr(self.lbv1_client, 'create_' + obj_name)
        delete_obj = getattr(self.lbv1_client, 'delete_' + obj_name)
        list_objs = getattr(self.lbv1_client, 'list_' + obj_name + 's')

        body = create_obj(**kwargs)
        obj = body[obj_name]
        self.addCleanup(delete_obj, obj['id'])
        for key, value in six.iteritems(obj):
            # It is not relevant to filter by all arguments. That is why
            # there is a list of attr to except
            if key not in attr_exceptions:
                body = list_objs(**{key: value})
                objs = [v[key] for v in body[obj_name + 's']]
                self.assertIn(value, objs)

    @test.idempotent_id('1c959a37-feb3-4d58-b5fc-58ba653de065')
    def test_list_vips(self):
        # Verify the vIP exists in the list of all vIPs
        body = self.lbv1_client.list_vips()
        vips = body['vips']
        self.assertIn(self.vip['id'], [v['id'] for v in vips])

    @test.idempotent_id('687b7fd1-fd15-4ffd-8166-f376407a6081')
    def test_list_vips_with_filter(self):
        pool_name = data_utils.rand_name("pool-")
        vip_name = data_utils.rand_name('vip-')
        body = self.lbv1_client.create_pool(pool_name,
                                            lb_method="ROUND_ROBIN",
                                            protocol="HTTPS",
                                            subnet_id=self.subnet['id'])
        pool = body['pool']
        self.addCleanup(self.lbv1_client.delete_pool, pool['id'])
        attr_exceptions = ['status', 'session_persistence',
                           'status_description']
        self._check_list_with_filter(
            'vip', attr_exceptions, name=vip_name, protocol="HTTPS",
            protocol_port=81, subnet_id=self.subnet['id'], pool_id=pool['id'],
            description=data_utils.rand_name('description-'),
            admin_state_up=False)

    @test.idempotent_id('73dfc119-b64b-4e56-90d2-df61d7181098')
    def test_create_update_delete_pool_vip(self):
        # Creates a vip
        pool_name = data_utils.rand_name("pool-")
        vip_name = data_utils.rand_name('vip-')
        address = self.subnet['allocation_pools'][0]['end']
        body = self.lbv1_client.create_pool(
            pool_name,
            lb_method='ROUND_ROBIN',
            protocol='HTTP',
            subnet_id=self.subnet['id'])
        pool = body['pool']
        body = self.lbv1_client.create_vip(pool['id'],
                                           name=vip_name,
                                           protocol="HTTP",
                                           protocol_port=80,
                                           subnet_id=self.subnet['id'],
                                           address=address)
        vip = body['vip']
        vip_id = vip['id']
        # Confirm VIP's address correctness with a show
        body = self.lbv1_client.show_vip(vip_id)
        vip = body['vip']
        self.assertEqual(address, vip['address'])
        # Verification of vip update
        new_name = "New_vip"
        new_description = "New description"
        persistence_type = "HTTP_COOKIE"
        update_data = {"session_persistence": {
            "type": persistence_type}}
        body = self.lbv1_client.update_vip(vip_id,
                                           name=new_name,
                                           description=new_description,
                                           connection_limit=10,
                                           admin_state_up=False,
                                           **update_data)
        updated_vip = body['vip']
        self.assertEqual(new_name, updated_vip['name'])
        self.assertEqual(new_description, updated_vip['description'])
        self.assertEqual(10, updated_vip['connection_limit'])
        self.assertFalse(updated_vip['admin_state_up'])
        self.assertEqual(persistence_type,
                         updated_vip['session_persistence']['type'])
        self.lbv1_client.delete_vip(vip['id'])
        self.lbv1_client.wait_for_resource_deletion('vip', vip['id'])
        # Verification of pool update
        new_name = "New_pool"
        body = self.lbv1_client.update_pool(pool['id'],
                                            name=new_name,
                                            description="new_description",
                                            lb_method='LEAST_CONNECTIONS')
        updated_pool = body['pool']
        self.assertEqual(new_name, updated_pool['name'])
        self.assertEqual('new_description', updated_pool['description'])
        self.assertEqual('LEAST_CONNECTIONS', updated_pool['lb_method'])
        self.lbv1_client.delete_pool(pool['id'])

    @test.idempotent_id('277a99ce-4b3e-451d-a18a-d26c0376d176')
    def test_show_vip(self):
        # Verifies the details of a vip
        body = self.lbv1_client.show_vip(self.vip['id'])
        vip = body['vip']
        for key, value in six.iteritems(vip):
            # 'status' should not be confirmed in api tests
            if key != 'status':
                self.assertEqual(self.vip[key], value)

    @test.idempotent_id('432470dd-836b-4555-8388-af95a1c74d32')
    def test_show_pool(self):
        # Here we need to new pool without any dependence with vips
        pool_name = data_utils.rand_name("pool-")
        body = self.lbv1_client.create_pool(pool_name,
                                            lb_method='ROUND_ROBIN',
                                            protocol='HTTP',
                                            subnet_id=self.subnet['id'])
        pool = body['pool']
        self.addCleanup(self.lbv1_client.delete_pool, pool['id'])
        # Verifies the details of a pool
        body = self.lbv1_client.show_pool(pool['id'])
        shown_pool = body['pool']
        for key, value in six.iteritems(pool):
            # 'status' should not be confirmed in api tests
            if key != 'status':
                self.assertEqual(value, shown_pool[key])

    @test.idempotent_id('c9951820-7b24-4e67-8c0c-41065ec66071')
    def test_list_pools(self):
        # Verify the pool exists in the list of all pools
        body = self.lbv1_client.list_pools()
        pools = body['pools']
        self.assertIn(self.pool['id'], [p['id'] for p in pools])

    @test.idempotent_id('55a1fb8e-e88e-4042-a46a-13a0282e4990')
    def test_list_pools_with_filters(self):
        attr_exceptions = ['status', 'vip_id', 'members', 'provider',
                           'status_description']
        self._check_list_with_filter(
            'pool', attr_exceptions, name=data_utils.rand_name("pool-"),
            lb_method="ROUND_ROBIN", protocol="HTTPS",
            subnet_id=self.subnet['id'],
            description=data_utils.rand_name('description-'),
            admin_state_up=False)

    @test.idempotent_id('dd441433-de8f-4992-a721-0755dec737ff')
    def test_list_members(self):
        # Verify the member exists in the list of all members
        body = self.lbv1_client.list_members()
        members = body['members']
        self.assertIn(self.member['id'], [m['id'] for m in members])

    @test.idempotent_id('ccebe68a-f096-478d-b495-f17d5c0eac7b')
    def test_list_members_with_filters(self):
        attr_exceptions = ['status', 'status_description']
        self._check_list_with_filter('member', attr_exceptions,
                                     address=self.member_address,
                                     protocol_port=80,
                                     pool_id=self.pool['id'])

    @test.idempotent_id('b4efe862-0439-4260-828c-cc09ff7e12a6')
    def test_create_update_delete_member(self):
        # Creates a member
        body = self.lbv1_client.create_member(address=self.member_address,
                                              protocol_port=80,
                                              pool_id=self.pool['id'])
        member = body['member']
        # Verification of member update
        body = self.lbv1_client.update_member(member['id'],
                                              admin_state_up=False)
        updated_member = body['member']
        self.assertFalse(updated_member['admin_state_up'])
        # Verification of member delete
        self.lbv1_client.delete_member(member['id'])

    @test.idempotent_id('4806ca47-b3a0-4280-9962-6631c6815e93')
    def test_show_member(self):
        # Verifies the details of a member
        body = self.lbv1_client.show_member(self.member['id'])
        member = body['member']
        for key, value in six.iteritems(member):
            # 'status' should not be confirmed in api tests
            if key != 'status':
                self.assertEqual(self.member[key], value)

    @test.idempotent_id('65c4d817-d8d2-44df-9c15-86fc7b910044')
    def test_list_health_monitors(self):
        # Verify the health monitor exists in the list of all health monitors
        body = self.lbv1_client.list_health_monitors()
        health_monitors = body['health_monitors']
        self.assertIn(self.health_monitor['id'],
                      [h['id'] for h in health_monitors])

    @test.idempotent_id('a2c749a0-4eac-4acc-b729-6b469c3c616a')
    def test_list_health_monitors_with_filters(self):
        attr_exceptions = ['status', 'status_description', 'pools']
        self._check_list_with_filter('health_monitor', attr_exceptions,
                                     delay=5, max_retries=4, type="TCP",
                                     timeout=2)

    @test.idempotent_id('94f1e066-de6e-4cd8-b352-533d216956b7')
    def test_create_update_delete_health_monitor(self):
        # Creates a health_monitor
        body = self.lbv1_client.create_health_monitor(delay=4,
                                                      max_retries=3,
                                                      type="TCP",
                                                      timeout=1)
        health_monitor = body['health_monitor']
        # Verification of health_monitor update
        body = (self.lbv1_client.update_health_monitor
                (health_monitor['id'],
                 admin_state_up=False))
        updated_health_monitor = body['health_monitor']
        self.assertFalse(updated_health_monitor['admin_state_up'])
        # Verification of health_monitor delete
        body = self.lbv1_client.delete_health_monitor(health_monitor['id'])

    @test.idempotent_id('82943dcf-d424-43f0-890f-4b796f5043dc')
    def test_create_health_monitor_http_type(self):
        hm_type = "HTTP"
        body = self.lbv1_client.create_health_monitor(delay=4,
                                                      max_retries=3,
                                                      type=hm_type,
                                                      timeout=1)
        health_monitor = body['health_monitor']
        self.addCleanup(self.lbv1_client.delete_health_monitor,
                        health_monitor['id'])
        self.assertEqual(hm_type, health_monitor['type'])

    @test.idempotent_id('b1279c46-822a-4406-bb16-6a6ce7bf4e4e')
    def test_update_health_monitor_http_method(self):
        body = self.lbv1_client.create_health_monitor(delay=4,
                                                      max_retries=3,
                                                      type="HTTP",
                                                      timeout=1)
        health_monitor = body['health_monitor']
        self.addCleanup(self.lbv1_client.delete_health_monitor,
                        health_monitor['id'])
        body = (self.lbv1_client.update_health_monitor
                (health_monitor['id'],
                 http_method="POST",
                 url_path="/home/user",
                 expected_codes="290"))
        updated_health_monitor = body['health_monitor']
        self.assertEqual("POST", updated_health_monitor['http_method'])
        self.assertEqual("/home/user", updated_health_monitor['url_path'])
        self.assertEqual("290", updated_health_monitor['expected_codes'])

    @test.idempotent_id('7beabd44-0200-4cc4-b18d-5fb1f44cf36c')
    def test_show_health_monitor(self):
        # Verifies the details of a health_monitor
        body = self.lbv1_client.show_health_monitor(self.health_monitor['id'])
        health_monitor = body['health_monitor']
        for key, value in six.iteritems(health_monitor):
            # 'status' should not be confirmed in api tests
            if key != 'status':
                self.assertEqual(self.health_monitor[key], value)

    @test.idempotent_id('5386d600-1372-4f99-b0f2-316401718ac4')
    def test_associate_disassociate_health_monitor_with_pool(self):
        # Verify that a health monitor can be associated with a pool
        self.lbv1_client.associate_health_monitor_with_pool(
            self.health_monitor['id'], self.pool['id'])
        body = self.lbv1_client.show_health_monitor(
            self.health_monitor['id'])
        health_monitor = body['health_monitor']
        body = self.lbv1_client.show_pool(self.pool['id'])
        pool = body['pool']
        self.assertIn(pool['id'],
                      [p['pool_id'] for p in health_monitor['pools']])
        self.assertIn(health_monitor['id'], pool['health_monitors'])
        # Verify that a health monitor can be disassociated from a pool
        (self.lbv1_client.disassociate_health_monitor_with_pool
         (self.health_monitor['id'], self.pool['id']))
        body = self.lbv1_client.show_pool(self.pool['id'])
        pool = body['pool']
        body = self.lbv1_client.show_health_monitor(
            self.health_monitor['id'])
        health_monitor = body['health_monitor']
        self.assertNotIn(health_monitor['id'], pool['health_monitors'])
        self.assertNotIn(pool['id'],
                         [p['pool_id'] for p in health_monitor['pools']])

    @test.idempotent_id('17a6b730-0780-46c9-bca0-cec67387e469')
    def test_get_lb_pool_stats(self):
        # Verify the details of pool stats
        body = self.lbv1_client.list_lb_pool_stats(self.pool['id'])
        stats = body['stats']
        self.assertIn("bytes_in", stats)
        self.assertIn("total_connections", stats)
        self.assertIn("active_connections", stats)
        self.assertIn("bytes_out", stats)

    @test.idempotent_id('a113c740-6194-4622-a187-8343ad3e5208')
    def test_update_list_of_health_monitors_associated_with_pool(self):
        (self.lbv1_client.associate_health_monitor_with_pool
         (self.health_monitor['id'], self.pool['id']))
        self.lbv1_client.update_health_monitor(
            self.health_monitor['id'], admin_state_up=False)
        body = self.lbv1_client.show_pool(self.pool['id'])
        health_monitors = body['pool']['health_monitors']
        for health_monitor_id in health_monitors:
            body = self.lbv1_client.show_health_monitor(health_monitor_id)
            self.assertFalse(body['health_monitor']['admin_state_up'])
            (self.lbv1_client.disassociate_health_monitor_with_pool
             (self.health_monitor['id'], self.pool['id']))

    @test.idempotent_id('a2843ec6-80d8-4617-b985-8c8565daac8d')
    def test_update_admin_state_up_of_pool(self):
        self.lbv1_client.update_pool(self.pool['id'],
                                     admin_state_up=False)
        body = self.lbv1_client.show_pool(self.pool['id'])
        pool = body['pool']
        self.assertFalse(pool['admin_state_up'])

    @test.idempotent_id('fd45c684-b847-472f-a7e8-a3f70e8e08e0')
    def test_show_vip_associated_with_pool(self):
        body = self.lbv1_client.show_pool(self.pool['id'])
        pool = body['pool']
        body = self.lbv1_client.show_vip(pool['vip_id'])
        vip = body['vip']
        self.assertEqual(self.vip['name'], vip['name'])
        self.assertEqual(self.vip['id'], vip['id'])

    @test.idempotent_id('1ac0ca5f-7d6a-4ac4-b286-d68c92a98405')
    def test_show_members_associated_with_pool(self):
        body = self.lbv1_client.show_pool(self.pool['id'])
        members = body['pool']['members']
        for member_id in members:
            body = self.lbv1_client.show_member(member_id)
            self.assertIsNotNone(body['member']['status'])
            self.assertEqual(member_id, body['member']['id'])
            self.assertIsNotNone(body['member']['admin_state_up'])

    @test.idempotent_id('4fa308fa-ac2b-4acf-87db-adfe2ee4739c')
    def test_update_pool_related_to_member(self):
        # Create new pool
        pool_name = data_utils.rand_name("pool-")
        body = self.lbv1_client.create_pool(
            pool_name,
            lb_method='ROUND_ROBIN',
            protocol='HTTP',
            subnet_id=self.subnet['id'])
        new_pool = body['pool']
        self.addCleanup(self.lbv1_client.delete_pool, new_pool['id'])
        # Update member with new pool's id
        body = self.lbv1_client.update_member(self.member['id'],
                                              pool_id=new_pool['id'])
        # Confirm with show that pool_id change
        body = self.lbv1_client.show_member(self.member['id'])
        member = body['member']
        self.assertEqual(member['pool_id'], new_pool['id'])
        # Update member with old pool id, this is needed for clean up
        body = self.lbv1_client.update_member(self.member['id'],
                                              pool_id=self.pool['id'])

    @test.idempotent_id('0af2ff6b-a896-433d-8107-3c76262a9dfa')
    def test_update_member_weight(self):
        self.lbv1_client.update_member(self.member['id'],
                                       weight=2)
        body = self.lbv1_client.show_member(self.member['id'])
        member = body['member']
        self.assertEqual(2, member['weight'])


@decorators.skip_because(bug="1402007")
class LoadBalancerIpV6TestJSON(LoadBalancerTestJSON):
    _ip_version = 6
