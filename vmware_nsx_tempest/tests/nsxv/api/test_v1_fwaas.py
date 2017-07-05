# Copyright 2014 NEC Corporation. All rights reserved.
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

import re
import time

from neutron_lib import constants as nl_constants
import six
from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
from tempest import test

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.services import fwaas_client as FWAASC
from vmware_nsx_tempest.services import nsxv_client

CONF = config.CONF


class FWaaSTestJSON(base.BaseNetworkTest):

    """
    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        CRUD firewall rules
        CRUD firewall policies
        CRUD firewall rules
        Insert firewall rule to policy
        Remove firewall rule from policy
        Insert firewall rule after/before rule in policy
        Update firewall policy audited attribute
        Create exclusive router and attach to Firewall and check backend
        Create distributed router and attach to Firewall and check backend
        Create exclusive/distributed router and attach to Firewall and
        check backend
    """
    @classmethod
    def resource_setup(cls):
        super(FWaaSTestJSON, cls).resource_setup()
        cls.fwaasv1_client = FWAASC.get_client(cls.manager)
        if not test.is_extension_enabled('fwaas', 'network'):
            msg = "FWaaS Extension not enabled."
            raise cls.skipException(msg)
        manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                               CONF.nsxv.manager_uri).group(0)
        cls.vsm = nsxv_client.VSMClient(
            manager_ip, CONF.nsxv.user, CONF.nsxv.password)

        cls.fw_rule = cls.fwaasv1_client.create_firewall_rule(action="allow",
                                                              protocol="tcp")
        cls.fw_policy = cls.fwaasv1_client.create_firewall_policy()

    def create_firewall_rule(self, **kwargs):
        body = self.fwaasv1_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            **kwargs)
        fw_rule = body['firewall_rule']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.fwaasv1_client.delete_firewall_rule,
                        fw_rule['id'])
        return fw_rule

    def create_firewall_policy(self, **kwargs):
        body = self.fwaasv1_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"),
            **kwargs)
        fw_policy = body['firewall_policy']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.fwaasv1_client.delete_firewall_policy,
                        fw_policy['id'])
        return fw_policy

    def delete_firewall_and_wait(self, firewall_id):
        self.fwaasv1_client.delete_firewall(firewall_id)
        self._wait_firewall_while(firewall_id, [nl_constants.PENDING_DELETE],
                                  not_found_ok=True)

    def create_firewall(self, **kwargs):
        body = self.fwaasv1_client.create_firewall(
            name=data_utils.rand_name("fw"),
            **kwargs)
        fw = body['firewall']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_firewall_and_wait,
                        fw['id'])
        return fw

    def _wait_firewall_while(self, firewall_id, statuses, not_found_ok=False):
        start = int(time.time())
        if not_found_ok:
            expected_exceptions = (lib_exc.NotFound)
        else:
            expected_exceptions = ()
        while True:
            try:
                fw = self.fwaasv1_client.show_firewall(firewall_id)
            except expected_exceptions:
                break
            status = fw['firewall']['status']
            if status not in statuses:
                break
            if int(time.time()) - start >= self.fwaasv1_client.build_timeout:
                msg = ("Firewall %(firewall)s failed to reach "
                       "non PENDING status (current %(status)s)") % {
                    "firewall": firewall_id,
                    "status": status,
                }
                raise lib_exc.TimeoutException(msg)
            time.sleep(constants.NSX_BACKEND_VERY_SMALL_TIME_INTERVAL)

    def _wait_firewall_ready(self, firewall_id):
        self._wait_firewall_while(firewall_id,
                                  [nl_constants.PENDING_CREATE,
                                   nl_constants.PENDING_UPDATE])

    def _try_delete_router(self, router):
        # delete router, if it exists
        try:
            self.delete_router(router)
        # if router is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _try_delete_policy(self, policy_id):
        # delete policy, if it exists
        try:
            self.fwaasv1_client.delete_firewall_policy(policy_id)
        # if policy is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _try_delete_rule(self, rule_id):
        # delete rule, if it exists
        try:
            self.fwaasv1_client.delete_firewall_rule(rule_id)
        # if rule is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _try_delete_firewall(self, fw_id):
        # delete firewall, if it exists
        try:
            self.fwaasv1_client.delete_firewall(fw_id)
        # if firewall is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass
        self.fwaasv1_client.wait_for_resource_deletion(fw_id)

    def _wait_until_ready(self, fw_id):
        target_states = ('ACTIVE', 'CREATED')

        def _wait():
            firewall = self.fwaasv1_client.show_firewall(fw_id)
            firewall = firewall['firewall']
            return firewall['status'] in target_states
        if not test_utils.call_until_true(_wait, CONF.network.build_timeout,
                                          CONF.network.build_interval):
            m = ("Timed out waiting for firewall %s to reach %s state(s)" %
                 (fw_id, target_states))
            raise lib_exc.TimeoutException(m)

    def _wait_until_deleted(self, fw_id):
        def _wait():
            try:
                firewall = self.fwaasv1_client.show_firewall(fw_id)
            except lib_exc.NotFound:
                return True
            fw_status = firewall['firewall']['status']
            if fw_status == 'ERROR':
                raise lib_exc.DeleteErrorException(resource_id=fw_id)

        if not test_utils.call_until_true(_wait, CONF.network.build_timeout,
                                          CONF.network.build_interval):
            m = ("Timed out waiting for firewall %s deleted" % fw_id)
            raise lib_exc.TimeoutException(m)

    def _check_firewall_rule_exists_at_backend(self, rules,
                                               firewall_rule_name):
        for rule in rules:
            if rule['name'] in firewall_rule_name:
                self.assertIn(rule['name'], firewall_rule_name)
                return True
        return False

    def _create_firewall_rule_name(self, body):
        firewall_rule_name = body['firewall_rule']['name']
        firewall_rule_name = "Fwaas-" + firewall_rule_name
        return firewall_rule_name

    def _create_firewall_advanced_topo(self, router_type):
        fw_rule_id_list = []
        router = self.create_router_by_type(router_type)
        self.addCleanup(self._try_delete_router, router)
        edges = self.vsm.get_all_edges()
        for key in edges:
            if router['name'] in key['name']:
                edge_id = key['id']
                break
        rules = self.vsm.get_edge_firewall_rules(edge_id)
        rules_before = len(rules)
        for rule_id in range(0, constants.NO_OF_ENTRIES):
            if rule_id % 2 == 0:
                action = "allow"
                protocol = "tcp"
            else:
                action = "allow"
                protocol = "udp"
            firewall_rule = self.fwaasv1_client.create_firewall_rule(
                name=data_utils.rand_name("fw-rule"),
                action=action,
                protocol=protocol)
            fw_rule_id = firewall_rule['firewall_rule']['id']
            firewall_name = self._create_firewall_rule_name(firewall_rule)
            self.addCleanup(self._try_delete_rule, fw_rule_id)
            fw_rule_id_list.append(fw_rule_id)
        # Update firewall policy
        body = self.fwaasv1_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)
        # Insert rule to firewall policy
        for fw_rule_id in fw_rule_id_list:
            self.fwaasv1_client.insert_firewall_rule_in_policy(
                fw_policy_id, fw_rule_id, '', '')
        firewall_1 = self.fwaasv1_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=fw_policy_id,
            router_ids=[router['id']])
        created_firewall = firewall_1['firewall']
        self.addCleanup(self._try_delete_firewall, created_firewall['id'])
        # Wait for the firewall resource to become ready
        self._wait_until_ready(created_firewall['id'])
        firewall_topo = dict(router=router, firewall_name=firewall_name,
                             fw_policy_id=fw_policy_id,
                             firewall_id=created_firewall['id'],
                             rules_before=rules_before)
        return firewall_topo

    def _create_firewall_basic_topo(self, router_type, policy=None):
        router = self.create_router_by_type(router_type)
        self.addCleanup(self._try_delete_router, router)
        body = self.fwaasv1_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="tcp")
        fw_rule_id1 = body['firewall_rule']['id']
        firewall_name = self._create_firewall_rule_name(body)
        self.addCleanup(self._try_delete_rule, fw_rule_id1)
        # Create firewall policy
        if not policy:
            body = self.fwaasv1_client.create_firewall_policy(
                name=data_utils.rand_name("fw-policy"))
            fw_policy_id = body['firewall_policy']['id']
            self.addCleanup(self._try_delete_policy, fw_policy_id)
            # Insert rule to firewall policy
            self.fwaasv1_client.insert_firewall_rule_in_policy(
                fw_policy_id, fw_rule_id1, '', '')
        else:
            fw_policy_id = policy
        # Create firewall
        firewall_1 = self.fwaasv1_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=fw_policy_id,
            router_ids=[router['id']])
        created_firewall = firewall_1['firewall']
        self.addCleanup(self._try_delete_firewall, created_firewall['id'])
        # Wait for the firewall resource to become ready
        self._wait_until_ready(created_firewall['id'])
        firewall_topo = dict(router=router, firewall_name=firewall_name,
                             fw_policy_id=fw_policy_id,
                             fw_rule_id1=fw_rule_id1,
                             firewall_id=created_firewall['id'])
        return firewall_topo

    def _get_list_fw_rule_ids(self, fw_policy_id):
        fw_policy = self.fwaasv1_client.show_firewall_policy(
            fw_policy_id)
        return [ruleid for ruleid in fw_policy['firewall_policy']
                ['firewall_rules']]

    def create_router_by_type(self, router_type, name=None, **kwargs):
        routers_client = self.manager.routers_client
        router_name = name or data_utils.rand_name('mtz-')
        create_kwargs = dict(name=router_name, external_gateway_info={
            "network_id": CONF.network.public_network_id})
        if router_type in ('shared', 'exclusive'):
            create_kwargs['router_type'] = router_type
        elif router_type in ('distributed'):
            create_kwargs['distributed'] = True
        kwargs.update(create_kwargs)
        router = routers_client.create_router(**kwargs)
        router = router['router'] if 'router' in router else router
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        routers_client.delete_router, router['id'])
        self.assertEqual(router['name'], router_name)
        return router

    @test.attr(type='nsxv')
    @decorators.idempotent_id('c72197f1-b5c6-453f-952e-007acea6df86')
    def test_list_firewall_rules(self):
        # List firewall rules
        fw_rules = self.fwaasv1_client.list_firewall_rules()
        fw_rules = fw_rules['firewall_rules']
        self.assertEqual(self.fw_rule['firewall_rule']['id'],
                         fw_rules[0]['id'])
        self.assertEqual(self.fw_rule['firewall_rule']['name'],
                         fw_rules[0]['name'])
        self.assertEqual(self.fw_rule['firewall_rule']['action'],
                         fw_rules[0]['action'])
        self.assertEqual(self.fw_rule['firewall_rule']['protocol'],
                         fw_rules[0]['protocol'])
        self.assertEqual(self.fw_rule['firewall_rule']['enabled'],
                         fw_rules[0]['enabled'])

    @test.attr(type='nsxv')
    @decorators.idempotent_id('ef92ba0d-f7c2-46cb-ad4b-21c62cfa85a0')
    def test_create_update_delete_firewall_rule(self):
        # Create firewall rule
        body = self.fwaasv1_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="tcp")
        fw_rule_id = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id)

        # Update firewall rule
        body = self.fwaasv1_client.update_firewall_rule(fw_rule_id,
                                                        action="deny")
        self.assertEqual("deny", body["firewall_rule"]['action'])

        # Delete firewall rule
        self.fwaasv1_client.delete_firewall_rule(fw_rule_id)
        # Confirm deletion
        fw_rules = self.fwaasv1_client.list_firewall_rules()
        self.assertNotIn(fw_rule_id,
                         [m['id'] for m in fw_rules['firewall_rules']])

    @test.attr(type='nsxv')
    @decorators.idempotent_id('264e8b67-a1ef-4ba1-8757-808b249a5320')
    def test_show_firewall_rule(self):
        # show a created firewall rule
        fw_rule = self.fwaasv1_client.show_firewall_rule(
            self.fw_rule['firewall_rule']['id'])
        for key, value in six.iteritems(fw_rule['firewall_rule']):
            self.assertEqual(self.fw_rule['firewall_rule'][key], value)

    @test.attr(type='nsxv')
    @decorators.idempotent_id('029cd998-9dd4-4a0a-b79d-8bafd8223bda')
    def test_list_firewall_policies(self):
        fw_policies = self.fwaasv1_client.list_firewall_policies()
        fw_policies = fw_policies['firewall_policies']
        self.assertEqual(self.fw_policy['firewall_policy']['id'],
                         fw_policies[0]['id'])
        self.assertEqual(self.fw_policy['firewall_policy']['name'],
                         fw_policies[0]['name'])
        self.assertEqual(self.fw_policy['firewall_policy']['firewall_rules'],
                         fw_policies[0]['firewall_rules'])

    @test.attr(type='nsxv')
    @decorators.idempotent_id('28c261c8-4fb3-4630-8a9b-707c93536a54')
    def test_create_update_delete_firewall_policy(self):
        # Create firewall policy
        body = self.fwaasv1_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)

        # Update firewall policy
        body = self.fwaasv1_client.update_firewall_policy(
            fw_policy_id,
            name="updated_policy")
        updated_fw_policy = body["firewall_policy"]
        self.assertEqual("updated_policy", updated_fw_policy['name'])

        # Delete firewall policy
        self.fwaasv1_client.delete_firewall_policy(fw_policy_id)
        # Confirm deletion
        fw_policies = self.fwaasv1_client.list_firewall_policies()
        fw_policies = fw_policies['firewall_policies']
        self.assertNotIn(fw_policy_id, [m['id'] for m in fw_policies])

    @test.attr(type='nsxv')
    @decorators.idempotent_id('8bc7ad6d-4163-4def-9e1d-b9d24d9e8bf8')
    def test_show_firewall_policy(self):
        # show a created firewall policy
        fw_policy = self.fwaasv1_client.show_firewall_policy(
            self.fw_policy['firewall_policy']['id'])
        fw_policy = fw_policy['firewall_policy']
        for key, value in six.iteritems(fw_policy):
            self.assertEqual(self.fw_policy['firewall_policy'][key], value)

    @test.attr(type='nsxv')
    @decorators.idempotent_id('0c320840-f3e4-4960-987d-a6f06d327fe1')
    def test_create_show_delete_firewall(self):
        # Create tenant network resources required for an ACTIVE firewall
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router_by_type('exclusive')
        self.addCleanup(self._try_delete_router, router)
        self.routers_client.add_router_interface(router['id'],
                                                 subnet_id=subnet['id'])
        # Create firewall
        body = self.fwaasv1_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['firewall_policy']['id'])
        created_firewall = body['firewall']
        firewall_id = created_firewall['id']
        self.addCleanup(self._try_delete_firewall, firewall_id)
        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)
        # show a created firewall
        firewall = self.fwaasv1_client.show_firewall(firewall_id)
        firewall = firewall['firewall']
        for key, value in six.iteritems(firewall):
            if key == 'status':
                continue
            self.assertEqual(created_firewall[key], value)
        # list firewall
        firewalls = self.fwaasv1_client.list_firewalls()
        firewalls = firewalls['firewalls']
        # Delete firewall
        self.fwaasv1_client.delete_firewall(firewall_id)
        # Wait for the firewall resource to be deleted
        self._wait_until_deleted(firewall_id)
        # Confirm deletion
        firewalls = self.fwaasv1_client.list_firewalls()['firewalls']
        self.assertNotIn(firewall_id, [m['id'] for m in firewalls])

    @test.attr(type='nsxv')
    @decorators.idempotent_id('d9b23b3a-66ea-4591-9f8f-fa5a71fe0645')
    def test_firewall_insertion_mode_add_remove_mix_router(self):
        # Create legacy routers
        router1 = self.create_router_by_type('exclusive')
        self.addCleanup(self._try_delete_router, router1)
        router2 = self.create_router_by_type('distributed')
        self.addCleanup(self._try_delete_router, router2)

        # Create firewall on a router1
        body = self.fwaasv1_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['firewall_policy']['id'],
            router_ids=[router1['id']])
        created_firewall = body['firewall']
        firewall_id = created_firewall['id']
        self.addCleanup(self._try_delete_firewall, firewall_id)
        self.assertEqual([router1['id']], created_firewall['router_ids'])
        # Legacy routers are scheduled on L3 agents on network plug events
        # Hence firewall resource will not became ready at this stage
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.routers_client.add_router_interface(router1['id'],
                                                 subnet_id=subnet['id'])
        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)
        # Add router2 to the firewall
        body = self.fwaasv1_client.update_firewall(
            firewall_id, router_ids=[router1['id'], router2['id']])
        updated_firewall = body['firewall']
        self.assertIn(router2['id'], updated_firewall['router_ids'])
        self.assertEqual(2, len(updated_firewall['router_ids']))
        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)
        # Remove router1 from the firewall
        body = self.fwaasv1_client.update_firewall(
            firewall_id, router_ids=[router2['id']])
        updated_firewall = body['firewall']
        self.assertNotIn(router1['id'], updated_firewall['router_ids'])
        self.assertEqual(1, len(updated_firewall['router_ids']))

    @test.attr(type='nsxv')
    @decorators.idempotent_id('964e0254-e7f2-4bbe-a4c8-db09da8d79ee')
    def test_firewall_insertion_mode_add_remove_router(self):
        # Create legacy routers
        router1 = self.create_router_by_type('exclusive')
        self.addCleanup(self._try_delete_router, router1)
        router2 = self.create_router_by_type('exclusive')
        self.addCleanup(self._try_delete_router, router2)

        # Create firewall on a router1
        body = self.fwaasv1_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['firewall_policy']['id'],
            router_ids=[router1['id']])
        created_firewall = body['firewall']
        firewall_id = created_firewall['id']
        self.addCleanup(self._try_delete_firewall, firewall_id)

        self.assertEqual([router1['id']], created_firewall['router_ids'])

        # Legacy routers are scheduled on L3 agents on network plug events
        # Hence firewall resource will not became ready at this stage
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.routers_client.add_router_interface(router1['id'],
                                                 subnet_id=subnet['id'])
        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)

        # Add router2 to the firewall
        body = self.fwaasv1_client.update_firewall(
            firewall_id, router_ids=[router1['id'], router2['id']])
        updated_firewall = body['firewall']
        self.assertIn(router2['id'], updated_firewall['router_ids'])
        self.assertEqual(2, len(updated_firewall['router_ids']))

        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)

        # Remove router1 from the firewall
        body = self.fwaasv1_client.update_firewall(
            firewall_id, router_ids=[router2['id']])
        updated_firewall = body['firewall']
        self.assertNotIn(router1['id'], updated_firewall['router_ids'])
        self.assertEqual(1, len(updated_firewall['router_ids']))

    @test.attr(type='nsxv')
    @decorators.idempotent_id('662b252f-fa1b-49fe-8599-a37feab9fae8')
    def test_firewall_insertion_one_policy_two_router_backend(self):
        # Create router required for an ACTIVE firewall
        edge_id_excl = 0
        edge_id_dist = 0
        firewall_topo1 = self._create_firewall_basic_topo('exclusive')
        firewall_topo2 = \
            self._create_firewall_basic_topo('distributed',
                                             firewall_topo1['fw_policy_id'])
        edges = self.vsm.get_all_edges()
        firewall_topo2['router']['name'] += '-plr'
        for key in edges:
            if firewall_topo1['router']['name'] in key['name']:
                edge_id_excl = key['id']
            if firewall_topo2['router']['name'] in key['name']:
                edge_id_dist = key['id']
            if edge_id_excl and edge_id_dist:
                break
        rules = self.vsm.get_edge_firewall_rules(edge_id_excl)
        self.assertEqual(
            True, self._check_firewall_rule_exists_at_backend(
                rules, firewall_topo1['firewall_name']))
        rules = self.vsm.get_edge_firewall_rules(edge_id_dist)
        self.assertEqual(
            True, self._check_firewall_rule_exists_at_backend(
                rules, firewall_topo1['firewall_name']))

    @test.attr(type='nsxv')
    @decorators.idempotent_id('00330ef3-0a2e-4556-84d1-448d09c5ca2e')
    def test_firewall_insertion_two_policy_two_router_backend(self):
        # Create router required for an ACTIVE firewall
        edge_id_excl = 0
        edge_id_dist = 0
        firewall_topo1 = self._create_firewall_basic_topo('exclusive')
        firewall_topo2 = self._create_firewall_basic_topo('distributed')
        edges = self.vsm.get_all_edges()
        for key in edges:
            if firewall_topo1['router']['name'] in key['name']:
                edge_id_excl = key['id']
            if firewall_topo2['router']['name'] in key['name']:
                edge_id_dist = key['id']
            if edge_id_excl and edge_id_dist:
                break
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        rules = self.vsm.get_edge_firewall_rules(edge_id_excl)
        self.assertEqual(
            True, self._check_firewall_rule_exists_at_backend(
                rules, firewall_topo1['firewall_name']))
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        rules = self.vsm.get_edge_firewall_rules(edge_id_dist)
        self.assertEqual(
            True, self._check_firewall_rule_exists_at_backend(
                rules, firewall_topo2['firewall_name']))

    @test.attr(type='nsxv')
    @decorators.idempotent_id('8092bd48-e4c1-4709-8a3b-70e7bf6a78c9')
    def test_firewall_insertion_mode_two_firewall_rules_check_backend(self):
        rule_no = 1
        # Create router required for an ACTIVE firewall
        firewall_topo = self._create_firewall_basic_topo('exclusive')
        # Create second firewall rule
        firewall_rule_2 = self.fwaasv1_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="deny",
            protocol="icmp")
        fw_rule_id2 = firewall_rule_2['firewall_rule']['id']
        firewall_rule_name_2 = \
            "Fwaas-" + firewall_rule_2['firewall_rule']['name']
        self.addCleanup(self._try_delete_rule, fw_rule_id2)
        self.addCleanup(self._try_delete_policy, firewall_topo['fw_policy_id'])
        self.addCleanup(self._try_delete_firewall,
                        firewall_topo['firewall_id'])
        # Insert rule-2 to firewall policy
        self.fwaasv1_client.insert_firewall_rule_in_policy(
            firewall_topo['fw_policy_id'], fw_rule_id2, '',
            firewall_topo['fw_rule_id1'])
        self._wait_firewall_ready(firewall_topo['firewall_id'])
        edges = self.vsm.get_all_edges()
        for key in edges:
            if firewall_topo['router']['name'] in key['name']:
                edge_id = key['id']
                break
        rules = self.vsm.get_edge_firewall_rules(edge_id)
        for rule in rules:
            if rule['name'] in ('VSERule', 'MDServiceIP', 'MDInterEdgeNet'):
                continue
            if rule_no == 1:
                self.assertIn(rule['name'], firewall_rule_name_2,
                              "Rule exists at position 1")
                rule_no += rule_no
                continue
            if rule_no == 2:
                self.assertIn(rule['name'], firewall_topo['firewall_name'],
                              "Rule exists at position 2")
                break

    @test.attr(type='nsxv')
    @decorators.idempotent_id('da65de07-a60f-404d-ad1d-2d2c71a3b6a5')
    def test_firewall_add_delete_between_routers(self):
        firewall_topo = self._create_firewall_basic_topo('exclusive')
        router = self.create_router_by_type('exclusive')
        self.addCleanup(self._try_delete_router, router)
        self.fwaasv1_client.update_firewall(
            firewall_topo['firewall_id'],
            router_ids=[router['id']])
        self._wait_firewall_ready(firewall_topo['firewall_id'])
        edges = self.vsm.get_all_edges()
        for key in edges:
            if router['name'] in key['name']:
                edge_id = key['id']
                break
        rules = self.vsm.get_edge_firewall_rules(edge_id)
        self.assertEqual(
            True, self._check_firewall_rule_exists_at_backend(
                rules,
                firewall_topo['firewall_name']))
        self.fwaasv1_client.update_firewall(
            firewall_topo['firewall_id'],
            router_ids=[router['id'], firewall_topo['router']['id']])
        self._wait_firewall_ready(firewall_topo['firewall_id'])
        rules = self.vsm.get_edge_firewall_rules(edge_id)
        self.assertEqual(
            True, self._check_firewall_rule_exists_at_backend(
                rules, firewall_topo['firewall_name']))
        edges = self.vsm.get_all_edges()
        for key in edges:
            if firewall_topo['router']['name'] in key['name']:
                edge_id = key['id']
                break
        rules = self.vsm.get_edge_firewall_rules(edge_id)
        self.assertEqual(
            True, self._check_firewall_rule_exists_at_backend(
                rules, firewall_topo['firewall_name']))

    @test.attr(type='nsxv')
    @decorators.idempotent_id('c60ceff5-d51f-451d-b6e6-cb983d16ab6b')
    def test_firewall_insertion_with_multiple_rules_check_backend(self):
        # Create router required for an ACTIVE firewall
        firewall_topo = self._create_firewall_basic_topo('exclusive')
        edges = self.vsm.get_all_edges()
        for key in edges:
            if firewall_topo['router']['name'] in key['name']:
                edge_id = key['id']
                break
        rules = self.vsm.get_edge_firewall_rules(edge_id)
        self.assertEqual(
            True, self._check_firewall_rule_exists_at_backend(
                rules, firewall_topo['firewall_name']))
        firewall_rule_2 = self.fwaasv1_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="tcp")
        fw_rule_id2 = firewall_rule_2['firewall_rule']['id']
        firewall_name_2 = self._create_firewall_rule_name(firewall_rule_2)
        self.addCleanup(self._try_delete_rule, fw_rule_id2)
        # Update firewall policy
        self.fwaasv1_client.insert_firewall_rule_in_policy(
            firewall_topo['fw_policy_id'], fw_rule_id2,
            firewall_topo['fw_rule_id1'], '')
        self._wait_firewall_ready(firewall_topo['firewall_id'])
        rules = self.vsm.get_edge_firewall_rules(edge_id)
        self.assertEqual(
            True, self._check_firewall_rule_exists_at_backend(
                rules, firewall_name_2))
        firewall_rule_3 = self.fwaasv1_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="tcp")
        fw_rule_id3 = firewall_rule_3['firewall_rule']['id']
        firewall_name_3 = self._create_firewall_rule_name(firewall_rule_3)
        self.addCleanup(self._try_delete_rule, fw_rule_id3)
        # Update firewall policy
        self.fwaasv1_client.insert_firewall_rule_in_policy(
            firewall_topo['fw_policy_id'], fw_rule_id3, fw_rule_id2, '')
        self._wait_firewall_ready(firewall_topo['firewall_id'])
        self.addCleanup(self._try_delete_policy, firewall_topo['fw_policy_id'])
        self.addCleanup(self._try_delete_firewall,
                        firewall_topo['firewall_id'])
        rules = self.vsm.get_edge_firewall_rules(edge_id)
        self.assertEqual(
            True, self._check_firewall_rule_exists_at_backend(
                rules, firewall_name_3))

    @test.attr(type='nsxv')
    @decorators.idempotent_id('a1734149-9c4b-46d3-86c8-d61f57458095')
    def test_firewall_add_remove_rule_check_backend(self):
        # Create router required for an ACTIVE firewall
        firewall_topo = self._create_firewall_basic_topo('exclusive')
        edges = self.vsm.get_all_edges()
        for key in edges:
            if firewall_topo['router']['name'] in key['name']:
                edge_id = key['id']
                break
        rules = self.vsm.get_edge_firewall_rules(edge_id)
        self.assertEqual(
            True, self._check_firewall_rule_exists_at_backend(
                rules, firewall_topo['firewall_name']))
        self.fwaasv1_client.remove_firewall_rule_from_policy(
            firewall_topo['fw_policy_id'], firewall_topo['fw_rule_id1'])
        self.delete_firewall_and_wait(firewall_topo['firewall_id'])
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        rules = self.vsm.get_edge_firewall_rules(edge_id)
        self.assertEqual(
            False, self._check_firewall_rule_exists_at_backend(
                rules, firewall_topo['firewall_name']))

    @test.attr(type='nsxv')
    @decorators.idempotent_id('e1111959-c36a-41d6-86ee-ea6c0b927eb3')
    def test_firewall_insertion_mode_one_firewall_rule_check_backend(self):
        # Create router required for an ACTIVE firewall
        firewall_topo = self._create_firewall_basic_topo('exclusive')
        edges = self.vsm.get_all_edges()
        for key in edges:
            if firewall_topo['router']['name'] in key['name']:
                edge_id = key['id']
                break
        rules = self.vsm.get_edge_firewall_rules(edge_id)
        self.assertEqual(
            True, self._check_firewall_rule_exists_at_backend(
                rules, firewall_topo['firewall_name']))

    @test.attr(type='nsxv')
    @decorators.idempotent_id('e434b3c9-1148-499a-bb52-b094cdb0a186')
    def test_firewall_insertion_mode_one_firewall_per_router(self):
        # Create router required for an ACTIVE firewall
        firewall_topo = self._create_firewall_basic_topo('exclusive')
        # Try to create firewall with the same router
        self.assertRaisesRegexp(
            lib_exc.Conflict,
            "already associated with other Firewall",
            self.fwaasv1_client.create_firewall,
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['firewall_policy']['id'],
            router_ids=[firewall_topo['router']['id']])

    @test.attr(type='nsxv')
    @decorators.idempotent_id('d162abb2-9c14-45d6-bed1-06646a66803a')
    def test_firewall_insertion_mode_one_firewall_per_dist_router(self):
        # Create router required for an ACTIVE firewall
        firewall_topo = self._create_firewall_basic_topo('distributed')
        # Try to create firewall with the same router
        self.assertRaisesRegexp(
            lib_exc.Conflict,
            "already associated with other Firewall",
            self.fwaasv1_client.create_firewall,
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['firewall_policy']['id'],
            router_ids=[firewall_topo['router']['id']])

    @test.attr(type='nsxv')
    @decorators.idempotent_id('d5531558-9b18-40bc-9388-3eded0894a85')
    def test_firewall_rule_insertion_position_removal_rule_from_policy(self):
        # Create firewall rule
        body = self.fwaasv1_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="tcp")
        fw_rule_id1 = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id1)
        # Create firewall policy
        body = self.fwaasv1_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)
        # Insert rule to firewall policy
        self.fwaasv1_client.insert_firewall_rule_in_policy(
            fw_policy_id, fw_rule_id1, '', '')
        # Verify insertion of rule in policy
        self.assertIn(fw_rule_id1, self._get_list_fw_rule_ids(fw_policy_id))
        # Create another firewall rule
        body = self.fwaasv1_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="icmp")
        fw_rule_id2 = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id2)
        # Insert rule to firewall policy after the first rule
        self.fwaasv1_client.insert_firewall_rule_in_policy(
            fw_policy_id, fw_rule_id2, fw_rule_id1, '')
        # Verify the position of rule after insertion
        fw_rule = self.fwaasv1_client.show_firewall_rule(
            fw_rule_id2)
        self.assertEqual(int(fw_rule['firewall_rule']['position']), 2)
        # Remove rule from the firewall policy
        self.fwaasv1_client.remove_firewall_rule_from_policy(
            fw_policy_id, fw_rule_id2)
        # Insert rule to firewall policy before the first rule
        self.fwaasv1_client.insert_firewall_rule_in_policy(
            fw_policy_id, fw_rule_id2, '', fw_rule_id1)
        # Verify the position of rule after insertion
        fw_rule = self.fwaasv1_client.show_firewall_rule(
            fw_rule_id2)
        self.assertEqual(int(fw_rule['firewall_rule']['position']), 1)
        # Remove rule from the firewall policy
        self.fwaasv1_client.remove_firewall_rule_from_policy(
            fw_policy_id, fw_rule_id2)
        # Verify removal of rule from firewall policy
        self.assertNotIn(fw_rule_id2, self._get_list_fw_rule_ids(fw_policy_id))
        # Remove rule from the firewall policy
        self.fwaasv1_client.remove_firewall_rule_from_policy(
            fw_policy_id, fw_rule_id1)
        # Verify removal of rule from firewall policy
        self.assertNotIn(fw_rule_id1, self._get_list_fw_rule_ids(fw_policy_id))

    @test.attr(type='nsxv')
    @decorators.idempotent_id('901dae30-b148-43d9-ac86-09777aeaba20')
    def test_update_firewall_name_at_backend_excl_edge(self):
        firewall_topo = self._create_firewall_basic_topo('exclusive')
        fw_rule_id = firewall_topo['fw_rule_id1']
        body = self.fwaasv1_client.update_firewall_rule(fw_rule_id,
                                                        name="updated_rule")
        updated_fw_rule = body["firewall_rule"]
        self.assertEqual("updated_rule", updated_fw_rule['name'])
        edges = self.vsm.get_all_edges()
        for key in edges:
            if firewall_topo['router']['name'] in key['name']:
                edge_id = key['id']
                break
        rules = self.vsm.get_edge_firewall_rules(edge_id)
        self.assertEqual(
            True, self._check_firewall_rule_exists_at_backend(
                rules, "Fwaas-updated_rule"))

    @test.attr(type='nsxv')
    @decorators.idempotent_id('471ebc13-8e3b-4aca-85b8-747935bf0559')
    def test_update_firewall_name_at_backend_dist_edge(self):
        firewall_topo = self._create_firewall_basic_topo('distributed')
        fw_rule_id = firewall_topo['fw_rule_id1']
        body = self.fwaasv1_client.update_firewall_rule(fw_rule_id,
                                                        name="updated_rule")
        updated_fw_rule = body["firewall_rule"]
        self.assertEqual("updated_rule", updated_fw_rule['name'])
        edges = self.vsm.get_all_edges()
        firewall_topo['router']['name'] += '-plr'
        for key in edges:
            if firewall_topo['router']['name'] in key['name']:
                edge_id = key['id']
                break
        rules = self.vsm.get_edge_firewall_rules(edge_id)
        self.assertEqual(
            True, self._check_firewall_rule_exists_at_backend(
                rules, "Fwaas-updated_rule"))

    @test.attr(type='nsxv')
    @decorators.idempotent_id('0bdc9670-17b8-4dd5-80c8-dc6e956fc6ef')
    def test_create_multiple_firewall_rules_check_at_backend(self):
        firewall_topo = self._create_firewall_advanced_topo('exclusive')
        edges = self.vsm.get_all_edges()
        for key in edges:
            if firewall_topo['router']['name'] in key['name']:
                edge_id = key['id']
                break
        firewall_rules = self.vsm.get_edge_firewall_rules(edge_id)
        total_rules = firewall_topo['rules_before'] + len(firewall_rules)
        self.assertGreaterEqual(total_rules, constants.NO_OF_ENTRIES,
                                "Firewall Rules are greater than %s" %
                                constants.NO_OF_ENTRIES)

    @test.attr(type='nsxv')
    @decorators.idempotent_id('0249db39-6284-456a-9449-2adacdca4d3b')
    def test_update_firewall_policy_audited_attribute(self):
        # Create firewall rule
        body = self.fwaasv1_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="icmp")
        fw_rule_id = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id)
        # Create firewall policy
        body = self.fwaasv1_client.create_firewall_policy(
            name=data_utils.rand_name('fw-policy'))
        fw_policy_id = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)
        self.assertFalse(body['firewall_policy']['audited'])
        # Update firewall policy audited attribute to true
        self.fwaasv1_client.update_firewall_policy(fw_policy_id,
                                                   audited=True)
        # Insert Firewall rule to firewall policy
        self.fwaasv1_client.insert_firewall_rule_in_policy(
            fw_policy_id, fw_rule_id, '', '')
        body = self.fwaasv1_client.show_firewall_policy(
            fw_policy_id)
        self.assertFalse(body['firewall_policy']['audited'])
