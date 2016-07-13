# Copyright 2015 VMware, Inc.
# All Rights Reserved
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

import testtools

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest import test

from vmware_nsx_tempest.services.qos import base_qos

CONF = config.CONF


class BaseQosTest(base.BaseAdminNetworkTest):
    """Base class for Qos Test.

    1. Setup QoS clients for admin and primary users.
    2. Manages qos resources creation and deletion.
    3. Manages network/port creation and deletion as network cannot be
       deleted if ports are associated which test framework won't handle.
    """

    @classmethod
    def skip_checks(cls):
        """skip tests if qos is not enabled."""
        super(BaseQosTest, cls).skip_checks()
        if not test.is_extension_enabled('qos', 'network'):
            msg = "q-qos extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(BaseQosTest, cls).resource_setup()
        cls.admin_mgr = cls.get_client_manager(credential_type='admin')
        cls.primary_mgr = cls.get_client_manager()
        cls.adm_qos_client = base_qos.BaseQosClient(cls.admin_mgr)
        cls.pri_qos_client = base_qos.BaseQosClient(cls.primary_mgr)
        cls.qos_available_rule_types = (
            cls.adm_qos_client.available_rule_types())
        cls.policies_created = []

    @classmethod
    def resource_cleanup(cls):
        """cleanup resources before handing over to framework."""
        for network in cls.networks:
            # network cannot be deleted if its ports have policy associated.
            port_list = cls.admin_mgr.ports_client.list_ports(
                network_id=network['id'])['ports']
            for port in port_list:
                cls.delete_port(port['id'])
            cls.delete_network(network['id'])
        for policy in cls.policies_created:
            cls._try_delete_resource(
                cls.adm_qos_client.delete_policy, policy['id'])
        super(BaseQosTest, cls).resource_cleanup()

    @classmethod
    def create_port(cls, network, client_mgr=None, **kwargs):
        """create port."""
        client_mgr = client_mgr if client_mgr else cls.admin_mgr
        body = client_mgr.ports_client.create_port(
            network_id=network['id'], **kwargs)
        port = body.get('port', body)
        cls.ports.append(port)
        return port

    @classmethod
    def update_port(cls, port_id, client_mgr=None, **kwargs):
        """update port."""
        client_mgr = client_mgr if client_mgr else cls.admin_mgr
        body = client_mgr.ports_client.update_port(
            port_id, **kwargs)
        return body.get('port', body)

    @classmethod
    def show_port(cls, port_id, client_mgr=None):
        """show port."""
        client_mgr = client_mgr if client_mgr else cls.admin_mgr
        body = client_mgr.ports_client.show_port(port_id)
        return body.get('port', body)

    @classmethod
    def delete_port(cls, port_id, client_mgr=None, **kwargs):
        """delete port."""
        client_mgr = client_mgr if client_mgr else cls.admin_mgr
        body = client_mgr.ports_client.delete_port(port_id)
        return body.get('port', body)

    @classmethod
    def create_network(cls, network_name=None, client_mgr=None, **kwargs):
        """create network."""
        network_name = network_name or data_utils.rand_name('qos-net')
        client_mgr = client_mgr if client_mgr else cls.admin_mgr

        body = client_mgr.networks_client.create_network(
            name=network_name, **kwargs)
        network = body['network']
        cls.networks.append(network)
        return network

    @classmethod
    def create_shared_network(cls, network_name=None, client_mgr=None,
                              **kwargs):
        """create shared network."""
        return cls.create_network(network_name, client_mgr,
                                  shared=True, **kwargs)

    @classmethod
    def show_network(cls, network_id, client_mgr=None):
        """show network."""
        client_mgr = client_mgr if client_mgr else cls.admin_mgr
        network = client_mgr.networks_client.show_network(network_id)
        return network.get('network', network)

    @classmethod
    def update_network(cls, network_id, client_mgr=None, **kwargs):
        """update network."""
        client_mgr = client_mgr if client_mgr else cls.admin_mgr
        network = client_mgr.networks_client.update_network(
            network_id, **kwargs)
        return network.get('network', network)

    @classmethod
    def delete_network(cls, network_id, client_mgr=None):
        """delete network."""
        client_mgr = client_mgr if client_mgr else cls.admin_mgr
        network = client_mgr.networks_client.delete_network(network_id)
        return network.get('network', network)

    @classmethod
    def create_qos_policy(cls, name='test-policy',
                          description='test policy desc',
                          shared=False,
                          qos_client=None, **kwargs):
        """create qos policy."""
        qos_client = qos_client if qos_client else cls.adm_qos_client
        policy = qos_client.create_policy(
            name=name, description=description,
            shared=shared, **kwargs)
        cls.policies_created.append(policy)
        return policy

    @classmethod
    def create_qos_bandwidth_limit_rule(cls, policy_id,
                                        qos_client=None, **kwargs):
        """create qos-bandwidth-limit-rule."""
        qos_client = qos_client if qos_client else cls.adm_qos_client
        rule = qos_client.create_bandwidth_limit_rule(policy_id, **kwargs)
        return rule

    @classmethod
    def create_qos_dscp_marking_rule(cls, policy_id, dscp_mark,
                                     qos_client=None, **kwargs):
        """create qos-dscp-marking-rule."""
        qos_client = qos_client if qos_client else cls.adm_qos_client
        rule = qos_client.create_dscp_marking_rule(
            policy_id, dscp_mark, **kwargs)
        return rule


class QosPolicyTest(BaseQosTest):
    """QoS Policy CURD operations.

    test qos policies and network/port association and disassociation.
    """

    @test.idempotent_id('108fbdf7-3463-4e47-9871-d07f3dcf5bbb')
    def test_create_policy(self):
        """qos-policy-create: create policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy desc1',
                                        shared=False)

        # Test 'show policy'
        retrieved_policy = self.adm_qos_client.show_policy(policy['id'])
        self.assertEqual('test-policy', retrieved_policy['name'])
        self.assertEqual('test policy desc1',
                         retrieved_policy['description'])
        self.assertFalse(retrieved_policy['shared'])

        # Test 'list policies'
        policies = self.adm_qos_client.list_policies()
        policies_ids = [p['id'] for p in policies]
        self.assertIn(policy['id'], policies_ids)

    @test.idempotent_id('f8d20e92-f06d-4805-b54f-230f77715815')
    def test_list_policy_filter_by_name(self):
        """qos-policy-list --name=<name>: list policies."""
        name1 = data_utils.rand_name('test-policy')
        name2 = name1 + "0"
        self.create_qos_policy(name=name1, description='test policy',
                               shared=False)
        self.create_qos_policy(name=name2, description='test policy',
                               shared=False)

        policies = self.adm_qos_client.list_policies(name=name1)
        self.assertEqual(1, len(policies))

        retrieved_policy = policies[0]
        self.assertEqual(name1, retrieved_policy['name'])

    @test.idempotent_id('8e88a54b-f0b2-4b7d-b061-a15d93c2c7d6')
    def test_policy_update(self):
        """qos-policy-update POLICY_ID."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='',
                                        shared=False)
        self.adm_qos_client.update_policy(policy['id'],
                                          description='test policy desc2',
                                          shared=True)

        retrieved_policy = self.adm_qos_client.show_policy(policy['id'])
        self.assertEqual('test policy desc2',
                         retrieved_policy['description'])
        self.assertTrue(retrieved_policy['shared'])
        self.assertEqual([], retrieved_policy['rules'])

    @test.idempotent_id('1cb42653-54bd-4a9a-b888-c55e18199201')
    def test_delete_policy(self):
        """qos-policy-delete POLICY_ID."""
        policy = self.create_qos_policy(
            'test-policy', 'desc', True)

        retrieved_policy = self.adm_qos_client.show_policy(policy['id'])
        self.assertEqual('test-policy', retrieved_policy['name'])

        self.adm_qos_client.delete_policy(policy['id'])
        self.assertRaises(exceptions.NotFound,
                          self.adm_qos_client.show_policy, policy['id'])

    @test.idempotent_id('cf776f77-8d3d-49f2-8572-12d6a1557224')
    def _test_list_admin_rule_types(self):
        """qos-available-rule-types: available rule type from admin view."""
        self._test_list_rule_types(self.adm_qos_client)

    @test.idempotent_id('49c8ea35-83a9-453a-bd23-239cf3b13929')
    def _test_list_regular_rule_types(self):
        """qos-available-rule-types: available rule type from project view."""
        self._test_list_rule_types(self.pri_qos_client)

    def _test_list_rule_types(self, client):
        # List supported rule types
        # TODO(QoS): since in gate we run both ovs and linuxbridge ml2 drivers,
        # and since Linux Bridge ml2 driver does not have QoS support yet, ml2
        # plugin reports no rule types are supported. Once linuxbridge will
        # receive support for QoS, the list of expected rule types will change.
        #
        # In theory, we could make the test conditional on which ml2 drivers
        # are enabled in gate (or more specifically, on which supported qos
        # rules are claimed by core plugin), but that option doesn't seem to be
        # available thru tempest.lib framework
        expected_rule_types = []
        expected_rule_details = ['type']

        rule_types = client.available_rule_types()
        actual_rule_types = [rule['type'] for rule in rule_types]

        # TODO(akang): seems not correct
        # Verify that only required fields present in rule details
        for rule in actual_rule_types:
            self.assertEqual(tuple(rule.keys()), tuple(expected_rule_details))

        # Verify if expected rules are present in the actual rules list
        for rule in expected_rule_types:
            self.assertIn(rule, actual_rule_types)

    def _disassociate_network(self, network_id, client_mgr=None):
        self.update_network(network_id, client_mgr=client_mgr,
                            qos_policy_id=None)
        updated_network = self.show_network(network_id,
                                            client_mgr=client_mgr)
        self.assertIsNone(updated_network['qos_policy_id'])

    @test.idempotent_id('65b9ef75-1911-406a-bbdb-ca1d68d528b0')
    def test_policy_association_with_admin_network(self):
        """admin can create network with non-shared policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        network = self.create_shared_network('test network',
                                             qos_policy_id=policy['id'])

        retrieved_network = self.show_network(network['id'])
        self.assertEqual(
            policy['id'], retrieved_network['qos_policy_id'])

        self._disassociate_network(network['id'], self.admin_mgr)

    @test.idempotent_id('1738de5d-0476-4163-9022-5e1b548c208e')
    def test_policy_association_with_tenant_network(self):
        """project/tenant can create network with shared policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        network = self.create_network('test network',
                                      client_mgr=self.primary_mgr,
                                      qos_policy_id=policy['id'])

        retrieved_network = self.show_network(network['id'],
                                              client_mgr=self.primary_mgr)
        self.assertEqual(
            policy['id'], retrieved_network['qos_policy_id'])

        self._disassociate_network(network['id'], self.primary_mgr)

    @test.attr(type='negative')
    @test.idempotent_id('9efe63d0-836f-4cc2-b00c-468e63aa614e')
    def test_policy_association_with_network_nonexistent_policy(self):
        """Can not create network with nonexist policy."""
        self.assertRaises(
            exceptions.NotFound,
            self.create_network,
            'test network',
            qos_policy_id='9efe63d0-836f-4cc2-b00c-468e63aa614e')

    @test.attr(type='negative')
    @test.idempotent_id('1aa55a79-324f-47d9-a076-894a8fc2448b')
    def test_policy_association_with_network_non_shared_policy(self):
        """tenant/project can not create network with not-shared policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.assertRaises(
            exceptions.NotFound,
            self.create_network,
            'test network', qos_policy_id=policy['id'],
            client_mgr=self.primary_mgr)

    @test.idempotent_id('10a9392c-1359-4cbb-989f-fb768e5834a8')
    def test_policy_update_association_with_admin_network(self):
        """admin can create associate non-shared policy to network."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        network = self.create_shared_network('test network')
        retrieved_network = self.show_network(network['id'])
        self.assertIsNone(retrieved_network['qos_policy_id'])

        self.update_network(
            network['id'], qos_policy_id=policy['id'])
        retrieved_network = self.show_network(network['id'])
        self.assertEqual(
            policy['id'], retrieved_network['qos_policy_id'])

        self._disassociate_network(network['id'], self.admin_mgr)

    def _disassociate_port(self, port_id, client_mgr=None):
        client_mgr = client_mgr if client_mgr else self.admin_mgr
        self.update_port(port_id, qos_policy_id=None,
                         client_mgr=client_mgr)
        updated_port = self.show_port(port_id, client_mgr=client_mgr)
        self.assertIsNone(updated_port['qos_policy_id'])

    @test.idempotent_id('98fcd95e-84cf-4746-860e-44692e674f2e')
    def test_policy_association_with_port_shared_policy(self):
        """test port can associate shared policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        network = self.create_shared_network('test network')
        port = self.create_port(network, qos_policy_id=policy['id'],
                                client_mgr=self.primary_mgr)

        retrieved_port = self.show_port(port['id'],
                                        client_mgr=self.primary_mgr)
        self.assertEqual(
            policy['id'], retrieved_port['qos_policy_id'])

        self._disassociate_port(port['id'], client_mgr=self.primary_mgr)

    @test.attr(type='negative')
    @test.idempotent_id('49e02f5a-e1dd-41d5-9855-cfa37f2d195e')
    def test_policy_association_with_port_nonexistent_policy(self):
        """test port cannot be created with nonexist policy."""
        network = self.create_shared_network('test network')
        self.assertRaises(
            exceptions.NotFound,
            self.create_port,
            network,
            qos_policy_id='49e02f5a-e1dd-41d5-9855-cfa37f2d195e')

    @test.attr(type='negative')
    @test.idempotent_id('f53d961c-9fe5-4422-8b66-7add972c6031')
    def test_policy_association_with_port_non_shared_policy(self):
        """project/tenant can not associate port with non-shared policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        network = self.create_shared_network('test network')
        self.assertRaises(
            exceptions.NotFound,
            self.create_port,
            network, qos_policy_id=policy['id'],
            client_mgr=self.primary_mgr)

    @test.idempotent_id('f8163237-fba9-4db5-9526-bad6d2343c76')
    def test_policy_update_association_with_port_shared_policy(self):
        """project/tenant can update port with shared policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        network = self.create_shared_network('test network')
        port = self.create_port(network, client_mgr=self.primary_mgr)
        retrieved_port = self.show_port(port['id'],
                                        client_mgr=self.primary_mgr)
        self.assertIsNone(retrieved_port['qos_policy_id'])

        self.update_port(port['id'], qos_policy_id=policy['id'],
                         client_mgr=self.primary_mgr)
        retrieved_port = self.show_port(port['id'],
                                        client_mgr=self.primary_mgr)
        self.assertEqual(
            policy['id'], retrieved_port['qos_policy_id'])

        self._disassociate_port(port['id'])

    @test.attr(type='negative')
    @test.idempotent_id('18163237-8ba9-4db5-9525-bad6d2343c75')
    def test_delete_not_allowed_if_policy_in_use_by_network(self):
        """can not delete policy if used by network."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        network = self.create_shared_network(
            'test network', qos_policy_id=policy['id'])
        self.assertRaises(
            exceptions.Conflict,
            self.adm_qos_client.delete_policy, policy['id'])

        self._disassociate_network(network['id'], self.admin_mgr)
        self.adm_qos_client.delete_policy(policy['id'])

    @test.attr(type='negative')
    @test.idempotent_id('24153230-84a9-4dd5-9525-bad6d2343c75')
    def test_delete_not_allowed_if_policy_in_use_by_port(self):
        """can not delete policy if used by port."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        network = self.create_shared_network('test network')
        port = self.create_port(network, qos_policy_id=policy['id'],
                                client_mgr=self.primary_mgr)
        self.assertRaises(
            exceptions.Conflict,
            self.adm_qos_client.delete_policy, policy['id'])

        self._disassociate_port(port['id'], client_mgr=self.primary_mgr)
        self.adm_qos_client.delete_policy(policy['id'])

    @test.idempotent_id('a2a5849b-dd06-4b18-9664-0b6828a1fc27')
    def test_qos_policy_delete_with_rules(self):
        """Policy with rules attached can be deleted."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.adm_qos_client.create_bandwidth_limit_rule(
            policy['id'], 200, 1337)

        self.adm_qos_client.delete_policy(policy['id'])

        with testtools.ExpectedException(exceptions.NotFound):
            self.adm_qos_client.show_policy(policy['id'])


class QosBandwidthLimitRuleTest(BaseQosTest):
    """QoS Bandwidth limit rule CURD operations."""

    @test.idempotent_id('8a59b00b-3e9c-4787-92f8-93a5cdf5e378')
    def test_rule_create(self):
        """qos-bandwidth-limit-rule-create POLICY_ID."""
        qos_client = self.adm_qos_client
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=200, max_burst_kbps=1337)

        # Test 'show rule'
        retrieved_rule = qos_client.show_bandwidth_limit_rule(
            rule['id'], policy['id'])
        self.assertEqual(rule['id'], retrieved_rule['id'])
        self.assertEqual(200, retrieved_rule['max_kbps'])
        self.assertEqual(1337, retrieved_rule['max_burst_kbps'])

        # Test 'list rules'
        rules = qos_client.list_bandwidth_limit_rules(policy['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule['id'], rules_ids)

        # Test 'show policy'
        retrieved_policy = qos_client.show_policy(policy['id'])
        policy_rules = retrieved_policy['rules']
        self.assertEqual(1, len(policy_rules))
        self.assertEqual(rule['id'], policy_rules[0]['id'])
        self.assertEqual(base_qos.RULE_TYPE_BANDWIDTH_LIMIT,
                         policy_rules[0]['type'])

    @test.attr(type='negative')
    @test.idempotent_id('8a59b00b-ab01-4787-92f8-93a5cdf5e378')
    def test_rule_create_fail_for_the_same_type(self):
        """One bandwidth limit rule per policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=200, max_burst_kbps=1337)

        self.assertRaises(exceptions.Conflict,
                          self.create_qos_bandwidth_limit_rule,
                          policy_id=policy['id'],
                          max_kbps=201, max_burst_kbps=1338)

    @test.idempotent_id('149a6988-2568-47d2-931e-2dbc858943b3')
    def test_rule_update(self):
        """qos-bandwidth-limit-rule-update RULE-ID POLICY_ID."""
        qos_client = self.adm_qos_client
        max_kbps = 200
        max_burst_kbps = 1337
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=1, max_burst_kbps=1)

        qos_client.update_bandwidth_limit_rule(
            rule['id'], policy['id'],
            max_kbps=max_kbps, max_burst_kbps=max_burst_kbps)

        retrieved_rule = qos_client.show_bandwidth_limit_rule(
            rule['id'], policy['id'])
        self.assertEqual(max_kbps, retrieved_rule['max_kbps'])
        self.assertEqual(max_burst_kbps, retrieved_rule['max_burst_kbps'])

    @test.idempotent_id('67ee6efd-7b33-4a68-927d-275b4f8ba958')
    def test_rule_delete(self):
        """qos-bandwidth-limit-rule-delete RULE-ID POLICY_ID."""
        qos_client = self.adm_qos_client
        max_kbps = 200
        max_burst_kbps = 1337
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.create_qos_bandwidth_limit_rule(
            policy['id'],
            max_kbps=max_kbps, max_burst_kbps=max_burst_kbps)

        retrieved_rule = qos_client.show_bandwidth_limit_rule(
            rule['id'], policy['id'])
        self.assertEqual(rule['id'], retrieved_rule['id'])

        qos_client.delete_bandwidth_limit_rule(
            rule['id'], policy['id'])
        self.assertRaises(exceptions.NotFound,
                          qos_client.show_bandwidth_limit_rule,
                          rule['id'], policy['id'])

    @test.attr(type='negative')
    @test.idempotent_id('f211222c-5808-46cb-a961-983bbab6b852')
    def test_rule_create_rule_nonexistent_policy(self):
        """Cannot create rule with nonexist policy."""
        self.assertRaises(
            exceptions.NotFound,
            self.create_qos_bandwidth_limit_rule,
            'policy', max_kbps=200, max_burst_kbps=1337)

    @test.attr(type='negative')
    @test.idempotent_id('eed8e2a6-22da-421b-89b9-935a2c1a1b50')
    def test_policy_create_forbidden_for_regular_tenants(self):
        """project/tenant cannot create policy."""
        self.assertRaises(
            exceptions.Forbidden,
            self.create_qos_policy,
            'test-policy', 'test policy', False,
            qos_client=self.pri_qos_client)

    @test.attr(type='negative')
    @test.idempotent_id('a4a2e7ad-786f-4927-a85a-e545a93bd274')
    def test_rule_create_forbidden_for_regular_tenants(self):
        """project/tenant cannot create rule."""
        self.assertRaises(
            exceptions.Forbidden,
            self.create_qos_bandwidth_limit_rule,
            'policy', max_kbps=1, max_burst_kbps=2,
            qos_client=self.pri_qos_client)

    @test.idempotent_id('ce0bd0c2-54d9-4e29-85f1-cfb36ac3ebe2')
    def test_get_rules_by_policy(self):
        """qos-bandwidth-limit-rule-list POLICY_ID."""
        policy1 = self.create_qos_policy(name='test-policy1',
                                         description='test policy1',
                                         shared=False)
        rule1 = self.create_qos_bandwidth_limit_rule(
            policy_id=policy1['id'], max_kbps=200, max_burst_kbps=1337)

        policy2 = self.create_qos_policy(name='test-policy2',
                                         description='test policy2',
                                         shared=False)
        rule2 = self.create_qos_bandwidth_limit_rule(
            policy_id=policy2['id'], max_kbps=5000, max_burst_kbps=2523)

        # Test 'list rules'
        rules = self.adm_qos_client.list_bandwidth_limit_rules(policy1['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule1['id'], rules_ids)
        self.assertNotIn(rule2['id'], rules_ids)


class QosDscpMarkingRuleTest(BaseQosTest):
    """QoS Dscp Marking Rule CRUD operation."""

    VALID_DSCP_MARK1 = 56
    VALID_DSCP_MARK2 = 48

    @test.idempotent_id('8a59b40b-3e9c-4787-92f8-93a5cdf5e378')
    def test_rule_create(self):
        """qos-dscp-marking-rule-create POLICY_ID."""
        qos_client = self.adm_qos_client
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.create_qos_dscp_marking_rule(
            policy['id'], self.VALID_DSCP_MARK1)

        # Test 'show rule'
        retrieved_rule = qos_client.show_dscp_marking_rule(
            rule['id'], policy['id'])
        self.assertEqual(rule['id'], retrieved_rule['id'])
        self.assertEqual(self.VALID_DSCP_MARK1, retrieved_rule['dscp_mark'])

        # Test 'list rules'
        rules = qos_client.list_dscp_marking_rules(policy['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule['id'], rules_ids)

        # Test 'show policy'
        retrieved_policy = qos_client.show_policy(policy['id'])
        policy_rules = retrieved_policy['rules']
        self.assertEqual(1, len(policy_rules))
        self.assertEqual(rule['id'], policy_rules[0]['id'])
        self.assertEqual(base_qos.RULE_TYPE_DSCP_MARK,
                         policy_rules[0]['type'])

    @test.attr(type='negative')
    @test.idempotent_id('8b59b10b-ab01-4787-92f8-93a5cdf5e378')
    def test_rule_create_fail_for_the_same_type(self):
        """One dscp marking rule per policy."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.create_qos_dscp_marking_rule(
            policy['id'], self.VALID_DSCP_MARK1)

        self.assertRaises(exceptions.Conflict,
                          self.create_qos_dscp_marking_rule,
                          policy_id=policy['id'],
                          dscp_mark=self.VALID_DSCP_MARK2)

    @test.idempotent_id('249a6988-2568-47d2-931e-2dbc858943b3')
    def test_rule_update(self):
        """qos-dscp-marking-rule-create POLICY_ID."""
        qos_client = self.adm_qos_client
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.create_qos_dscp_marking_rule(
            policy['id'], self.VALID_DSCP_MARK1)

        qos_client.update_dscp_marking_rule(
            rule['id'], policy['id'], dscp_mark=self.VALID_DSCP_MARK2)

        retrieved_rule = qos_client.show_dscp_marking_rule(
            rule['id'], policy['id'])
        self.assertEqual(self.VALID_DSCP_MARK2, retrieved_rule['dscp_mark'])

    @test.idempotent_id('67ed6efd-7b33-4a68-927d-275b4f8ba958')
    def test_rule_delete(self):
        """qos-dscp-marking-rule-delete POLICY_ID."""
        qos_client = self.adm_qos_client
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.create_qos_dscp_marking_rule(
            policy['id'], self.VALID_DSCP_MARK1)

        retrieved_rule = qos_client.show_dscp_marking_rule(
            rule['id'], policy['id'])
        self.assertEqual(rule['id'], retrieved_rule['id'])

        qos_client.delete_dscp_marking_rule(rule['id'], policy['id'])
        self.assertRaises(exceptions.NotFound,
                          qos_client.show_dscp_marking_rule,
                          rule['id'], policy['id'])

    @test.attr(type='negative')
    @test.idempotent_id('f215222c-5808-46cb-a961-983bbab6b852')
    def test_rule_create_rule_nonexistent_policy(self):
        """can not create dscp marking rule with nonexist policy."""
        self.assertRaises(
            exceptions.NotFound,
            self.create_qos_dscp_marking_rule,
            'policy', self.VALID_DSCP_MARK1)

    @test.attr(type='negative')
    @test.idempotent_id('a4a2e3ad-786f-4927-a85a-e545a93bd274')
    def test_rule_create_forbidden_for_regular_tenants(self):
        """project/tenant can not create dscp marking rule."""
        self.assertRaises(
            exceptions.Forbidden,
            self.create_qos_dscp_marking_rule,
            'policy', self.VALID_DSCP_MARK1,
            qos_client=self.pri_qos_client)

    @test.attr(type='negative')
    @test.idempotent_id('32646b08-4f05-4493-a48a-bde768a18533')
    def test_invalid_rule_create(self):
        """Can not create rule with invalid dscp_mark value."""
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.assertRaises(
            exceptions.BadRequest,
            self.create_qos_dscp_marking_rule,
            policy['id'], 58)

    @test.idempotent_id('cf0bd0c2-54d9-4e29-85f1-cfb36ac3ebe2')
    def test_get_rules_by_policy(self):
        """qos-dscp-marking-rule-list POLICY_ID."""
        policy1 = self.create_qos_policy(name='test-policy1',
                                         description='test policy1',
                                         shared=False)
        rule1 = self.create_qos_dscp_marking_rule(
            policy1['id'], self.VALID_DSCP_MARK1)

        policy2 = self.create_qos_policy(name='test-policy2',
                                         description='test policy2',
                                         shared=False)
        rule2 = self.create_qos_dscp_marking_rule(
            policy2['id'], self.VALID_DSCP_MARK2)

        # Test 'list rules'
        rules = self.adm_qos_client.list_dscp_marking_rules(policy1['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule1['id'], rules_ids)
        self.assertNotIn(rule2['id'], rules_ids)
