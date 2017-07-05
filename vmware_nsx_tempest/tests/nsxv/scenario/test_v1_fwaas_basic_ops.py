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

import os
import re
import time

from neutron_lib import constants as nl_constants
import paramiko
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
from tempest import test

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.services import fwaas_client as FWAASC
from vmware_nsx_tempest.services import nsxv_client
from vmware_nsx_tempest.tests.nsxv.scenario import (
    manager_topo_deployment as dmgr)
from vmware_nsx_tempest.tests.nsxv.scenario import (
    network_addon_methods as NAM)

CONF = config.CONF


class FWaaSTestBasicOps(dmgr.TopoDeployScenarioManager):

    """
    Tests the following scenario cases for FWaaS:

        Add ICMP FWAAS rule and check north south traffic
        Add TCP FWAAS rule and check north south traffic
        Update ICMP FWAAS rule and check north south traffic
        Update TCP FWAAS rule and check north south traffic
        Check above scenario's with exclusive and distributed router
    """
    @classmethod
    def resource_setup(cls):
        super(FWaaSTestBasicOps, cls).resource_setup()
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

    def check_server_connected(self, serv):
        # Fetch tenant-network from where vm deployed
        serv_net = list(serv['addresses'].keys())[0]
        serv_addr = serv['addresses'][serv_net][0]
        host_ip = serv_addr['addr']
        self.waitfor_host_connected(host_ip)

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

    def _delete_router_if_exists(self, router):
        # delete router, if it exists
        try:
            routers_client = self.manager.routers_client
            routers_client.delete_router(router['id'])
        # if router is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _delete_policy_if_exists(self, policy_id):
        # delete policy, if it exists
        try:
            self.fwaasv1_client.delete_firewall_policy(policy_id)
        # if policy is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _delete_rule_if_exists(self, rule_id):
        # delete rule, if it exists
        try:
            self.fwaasv1_client.delete_firewall_rule(rule_id)
        # if rule is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _delete_firewall_if_exists(self, fw_id):
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

    def _test_ping_from_external_network(self, fip_ip):
        out = os.popen('ping -c 2  %s' % fip_ip).read().strip()
        return out

    def _test_ssh_connectivity_from_external_network(self, fip_ip):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(
            paramiko.AutoAddPolicy())
        try:
            ssh.connect(fip_ip, self.username, self.password, timeout=10)
        except Exception as e:
            return str(e)

    def _create_firewall_rule_name(self, body):
        firewall_rule_name = body['firewall_rule']['name']
        firewall_rule_name = "Fwaas-" + firewall_rule_name
        return firewall_rule_name

    def _create_firewall_advanced_topo(self, router_type):
        fw_rule_id_list = []
        router = self.create_router_by_type(router_type)
        self.addCleanup(self._delete_router_if_exists, router)
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
            self.addCleanup(self._delete_rule_if_exists, fw_rule_id)
            fw_rule_id_list.append(fw_rule_id)
        # Update firewall policy
        body = self.fwaasv1_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id = body['firewall_policy']['id']
        self.addCleanup(self._delete_policy_if_exists, fw_policy_id)
        # Insert rule to firewall policy
        for fw_rule_id in fw_rule_id_list:
            self.fwaasv1_client.insert_firewall_rule_in_policy(
                fw_policy_id, fw_rule_id, '', '')
        firewall_1 = self.fwaasv1_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=fw_policy_id,
            router_ids=[router['id']])
        created_firewall = firewall_1['firewall']
        self.addCleanup(self._delete_firewall_if_exists,
                        created_firewall['id'])
        # Wait for the firewall resource to become ready
        self._wait_until_ready(created_firewall['id'])
        firewall_topo = dict(router=router, firewall_name=firewall_name,
                             fw_policy_id=fw_policy_id,
                             firewall_id=created_firewall['id'],
                             rules_before=rules_before)
        return firewall_topo

    def _create_firewall_basic_topo(self, router_type, protocol_name,
                                    policy=None):
        self.keypairs = {}
        router = self.create_router_by_type(router_type)
        self.addCleanup(self._delete_router_if_exists, router)
        body = self.fwaasv1_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol=protocol_name)
        fw_rule_id1 = body['firewall_rule']['id']
        firewall_name = self._create_firewall_rule_name(body)
        self.addCleanup(self._delete_rule_if_exists, fw_rule_id1)
        # Create firewall policy
        if not policy:
            body = self.fwaasv1_client.create_firewall_policy(
                name=data_utils.rand_name("fw-policy"))
            fw_policy_id = body['firewall_policy']['id']
            self.addCleanup(self._delete_policy_if_exists, fw_policy_id)
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
        self.addCleanup(self._delete_firewall_if_exists,
                        created_firewall['id'])
        # Wait for the firewall resource to become ready
        self._wait_until_ready(created_firewall['id'])
        sg_name = data_utils.rand_name('sg')
        sg_desc = sg_name + " description"
        t_security_group = \
            self.compute_security_groups_client.create_security_group(
                name=sg_name, description=sg_desc)['security_group']
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.compute_security_groups_client.delete_security_group,
            t_security_group['id'])
        rule = {'direction': 'ingress', 'protocol': 'tcp'}
        self._create_security_group_rule(secgroup=t_security_group, **rule)
        rule = {'direction': 'ingress'}
        rule_id = self._create_security_group_rule(secgroup=t_security_group,
                                                   **rule)['id']
        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        client_mgr = self.manager
        tenant_id = t_security_group['tenant_id']
        network, subnet = self.create_network_subnet(client_mgr=client_mgr,
                                                     tenant_id=tenant_id,
                                                     cidr_offset=0)
        subnet_id = subnet['id']
        router_id = router['id']
        routers_client = client_mgr.routers_client
        NAM.router_interface_add(self, router_id, subnet_id,
                                 routers_client)
        self.username, self.password = self.get_image_userpass()
        security_groups = [{'name': t_security_group['id']}]
        key_name = keypair['name']
        t_serv1 = self.create_server_on_network(
            network, security_groups, key_name=key_name,
            image=self.get_server_image(),
            flavor=self.get_server_flavor(),
            name=network['name'])
        self.check_server_connected(t_serv1)
        t_floatingip = self.create_floatingip_for_server(
            t_serv1, client_mgr=client_mgr)
        msg = ("Associate t_floatingip[%s] to server[%s]"
               % (t_floatingip, t_serv1['name']))
        self._check_floatingip_connectivity(
            t_floatingip, t_serv1, should_connect=True, msg=msg)
        firewall_topo = dict(router=router, firewall_name=firewall_name,
                             fw_policy_id=fw_policy_id,
                             fw_rule_id1=fw_rule_id1,
                             firewall_id=created_firewall['id'],
                             security_group=t_security_group,
                             network=network, subnet=subnet,
                             client_mgr=client_mgr, serv1=t_serv1,
                             fip1=t_floatingip,
                             rule_id=rule_id)
        return firewall_topo

    def _perform_operations_on_firewall(self, firewall_topo, protocol_name):
        self._check_floatingip_connectivity(
            firewall_topo['fip1'], firewall_topo['serv1'],
            should_connect=True)
        firewall_rule_2 = self.fwaasv1_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="deny",
            protocol=protocol_name)
        fw_rule_id2 = firewall_rule_2['firewall_rule']['id']
        self.addCleanup(self._delete_rule_if_exists, fw_rule_id2)
        self.addCleanup(self._delete_policy_if_exists,
                        firewall_topo['fw_policy_id'])
        self.addCleanup(self._delete_firewall_if_exists,
                        firewall_topo['firewall_id'])
        # Insert rule-2 to firewall policy
        self.fwaasv1_client.insert_firewall_rule_in_policy(
            firewall_topo['fw_policy_id'], fw_rule_id2, '',
            firewall_topo['fw_rule_id1'])
        self._wait_firewall_ready(firewall_topo['firewall_id'])
        return fw_rule_id2

    def _get_list_fw_rule_ids(self, fw_policy_id):
        fw_policy = self.fwaasv1_client.show_firewall_policy(
            fw_policy_id)
        return [ruleid for ruleid in fw_policy['firewall_policy']
                ['firewall_rules']]

    def create_router_by_type(self, router_type, name=None, **kwargs):
        routers_client = self.manager.routers_client
        router_name = name or data_utils.rand_name('fwaas-')
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
    @decorators.idempotent_id('e2ab2d1a-4dc0-4efd-b03d-8c2322b427f0')
    def test_firewall_icmp_rule_with_exclusive_router(self):
        # Create router required for an ACTIVE firewall
        firewall_topo = \
            self._create_firewall_basic_topo(constants.EXCLUSIVE_ROUTER,
                                             constants.ICMP_PROTOCOL)
        fip_ip = firewall_topo['fip1']['floating_ip_address']
        self._perform_operations_on_firewall(firewall_topo,
                                             constants.ICMP_PROTOCOL)
        out = self._test_ping_from_external_network(fip_ip)
        self.assertIn("0 received", str(out))

    @test.attr(type='nsxv')
    @decorators.idempotent_id('fd39455a-232e-4f7f-b102-2853688335dc')
    def test_firewall_tcp_rule_with_exclusive_router(self):
        # Create router required for an ACTIVE firewall
        firewall_topo = \
            self._create_firewall_basic_topo(constants.EXCLUSIVE_ROUTER,
                                             constants.TCP_PROTOCOL)
        fip_ip = firewall_topo['fip1']['floating_ip_address']
        self._perform_operations_on_firewall(firewall_topo,
                                             constants.TCP_PROTOCOL)
        out = self._test_ssh_connectivity_from_external_network(fip_ip)
        self.assertIn("Servname not supported", out)

    @test.attr(type='nsxv')
    @decorators.idempotent_id('3628448a-5977-44e3-b34a-690e4e2ba847')
    def test_firewall_icmp_rule_with_distributed_router(self):
        # Create router required for an ACTIVE firewall
        firewall_topo = \
            self._create_firewall_basic_topo(constants.DISTRIBUTED_ROUTER,
                                             constants.ICMP_PROTOCOL)
        fip_ip = firewall_topo['fip1']['floating_ip_address']
        self._perform_operations_on_firewall(firewall_topo,
                                             constants.ICMP_PROTOCOL)
        out = self._test_ping_from_external_network(fip_ip)
        self.assertIn("0 received", str(out))

    @test.attr(type='nsxv')
    @decorators.idempotent_id('0aeb2acc-0b68-4cca-889d-078f61bbe5b2')
    def test_firewall_tcp_rule_with_distributed_router(self):
        # Create router required for an ACTIVE firewall
        firewall_topo = \
            self._create_firewall_basic_topo(constants.DISTRIBUTED_ROUTER,
                                             constants.TCP_PROTOCOL)
        fip_ip = firewall_topo['fip1']['floating_ip_address']
        self._perform_operations_on_firewall(firewall_topo,
                                             constants.TCP_PROTOCOL)
        out = self._test_ssh_connectivity_from_external_network(fip_ip)
        self.assertIn("Servname not supported", out)

    @test.attr(type='nsxv')
    @decorators.idempotent_id('4a0306e5-663c-4981-8177-e8a255a8859c')
    def test_firewall_update_delete_ops_on_exclusive_router(self):
        # Create router required for an ACTIVE firewall
        firewall_topo = \
            self._create_firewall_basic_topo(constants.EXCLUSIVE_ROUTER,
                                             constants.ICMP_PROTOCOL)
        firewall_rule_id = \
            self._perform_operations_on_firewall(firewall_topo,
                                                 constants.ICMP_PROTOCOL)
        fip_ip = firewall_topo['fip1']['floating_ip_address']
        out = self._test_ping_from_external_network(fip_ip)
        self.assertIn("0 received", str(out))
        self.fwaasv1_client.update_firewall_rule(
            firewall_rule_id,
            action="allow")
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        out = self._test_ping_from_external_network(fip_ip)
        self.assertIn("64 bytes from ", str(out))
        self.fwaasv1_client.update_firewall_rule(
            firewall_rule_id, protocol="tcp",
            action="deny")
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        out = self._test_ssh_connectivity_from_external_network(fip_ip)
        self.assertIn("Servname not supported", out)
        out = self._test_ping_from_external_network(fip_ip)
        self.assertIn("64 bytes from ", str(out))
        self.fwaasv1_client.update_firewall_rule(
            firewall_rule_id, action="allow")
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        out = self._test_ssh_connectivity_from_external_network(fip_ip)
        self._wait_firewall_ready(firewall_topo['firewall_id'])
        out = self._test_ping_from_external_network(fip_ip)
        self.assertIn("64 bytes from ", str(out))
