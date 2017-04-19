# Copyright 2017 VMware, Inc.
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
# Below are the requirements to run this test
#   1) Ensure openstack image supports iperf and tcpdump
#   2) Install pyshark on machine running the tests
#   3) Install sshpass on machine running the tests

import subprocess
import time

from oslo_log import log as logging

import pyshark

from tempest import config
from tempest import test

from tempest.common.utils.linux import remote_client

from tempest.lib import decorators

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils

from tempest.scenario import manager

from vmware_nsx_tempest.services.qos import base_qos

CONF = config.CONF
LOG = logging.getLogger(__name__)


class TestQoSOps(manager.NetworkScenarioTest):

    @classmethod
    def skip_checks(cls):
        super(TestQoSOps, cls).skip_checks()
        if not (CONF.network.project_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        if not test.is_extension_enabled('qos', 'network'):
            msg = "q-qos extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(TestQoSOps, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(TestQoSOps, cls).resource_setup()
        cls.admin_mgr = cls.get_client_manager('admin')
        cls.primary_mgr = cls.get_client_manager('primary')
        cls.adm_qos_client = base_qos.BaseQosClient(cls.admin_mgr)
        cls.pri_qos_client = base_qos.BaseQosClient(cls.primary_mgr)
        cls.qos_available_rule_types = (
            cls.adm_qos_client.available_rule_types())
        cls.policies_created = []

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

    def _create_subnet(self, network, cidr, subnets_client=None, **kwargs):
        client = subnets_client or self.subnets_client
        body = client.create_subnet(
            name=data_utils.rand_name('subnet-qos'),
            network_id=network['id'], tenant_id=network['tenant_id'],
            cidr=cidr, ip_version=4, **kwargs)
        subnet = body.get('subnet', body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        client.delete_subnet, subnet['id'])
        return subnet

    def _create_router(self, router_name=None, admin_state_up=True,
                       external_network_id=None, enable_snat=None,
                       **kwargs):
        ext_gw_info = {}
        if external_network_id:
            ext_gw_info['network_id'] = external_network_id
        if enable_snat is not None:
            ext_gw_info['enable_snat'] = enable_snat
        body = self.routers_client.create_router(
            name=router_name, external_gateway_info=ext_gw_info,
            admin_state_up=admin_state_up, **kwargs)
        router = body.get('router', body)
        self.addCleanup(self._delete_router, router)
        return router

    def _delete_router(self, router):
        body = self.ports_client.list_ports(device_id=router['id'])
        interfaces = body['ports']
        for i in interfaces:
            test_utils.call_and_ignore_notfound_exc(
                self.routers_client.remove_router_interface, router['id'],
                subnet_id=i['fixed_ips'][0]['subnet_id'])
        self.routers_client.delete_router(router['id'])

    def _create_security_group(self):
        # Create security group
        sg_name = data_utils.rand_name(self.__class__.__name__)
        sg_desc = sg_name + " description"
        secgroup = self.compute_security_groups_client.create_security_group(
            name=sg_name, description=sg_desc)['security_group']
        self.assertEqual(secgroup['name'], sg_name)
        self.assertEqual(secgroup['description'], sg_desc)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.compute_security_groups_client.delete_security_group,
            secgroup['id'])
        rulesets = [
            dict(protocol='tcp', port_range_min=22, port_range_max=22),
            dict(protocol='icmp'),
            dict(protocol='icmp', ethertype='IPv6'),
            dict(protocol='udp', ethertype='IPv4')
        ]
        for ruleset in rulesets:
            for r_direction in ['ingress', 'egress']:
                ruleset['direction'] = r_direction
                self._create_security_group_rule(
                    secgroup=secgroup,
                    **ruleset)
        return secgroup

    def create_security_group_rule(self, security_group_id,
                                   cmgr=None, project_id=None,
                                   protocol=None):
        cmgr = cmgr or self.cmgr_adm
        sgr_client = cmgr.security_group_rules_client
        sgr_dict = dict(security_group_id=security_group_id,
                        direction='ingress', protocol=protocol)
        if project_id:
            sgr_dict['tenant_id'] = project_id
        sgr = sgr_client.create_security_group_rule(**sgr_dict)
        return sgr.get('security_group_rule', sgr)

    def _create_server(self, name, network, image_id=None):
        security_groups = [{'name': self.security_group['name']}]
        network = {'uuid': network['id']}
        server = self.create_server(name=name, networks=[network],
                                    security_groups=security_groups,
                                    image_id=CONF.compute.image_ref_alt,
                                    wait_until='ACTIVE')
        return server

    def _get_server_ip(self, server):
        addresses = server['addresses'][self.network['name']]
        for address in addresses:
            if address['version'] == CONF.validation.ip_version_for_ssh:
                return address['addr']

    def _create_vms(self, network_topo):
        """create a source and dest vm for traffic"""
        source_vm = data_utils.rand_name('source_vm')
        network = network_topo['network']
        src_vm = self._create_server(source_vm, network)
        dest_vm = data_utils.rand_name('dest_vm')
        dst_vm = self._create_server(dest_vm, network)
        servers = dict(dst_vm=dst_vm, src_vm=src_vm)
        return servers

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

    def check_show_policy(self, policy_id, rule_type=None,
                          rule_bw=None, rule_dscp=None):
        retrieved_policy = self.adm_qos_client.show_policy(policy_id)
        policy_rules = retrieved_policy['rules']
        if rule_type == 'bw':
            self.assertEqual(1, len(policy_rules))
            self.assertEqual(rule_bw['id'], policy_rules[0]['id'])
            self.assertEqual(base_qos.RULE_TYPE_BANDWIDTH_LIMIT,
                             policy_rules[0]['type'])
        elif rule_type == 'dscp':
            self.assertEqual(1, len(policy_rules))
            self.assertEqual(rule_dscp['id'], policy_rules[0]['id'])
            self.assertEqual(base_qos.RULE_TYPE_DSCP_MARK,
                             policy_rules[0]['type'])
        elif rule_type == 'bw+dscp':
            self.assertEqual(2, len(policy_rules))
            self.assertEqual(rule_bw['id'], policy_rules[0]['id'])
            self.assertEqual(rule_dscp['id'], policy_rules[1]['id'])
            self.assertEqual(base_qos.RULE_TYPE_BANDWIDTH_LIMIT,
                             policy_rules[0]['type'])
            self.assertEqual(base_qos.RULE_TYPE_DSCP_MARK,
                             policy_rules[1]['type'])

    def create_qos_network_topo(self):
        """Create basic network topology with 2 instances"""
        self.security_group = self._create_security_group()
        self.network = self._create_network(namestart="net-qos")
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_network, network_id=self.network['id'])
        self.subnet = self._create_subnet(self.network,
                                          cidr='192.153.1.0/24')
        self.router = self._create_router(
            router_name=data_utils.rand_name('router-qos'),
            external_network_id=CONF.network.public_network_id)
        self.routers_client.add_router_interface(
            self.router['id'], subnet_id=self.subnet['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        self.router['id'], subnet_id=self.subnet['id'])
        qos_topo = dict(network=self.network,
                        subnet=self.subnet, router=self.router)
        return qos_topo

    def _test_connectivity_between_vms(self, network_topo, servers):
        """To check if private ip is reachable from both vms"""
        floating_ip_src = self.create_floating_ip(
            servers['src_vm'])
        floating_ip_dst = self.create_floating_ip(servers['dst_vm'])
        private_ip_address_dst_vm = floating_ip_dst['fixed_ip_address']
        public_ip_address_dst_vm = \
            floating_ip_dst['floating_ip_address']
        private_ip_address_src_vm = floating_ip_src['fixed_ip_address']
        public_ip_address_src_vm = \
            floating_ip_src['floating_ip_address']
        src_client = remote_client.RemoteClient(
            public_ip_address_src_vm,
            username=CONF.validation.image_ssh_user,
            password=CONF.validation.image_ssh_password)
        cmd = ('ifconfig eth0 | grep %s' % private_ip_address_src_vm)
        timeout = time.time() + 60 * 5
        while True:
            if not src_client.exec_command(cmd) or time.time() < timeout:
                continue
            else:
                break
        dst_client = remote_client.RemoteClient(
            public_ip_address_dst_vm,
            username=CONF.validation.image_ssh_user,
            password=CONF.validation.image_ssh_password)
        # To ensure IP address is assigned to the VM before checking ping
        cmd = ('ifconfig eth0 | grep %s' % private_ip_address_dst_vm)
        timeout = time.time() + 60 * 5
        while True:
            if not dst_client.exec_command(cmd) or time.time() < timeout:
                continue
            else:
                break
        cmd = ('ping %s -c 3' % private_ip_address_dst_vm)
        output_data = src_client.exec_command(cmd)
        expected_output = "64 bytes from %s" % private_ip_address_dst_vm
        self.assertIn(expected_output, output_data)
        cmd = ('ping %s -c 3' % private_ip_address_src_vm)
        output_data = dst_client.exec_command(cmd)
        expected_output = "64 bytes from %s" % private_ip_address_src_vm
        self.assertIn(expected_output, output_data)
        vm_environment = dict(src_public_ip=public_ip_address_src_vm,
                              dst_public_ip=public_ip_address_dst_vm,
                              src_private_ip=private_ip_address_src_vm,
                              dst_private_ip=private_ip_address_dst_vm)
        return vm_environment

    def _test_bandwidth_rule(self, vm_env, max_mbps):
        """To verify traffic being capped according to bandwidth_rule"""
        src_client = remote_client.RemoteClient(
            vm_env['src_public_ip'], username='root', password='nicira')
        dst_client = remote_client.RemoteClient(
            vm_env['dst_public_ip'], username='root', password='nicira')
        # set up iperf server on destination VM
        cmd = ('iperf -p 49162 -s -u > /dev/null 2>&1 &')
        dst_client.exec_command(cmd)
        # sending traffic greater than configured value
        sending_rate = max_mbps + 1
        # set up iperf client on source VM
        LOG.info("Traffic sending rate: {sr}".format(sr=sending_rate))
        cmd = ('iperf -p 49162 -c %s -b %sM -t 1 -u | grep %%'
               % (unicode(vm_env['dst_private_ip']), unicode(sending_rate)))
        output = src_client.exec_command(cmd)
        bandwidth_value = output.split()[7]

        # kill the iperf process on destination VM
        cmd = ('ps -ef | grep iperf ')
        output = dst_client.exec_command(cmd)
        for line in output.splitlines():
            if 'iperf -p 49162 -s -u' not in line:
                continue
            else:
                iperf_process_id = line.split()[1]
                cmd = ('kill %s' % (unicode(iperf_process_id)))
                dst_client.exec_command(cmd)

        """Check if traffic received is greater than configured value
        For example if configured value is 5Mbps and sending rate is 6Mbps
        Traffic should be capped below 5.5 which includes default burst"""

        if (float(bandwidth_value) - float(max_mbps)) > 0.5:
            LOG.info("Traffic received: {bw}".format(bw=bandwidth_value))
            raise Exception('Traffic is not limited by bw-limit rule')
        elif(float(max_mbps) - float(bandwidth_value)) > 0.5:
            LOG.info("Traffic received: {bw}".format(bw=bandwidth_value))
            raise Exception('Traffic is limited below configured value')

    def _test_dscp_rule(self, vm_env, dscp_value):
        """To verify if traffic is being marked according to dscp_value"""
        src_client = remote_client.RemoteClient(
            vm_env['src_public_ip'], username='root', password='nicira')
        dst_client = remote_client.RemoteClient(
            vm_env['dst_public_ip'], username='root', password='nicira')
        dscp_filename = 'dscp_' + str(dscp_value) + '.pcap'
        # To capture packets from eth0
        cmd = ('nohup tcpdump -ni eth0 -w %s > /dev/null 2>&1 &'
               % dscp_filename)
        dst_client.exec_command(cmd)
        # Iperf server on destination VM
        cmd = ('iperf -p 49162 -s -u > /dev/null 2>&1 &')
        dst_client.exec_command(cmd)
        # Iperf client on source VM
        cmd = ('iperf -p 49162 -c %s -b 1M -t 1 -u | grep %%'
               % (unicode(vm_env['dst_private_ip'])))
        output = src_client.exec_command(cmd)
        loss_prcnt = output.split()[13].strip('()%')
        loss_val = float(loss_prcnt) if '.' in loss_prcnt else int(loss_prcnt)
        if (loss_val > 50.0):
            raise Exception('Huge packet loss at the destination VM')
        # Kill iperf process on destination VM
        cmd = ('ps -ef | grep iperf ')
        output = dst_client.exec_command(cmd)
        for line in output.splitlines():
            if 'iperf -p 49162 -s -u' not in line:
                continue
            else:
                iperf_process_id = line.split()[1]
                cmd = ('kill %s' % (unicode(iperf_process_id)))
                dst_client.exec_command(cmd)
        # kill tcpdump process on destination VM
        cmd = ('ps -ef | grep tcpdump')
        output = dst_client.exec_command(cmd)
        for line in output.splitlines():
            if 'tcpdump -ni eth0 -w' not in line:
                continue
            else:
                tcpdump_process_id = line.split()[1]
                cmd = ('kill %s' % (unicode(tcpdump_process_id)))
                dst_client.exec_command(cmd)
        # To copy pcap (packet capture) file from destination VM to external VM
        cmd = ('sshpass -p  \"nicira\" scp -o StrictHostKeyChecking=no'
               ' root@%s:/root/%s .'
               % (unicode(vm_env['dst_public_ip']), unicode(dscp_filename)))
        try:
            subprocess.check_call(cmd, shell=True, executable='/bin/bash',
                                  stderr=subprocess.STDOUT)
        except Exception as e:
            message = ('Failed to copy file from VM.'
                       'Error: %(error)s' % {'error': e})
            LOG.exception(message)
            raise

        """Check the entire file to see if any UDP packets are sent without configured
        dscp value.Example capture all UDP packets with DSCP value !=12"""

        filter_string = (
            'ip.dsfield.dscp != %s && udp.dstport == 49162 '
            '&& ip.src == %s && ip.dst == %s' %
            (str(dscp_value), (unicode(
                vm_env['src_private_ip'])), (unicode(
                    vm_env['dst_private_ip']))))
        capture = pyshark.FileCapture(dscp_filename,
                                      display_filter=filter_string)
        # capture file includes all packets that match the filter criteria
        if len(capture) > 0:
            raise Exception('Traffic is being marked with incorrect DSCP')


class QosBandwidthLimitRuleTest(TestQoSOps):

    BW_VALUE_KBPS = 5000
    BW_VALUE_MBPS = 5

    @decorators.idempotent_id('68fa3170-b61c-4e69-b0b7-6cbe34b57724')
    def test_qos_bw_rule(self):
        """Test bandwidth_limit rule by sending traffic between two instances
        and verifying if egress traffic is being bandwidth-limited
        """
        qos_client = self.adm_qos_client
        policy = self.create_qos_policy(name='test-qos-policy',
                                        description='bandwidth_rule',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        rule = self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=self.BW_VALUE_KBPS,
            max_burst_kbps=0)

        # Test 'show rule'
        retrieved_rule = qos_client.show_bandwidth_limit_rule(
            rule['id'], policy['id'])
        self.assertEqual(rule['id'], retrieved_rule['id'])
        self.assertEqual(self.BW_VALUE_KBPS, retrieved_rule['max_kbps'])

        # Test 'list rules'
        rules = qos_client.list_bandwidth_limit_rules(policy['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule['id'], rules_ids)

        # Test 'show policy'
        self.check_show_policy(policy_id=policy['id'], rule_type='bw',
            rule_bw=rule)

        self.network_topo = self.create_qos_network_topo()
        self.update_network(
            self.network_topo['network']['id'], qos_policy_id=policy['id'])
        updated_network = self.show_network(self.network_topo['network']['id'])
        self.assertEqual(
            policy['id'], updated_network['qos_policy_id'])
        self.servers = self._create_vms(self.network_topo)
        vm_env = self._test_connectivity_between_vms(self.network_topo,
                                                     self.servers)
        self._test_bandwidth_rule(vm_env, max_mbps=self.BW_VALUE_MBPS)


class QosDSCPRuleTest(TestQoSOps):

    DSCP_MARK = 12

    @decorators.idempotent_id('f00f77c4-2963-4e28-8cb9-d6a51d92262d')
    def test_qos_dscp_rule(self):
        """Test DSCP rule by sending traffic between two instances
        and verifying if egress traffic is being marked
        """
        qos_client = self.adm_qos_client
        policy = self.create_qos_policy(name='test-qos-policy',
                                        description='dscp_rule',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        # add dscp rule
        rule = self.create_qos_dscp_marking_rule(
            policy_id=policy['id'], dscp_mark=12)

        # Test 'show rule'
        retrieved_rule = qos_client.show_dscp_marking_rule(
            rule['id'], policy['id'])
        self.assertEqual(rule['id'], retrieved_rule['id'])
        self.assertEqual(self.DSCP_MARK, retrieved_rule['dscp_mark'])

        # Test 'list rules'
        rules = qos_client.list_dscp_marking_rules(policy['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule['id'], rules_ids)

        # Test 'show policy'
        self.check_show_policy(policy_id=policy['id'],
            rule_type='dscp', rule_dscp=rule)

        self.network_topo = self.create_qos_network_topo()
        self.update_network(
            self.network_topo['network']['id'], qos_policy_id=policy['id'])
        updated_network = self.show_network(self.network_topo['network']['id'])
        self.assertEqual(
            policy['id'], updated_network['qos_policy_id'])
        self.servers = self._create_vms(self.network_topo)
        vm_env = self._test_connectivity_between_vms(self.network_topo,
                                                     self.servers)
        self._test_dscp_rule(vm_env, dscp_value=self.DSCP_MARK)


class QosBWDSCPRuleTest(TestQoSOps):

    BW_VALUE_KBPS = 5000
    BW_VALUE_MBPS = 5
    DSCP_MARK = 16

    @decorators.idempotent_id('77ae2231-029f-4f7f-9858-3d610fb62386')
    def test_qos_bw_dscp_rule(self):
        """Test BW and DSCP rule by sending traffic between two instances
        and verifying if egress traffic is being marked and bandwidth-limited
        """
        qos_client = self.adm_qos_client
        policy = self.create_qos_policy(name='test-qos-policy',
                                        description='dscp_rule and bw_rule',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        # add bw rule
        rule_bw = self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'], max_kbps=self.BW_VALUE_KBPS,
            max_burst_kbps=0)
        # add dscp rule
        rule_dscp = self.create_qos_dscp_marking_rule(
            policy_id=policy['id'], dscp_mark=self.DSCP_MARK)

        # Test 'show rule'
        retrieved_rule = qos_client.show_bandwidth_limit_rule(
            rule_bw['id'], policy['id'])
        self.assertEqual(rule_bw['id'], retrieved_rule['id'])
        self.assertEqual(self.BW_VALUE_KBPS, retrieved_rule['max_kbps'])

        # Test 'show rule'
        retrieved_rule = qos_client.show_dscp_marking_rule(
            rule_dscp['id'], policy['id'])
        self.assertEqual(rule_dscp['id'], retrieved_rule['id'])
        self.assertEqual(self.DSCP_MARK, retrieved_rule['dscp_mark'])

        # Test 'list rules'
        rules = qos_client.list_bandwidth_limit_rules(policy['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule_bw['id'], rules_ids)

        # Test 'list rules'
        rules = qos_client.list_dscp_marking_rules(policy['id'])
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule_dscp['id'], rules_ids)

        # Test 'show policy'
        self.check_show_policy(policy_id=policy['id'], rule_type='bw+dscp',
            rule_bw=rule_bw, rule_dscp=rule_dscp)

        self.network_topo = self.create_qos_network_topo()
        self.update_network(
            self.network_topo['network']['id'], qos_policy_id=policy['id'])
        updated_network = self.show_network(self.network_topo['network']['id'])
        self.assertEqual(
            policy['id'], updated_network['qos_policy_id'])
        self.servers = self._create_vms(self.network_topo)
        vm_env = self._test_connectivity_between_vms(self.network_topo,
                                                     self.servers)
        self._test_bandwidth_rule(vm_env, max_mbps=self.BW_VALUE_MBPS)
        self._test_dscp_rule(vm_env, dscp_value=self.DSCP_MARK)
