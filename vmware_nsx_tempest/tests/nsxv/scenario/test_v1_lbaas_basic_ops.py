# Copyright 2014 Mirantis.inc
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

import shlex
import six
import subprocess
import tempfile
import time
import urllib2

from tempest import config
from tempest import exceptions
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.scenario import manager
from tempest import test

from vmware_nsx_tempest.services import load_balancer_v1_client as LBV1C
from vmware_nsx_tempest.tests.nsxv.scenario import (
    network_addon_methods as HELO)

CONF = config.CONF


class TestLBaaSBasicOps(manager.NetworkScenarioTest):

    """This test checks basic load balancing.

    The following is the scenario outline:
    1. Create an instance
    2. SSH to the instance and start two servers
    3. Create a load balancer with two members and with ROUND_ROBIN algorithm
       associate the VIP with a floating ip
    4. Send NUM requests to the floating ip and check that they are shared
       between the two servers.
    """

    @classmethod
    def skip_checks(cls):
        super(TestLBaaSBasicOps, cls).skip_checks()
        cfg = CONF.network
        if not test.is_extension_enabled('lbaas', 'network'):
            msg = 'LBaaS Extension is not enabled'
            raise cls.skipException(msg)
        if not (cfg.project_networks_reachable or cfg.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        # Ask framework to not create network resources for these tests.
        cls.set_network_resources()
        super(TestLBaaSBasicOps, cls).setup_credentials()

    def setUp(self):
        super(TestLBaaSBasicOps, self).setUp()
        # https://review.openstack.org/#/c/262571/
        CONF.validation.ssh_shell_prologue = ''
        self.servers_keypairs = {}
        self.members = []
        self.floating_ips = {}
        self.server_ips = {}
        self.port1 = 80
        self.port2 = 88
        self.num = 50
        self.server_ips = {}
        self.server_fixed_ips = {}
        self.lbv1_client = LBV1C.get_client(self.manager)
        self._create_security_group_for_test()
        self._set_net_and_subnet()

    def tearDown(self):
        for s_id in self.server_ips.keys():
            try:
                self.servers_client.delete_server(s_id)
            except Exception:
                pass
        try:
            for mem in self.members:
                mem.delete()
            self.vip.delete()
            self.pool.delete()
        except Exception:
            pass
        super(TestLBaaSBasicOps, self).tearDown()

    def _set_net_and_subnet(self):
        """Create network, subnet and router.

        Query and set appropriate network and subnet attributes to be used
        for the test.  Existing tenant networks are used if they are found.
        The configured private network and associated subnet is used as a
        fallback in absence of tenant networking.
        """
        self.network, self.subnet, self.router = (
            self.create_networks(router_type='exclusive'))
        self.check_networks()

    # overwrite super class who does not accept router attributes
    def create_networks(self, dns_nameservers=None, **kwargs):
        namestart = 'lbv1-ops'
        routers_client = self.routers_client
        networks_client = self.networks_client
        subnets_client = self.subnets_client

        router_kwargs = dict(client=routers_client, namestart=namestart)
        for k in kwargs.keys():
            if k in ('distributed', 'router_type', 'router_size'):
                router_kwargs[k] = kwargs.pop(k)
        router = self._create_router(**router_kwargs)
        HELO.router_gateway_set(self, router['id'],
                                CONF.network.public_network_id)

        network = self._create_network(
            routers_client=routers_client,
            networks_client=networks_client,
            namestart=namestart,
            tenant_id=self.tenant_id)

        subnet_kwargs = dict(network=network,
                             namestart=namestart,
                             subnets_client=subnets_client)
        # use explicit check because empty list is a valid option
        if dns_nameservers is not None:
            subnet_kwargs['dns_nameservers'] = dns_nameservers
        subnet = self._create_subnet(**subnet_kwargs)
        HELO.router_interface_add(self, router['id'], subnet['id'],
                                  routers_client)
        return network, subnet, router

    # overwrite super class
    def _create_router(self, client=None, tenant_id=None,
                       namestart='router-lbv1', **kwargs):
        return HELO.router_create(self, client,
                                  tenant_id=tenant_id,
                                  namestart=namestart,
                                  admin_state_up=True,
                                  **kwargs)

    def check_networks(self):
        HELO.check_networks(self, self.network, self.subnet, self.router)

    def _create_security_group_for_test(self):
        self.security_group = self._create_security_group(
            tenant_id=self.tenant_id)
        self._create_security_group_rules_for_port(self.port1)
        self._create_security_group_rules_for_port(self.port2)

    def _create_security_group_rules_for_port(self, port):
        rule = {
            'direction': 'ingress',
            'protocol': 'tcp',
            'port_range_min': port,
            'port_range_max': port,
        }
        self._create_security_group_rule(
            secgroup=self.security_group,
            tenant_id=self.tenant_id,
            **rule)

    def _create_server(self, name):
        keypair = self.create_keypair()
        security_groups = [{'name': self.security_group['name']}]
        create_kwargs = {
            'networks': [
                {'uuid': self.network['id']},
            ],
            'key_name': keypair['name'],
            'security_groups': security_groups,
            'wait_until': 'ACTIVE',
        }
        net_name = self.network['name']
        server = self.create_server(name=name, **create_kwargs)
        serv_id = server['id']
        self.servers_keypairs[serv_id] = keypair
        if (CONF.network.public_network_id and not
                CONF.network.project_networks_reachable):
            public_network_id = CONF.network.public_network_id
            floating_ip = self.create_floating_ip(
                server, public_network_id)
            self.floating_ips[floating_ip] = server
            self.server_ips[serv_id] = floating_ip['floating_ip_address']
        else:
            self.server_ips[serv_id] = self._server_ip(server, net_name)
        self.server_fixed_ips[serv_id] = self._server_ip(server, net_name)
        self.assertTrue(self.servers_keypairs)
        return server

    def _server_ip(self, server, net_name):
        return server['addresses'][net_name][0]['addr']

    def _create_servers(self):
        for count in range(2):
            self._create_server(name=("server%s" % (count + 1)))
        self.assertEqual(len(self.servers_keypairs), 2)

    def _start_servers(self):
        """Start two hardcoded named servers: server1 & server2

        1. SSH to the instance
        2. Start two http backends listening on ports 80 and 88 respectively
        """
        for server_id, ip in six.iteritems(self.server_ips):
            private_key = self.servers_keypairs[server_id]['private_key']
            # server = self.servers_client.show_server(server_id)['server']
            # server['name'] is not 'server1' as 2015-12 due to upstream change
            # server_name = server['name']
            username = CONF.validation.image_ssh_user
            ssh_client = self.get_remote_client(
                ip,
                private_key=private_key)

            # Write a backend's response into a file
            resp = ('echo -ne "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n'
                    'Connection: close\r\nContent-Type: text/html; '
                    'charset=UTF-8\r\n\r\n%s"; cat >/dev/null')

            with tempfile.NamedTemporaryFile() as script:
                script.write(resp % 'server1')
                script.flush()
                with tempfile.NamedTemporaryFile() as key:
                    key.write(private_key)
                    key.flush()
                    copy_file_to_host(script.name,
                                      "/tmp/script1",
                                      ip,
                                      username, key.name)

            # Start netcat
            start_server = ('while true; do '
                            'sudo nc -ll -p %(port)s -e sh /tmp/%(script)s; '
                            'done > /dev/null &')
            cmd = start_server % {'port': self.port1,
                                  'script': 'script1'}
            # https://review.openstack.org/#/c/262571/
            # ssh_client.exec_command(cmd, False)
            ssh_client.exec_command(cmd)

            if len(self.server_ips) == 1:
                with tempfile.NamedTemporaryFile() as script:
                    script.write(resp % 'server2')
                    script.flush()
                    with tempfile.NamedTemporaryFile() as key:
                        key.write(private_key)
                        key.flush()
                        copy_file_to_host(script.name,
                                          "/tmp/script2", ip,
                                          username, key.name)
                cmd = start_server % {'port': self.port2,
                                      'script': 'script2'}
                # https://review.openstack.org/#/c/262571/
                # ssh_client.exec_command(cmd, False)
                ssh_client.exec_command(cmd)

    def _check_connection(self, check_ip, port=80):
        def try_connect(ip, port):
            try:
                resp = urllib2.urlopen("http://{0}:{1}/".format(ip, port))
                if resp.getcode() == 200:
                    return True
                return False
            except IOError:
                return False
            except urllib2.HTTPError:
                return False
        timeout = CONF.validation.ping_timeout
        start = time.time()
        while not try_connect(check_ip, port):
            if (time.time() - start) > timeout:
                message = "Timed out trying to connect to %s" % check_ip
                raise exceptions.TimeoutException(message)

    def _create_pool(self):
        """Create a pool with ROUND_ROBIN algorithm."""
        pool_name = data_utils.rand_name('pool-')
        pool = self.lbv1_client.create_pool(
            pool_name,
            lb_method='ROUND_ROBIN',
            protocol='HTTP',
            subnet_id=self.subnet['id'])
        self.pool = pool.get('pool', pool)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.lbv1_client.delete_pool,
                        self.pool['id'])
        self.assertTrue(self.pool)
        return self.pool

    def _create_vip(self, pool_id, **kwargs):
        result = self.lbv1_client.create_vip(pool_id, **kwargs)
        vip = result.get('vip', result)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.lbv1_client.delete_vip,
                        vip['id'])
        return vip

    def _create_member(self, protocol_port, pool_id, ip_version=4, **kwargs):
        result = self.lbv1_client.create_member(protocol_port, pool_id,
                                                ip_version, **kwargs)
        member = result.get('member', result)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.lbv1_client.delete_member,
                        member['id'])

    def _create_members(self):
        """Create two members.

        In case there is only one server, create both members with the same ip
        but with different ports to listen on.
        """

        pool_id = self.pool['id']
        for server_id, ip in six.iteritems(self.server_fixed_ips):
            if len(self.server_fixed_ips) == 1:
                member1 = self._create_member(address=ip,
                                              protocol_port=self.port1,
                                              pool_id=pool_id)
                member2 = self._create_member(address=ip,
                                              protocol_port=self.port2,
                                              pool_id=pool_id)
                self.members.extend([member1, member2])
            else:
                member = self._create_member(address=ip,
                                             protocol_port=self.port1,
                                             pool_id=pool_id)
                self.members.append(member)
        self.assertTrue(self.members)

    def _assign_floating_ip_to_vip(self, vip):
        public_network_id = CONF.network.public_network_id
        vip_id = vip['id']
        port_id = vip['port_id']
        floating_ip = self.create_floating_ip(vip, public_network_id,
                                              port_id=port_id)
        #?# self.floating_ips.setdefault(vip_id, [])
        self.floating_ips[vip_id].append(floating_ip)
        # Check for floating ip status before you check load-balancer
        self.check_floating_ip_status(floating_ip, "ACTIVE")

    def _create_load_balancer(self):
        self._create_pool()
        self._create_members()
        vip_id = self.vip['id']
        self.vip = self._create_vip(protocol='HTTP',
                                    protocol_port=80,
                                    subnet_id=self.subnet['id'],
                                    pool_id=self.pool['id'])
        self.vip_wait_for_status(self.vip, 'ACTIVE')
        if (CONF.network.public_network_id and not
                CONF.network.project_networks_reachable):
            self._assign_floating_ip_to_vip(self.vip)
            self.vip_ip = self.floating_ips[
                vip_id][0]['floating_ip_address']
        else:
            self.vip_ip = self.vip['address']

        # Currently the ovs-agent is not enforcing security groups on the
        # vip port - see https://bugs.launchpad.net/neutron/+bug/1163569
        # However the linuxbridge-agent does, and it is necessary to add a
        # security group with a rule that allows tcp port 80 to the vip port.
        self.ports_client.update_port(
            self.vip['port_id'],
            security_groups=[self.security_group['id']])

    def vip_wait_for_status(self, vip, status='ACTIVE'):
        # vip is DelatableVip
        interval = self.lbv1_client.build_interval
        timeout = self.lbv1_client.build_timeout
        start_time = time.time()

        vip_id = vip['id']
        while time.time() - start_time <= timeout:
            resource = self.lbv1_client.show_vip(vip_id)['vip']
            if resource['status'] == status:
                return
            time.sleep(interval)
        message = "Wait for VIP become ACTIVE"
        raise exceptions.TimeoutException(message)

    def _check_load_balancing(self):
        """http to load balancer to check message handled by both servers.

        1. Send NUM requests on the floating ip associated with the VIP
        2. Check that the requests are shared between the two servers
        """

        self._check_connection(self.vip_ip)
        self._send_requests(self.vip_ip, ["server1", "server2"])

    def _send_requests(self, vip_ip, servers):
        counters = dict.fromkeys(servers, 0)
        for i in range(self.num):
            try:
                server = urllib2.urlopen("http://{0}/".format(vip_ip)).read()
                counters[server] += 1
            # HTTP exception means fail of server, so don't increase counter
            # of success and continue connection tries
            except urllib2.HTTPError:
                continue
        # Assert that each member of the pool gets balanced at least once
        for member, counter in six.iteritems(counters):
            self.assertGreater(counter, 0, 'Member %s never balanced' % member)

    @test.idempotent_id('e81b5af1-d854-4e16-9d2d-16187bdf1334')
    @test.services('compute', 'network')
    def test_load_balancer_basic(self):
        self._create_server('server1')
        self._start_servers()
        self._create_load_balancer()
        self._check_load_balancing()


def copy_file_to_host(file_from, dest, host, username, pkey):
    dest = "%s@%s:%s" % (username, host, dest)
    cmd = "scp -v -o UserKnownHostsFile=/dev/null " \
          "-o StrictHostKeyChecking=no " \
          "-i %(pkey)s %(file1)s %(dest)s" % {'pkey': pkey,
                                              'file1': file_from,
                                              'dest': dest}
    args = shlex.split(cmd.encode('utf-8'))
    subprocess_args = {'stdout': subprocess.PIPE,
                       'stderr': subprocess.STDOUT}
    proc = subprocess.Popen(args, **subprocess_args)
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise exceptions.CommandFailed(cmd,
                                       proc.returncode,
                                       stdout,
                                       stderr)
    return stdout
