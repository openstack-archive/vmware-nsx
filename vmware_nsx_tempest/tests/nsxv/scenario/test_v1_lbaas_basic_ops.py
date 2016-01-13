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


import six
import tempfile
import time
import urllib2

from tempest_lib.common.utils import data_utils

from tempest.common import commands
from tempest import config
from tempest import exceptions
from tempest.scenario import manager
from tempest.services.network import resources as net_resources
from tempest import test

from vmware_nsx_tempest.services import load_balancer_v1_client as LBV1C

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
        if not (cfg.tenant_networks_reachable or cfg.public_network_id):
            msg = ('Either tenant_networks_reachable must be "true", or '
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
        client = self.network_client
        networks_client = self.networks_client
        subnets_client = self.subnets_client

        router_kwargs = {}
        for k in kwargs.keys():
            if k in ('distributed', 'router_type', 'router_size'):
                router_kwargs[k] = kwargs.pop(k)
        router = self._create_router(**router_kwargs)
        router.set_gateway(CONF.network.public_network_id)

        network = self._create_network(
            client=client, networks_client=networks_client,
            tenant_id=self.tenant_id)

        subnet_kwargs = dict(network=network, client=client,
                             subnets_client=subnets_client)
        # use explicit check because empty list is a valid option
        if dns_nameservers is not None:
            subnet_kwargs['dns_nameservers'] = dns_nameservers
        subnet = self._create_subnet(**subnet_kwargs)
        subnet.add_to_router(router.id)
        return network, subnet, router

    # overwrite super class
    def _create_router(self, client=None, tenant_id=None,
                       namestart='router-smoke', **kwargs):
        if not client:
            client = self.network_client
        if not tenant_id:
            tenant_id = client.tenant_id
        name = data_utils.rand_name(namestart)
        result = client.create_router(name=name,
                                      admin_state_up=True,
                                      tenant_id=tenant_id,
                                      **kwargs)
        router = net_resources.DeletableRouter(client=client,
                                               **result['router'])
        self.assertEqual(router.name, name)
        self.addCleanup(self.delete_wrapper, router.delete)
        return router

    def check_networks(self):
        """Checks that we see the newly created network/subnet/router.

        checking the result of list_[networks,routers,subnets]
        """

        seen_nets = self._list_networks()
        seen_names = [n['name'] for n in seen_nets]
        seen_ids = [n['id'] for n in seen_nets]
        self.assertIn(self.network.name, seen_names)
        self.assertIn(self.network.id, seen_ids)

        if self.subnet:
            seen_subnets = self._list_subnets()
            seen_net_ids = [n['network_id'] for n in seen_subnets]
            seen_subnet_ids = [n['id'] for n in seen_subnets]
            self.assertIn(self.network.id, seen_net_ids)
            self.assertIn(self.subnet.id, seen_subnet_ids)

        if self.router:
            seen_routers = self._list_routers()
            seen_router_ids = [n['id'] for n in seen_routers]
            seen_router_names = [n['name'] for n in seen_routers]
            self.assertIn(self.router.name,
                          seen_router_names)
            self.assertIn(self.router.id,
                          seen_router_ids)

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
                CONF.network.tenant_networks_reachable):
            public_network_id = CONF.network.public_network_id
            floating_ip = self.create_floating_ip(
                server, public_network_id)
            self.floating_ips[floating_ip] = server
            self.server_ips[serv_id] = floating_ip.floating_ip_address
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
                server_or_ip=ip,
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
                    commands.copy_file_to_host(script.name,
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
                        commands.copy_file_to_host(script.name,
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
            subnet_id=self.subnet.id)['pool']
        self.pool = net_resources.DeletablePool(client=self.lbv1_client,
                                                **pool)
        self.assertTrue(self.pool)
        return self.pool

    def _create_vip(self, pool_id, **kwargs):
        result = self.lbv1_client.create_vip(pool_id, **kwargs)
        vip = net_resources.DeletableVip(client=self.lbv1_client,
                                         **result['vip'])
        return vip

    def _create_member(self, protocol_port, pool_id, ip_version=4, **kwargs):
        result = self.lbv1_client.create_member(protocol_port, pool_id,
                                                ip_version, **kwargs)
        member = net_resources.DeletableMember(client=self.lbv1_client,
                                               **result['member'])
        return member

    def _create_members(self):
        """Create two members.

        In case there is only one server, create both members with the same ip
        but with different ports to listen on.
        """

        for server_id, ip in six.iteritems(self.server_fixed_ips):
            if len(self.server_fixed_ips) == 1:
                member1 = self._create_member(address=ip,
                                              protocol_port=self.port1,
                                              pool_id=self.pool.id)
                member2 = self._create_member(address=ip,
                                              protocol_port=self.port2,
                                              pool_id=self.pool.id)
                self.members.extend([member1, member2])
            else:
                member = self._create_member(address=ip,
                                             protocol_port=self.port1,
                                             pool_id=self.pool.id)
                self.members.append(member)
        self.assertTrue(self.members)

    def _assign_floating_ip_to_vip(self, vip):
        public_network_id = CONF.network.public_network_id
        port_id = vip.port_id
        floating_ip = self.create_floating_ip(vip, public_network_id,
                                              port_id=port_id)
        self.floating_ips.setdefault(vip.id, [])
        self.floating_ips[vip.id].append(floating_ip)
        # Check for floating ip status before you check load-balancer
        self.check_floating_ip_status(floating_ip, "ACTIVE")

    def _create_load_balancer(self):
        self._create_pool()
        self._create_members()
        self.vip = self._create_vip(protocol='HTTP',
                                    protocol_port=80,
                                    subnet_id=self.subnet.id,
                                    pool_id=self.pool.id)
        self.vip.wait_for_status('ACTIVE')
        if (CONF.network.public_network_id and not
                CONF.network.tenant_networks_reachable):
            self._assign_floating_ip_to_vip(self.vip)
            self.vip_ip = self.floating_ips[
                self.vip.id][0]['floating_ip_address']
        else:
            self.vip_ip = self.vip.address

        # Currently the ovs-agent is not enforcing security groups on the
        # vip port - see https://bugs.launchpad.net/neutron/+bug/1163569
        # However the linuxbridge-agent does, and it is necessary to add a
        # security group with a rule that allows tcp port 80 to the vip port.
        self.ports_client.update_port(
            self.vip.port_id, security_groups=[self.security_group.id])

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
