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
import tempfile
import time
import urllib3

from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest import test

from vmware_nsx_tempest.services.lbaas import health_monitors_client
from vmware_nsx_tempest.services.lbaas import listeners_client
from vmware_nsx_tempest.services.lbaas import load_balancers_client
from vmware_nsx_tempest.services.lbaas import members_client
from vmware_nsx_tempest.services.lbaas import pools_client
from vmware_nsx_tempest.tests.nsxv.scenario import (
    manager_topo_deployment as dmgr)
from vmware_nsx_tempest.tests.nsxv.scenario import test_v1_lbaas_basic_ops


CONF = config.CONF
LOG = dmgr.manager.log.getLogger(__name__)


class TestLBaasRoundRobinOps(dmgr.TopoDeployScenarioManager):

    """This test checks basic load balancer V2 ROUND-ROBIN operation.

    The following is the scenario outline:
    1. Create network with exclusive router, and 2 servers
    2. SSH to each instance and start web server
    3. Create a load balancer with 1 listener, 1 pool, 1 healthmonitor
       and 2 members and with ROUND_ROBIN algorithm.
    4. Associate loadbalancer's vip_address with a floating ip
    5. Send NUM requests to vip's floating ip and check that they are shared
       between the two servers.
    """

    tenant_router_attrs = {'router_type': 'exclusive'}

    @classmethod
    def skip_checks(cls):
        super(TestLBaasRoundRobinOps, cls).skip_checks()
        cfg = CONF.network
        if not test.is_extension_enabled('lbaasv2', 'network'):
            msg = 'lbaasv2 extension is not enabled.'
            raise cls.skipException(msg)
        if not (cfg.project_networks_reachable or cfg.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TestLBaasRoundRobinOps, cls).resource_setup()
        cls.create_lbaas_clients(cls.manager)

    @classmethod
    def create_lbaas_clients(cls, mgr):
        cls.load_balancers_client = load_balancers_client.get_client(mgr)
        cls.listeners_client = listeners_client.get_client(mgr)
        cls.pools_client = pools_client.get_client(mgr)
        cls.members_client = members_client.get_client(mgr)
        cls.health_monitors_client = health_monitors_client.get_client(mgr)

    @classmethod
    def setup_credentials(cls):
        # Ask framework to not create network resources for these tests.
        cls.set_network_resources()
        super(TestLBaasRoundRobinOps, cls).setup_credentials()

    def setUp(self):
        super(TestLBaasRoundRobinOps, self).setUp()
        CONF.validation.ssh_shell_prologue = ''
        self.namestart = 'lbaas-ops'
        self.poke_counters = 10
        self.protocol_type = 'HTTP'
        self.protocol_port = 80
        self.lb_algorithm = "ROUND_ROBIN"
        self.hm_delay = 4
        self.hm_max_retries = 3
        self.hm_timeout = 10
        self.server_names = []
        self.loadbalancer = None
        self.vip_fip = None
        self.web_service_start_delay = 2.5

    def tearDown(self):
        if self.vip_fip:
            LOG.debug("tearDown lbass vip fip")
            self.disassociate_floatingip(self.vip_fip, and_delete=True)
        if self.loadbalancer:
            LOG.debug("tearDown lbass")
            lb_id = self.loadbalancer['id']
            self.delete_loadbalancer_resources(lb_id)

        # make sure servers terminated before teardown network resources
        LOG.debug("tearDown lbaas servers")
        server_id_list = []
        for servid in ['server1', 'server2']:
            server = getattr(self, servid, None)
            if server:
                if '_floating_ip' in server:
                    fip = server['_floating_ip']
                    self.disassociate_floatingip(fip, and_delete=True)
                self.manager.servers_client.delete_server(server['id'])
                server_id_list.append(server['id'])
        for server_id in server_id_list:
            waiters.wait_for_server_termination(
                self.manager.servers_client, server_id)
        # delete lbaas network before handing back to framework
        super(TestLBaasRoundRobinOps, self).tearDown()
        LOG.debug("tearDown lbaas exiting...")

    def delete_loadbalancer_resources(self, lb_id):
        lb_client = self.load_balancers_client
        statuses = lb_client.show_load_balancer_status_tree(lb_id)
        statuses = statuses.get('statuses', statuses)
        lb = statuses.get('loadbalancer')
        for listener in lb.get('listeners', []):
            for pool in listener.get('pools'):
                pool_id = pool.get('id')
                hm = pool.get('healthmonitor')
                if hm:
                    test_utils.call_and_ignore_notfound_exc(
                        self.health_monitors_client.delete_health_monitor,
                        pool.get('healthmonitor').get('id'))
                    self.wait_for_load_balancer_status(lb_id)
                test_utils.call_and_ignore_notfound_exc(
                    self.pools_client.delete_pool, pool.get('id'))
                self.wait_for_load_balancer_status(lb_id)
                for member in pool.get('members', []):
                    test_utils.call_and_ignore_notfound_exc(
                        self.members_client.delete_member,
                        pool_id, member.get('id'))
                    self.wait_for_load_balancer_status(lb_id)
            test_utils.call_and_ignore_notfound_exc(
                self.listeners_client.delete_listener,
                listener.get('id'))
            self.wait_for_load_balancer_status(lb_id)
        test_utils.call_and_ignore_notfound_exc(
            lb_client.delete_load_balancer, lb_id)
        self.load_balancers_client.wait_for_load_balancer_status(
            lb_id, is_delete_op=True)
        lbs = lb_client.list_load_balancers()['loadbalancers']
        self.assertEqual(0, len(lbs))

    def wait_for_load_balancer_status(self, lb_id):
        # Wait for load balancer become ONLINE and ACTIVE
        self.load_balancers_client.wait_for_load_balancer_status(lb_id)

    def create_lbaas_networks(self):
        """Create network, subnet and router for lbaasv2 environment."""
        self.network, self.subnet, self.router = self.setup_project_network(
            self.public_network_id, client_mgr=self.manager,
            namestart=self.namestart)
        self._create_security_group_for_test()
        security_groups = [{'name': self.security_group['id']}]
        self.keypair = self.create_keypair()
        key_name = self.keypair['name']
        network_name = self.network['name']
        self.server1 = self.create_server_on_network(
            self.network, name=(network_name + "-1"),
            security_groups=security_groups,
            key_name=key_name, wait_on_boot=False,
            servers_client=self.manager.servers_client)
        self.server2 = self.create_server_on_network(
            self.network, name=(network_name + "-2"),
            security_groups=security_groups,
            key_name=key_name,
            servers_client=self.manager.servers_client)
        self.wait_for_servers_become_active()

    def wait_for_servers_become_active(self):
        for serv in [self.server1, self.server2]:
            waiters.wait_for_server_status(
                self.manager.servers_client,
                serv['id'], 'ACTIVE')

    def _create_security_group_for_test(self):
        self.security_group = self._create_security_group(
            tenant_id=self.tenant_id)
        self._create_security_group_rules_for_port(self.protocol_port)

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

    def start_web_servers(self):
        """Start predefined servers:

        1. SSH to the instance
        2. Start http backends listening on port 80
        """
        for server in [self.server1, self.server2]:
            fip = self.create_floatingip_for_server(
                server, self.public_network_id,
                client_mgr=self.manager)
            server['_floating_ip'] = fip
            server_fip = fip['floating_ip_address']
            self.start_web_server(server, server_fip, server['name'])
        # need to wait for web server to be able to response
        time.sleep(self.web_service_start_delay)
        for server in [self.server1, self.server2]:
            server_name = server['name']
            fip = server['_floating_ip']
            web_fip = fip['floating_ip_address']
            response = self.send_request(web_fip)
            # by design, each lbaas member server response its server_name
            self.assertEqual(response, server_name)
            self.server_names.append(server_name)

    def start_web_server(self, server, server_fip, server_name):
        """start server's web service which return its server_name."""

        private_key = self.keypair['private_key']
        username = CONF.validation.image_ssh_user
        ssh_client = self.get_remote_client(
            server_fip, private_key=private_key)

        # Write a backend's response into a file
        resp = ('echo -ne "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n'
                'Connection: close\r\nContent-Type: text/html; '
                'charset=UTF-8\r\n\r\n%s"; cat >/dev/null')

        with tempfile.NamedTemporaryFile() as script:
            script.write(resp % (len(server_name), server_name))
            script.flush()
            with tempfile.NamedTemporaryFile() as key:
                key.write(private_key)
                key.flush()
                test_v1_lbaas_basic_ops.copy_file_to_host(
                        script.name,
                        "/tmp/script",
                        server_fip, username, key.name)

        # Start netcat
        start_server = ('while true; do '
                        'sudo nc -ll -p %(port)s -e sh /tmp/%(script)s; '
                        'done > /dev/null &')
        cmd = start_server % {'port': self.protocol_port,
                              'script': 'script'}
        ssh_client.exec_command(cmd)
        return server_name

    def send_request(self, web_ip):
        try:
            url_path = "http://{0}/".format(web_ip)
            # lbaas servers use nc, might be slower to response
            http = urllib3.PoolManager(retries=10)
            resp = http.request('GET', url_path)
            return resp.data.strip()
        except Exception:
            return None

    def create_project_lbaas(self):
        vip_subnet_id = self.subnet['id']
        lb_name = data_utils.rand_name(self.namestart)
        self.loadbalancer = self.load_balancers_client.create_load_balancer(
            name=lb_name, vip_subnet_id=vip_subnet_id)['loadbalancer']
        lb_id = self.loadbalancer['id']
        self.wait_for_load_balancer_status(lb_id)

        self.listener = self.listeners_client.create_listener(
            loadbalancer_id=lb_id, protocol=self.protocol_type,
            protocol_port=self.protocol_port, name=lb_name)['listener']
        self.wait_for_load_balancer_status(lb_id)

        self.pool = self.pools_client .create_pool(
            listener_id=self.listener['id'],
            lb_algorithm=self.lb_algorithm, protocol=self.protocol_type,
            name=lb_name)['pool']
        self.wait_for_load_balancer_status(lb_id)
        pool_id = self.pool['id']

        self.healthmonitor = (
            self.health_monitors_client.create_health_monitor(
                pool_id=pool_id, type=self.protocol_type,
                delay=self.hm_delay, max_retries=self.hm_max_retries,
                timeout=self.hm_timeout))
        self.wait_for_load_balancer_status(lb_id)

        self.members = []
        for server in [self.server1, self.server2]:
            fip = server['_floating_ip']
            fixed_ip_address = fip['fixed_ip_address']
            member = self.members_client.create_member(
                pool_id, subnet_id=vip_subnet_id,
                address=fixed_ip_address,
                protocol_port=self.protocol_port)
            self.wait_for_load_balancer_status(lb_id)
            self.members.append(member)

        # Currently the ovs-agent is not enforcing security groups on the
        # vip port - see https://bugs.launchpad.net/neutron/+bug/1163569
        # However the linuxbridge-agent does, and it is necessary to add a
        # security group with a rule that allows tcp port 80 to the vip port.
        # NSX-v lbaasv2 OK, but for upstream neutron-lbaas needs this.
        self.ports_client.update_port(
            self.loadbalancer['vip_port_id'],
            security_groups=[self.security_group['id']])
        # create lbaas public interface
        self.vip_fip = self.create_floatingip_for_server(
            self.loadbalancer, self.public_network_id,
            port_id=self.loadbalancer['vip_port_id'],
            client_mgr=self.manager)
        self.vip_ip_address = self.vip_fip['floating_ip_address']
        time.sleep(1.0)
        self.send_request(self.vip_ip_address)
        return self.vip_ip_address

    def check_project_lbaas(self):
        statuses = self.load_balancers_client.show_load_balancer_status_tree(
            self.loadbalancer['id'])
        statuses = statuses.get('statuses', statuses)
        self.http_cnt = {}
        http = urllib3.PoolManager(retries=10)
        url_path = "http://{0}/".format(self.vip_ip_address)
        for x in range(self.poke_counters):
            resp = http.request('GET', url_path)
            self.count_response(resp.data.strip())
        # should response from 2 servers
        self.assertEqual(2, len(self.http_cnt))
        # ROUND_ROUBIN, so equal counts
        s0 = self.server_names[0]
        s1 = self.server_names[1]
        self.assertEqual(self.http_cnt[s0], self.http_cnt[s1])

    def count_response(self, response):
        if response in self.http_cnt:
            self.http_cnt[response] += 1
        else:
            self.http_cnt[response] = 1

    @test.idempotent_id('077d2a5c-4938-448f-a80f-8e65f5cc49d7')
    @test.services('compute', 'network')
    def test_lbaas_round_robin_ops(self):
        self.create_lbaas_networks()
        self.start_web_servers()
        self.create_project_lbaas()
        self.check_project_lbaas()
