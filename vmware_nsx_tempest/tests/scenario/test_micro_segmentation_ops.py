# Copyright 2016 VMware Inc
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
import collections

from oslo_log import log as logging

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.scenario import manager
from tempest import test

from vmware_nsx_tempest._i18n import _LE

CONF = config.CONF

LOG = logging.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class TestMicroSegmentationOps(manager.NetworkScenarioTest):

    """Test suite for micro-segmentation scenario test

    The purpose of this scenario test is to test micro-segmentation use
    case which is one of the most important features of NSX. In the test,
    two-tier application web and app networks are created, and security
    group rules are defined based on this use case. Verify that VMs on
    these networks have the correct behaviors as expected.

    """

    @classmethod
    def skip_checks(cls):
        super(TestMicroSegmentationOps, cls).skip_checks()
        if not (CONF.network.project_networks_reachable or
                CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        for ext in ['router', 'security-group']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)
        if not (CONF.network.public_network_cidr):
            msg = "public_network_cidr must be defined in network section."
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(TestMicroSegmentationOps, cls).setup_credentials()

    def setUp(self):
        super(TestMicroSegmentationOps, self).setUp()
        self.keypairs = {}

    def _create_security_groups(self):
        web_sg = self._create_empty_security_group(tenant_id=self.tenant_id,
                                                   namestart="secgroup-web")
        app_sg = self._create_empty_security_group(tenant_id=self.tenant_id,
                                                   namestart="secgroup-app")
        # Common rules to allow the following traffic
        # 1. Egress ICMP IPv4 any any
        # 2. Egress ICMP IPv6 any any
        # 3. Ingress ICMP IPv4 from public network
        # 4. Ingress TCP 22 (SSH) from public network
        common_ruleset = [
            dict(
                direction='egress',
                protocol='icmp'
            ),
            dict(
                direction='egress',
                protocol='icmp',
                ethertype='IPv6'
            ),
            dict(
                direction='ingress',
                protocol='tcp',
                port_range_min=22,
                port_range_max=22,
                remote_ip_prefix=CONF.network.public_network_cidr
            ),
            dict(
                direction='ingress',
                protocol='icmp',
                remote_ip_prefix=CONF.network.public_network_cidr
            )
        ]
        # Rules that are specific to web tier network
        # 1. Ingress ICMP IPv4 from web_sg
        # 2. Ingress TCP 80 (HTTP) any any
        # 3. Ingress TCP 443 (HTTPS) any any
        web_ruleset = [
            dict(
                direction='ingress',
                protocol='icmp',
                remote_group_id=web_sg['id']
            ),
            dict(
                direction='ingress',
                protocol='tcp',
                port_range_min=80,
                port_range_max=80,
            ),
            dict(
                direction='ingress',
                protocol='tcp',
                port_range_min=443,
                port_range_max=443,
            )
        ]
        web_rulesets = common_ruleset + web_ruleset
        # Rules that are specific to app tier network
        # 1. Ingress ICMP IPv4 from app_sg
        # 2. Ingress TCP 22 (SSH) from web_sg
        app_ruleset = [
            dict(
                direction='ingress',
                protocol='icmp',
                remote_group_id=app_sg['id']
            ),
            dict(
                direction='ingress',
                protocol='tcp',
                port_range_min=22,
                port_range_max=22,
                remote_group_id=web_sg['id']
            )
        ]
        app_rulesets = common_ruleset + app_ruleset
        for ruleset in web_rulesets:
            self._create_security_group_rule(secgroup=web_sg, **ruleset)
        for ruleset in app_rulesets:
            self._create_security_group_rule(secgroup=app_sg, **ruleset)
        return (web_sg, app_sg)

    def _create_network_topo(self, **kwargs):
        self.web_net, self.web_subnet, self.router = self.create_networks(
            **kwargs)
        self.app_net = self._create_network(tenant_id=self.tenant_id)
        self.app_subnet = self._create_subnet(network=self.app_net)
        router_id = self.router['id']
        self.routers_client.add_router_interface(
            router_id, subnet_id=self.app_subnet['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.routers_client.remove_router_interface,
                        router_id, subnet_id=self.app_subnet['id'])

    def _create_servers(self):
        web_server1_name = data_utils.rand_name('web-vm1')
        web_server2_name = data_utils.rand_name('web-vm2')
        app_server1_name = data_utils.rand_name('app-vm1')
        app_server2_name = data_utils.rand_name('app-vm2')
        # Create two VMs on web-tier network
        self.web_server1, self.web_server1_fip_tuple = self._create_server(
            web_server1_name, self.web_net, self.web_sg)
        self.web_server2, self.web_server2_fip_tuple = self._create_server(
            web_server2_name, self.web_net, self.web_sg)
        # Create two VMs on app-tier network
        self.app_server1, self.app_server1_fip_tuple = self._create_server(
            app_server1_name, self.app_net, self.app_sg)
        self.app_server2, self.app_server2_fip_tuple = self._create_server(
            app_server2_name, self.app_net, self.app_sg)

    def _setup_micro_seg_topo(self, **kwargs):
        self.web_sg, self.app_sg = self._create_security_groups()
        self._create_network_topo(**kwargs)
        self._create_servers()

    def _create_server(self, name, network, secgroup, image_id=None):
        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        security_groups = [{'name': secgroup['name']}]
        network = {'uuid': network['id']}
        server = self.create_server(name=name, networks=[network],
                                    key_name=keypair['name'],
                                    security_groups=security_groups,
                                    image_id=image_id,
                                    wait_until='ACTIVE')
        floating_ip = self.create_floating_ip(server)
        fip_tuple = Floating_IP_tuple(floating_ip, server)
        return (server, fip_tuple)

    def _get_server_key(self, server):
        return self.keypairs[server['key_name']]['private_key']

    def _check_network_internal_connectivity(self, network, fip_tuple,
                                             should_connect=True):
        floating_ip, server = fip_tuple
        # test internal connectivity to the network ports on the network
        network_ips = (p['fixed_ips'][0]['ip_address'] for p in
                       self._list_ports(tenant_id=server['tenant_id'],
                                        network_id=network['id'])
                       if p['device_owner'].startswith('network'))
        self._check_server_connectivity(floating_ip,
                                        server,
                                        network_ips,
                                        should_connect)

    def _check_network_vm_connectivity(self, network, fip_tuple,
                                       should_connect=True):
        floating_ip, server = fip_tuple
        # test internal connectivity to the other VM on the same network
        compute_ips = (p['fixed_ips'][0]['ip_address'] for p in
                       self._list_ports(tenant_id=server['tenant_id'],
                                        network_id=network['id'])
                       if p['device_owner'].startswith('compute'))
        self._check_server_connectivity(floating_ip,
                                        server,
                                        compute_ips,
                                        should_connect)

    def _check_server_connectivity(self, floating_ip, server, address_list,
                                   should_connect=True):
        ip_address = floating_ip['floating_ip_address']
        private_key = self._get_server_key(server)
        ssh_source = self.get_remote_client(ip_address,
                                            private_key=private_key)
        for remote_ip in address_list:
            if should_connect:
                msg = ("Timed out waiting for %s to become "
                       "reachable") % remote_ip
            else:
                msg = "ip address %s is reachable" % remote_ip
            try:
                self.assertTrue(self._check_remote_connectivity
                                (ssh_source, remote_ip, should_connect),
                                msg)
            except Exception:
                LOG.exception(_LE("Unable to access %{dest}s via ssh to "
                                  "floating-ip %{src}s"),
                              {'dest': remote_ip, 'src': floating_ip})
                raise

    def _check_cross_network_connectivity(self, network, should_connect=False):
        if network['id'] == self.web_net['id']:
            net_id = self.app_net['id']
            floating_ip, server = self.web_server1_fip_tuple
        else:
            net_id = self.web_net['id']
            floating_ip, server = self.app_server1_fip_tuple
        # test internal connectivity to the other VM on the same network
        remote_ips = (p['fixed_ips'][0]['ip_address'] for p in
                      self._list_ports(tenant_id=server['tenant_id'],
                                       network_id=net_id)
                      if p['device_owner'].startswith('compute'))
        self._check_server_connectivity(floating_ip,
                                        server,
                                        remote_ips,
                                        should_connect)

    @test.attr(type='common')
    @test.idempotent_id('91e1ee1f-10d9-4b19-8350-804aea7e57b4')
    def test_micro_segmentation_ops(self):
        """Test micro-segmentation use case

        Create two-tier application web and app networks, define security
        group rules based on the requirements, apply them to the VMs created
        on the network, and verify the connectivity based on the rule.

        """
        self._setup_micro_seg_topo()
        network_server_list = [
            (self.web_net, self.web_server1_fip_tuple),
            (self.web_net, self.web_server2_fip_tuple),
            (self.app_net, self.app_server1_fip_tuple),
            (self.app_net, self.app_server2_fip_tuple)
        ]
        for net, fip_tuple in network_server_list:
            self._check_network_internal_connectivity(network=net,
                                                      fip_tuple=fip_tuple)
            self._check_network_vm_connectivity(network=net,
                                                fip_tuple=fip_tuple)
        for net in [self.web_net, self.app_net]:
            self._check_cross_network_connectivity(network=net)
