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


class TestMultiNetworksOps(manager.NetworkScenarioTest):

    """Test multiple networks scenario

    This scenario test is to test a topology consisting of multiple networks.
    The networks are connected through a router. Boot multiple VMs on each
    network and test traffic between the VMs.

    Test steps:
      - Create a class level network topology which contains router, networks
        and external network. Router sets gateway on external network and add
        interface of the networks.
      - Create floating ip and loginable security group.
      - Boot two VMs on each network. Assign floating ips to VMs.
      - Test external and internal connectivity of the VMs.

    """

    @classmethod
    def skip_checks(cls):
        super(TestMultiNetworksOps, cls).skip_checks()
        if not (CONF.network.project_networks_reachable or
                CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        for ext in ['router', 'security-group']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(TestMultiNetworksOps, cls).setup_credentials()

    def setUp(self):
        super(TestMultiNetworksOps, self).setUp()
        self.keypairs = {}
        self.servers = []

    def _setup_networks_and_servers(self, **kwargs):
        boot_with_port = kwargs.pop('boot_with_port', False)
        self.security_group = self._create_security_group()
        self.network = self._create_network()
        self.subnet = self._create_subnet(self.network)
        self.router = self._create_router(
            router_name=data_utils.rand_name('router-smoke'),
            external_network_id=CONF.network.public_network_id)
        self.routers_client.add_router_interface(
            self.router['id'], subnet_id=self.subnet['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        self.router['id'], subnet_id=self.subnet['id'])
        self.network2 = self._create_network()
        self.subnet2 = self._create_subnet(self.network2)
        self.routers_client.add_router_interface(
            self.router['id'], subnet_id=self.subnet2['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        self.router['id'], subnet_id=self.subnet2['id'])

        self.ports = []
        self.port_id = None
        if boot_with_port:
            # create a port on the network and boot with that
            self.port_id = self._create_port(self.network['id'])['id']
            self.ports.append({'port': self.port_id})

        name = data_utils.rand_name('server-smoke')
        # Create two servers on network 1 and one server on network 2
        net1_server1 = self._create_server(name, self.network, self.port_id)
        self._create_server(name, self.network)
        self._create_server(name, self.network2)

        floating_ip = self.create_floating_ip(net1_server1)
        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, net1_server1)

    def _delete_router(self, router):
        body = self.ports_client.list_ports(device_id=router['id'])
        interfaces = body['ports']
        for i in interfaces:
            test_utils.call_and_ignore_notfound_exc(
                self.routers_client.remove_router_interface, router['id'],
                subnet_id=i['fixed_ips'][0]['subnet_id'])
        self.routers_client.delete_router(router['id'])

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
        router = body['router']
        self.addCleanup(self._delete_router, router)
        return router

    def _create_server(self, name, network, port_id=None, image_id=None):
        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        security_groups = [{'name': self.security_group['name']}]
        network = {'uuid': network['id']}
        if port_id is not None:
            network['port'] = port_id
        server = self.create_server(name=name, networks=[network],
                                    key_name=keypair['name'],
                                    security_groups=security_groups,
                                    image_id=image_id,
                                    wait_until='ACTIVE')
        self.servers.append(server)
        return server

    def _get_server_key(self, server):
        return self.keypairs[server['key_name']]['private_key']

    def _check_network_connectivity(self, network, should_connect=True):
        floating_ip, server = self.floating_ip_tuple
        # test connectivity on the network
        network_ips = (p['fixed_ips'][0]['ip_address'] for p in
                       self._list_ports(tenant_id=server['tenant_id'],
                                        network_id=network['id'])
                       if (p['device_owner'].startswith('network') or
                           p['device_owner'].startswith('compute')))
        self._check_server_connectivity(floating_ip,
                                        network_ips,
                                        should_connect)

    def _check_same_network_connectivity(self):
        self._check_network_connectivity(self.network)

    def _check_cross_network_connectivity(self, should_connect=True):
        # Check east-west connectivity between different networks
        self._check_network_connectivity(self.network2)

    def _check_server_connectivity(self, floating_ip, address_list,
                                   should_connect=True):
        ip_address = floating_ip['floating_ip_address']
        private_key = self._get_server_key(self.floating_ip_tuple.server)
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

    @test.attr(type='nsxv3')
    @test.idempotent_id('d35d1301-bfa4-49ea-acdf-f67ba97b1937')
    def test_multi_networks_ops(self):
        """Test connectivity between VMs on same and cross network

        Boot VMs on the same network and different networks and test
        L2 network connectivity on same network and cross networks.

        """
        self._setup_networks_and_servers()
        self._check_same_network_connectivity()
        self._check_cross_network_connectivity()
