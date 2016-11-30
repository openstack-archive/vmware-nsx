# Copyright 2016 VMware Inc.
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

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest import test

from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF


class NSXv3NativeDHCPTest(base.BaseNetworkTest):
    """NSXv3 Native DHCP test

        - Create DHCP enabled subnet
        - Create two overlapping DHCP enabled subnets
        - Create DHCP enabled subnet with allocation pool
        - Create DHCP enabled subnet with DNS nameservers
        - Create DHCP enabled subnet host route
        - Create DHCP enabled subnet with gateway IP
        - Default in plugin configuration
    """

    @classmethod
    def skip_checks(cls):
        super(NSXv3NativeDHCPTest, cls).skip_checks()
        if not (CONF.nsxv3.nsx_manager and CONF.nsxv3.nsx_user and
                CONF.nsxv3.nsx_password):
            raise cls.skipException("Either NSX manager, user, or password "
                                    "is missing")

    @classmethod
    def resource_setup(cls):
        super(NSXv3NativeDHCPTest, cls).resource_setup()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)
        cls._subnet_data = {'gateway': '192.168.100.1',
                            'cidr': '192.168.100.0/24',
                            'ip_version': '4',
                            'allocation_pools': [{'start': '192.168.100.100',
                                                  'end': '192.168.100.200'}],
                            'dns_nameservers': ['8.8.4.4', '8.8.8.8'],
                            'host_routes': [{'destination': '192.168.100.0/32',
                                             'nexthop': '192.168.100.1'}],
                            'new_host_routes': [{'destination':
                                                 '192.168.100.0/32',
                                                 'nexthop':
                                                 '192.168.200.2'}],
                            'new_dns_nameservers': ['7.8.8.8', '7.8.4.4']}

    def _test_create_subnet_with_kwargs(self, **kwargs):
        name = data_utils.rand_name("network-")
        network = self.create_network(network_name=name)
        net_id = network['id']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.networks_client.delete_network, net_id)
        subnet = self.subnets_client.create_subnet(
            network_id=net_id, ip_version=self._subnet_data['ip_version'],
            cidr=self._subnet_data['cidr'], **kwargs)
        self.assertEqual('ACTIVE', network['status'])
        nsx_dhcp_server = self.nsx.get_logical_dhcp_server(network['name'],
                                                           network['id'])
        dhcp_server = nsx_dhcp_server['ipv4_dhcp_server']
        if 'gateway' in kwargs:
            self.assertEqual(dhcp_server['gateway_ip'],
                             self._subnet_data['gateway'])
        # allocation_pools doesn't translate into backend
        # we just need to check subnet data
        if 'allocation_pools' in kwargs:
            self.assertEqual(subnet['subnet']['allocation_pools'],
                             self._subnet_data['allocation_pools'])
        if 'dns_nameservers' in kwargs:
            self.assertEqual(subnet['subnet']['dns_nameservers'],
                             self._subnet_data['dns_nameservers'])
        if 'host_routes' in kwargs:
            host_routes = dhcp_server['options']['option121']['static_routes']
            route = {'next_hop':
                     self._subnet_data['host_routes'][0]['nexthop'],
                     'network':
                     self._subnet_data['host_routes'][0]['destination']}
            self.assertIn(route, host_routes)

    @test.attr(type='nsxv3')
    @test.idempotent_id('698f5503-a17a-43c2-b83b-353d3e28588b')
    def test_create_dhcp_enabled_subnet(self):
        name = data_utils.rand_name("network-")
        network = self.create_network(network_name=name)
        net_id = network['id']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.networks_client.delete_network, net_id)
        self.create_subnet(network)
        self.assertEqual('ACTIVE', network['status'])
        nsx_network = self.nsx.get_logical_switch(network['name'],
                                                  network['id'])
        self.assertIsNotNone(nsx_network)
        dhcp_server = self.nsx.get_logical_dhcp_server(network['name'],
                                                       network['id'])
        self.assertIsNotNone(dhcp_server)

    @test.attr(type='nsxv3')
    @test.idempotent_id('cc970d9b-786a-49c3-8bfb-2f8bc5580ead')
    def test_overlapping_dhcp_enabled_subnet(self):
        """Create two overlapping subnets"""
        for i in range(2):
            name = data_utils.rand_name("network-")
            network = self.create_network(network_name=name)
            net_id = network['id']
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.networks_client.delete_network, net_id)
            subnet = self.subnets_client.create_subnet(
                network_id=net_id,
                cidr=self._subnet_data['cidr'],
                ip_version=self._subnet_data['ip_version'])
            self.assertEqual(self._subnet_data['cidr'],
                             subnet['subnet']['cidr'])
            nsx_dhcp_server = self.nsx.get_logical_dhcp_server(network['name'],
                                                               network['id'])
            dhcp_server = nsx_dhcp_server['ipv4_dhcp_server']
            self.assertIsNotNone(dhcp_server)
            self.assertEqual(dhcp_server['dhcp_server_ip'], "192.168.100.2/24")
            self.assertEqual(dhcp_server['gateway_ip'],
                             self._subnet_data['gateway'])

    @test.attr(type='nsxv3')
    @test.idempotent_id('acee6ccb-92bb-48d8-ae6b-b10783b3791a')
    def test_create_subnet_with_allocation_pool(self):
        self._test_create_subnet_with_kwargs(
            allocation_pools=self._subnet_data['allocation_pools'])

    @test.attr(type='nsxv3')
    @test.idempotent_id('1b7d38c1-0674-43a7-8df1-0b9da531ad77')
    def test_create_subnet_with_dns_nameservers(self):
        self._test_create_subnet_with_kwargs(
            dns_nameservers=self._subnet_data['dns_nameservers'])

    @test.attr(type='nsxv3')
    @test.idempotent_id('3159111b-e332-4a41-a713-164a0ccfc2ad')
    def test_create_subnet_with_host_routes(self):
        self._test_create_subnet_with_kwargs(
            host_routes=self._subnet_data['host_routes'])

    @test.attr(type='nsxv3')
    @test.idempotent_id('addb0f46-3fa7-421b-aae7-820e798c096e')
    def test_create_subnet_with_gateway_ip(self):
        self._test_create_subnet_with_kwargs(
            gateway_ip=self._subnet_data['gateway'])
