# Copyright 2014 VMware.inc
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

import base_dvs as base

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest import test


class AdminNetworksTestJSON(base.BaseDvsAdminNetworkTest):
    _interface = 'json'

    """
    Test admin actions for networks, subnets.

        create/update/delete an admin network
        create/update/delete an admin subnets

    """

    @classmethod
    def resource_setup(cls):
        super(AdminNetworksTestJSON, cls).resource_setup()
        name = data_utils.rand_name('admin-network-')
        cls.network = cls.create_network(net_name=name)
        cls.name = cls.network['name']
        cls.subnet = cls.create_subnet(cls.network)
        cls.cidr = cls.subnet['cidr']

    @test.attr(type='smoke')
    @test.idempotent_id('1dcead1d-d773-4da1-9534-0b984ca684b3')
    def test_create_update_delete_flat_network_subnet(self):
        # Create an admin network
        name = data_utils.rand_name('admin-network-')
        network = self.create_network(net_name=name, net_type='flat')
        net_id = network['id']
        # Verify an exception thrown when updating network
        new_name = "New_network"
        self.assertRaises(exceptions.ServerFault,
                          self.update_network,
                          net_id,
                          name=new_name)
        # create a subnet and verify it is an admin tenant subnet
        subnet = self.create_subnet(network)
        subnet_id = subnet['id']
        self.assertEqual(network['tenant_id'], subnet['tenant_id'])
        # Verify subnet update
        new_name = "New_subnet"
        body = self.update_subnet(subnet_id, name=new_name)
        updated_subnet = body['subnet']
        self.assertEqual(updated_subnet['name'], new_name)
        # Delete subnet and network
        body = self.delete_subnet(subnet_id)
        # Remove subnet from cleanup list
        self.subnets.pop()
        body = self.delete_network(net_id)
        self.networks.pop()

    @test.attr(type='smoke')
    @test.idempotent_id('15d3d53c-3328-401f-b8f5-3a29aee2ea3a')
    def test_create_update_delete_vlan_network_subnet(self):
        # Create an admin network
        name = data_utils.rand_name('admin-network-')
        network = self.create_network(net_name=name,
                                      net_type='vlan',
                                      seg_id=1000)
        net_id = network['id']
        # Verify an exception thrown when updating network
        new_name = "New_network"
        self.assertRaises(exceptions.ServerFault,
                          self.update_network,
                          net_id,
                          name=new_name)
        # create a subnet and verify it is an admin tenant subnet
        subnet = self.create_subnet(network)
        subnet_id = subnet['id']
        self.assertEqual(network['tenant_id'], subnet['tenant_id'])
        # Verify subnet update
        new_name = "New_subnet"
        body = self.update_subnet(subnet_id, name=new_name)
        updated_subnet = body['subnet']
        self.assertEqual(updated_subnet['name'], new_name)
        # Delete subnet and network
        body = self.delete_subnet(subnet_id)
        # Remove subnet from cleanup list
        self.subnets.pop()
        body = self.delete_network(net_id)
        self.networks.pop()

    @test.attr(type='smoke')
    @test.idempotent_id('838aee5f-92f2-47b9-86c6-629a04aa6269')
    def test_show_network(self):
        # Verify the details of a network
        body = self.show_network(self.network['id'])
        network = body['network']
        for key in ['id', 'name', 'provider:network_type',
                    'provider:physical_network']:
            self.assertEqual(network[key], self.network[key])

    @test.attr(type='smoke')
    @test.idempotent_id('b86d50ef-39a7-4136-8c89-e5e534fe92aa')
    def test_list_networks(self):
        # Verify the network exists in the list of all networks
        body = self.list_networks()
        networks = [network['id'] for network in body['networks']
                    if network['id'] == self.network['id']]
        self.assertNotEmpty(networks, "Created network not found in the list")

    @test.attr(type='smoke')
    @test.idempotent_id('ee3f8b79-da3f-4394-9bea-012488202257')
    def test_show_subnet(self):
        # Verify the details of a subnet
        body = self.show_subnet(self.subnet['id'])
        subnet = body['subnet']
        self.assertNotEmpty(subnet, "Subnet returned has no fields")
        for key in ['id', 'cidr']:
            self.assertIn(key, subnet)
            self.assertEqual(subnet[key], self.subnet[key])
