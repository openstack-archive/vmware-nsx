# Copyright 2014 OpenStack Foundation
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
from tempest import test


class AdminPortsTestJSON(base.BaseDvsAdminNetworkTest):
    _interface = 'json'

    """
    Test the following operations for ports:

        port create
        port delete
        port list
        port show
        port update
    """

    @classmethod
    def resource_setup(cls):
        super(AdminPortsTestJSON, cls).resource_setup()
        name = data_utils.rand_name('admin-ports-')
        cls.network = cls.create_network(net_name=name)
        cls.port = cls.create_port(cls.network['id'])

    @test.idempotent_id('c3f751d4-e358-44b9-bfd2-3d563c4a2d04')
    def test_create_update_delete_port(self):
        # Verify port creation
        network_id = self.network['id']
        port = self.create_port(network_id)
        self.assertTrue(port['admin_state_up'])
        # Verify port update
        new_name = "New_Port"
        body = self.update_port(
            port['id'],
            name=new_name,
            admin_state_up=False)
        updated_port = body['port']
        self.assertEqual(updated_port['name'], new_name)
        self.assertFalse(updated_port['admin_state_up'])

    @test.attr(type='smoke')
    @test.idempotent_id('d3dcd23b-7d5a-4720-8d88-473fb154d609')
    def test_show_port(self):
        # Verify the details of port
        body = self.show_port(self.port['id'])
        port = body['port']
        self.assertIn('id', port)
        self.assertEqual(port['id'], self.port['id'])
        self.assertEqual(self.port['admin_state_up'], port['admin_state_up'])
        self.assertEqual(self.port['device_id'], port['device_id'])
        self.assertEqual(self.port['device_owner'], port['device_owner'])
        self.assertEqual(self.port['mac_address'], port['mac_address'])
        self.assertEqual(self.port['name'], port['name'])
        self.assertEqual(self.port['security_groups'],
                         port['security_groups'])
        self.assertEqual(self.port['network_id'], port['network_id'])
        self.assertEqual(self.port['security_groups'],
                         port['security_groups'])
        self.assertEqual(port['fixed_ips'], [])

    @test.attr(type='smoke')
    @test.idempotent_id('c5f74042-c512-4569-b9b9-bc2bf46e77e1')
    def test_list_ports(self):
        # Verify the port exists in the list of all ports
        body = self.list_ports()
        ports = [port['id'] for port in body['ports']
                 if port['id'] == self.port['id']]
        self.assertNotEmpty(ports, "Created port not found in the list")

    @test.attr(type='smoke')
    @test.idempotent_id('2775f96c-a09b-49e1-a5a4-adb83a3e91c7')
    def test_list_ports_fields(self):
        # Verify specific fields of ports
        fields = ['binding:vif_type', 'id', 'mac_address']
        body = self.list_ports(fields=fields)
        ports = body['ports']
        self.assertNotEmpty(ports, "Port list returned is empty")
        # Asserting the fields returned are correct
        # Verify binding:vif_type is dvs
        for port in ports:
            self.assertEqual(sorted(fields), sorted(port.keys()))
            self.assertEqual(port.get(fields[0]), 'dvs')
