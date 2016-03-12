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
from tempest import test

from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF


class NSXv3NetworksTest(base.BaseNetworkTest):
    """Tests the following operations in the Neutron API:
       - Create network
       - Update network
       - Delete network
    After the neutron API call, we also need to make sure the corresponding
    resource has been created/updated/deleted from NSX backend.
    """

    @classmethod
    def resource_setup(cls):
        super(NSXv3NetworksTest, cls).resource_setup()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)

    @test.attr(type='nsxv3')
    @test.idempotent_id('63085723-23ae-4109-ac86-69f895097957')
    def test_create_update_delete_nsx_network(self):
        # Create a network
        name = data_utils.rand_name('network-')
        network = self.create_network(network_name=name)
        net_id = network['id']
        nsx_network = self.nsx.get_logical_switch(network['name'],
                                                  network['id'])
        self.assertEqual('ACTIVE', network['status'])
        self.assertNotEqual(nsx_network, None)
        # Verify network update
        new_name = "New_network"
        body = self.networks_client.update_network(net_id, name=new_name)
        updated_net = body['network']
        nsx_network = self.nsx.get_logical_switch(updated_net['name'],
                                                  updated_net['id'])
        self.assertEqual(updated_net['name'], new_name)
        self.assertNotEqual(nsx_network, None)
        # Verify delete network
        self.networks_client.delete_network(updated_net['id'])
        nsx_network = self.nsx.get_logical_switch(updated_net['name'],
                                                  updated_net['id'])
        self.assertEqual(nsx_network, None)
