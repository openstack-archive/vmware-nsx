# Copyright 2015 OpenStack Foundation
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

from tempest import test

from oslo_log import log as logging
from tempest.lib.common.utils import data_utils
import test_subnets as SNET

LOG = logging.getLogger(__name__)


class FlatNetworksTestJSON(SNET.SubnetTestJSON):
    _interface = 'json'
    _provider_network_body = {
        'name': data_utils.rand_name('FLAT-network'),
        'provider:network_type': 'flat'}

    @classmethod
    def resource_setup(cls):
        super(FlatNetworksTestJSON, cls).resource_setup()

    def _create_network(self, _auto_clean_up=True, network_name=None,
                        **kwargs):
        network_name = network_name or data_utils.rand_name('flat-netwk')
        # self.create_network expect network_name
        # self.admin_client.create_network()
        #   and self.client.create_network() expect name
        post_body = {'name': network_name,
                     'provider:network_type': 'flat'}
        post_body.update(kwargs)
        LOG.debug("create FLAT network: %s", str(post_body))
        body = self.admin_networks_client.create_network(**post_body)
        network = body['network']
        if _auto_clean_up:
            self.addCleanup(self._try_delete_network, network['id'])
        return network

    @test.idempotent_id('dc2f2f46-0577-4e2a-b35d-3c8c8bbce5bf')
    def test_create_network(self):
        # Create a network as an admin user specifying the
        # flat network type attribute
        network = self._create_network()
        # Verifies router:network_type parameter
        self.assertIsNotNone(network['id'])
        self.assertEqual(network.get('provider:network_type'), 'flat')

    @test.idempotent_id('777fc335-b26c-42ea-9759-c71dff2ce1c6')
    def test_update_network(self):
        # Update flat network as an admin user specifying the
        # flat network attribute
        network = self._create_network(shared=True, _auto_clean_up=False)
        self.assertEqual(network.get('shared'), True)
        new_name = network['name'] + "-updated"
        update_body = {'shared': False, 'name': new_name}
        body = self.update_network(network['id'], **update_body)
        updated_network = body['network']
        # Verify that name and shared parameters were updated
        self.assertEqual(updated_network['shared'], False)
        self.assertEqual(updated_network['name'], new_name)
        # get flat network attributes and verify them
        body = self.show_network(network['id'])
        updated_network = body['network']
        # Verify that name and shared parameters were updated
        self.assertEqual(updated_network['shared'], False)
        self.assertEqual(updated_network['name'], new_name)
        self.assertEqual(updated_network['status'], network['status'])
        self.assertEqual(updated_network['subnets'], network['subnets'])
        self._delete_network(network['id'])

    @test.idempotent_id('1dfc1c11-e838-464c-85b2-ed5e4c477c64')
    def test_list_networks(self):
        # Create flat network
        network = self._create_network(shared=True)
        # List networks as a normal user and confirm it is available
        body = self.list_networks(client=self.networks_client)
        network_list = [net['id'] for net in body['networks']]
        self.assertIn(network['id'], network_list)
        update_body = {'shared': False}
        body = self.update_network(network['id'], **update_body)
        # List networks as a normal user and confirm it is not available
        body = self.list_networks(client=self.networks_client)
        network_list = [net['id'] for net in body['networks']]
        self.assertNotIn(network['id'], network_list)

    @test.idempotent_id('b5649fe2-a214-4105-8053-1825a877c45b')
    def test_show_network_attributes(self):
        # Create flat network
        network = self._create_network(shared=True)
        # Show a flat network as a normal user and confirm the
        # flat network attribute is returned.
        body = self.show_network(network['id'], client=self.networks_client)
        show_net = body['network']
        self.assertEqual(network['name'], show_net['name'])
        self.assertEqual(network['id'], show_net['id'])
        # provider attributes are for admin only
        body = self.show_network(network['id'])
        show_net = body['network']
        net_attr_list = show_net.keys()
        for attr in ('admin_state_up', 'port_security_enabled', 'shared',
                     'status', 'subnets', 'tenant_id', 'router:external',
                     'provider:network_type', 'provider:physical_network',
                     'provider:segmentation_id'):
            self.assertIn(attr, net_attr_list)
