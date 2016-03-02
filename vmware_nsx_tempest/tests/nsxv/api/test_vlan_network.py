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

import random

from tempest import config
from tempest import test

from oslo_log import log as logging
from tempest.lib.common.utils import data_utils
import test_subnets as SNET

CONF = config.CONF
LOG = logging.getLogger(__name__)

VLAN_PHYSICAL_NETWORK = CONF.nsxv.vlan_physical_network or None
VLAN_ID_PROVIDER = CONF.nsxv.provider_vlan_id


class VlanNetworksTestJSON(SNET.SubnetTestJSON):
    _interface = 'json'
    _vlanid = int(VLAN_ID_PROVIDER)
    _provider_network_body = {
        'name': data_utils.rand_name('VLAN-%04d-network' % _vlanid),
        'provider:network_type': 'vlan',
        'provider:physical_network': VLAN_PHYSICAL_NETWORK,
        'provider:segmentation_id': _vlanid}

    @classmethod
    def resource_setup(cls):
        cls.vlan_range = (2001, 2999)
        cls.vlan_assigned = []
        super(VlanNetworksTestJSON, cls).resource_setup()

    def get_next_vlan(self):
        next_vlan = self.next_vlan
        self.next_vlan += 1
        if self.next_vlan > self.vlan_range[1]:
            self.next_vlan = self.vlan_range[0]
        return next_vlan

    def get_vlan(self):
        for x in range(0, 10):
            next_vlan = random.randint(*self.vlan_range)
            if next_vlan in self.vlan_assigned:
                continue
            else:
                self.vlan_assigned.append(next_vlan)
                return next_vlan
        return 3000

    def _create_network(self, _auto_clean_up=True, network_name=None,
                        **kwargs):
        segmentation_id = kwargs.pop('provider:segmentation_id', None)
        if not segmentation_id:
            segmentation_id = self.get_vlan()
        network_name = (network_name or
                        data_utils.rand_name(
                            'vlan-' + str(segmentation_id) + '-netwk'))
        post_body = {'name': network_name,
                     'provider:network_type': 'vlan',
                     'provider:physical_network': VLAN_PHYSICAL_NETWORK,
                     'provider:segmentation_id': segmentation_id}
        post_body.update(kwargs)
        for k, v in post_body.items():
            if not v:
                post_body.pop(k)
        LOG.debug("create VLAN network: %s", str(post_body))
        body = self.create_network(**post_body)
        network = body['network']
        if _auto_clean_up:
            self.addCleanup(self._try_delete_network, network['id'])
        return network

    @test.idempotent_id('c5f98016-dee3-42f1-8c23-b9cd1e625561')
    def test_create_network(self):
        # Create a network as an admin user specifying the
        # vlan network type attribute
        provider_attrs = {
            'provider:network_type': 'vlan',
            'provider:physical_network': VLAN_PHYSICAL_NETWORK,
            'provider:segmentation_id': 1002}
        network = self._create_network(_auto_clean_up=False, **provider_attrs)
        # Verifies parameters
        self.assertIsNotNone(network['id'])
        self.assertEqual(network.get('provider:network_type'), 'vlan')
        if VLAN_PHYSICAL_NETWORK:
            self.assertEqual(network.get('provider:physical_network'),
                             VLAN_PHYSICAL_NETWORK)
        self.assertEqual(network.get('provider:segmentation_id'), 1002)
        self._delete_network(network['id'])

    @test.idempotent_id('714e69eb-bb31-4cfc-9804-8e988f04ca65')
    def test_update_network(self):
        # Update flat network as an admin user specifying the
        # flat network attribute
        net_profile = {'shared': True, '_auto_clean_up': False,
                       'provider:segmentation_id': 1003}
        network = self._create_network(**net_profile)
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

    @test.idempotent_id('8a8b9f2c-37f8-4c53-b8e3-0c9c0910380f')
    def test_list_networks(self):
        # Create flat network
        net_profile = {'shared': True, '_auto_clean_up': False,
                       'provider:segmentation_id': 1004}
        network = self._create_network(**net_profile)
        # List networks as a normal user and confirm it is available
        body = self.list_networks(client=self.networks_client)
        networks_list = [net['id'] for net in body['networks']]
        self.assertIn(network['id'], networks_list)
        update_body = {'shared': False}
        body = self.update_network(network['id'], **update_body)
        # List networks as a normal user and confirm it is not available
        body = self.list_networks(client=self.networks_client)
        networks_list = [net['id'] for net in body['networks']]
        self.assertNotIn(network['id'], networks_list)
        self._delete_network(network['id'])

    @test.idempotent_id('5807958d-9ee2-48a5-937e-ddde092956a6')
    def test_show_network_attributes(self):
        # Create flat network
        net_profile = {'shared': True, '_auto_clean_up': False,
                       'provider:segmentation_id': 1005}
        network = self._create_network(**net_profile)
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
        self._delete_network(network['id'])
