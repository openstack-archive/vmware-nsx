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

import base_provider as base
from tempest.common import custom_matchers
from tempest import config
from tempest import test

import netaddr
from oslo_log import log as logging
import six
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

CONF = config.CONF

LOG = logging.getLogger(__name__)


class SubnetTestJSON(base.BaseAdminNetworkTest):
    _provider_network_body = {}

    """
    [NOTE: This module copied/modified from api/network/test_networks.py
        to create provider networks/subnets tests]

    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        create a network for a tenant
        list tenant's networks
        show a tenant network details
        create a subnet for a tenant
        list tenant's subnets
        show a tenant subnet details
        network update
        subnet update
        delete a network also deletes its subnets

        All subnet tests are run once with ipv4 and once with ipv6.

    v2.0 of the Neutron API is assumed. It is also assumed that the following
    options are defined in the [network] section of etc/tempest.conf:

        project_network_cidr with a block of cidr's from which smaller blocks
        can be allocated for tenant ipv4 subnets

        project_network_v6_cidr is the equivalent for ipv6 subnets

        project_network_mask_bits with the mask bits to be used to partition
        the block defined by project_network_cidr

        project_network_v6_mask_bits is the equivalent for ipv6 subnets
    """

    @classmethod
    def resource_setup(cls):
        super(SubnetTestJSON, cls).resource_setup()
        for k, v in cls._provider_network_body.items():
            if not v:
                cls._provider_network_body.pop(k)
        body = cls.create_network(client=cls.admin_networks_client,
                                  **cls._provider_network_body)
        cls.network = body['network']
        cls.name = cls.network['name']
        cls.subnet = cls._create_subnet_with_last_subnet_block(cls.network)
        cls.cidr = cls.subnet['cidr']
        cls._subnet_data = {6: {'gateway':
                                str(cls._get_gateway_from_tempest_conf(6)),
                                'allocation_pools':
                                cls._get_allocation_pools_from_gateway(6),
                                'dns_nameservers': ['2001:4860:4860::8844',
                                                    '2001:4860:4860::8888'],
                                'host_routes': [{'destination': '2001::/64',
                                                 'nexthop': '2003::1'}],
                                'new_host_routes': [{'destination':
                                                     '2001::/64',
                                                     'nexthop': '2005::1'}],
                                'new_dns_nameservers':
                                ['2001:4860:4860::7744',
                                 '2001:4860:4860::7888']},
                            4: {'gateway':
                                str(cls._get_gateway_from_tempest_conf(4)),
                                'allocation_pools':
                                cls._get_allocation_pools_from_gateway(4),
                                'dns_nameservers': ['8.8.4.4', '8.8.8.8'],
                                'host_routes': [{'destination': '10.20.0.0/32',
                                                 'nexthop': '10.100.1.1'}],
                                'new_host_routes': [{'destination':
                                                     '10.20.0.0/32',
                                                     'nexthop':
                                                     '10.100.1.2'}],
                                'new_dns_nameservers': ['7.8.8.8', '7.8.4.4']}}

    @classmethod
    def _create_subnet_with_last_subnet_block(cls, network, ip_version=4):
        """Derive last subnet CIDR block from tenant CIDR and
           create the subnet with that derived CIDR
        """
        if ip_version == 4:
            cidr = netaddr.IPNetwork(CONF.network.project_network_cidr)
            mask_bits = CONF.network.project_network_mask_bits
        elif ip_version == 6:
            cidr = netaddr.IPNetwork(CONF.network.project_network_v6_cidr)
            mask_bits = CONF.network.project_network_v6_mask_bits

        subnet_cidr = list(cidr.subnet(mask_bits))[-1]
        gateway_ip = str(netaddr.IPAddress(subnet_cidr) + 1)
        body = cls.create_subnet(network, gateway=gateway_ip,
                                 cidr=subnet_cidr, mask_bits=mask_bits)
        return body['subnet']

    @classmethod
    def _get_gateway_from_tempest_conf(cls, ip_version):
        """Return first subnet gateway for configured CIDR."""
        if ip_version == 4:
            cidr = netaddr.IPNetwork(CONF.network.project_network_cidr)
            mask_bits = CONF.network.project_network_mask_bits
        elif ip_version == 6:
            cidr = netaddr.IPNetwork(CONF.network.project_network_v6_cidr)
            mask_bits = CONF.network.project_network_v6_mask_bits

        if mask_bits >= cidr.prefixlen:
            return netaddr.IPAddress(cidr) + 1
        else:
            for subnet in cidr.subnet(mask_bits):
                return netaddr.IPAddress(subnet) + 1

    @classmethod
    def _get_allocation_pools_from_gateway(cls, ip_version):
        """Return allocation range for subnet of given gateway."""
        gateway = cls._get_gateway_from_tempest_conf(ip_version)
        return [{'start': str(gateway + 2), 'end': str(gateway + 3)}]

    def subnet_dict(self, include_keys):
        """Return a subnet dict which has include_keys and their corresponding
           value from self._subnet_data
        """
        return dict((key, self._subnet_data[self._ip_version][key])
                    for key in include_keys)

    def _create_network(self, _auto_clean_up=True, network_name=None,
                        **kwargs):
        network_name = network_name or data_utils.rand_name('adm-netwk')
        post_body = {'name': network_name}
        post_body.update(kwargs)
        LOG.debug("create ADM network: %s", str(post_body))
        body = self.create_network(client=self.admin_networks_client,
                                   **post_body)
        network = body['network']
        if _auto_clean_up:
            self.addCleanup(self._try_delete_network, network['id'])
        return network

    # when you call _delete_network() you mean it is part of test,
    # so we will not pass exception
    def _delete_network(self, net_id):
        self._remove_network_from_book(net_id)
        return self.delete_network(net_id)

    def _remove_network_from_book(self, net_id):
        for idx, netwk_info in zip(range(0, len(self.admin_netwk_info)),
                                   self.admin_netwk_info):
            net_client, network = netwk_info
            if network['id'] == net_id:
                self.admin_netwk_info.pop(idx)
                return

    # call _try_delete_network() for teardown purpose, so pass exception
    def _try_delete_network(self, net_id):
        # delete network, if it exists
        self._remove_network_from_book(net_id)
        try:
            self.delete_network(net_id)
        # if network is not found, this means it was deleted in the test
        except exceptions.NotFound:
            pass

    # by default, subnet will be deleted when its network is deleted
    def _create_subnet(self, network, gateway='', cidr=None, mask_bits=None,
                       ip_version=None, cidr_offset=0,
                       _auto_clean_up=False, **kwargs):
        body = self.create_subnet(network,
                                  gateway=gateway,
                                  cidr=cidr,
                                  mask_bits=mask_bits,
                                  ip_version=ip_version,
                                  cidr_offset=cidr_offset,
                                  **kwargs)
        subnet = body['subnet']
        if _auto_clean_up:
            self.addCleanup(self._try_delete_subnet, subnet['id'])
        return subnet

    def _try_delete_subnet(self, net_id):
        # delete subnet, if it exists
        try:
            self.delete_subnet(net_id)
        # if network is not found, this means it was deleted in the test
        except exceptions.NotFound:
            pass

    def _compare_resource_attrs(self, actual, expected):
        exclude_keys = set(actual).symmetric_difference(expected)
        self.assertThat(actual, custom_matchers.MatchesDictExceptForKeys(
                        expected, exclude_keys))

    def _create_verify_delete_subnet(self, cidr=None, mask_bits=None,
                                     **kwargs):
        network = self._create_network(_auto_clean_up=True)
        net_id = network['id']
        gateway = kwargs.pop('gateway', None)
        subnet = self._create_subnet(network, gateway, cidr, mask_bits,
                                     **kwargs)
        compare_args_full = dict(gateway_ip=gateway, cidr=cidr,
                                 mask_bits=mask_bits, **kwargs)
        compare_args = (dict((k, v)
                        for k, v in six.iteritems(compare_args_full)
                        if v is not None))

        if 'dns_nameservers' in set(subnet).intersection(compare_args):
            self.assertEqual(sorted(compare_args['dns_nameservers']),
                             sorted(subnet['dns_nameservers']))
            del subnet['dns_nameservers'], compare_args['dns_nameservers']

        self._compare_resource_attrs(subnet, compare_args)
        self._delete_network(net_id)

    @test.idempotent_id('2ecbc3ab-93dd-44bf-a827-95beeb008e9a')
    def test_create_update_delete_network_subnet(self):
        # Create a network
        network = self._create_network(_auto_clean_up=True)
        net_id = network['id']
        self.assertEqual('ACTIVE', network['status'])
        # Verify network update
        new_name = data_utils.rand_name('new-adm-netwk')
        body = self.update_network(net_id, name=new_name)
        updated_net = body['network']
        self.assertEqual(updated_net['name'], new_name)
        # Find a cidr that is not in use yet and create a subnet with it
        subnet = self._create_subnet(network)
        subnet_id = subnet['id']
        # Verify subnet update
        new_name = data_utils.rand_name('new-subnet')
        body = self.update_subnet(subnet_id, name=new_name)
        updated_subnet = body['subnet']
        self.assertEqual(updated_subnet['name'], new_name)
        self._delete_network(net_id)

    @test.idempotent_id('a2cf6398-aece-4256-88a6-0dfe8aa44975')
    def test_show_network(self):
        # Verify the details of a network
        body = self.show_network(self.network['id'])
        network = body['network']
        for key in ['id', 'name']:
            self.assertEqual(network[key], self.network[key])

    @test.idempotent_id('5b42067d-4b9d-4f04-bb6a-adb9756ebe0c')
    def test_show_network_fields(self):
        # Verify specific fields of a network
        fields = ['id', 'name']
        body = self.show_network(self.network['id'], fields=fields)
        network = body['network']
        self.assertEqual(sorted(network.keys()), sorted(fields))
        for field_name in fields:
            self.assertEqual(network[field_name], self.network[field_name])

    @test.idempotent_id('324be3c2-457d-4e21-b0b3-5106bbbf1a28')
    def test_list_networks(self):
        # Verify the network exists in the list of all networks
        body = self.list_networks()
        networks = [network['id'] for network in body['networks']
                    if network['id'] == self.network['id']]
        self.assertNotEmpty(networks, "Created network not found in the list")

    @test.idempotent_id('3a934a8d-6b52-427e-af49-3dfdd224fdeb')
    def test_list_networks_fields(self):
        # Verify specific fields of the networks
        fields = ['id', 'name']
        body = self.list_networks(fields=fields)
        networks = body['networks']
        self.assertNotEmpty(networks, "Network list returned is empty")
        for network in networks:
            self.assertEqual(sorted(network.keys()), sorted(fields))

    @test.idempotent_id('5f6616c4-bfa7-4308-8eab-f45d75c94c6d')
    def test_show_subnet(self):
        # Verify the details of a subnet
        body = self.show_subnet(self.subnet['id'])
        subnet = body['subnet']
        self.assertNotEmpty(subnet, "Subnet returned has no fields")
        for key in ['id', 'cidr']:
            self.assertIn(key, subnet)
            self.assertEqual(subnet[key], self.subnet[key])

    @test.idempotent_id('2f326955-551e-4e9e-a4f6-e5db77c34c8d')
    def test_show_subnet_fields(self):
        # Verify specific fields of a subnet
        fields = ['id', 'network_id']
        body = self.show_subnet(self.subnet['id'], fields=fields)
        subnet = body['subnet']
        self.assertEqual(sorted(subnet.keys()), sorted(fields))
        for field_name in fields:
            self.assertEqual(subnet[field_name], self.subnet[field_name])

    @test.idempotent_id('66631557-2466-4827-bba6-d961b0242be3')
    def test_list_subnets(self):
        # Verify the subnet exists in the list of all subnets
        body = self.list_subnets()
        subnets = [subnet['id'] for subnet in body['subnets']
                   if subnet['id'] == self.subnet['id']]
        self.assertNotEmpty(subnets, "Created subnet not found in the list")

    @test.idempotent_id('3d5ea69b-f122-43e7-b7f4-c78586629eb8')
    def test_list_subnets_fields(self):
        # Verify specific fields of subnets
        fields = ['id', 'network_id']
        body = self.list_subnets(fields=fields)
        subnets = body['subnets']
        self.assertNotEmpty(subnets, "Subnet list returned is empty")
        for subnet in subnets:
            self.assertEqual(sorted(subnet.keys()), sorted(fields))

    @test.idempotent_id('e966bb2f-402c-49b7-8147-b275cee584c4')
    def test_delete_network_with_subnet(self):
        # Creates a network
        network = self._create_network(_auto_clean_up=True)
        net_id = network['id']

        # Find a cidr that is not in use yet and create a subnet with it
        subnet = self._create_subnet(network)
        subnet_id = subnet['id']

        # Delete network while the subnet still exists
        self._delete_network(net_id)

        # Verify that the subnet got automatically deleted.
        self.assertRaises(exceptions.NotFound,
                          self.show_subnet, subnet_id)

    @test.idempotent_id('8aba0e1b-4b70-4181-a8a4-792c08db699d')
    def test_create_delete_subnet_without_gateway(self):
        self._create_verify_delete_subnet()

    @test.idempotent_id('67364a4b-6725-4dbe-84cf-504bdb20ac06')
    def test_create_delete_subnet_with_gw(self):
        self._create_verify_delete_subnet(
            **self.subnet_dict(['gateway']))

    @test.idempotent_id('f8f43e65-5090-4902-b5d2-2b610505cca6')
    def test_create_delete_subnet_with_allocation_pools(self):
        self._create_verify_delete_subnet(
            **self.subnet_dict(['allocation_pools']))

    @test.idempotent_id('5b085669-97e6-48e0-b99e-315a9b4d8482')
    def test_create_delete_subnet_with_gw_and_allocation_pools(self):
        self._create_verify_delete_subnet(**self.subnet_dict(
            ['gateway', 'allocation_pools']))

    @decorators.skip_because(bug="1501827")
    @test.idempotent_id('3c4c36a1-684b-4e89-8e71-d528f19322a0')
    def test_create_delete_subnet_with_host_routes_and_dns_nameservers(self):
        self._create_verify_delete_subnet(
            **self.subnet_dict(['host_routes', 'dns_nameservers']))

    @test.idempotent_id('df518c87-b817-48b5-9365-bd1daaf68955')
    def test_create_delete_subnet_with_dns_nameservers(self):
        self._create_verify_delete_subnet(
            **self.subnet_dict(['dns_nameservers']))

    @test.idempotent_id('b6822feb-6760-4052-b550-f0fe8bac7451')
    def test_create_delete_subnet_with_dhcp_enabled(self):
        self._create_verify_delete_subnet(enable_dhcp=True)

    @decorators.skip_because(bug="1501827")
    @test.idempotent_id('3c4c36a1-684a-4e89-8e71-d528f19324a0')
    def test_update_subnet_gw_dns_host_routes_dhcp(self):
        network = self._create_network(_auto_clean_up=True)
        subnet_attrs = ['gateway', 'host_routes',
                        'dns_nameservers', 'allocation_pools']
        subnet_dict = self.subnet_dict(subnet_attrs)
        subnet = self._create_subnet(network, **subnet_dict)
        subnet_id = subnet['id']
        new_gateway = str(netaddr.IPAddress(
                          self._subnet_data[self._ip_version]['gateway']) + 1)
        # Verify subnet update
        new_host_routes = self._subnet_data[self._ip_version][
            'new_host_routes']

        new_dns_nameservers = self._subnet_data[self._ip_version][
            'new_dns_nameservers']
        kwargs = {'host_routes': new_host_routes,
                  'dns_nameservers': new_dns_nameservers,
                  'gateway_ip': new_gateway, 'enable_dhcp': True}

        new_name = "New_subnet"
        body = self.update_subnet(subnet_id, name=new_name, **kwargs)
        updated_subnet = body['subnet']
        kwargs['name'] = new_name
        self.assertEqual(sorted(updated_subnet['dns_nameservers']),
                         sorted(kwargs['dns_nameservers']))
        del subnet['dns_nameservers'], kwargs['dns_nameservers']

        self._compare_resource_attrs(updated_subnet, kwargs)
        self._delete_network(network['id'])

    @test.idempotent_id('a5caa7d9-ab71-4278-a57c-d6631b7474f8')
    def test_update_subnet_gw_dns_dhcp(self):
        network = self._create_network(_auto_clean_up=True)
        subnet_attrs = ['gateway',
                        'dns_nameservers', 'allocation_pools']
        subnet_dict = self.subnet_dict(subnet_attrs)
        subnet = self._create_subnet(network, **subnet_dict)
        subnet_id = subnet['id']
        new_gateway = str(netaddr.IPAddress(
                          self._subnet_data[self._ip_version]['gateway']) + 1)
        # Verify subnet update
        new_dns_nameservers = self._subnet_data[self._ip_version][
            'new_dns_nameservers']
        kwargs = {'dns_nameservers': new_dns_nameservers,
                  'gateway_ip': new_gateway, 'enable_dhcp': True}

        new_name = "New_subnet"
        body = self.update_subnet(subnet_id, name=new_name, **kwargs)
        updated_subnet = body['subnet']
        kwargs['name'] = new_name
        self.assertEqual(sorted(updated_subnet['dns_nameservers']),
                         sorted(kwargs['dns_nameservers']))
        del subnet['dns_nameservers'], kwargs['dns_nameservers']

        self._compare_resource_attrs(updated_subnet, kwargs)
        self._delete_network(network['id'])

    @decorators.skip_because(bug="1501827")
    @test.idempotent_id('a5caa7d5-ab71-4278-a57c-d6631b7474f8')
    def test_create_delete_subnet_all_attributes(self):
        self._create_verify_delete_subnet(
            enable_dhcp=True,
            **self.subnet_dict(['gateway',
                                'host_routes',
                                'dns_nameservers']))

    @test.idempotent_id('969f20b2-7eb5-44f5-98cd-381545b7c7e7')
    @test.idempotent_id('a5caa7d9-ab71-4278-a57c-d6631b7474c8')
    def test_create_delete_subnet_with_gw_dns(self):
        self._create_verify_delete_subnet(
            enable_dhcp=True,
            **self.subnet_dict(['gateway',
                                'dns_nameservers']))

    @test.idempotent_id('3c4c36a1-684b-4e89-8e71-d518f19324a0')
    def test_add_upd_del_multiple_overlapping_networks_subnet(self):
        r0, R1 = 0, 3   # (todo) get from CONF
        return self._add_upd_del_multiple_networks_subnet(
            r0, R1, "ovla-netwk")

    @test.idempotent_id('5267bf9d-de82-4af9-914a-8320e9f4c38c')
    def test_add_upd_del_multiple_nonoverlapping_networks_subnet(self):
        r0, R1 = 1, 4   # (todo) get from CONF
        return self._add_upd_del_multiple_networks_subnet(
            r0, R1, "noov-netwk", _step_cidr=2)

    def _add_upd_del_multiple_networks_subnet(self, r0, R1,
                                              name_prefix="m-network",
                                              _step_cidr=0):
        m_name = data_utils.rand_name(name_prefix)
        netwk = []
        for x in range(r0, R1):
            network = self._create_network(_auto_clean_up=True)
            net_id = network['id']
            self.assertEqual('ACTIVE', network['status'])
            new_name = m_name + "-%02d" % x
            body = self.update_network(net_id, name=new_name)
            network = body['network']
            cidr_offset = (x * _step_cidr) if _step_cidr > 0 else 0
            subnet = self._create_subnet(network, cidr_offset=cidr_offset)
            subnet_id = subnet['id']
            netwk.append([x, net_id, subnet_id])
        for x, net_id, subnet_id in netwk:
            # make sure subnet is updatable after creation
            new_name = m_name + "-%02d-snet" % x
            body = self.update_subnet(subnet_id, name=new_name)
            updated_subnet = body['subnet']
            self.assertEqual(updated_subnet['name'], new_name)
            self._delete_network(net_id)
