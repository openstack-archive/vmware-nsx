# Copyright 2016 VMware Inc
# All Rights Reserved
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

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils

from tempest import config
from tempest import test

from vmware_nsx_tempest.tests.nsxv.api import base_provider as base

CONF = config.CONF


class DnsSearchDomainTest(base.BaseAdminNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(DnsSearchDomainTest, cls).resource_setup()
        cls.dns_search_domain = CONF.network.dns_search_domain
        network_name = data_utils.rand_name('dns-search')
        resp = cls.create_network(client=cls.networks_client,
                                  name=network_name)
        cls.project_network = resp.get('network', resp)
        # addCleanup() only available at instance, not at class
        resp = cls.create_subnet(cls.project_network,
                                 name=network_name,
                                 client=cls.subnets_client,
                                 dns_search_domain=cls.dns_search_domain)
        cls.tenant_subnet = resp.get('subnet', resp)

    @classmethod
    def resource_cleanup(cls):
        # we need to cleanup resouces created at class methods
        test_utils.call_and_ignore_notfound_exc(
            cls.networks_client.delete_network,
            cls.project_network['id'])
        super(DnsSearchDomainTest, cls).resource_cleanup()

    def create_networks(self, network_name):
        resp = self.create_network(client=self.networks_client,
                                   name=network_name)
        network = resp.get('network', resp)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.networks_client.delete_network,
                        network['id'])
        resp = self.create_subnet(network,
                                  name=network_name,
                                  client=self.subnets_client,
                                  dns_search_domain=self.dns_search_domain)
        subnet = resp.get('subnet', resp)
        return (network, subnet)

    @test.idempotent_id('879d620c-535c-467f-9e62-f2bf3178b5b7')
    def test_dns_search_domain_crud_operations(self):
        """perform CRUD operation on subnet with dns_search_domain."""
        network_name = data_utils.rand_name('crud-search-domain')
        network, subnet = self.create_networks(network_name)
        self.assertEqual('ACTIVE', network['status'])
        new_name = network_name + "-update"
        resp = self.update_subnet(
            subnet['id'], name=new_name,
            client=self.subnets_client,
            dns_search_domain=self.dns_search_domain)
        subnet = resp.get('subnet', resp)
        self.assertEqual(subnet['name'], new_name)
        self.assertEqual(subnet['dns_search_domain'],
                         self.dns_search_domain)
        subnet_list = self.list_subnets(client=self.subnets_client,
                                        name=new_name)['subnets']
        self.assertEqual(1, len(subnet_list))
        self.delete_subnet(subnet['id'])
        subnet_list = self.list_subnets(client=self.subnets_client,
                                        name=new_name)['subnets']
        self.assertEqual(0, len(subnet_list))

    @test.idempotent_id('40facdd9-40c0-48a1-bff1-57ba0ed0dc49')
    def test_list_search_domain(self):
        subnet_list = self.list_subnets(client=self.subnets_client,
                                        subnet_id=self.tenant_subnet['id'])
        self.assertEqual(1, len(subnet_list))

    @test.idempotent_id('8d023934-b0c8-4588-b48b-17db047a4d8b')
    def test_show_search_domain(self):
        resp = self.show_subnet(self.tenant_subnet['id'],
                                client=self.subnets_client)
        subnet = resp.get('subnet', resp)
        self.assertEqual(self.dns_search_domain,
                         subnet['dns_search_domain'])

    @test.idempotent_id('2b5990bf-d904-4e18-b197-93f3c061c260')
    def test_update_subnet_search_domain_field(self):
        """attach 2nd subnet to network and update its dns_search_domain."""
        subnet_name = data_utils.rand_name('upd-search-domain')
        # 2nd subnet attached to a network, make sure to use different cidr
        resp = self.create_subnet(self.project_network,
                                  name=subnet_name,
                                  cidr_offset=1,
                                  client=self.subnets_client)
        subnet = resp.get('subnet', resp)
        self.assertNotIn('dns_search_domain', subnet)
        resp = self.update_subnet(
            subnet['id'],
            client=self.subnets_client,
            dns_search_domain=self.dns_search_domain)
        subnet = resp.get('subnet', resp)
        self.assertEqual(subnet['dns_search_domain'],
                         self.dns_search_domain)
        # no method to remove dns_search_domain attribute
        # set to '' to clear search domain
        resp = self.update_subnet(
            subnet['id'],
            client=self.subnets_client,
            dns_search_domain='')
        subnet = resp.get('subnet', resp)
        self.assertEqual(subnet['dns_search_domain'], '')
        self.delete_subnet(subnet['id'],
                           client=self.subnets_client)
