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

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions
from tempest import test

CONF = config.CONF


class DnsSearchDoaminsNegativeTest(base.BaseAdminNetworkTest):

    @classmethod
    def skip_checks(cls):
        super(DnsSearchDoaminsNegativeTest, cls).skip_checks()

    def create_network_with_bad_dns_search_domain(
            self, dns_search_domain="vmware@com"):
        networks_client = self.networks_client
        subnets_client = self.subnets_client
        network_name = data_utils.rand_name('dns-sear-negative')
        resp = networks_client.create_network(name=network_name)
        network = resp.get('network', resp)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        networks_client.delete_network,
                        network['id'])
        subnet_cfg = {
            'client': subnets_client,
            'name': network_name,
            'dns_search_domain': dns_search_domain}
        # should trigger exception of BadRequest with message:
        # Invalid input for dns_search_domain: ...
        resp = self.create_subnet(network, **subnet_cfg)
        subnet = resp.get('subnet', resp)
        return (network, subnet)

    @test.attr(type=['negative'])
    @test.idempotent_id('11bdc214-10d7-4926-8f49-2da3d8719143')
    def test_create_dns_search_domain_negative(self):
        self.assertRaises(exceptions.BadRequest,
                          self.create_network_with_bad_dns_search_domain)
