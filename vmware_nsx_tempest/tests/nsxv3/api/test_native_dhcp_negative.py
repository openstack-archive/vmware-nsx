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


class NSXv3NativeDHCPNegative(base.BaseNetworkTest):
    """NSXv3 Native DHCP negative test

        - Create network without subnet
        - Create network with DHCP disabled subnet
        - Create DHCP enabled subnet and update to disable DHCP
    """

    @classmethod
    def skip_checks(cls):
        super(NSXv3NativeDHCPNegative, cls).skip_checks()
        if not (CONF.nsxv3.nsx_manager and CONF.nsxv3.nsx_user and
                CONF.nsxv3.nsx_password):
            raise cls.skipException("Either NSX manager, user, or password "
                                    "is missing")

    @classmethod
    def resource_setup(cls):
        super(NSXv3NativeDHCPNegative, cls).resource_setup()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)

    @test.attr(type='nsxv3')
    @test.attr(type=['negative'])
    @test.idempotent_id('d1fb24b9-6ee8-4fb3-b6fe-169fed3cfa7e')
    def test_create_network_without_subnet(self):
        name = data_utils.rand_name('network-')
        network = self.create_network(network_name=name)
        net_id = network['id']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.networks_client.delete_network, net_id)
        self.assertTrue('ACTIVE', network['status'])
        nsx_switch = self.nsx.get_logical_switch(network['name'],
                                                 network['id'])
        dhcp_server = self.nsx.get_logical_dhcp_server(network['name'],
                                                       network['id'])
        self.assertIsNotNone(nsx_switch)
        self.assertIsNone(dhcp_server)

    @test.attr(type='nsxv3')
    @test.attr(type=['negative'])
    @test.idempotent_id('caab60b9-b78c-4127-983f-cfb515b555fe')
    def test_create_dhcp_disabled_subnet(self):
        name = data_utils.rand_name('network-')
        network = self.create_network(network_name=name)
        net_id = network['id']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.networks_client.delete_network, net_id)
        self.create_subnet(network, enable_dhcp=False)
        self.assertTrue('ACTIVE', network['status'])
        nsx_switch = self.nsx.get_logical_switch(network['name'],
                                                 network['id'])
        dhcp_server = self.nsx.get_logical_dhcp_server(network['name'],
                                                       network['id'])
        self.assertIsNotNone(nsx_switch)
        self.assertIsNone(dhcp_server)

    @test.attr(type='nsxv3')
    @test.attr(type=['negative'])
    @test.idempotent_id('bcfd9e1c-456f-43cc-a22a-baceb2188b53')
    def test_update_dhcp_disabled_subnet(self):
        name = data_utils.rand_name('network-')
        network = self.create_network(network_name=name)
        net_id = network['id']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.networks_client.delete_network, net_id)
        subnet = self.create_subnet(network)
        self.assertTrue('ACTIVE', network['status'])
        nsx_switch = self.nsx.get_logical_switch(network['name'],
                                                 network['id'])
        dhcp_server = self.nsx.get_logical_dhcp_server(network['name'],
                                                       network['id'])
        self.assertIsNotNone(nsx_switch)
        self.assertIsNotNone(dhcp_server)
        # Update subnet to disable DHCP
        self.subnets_client.update_subnet(subnet['id'], enable_dhcp=False)
        dhcp_server = self.nsx.get_logical_dhcp_server(network['name'],
                                                       network['id'])
        self.assertIsNone(dhcp_server)
