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

from oslo_log import log as logging

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest import test

from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF
LOG = logging.getLogger(__name__)


class NSXv3DHCPUniScaleTest(base.BaseNetworkTest):
    """Test NSXv3 native DHCP unidimensional scale:

        - Create 100 DHCP enabled networks/subnets
        - Create 500 DHCP enabled networks/subnets
        - Create 1000 DHCP enabled networks/subnets
        - Create 2000 DHCP enabled networks/subnets
        - Create 4000 DHCP enabled networks/subnets
        - Create 100 ports on a DHCP enabled network/subnet
        - Create 256 ports on a DHCP enabled network/subnet
        - Create 512 ports on a DHCP enabled network/subnet

    One logical DHCP server will be created on NSXv3 backend if a DHCP enabled
    subnet is created. Also, a DHCP static binding will be created on the
    logical DHCP server if one port with device_ower=compute:None is created
    on the subnet. Test is to first create Neutron network resource using
    Neutron API and then check the backend resource using NSXv3 API

    Note:
        The following networking quotas need to be changed on neutron conf.
        They can be set as above scale limit or -1 which means unlimited.
        - quota_network = -1
        - quota_subnet = -1
        - quota_port = -1

        Also, in tempest conf, the following requirements should be met.
        - project_network_cidr should be at least /21, e.g. 10.20.0.0/16
        - project_network_mask_bits should be at least 22
    """

    @classmethod
    def skip_checks(cls):
        super(NSXv3DHCPUniScaleTest, cls).skip_checks()
        if not (CONF.nsxv3.nsx_manager and CONF.nsxv3.nsx_user and
                CONF.nsxv3.nsx_password):
            raise cls.skipException("Either NSX manager, user, or password "
                                    "is missing")
        if CONF.network.project_network_mask_bits > 22:
            raise cls.skipException("Project network CIDR doesn't have "
                                    "enough ports")

    @classmethod
    def resource_setup(cls):
        super(NSXv3DHCPUniScaleTest, cls).resource_setup()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)

    def _create_scale_logical_dhcp_server(self, scale):
        # Create networks based on scale number
        for i in range(scale):
            name = data_utils.rand_name('uniscale-%s' % i)
            network = self.create_network(network_name=name)
            self.create_subnet(network)
        # Check if the following numbers are correct
        # - Correct number of neutron networks
        # - Correct number of logical switches on nsx backend
        # - COrrect number of logical dhcp servers on nsx backend
        networks = self.networks_client.list_networks()
        scale_nets = [net for net in networks['networks']
                      if net['name'].startswith('uniscale-')]
        error_msg = "Neutron networks created doesn't match the scale number"
        self.assertEqual(len(scale_nets), scale, error_msg)
        nsx_switches = self.nsx.get_logical_switches()
        scale_switches = [ls for ls in nsx_switches
                          if ls['display_name'].startswith('uniscale-')]
        error_msg = ("Logical switches on backend doesn't match the "
                     "number of networks on OpenStack")
        self.assertEqual(len(scale_switches), scale, error_msg)
        dhcp_servers = self.nsx.get_logical_dhcp_servers()
        scale_dhcp_servers = [ds for ds in dhcp_servers
                              if ds['display_name'].startswith('uniscale-')]
        error_msg = ("Logical DHCP servers on backend doesn't match the "
                     "number of networks on OpenStack")
        self.assertEqual(len(scale_dhcp_servers), scale, error_msg)

    def _create_scale_dhcp_bindings(self, scale):
        # Create a network with dhcp enabled subnet
        name = data_utils.rand_name('binding-')
        network = self.create_network(network_name=name)
        self.create_subnet(network)
        dhcp_server = self.nsx.get_logical_dhcp_server(network['name'],
                                                       network['id'])
        self.assertIsNotNone(dhcp_server)
        for i in range(scale):
            port = self.create_port(network, device_owner='compute:None')
            self.addCleanup(self.ports_client.delete_port, port['id'])
        dhcp_server = self.nsx.get_logical_dhcp_server(network['name'],
                                                       network['id'])
        dhcp_bindings = self.nsx.get_dhcp_server_static_bindings(
            dhcp_server['id'])
        self.assertEqual(len(dhcp_bindings), scale)

    @test.attr(type='nsxv3')
    @test.idempotent_id('c5fa8d5d-3973-4d77-a0d4-f28b2ae92a2c')
    def test_create_100_logical_dhcp_server(self):
        self._create_scale_logical_dhcp_server(100)

    @test.attr(type='nsxv3')
    @test.idempotent_id('c2b264a2-daab-451f-ad3b-f0713a390f47')
    def test_create_500_logical_dhcp_server(self):
        self._create_scale_logical_dhcp_server(500)

    @test.attr(type='nsxv3')
    @test.idempotent_id('5ba22b0f-4593-4509-8998-a3002ce63406')
    def test_create_1k_logical_dhcp_server(self):
        self._create_scale_logical_dhcp_server(1000)

    @test.attr(type='nsxv3')
    @test.idempotent_id('ddf3d789-838a-428a-b4fe-8fe214f0e956')
    def test_create_2k_logical_dhcp_server(self):
        self._create_scale_logical_dhcp_server(2000)

    @test.attr(type='nsxv3')
    @test.idempotent_id('ed5441be-a700-45fa-bec1-b1d100acbb73')
    def test_create_4k_logical_dhcp_server(self):
        self._create_scale_logical_dhcp_server(4000)

    @test.attr(type='nsxv3')
    @test.idempotent_id('4a5484e3-f9b8-4562-8a4c-d8974a703767')
    def test_create_100_dhcp_bindings(self):
        self._create_scale_dhcp_bindings(100)

    @test.attr(type='nsxv3')
    @test.idempotent_id('cbb8af8c-db3a-4ad2-8954-c41670956c52')
    def test_create_256_dhcp_bindings(self):
        self._create_scale_dhcp_bindings(256)

    @test.attr(type='nsxv3')
    @test.idempotent_id('ffa5db0b-5922-494d-bcd3-9d5b0b10b684')
    def test_create_512_dhcp_bindings(self):
        self._create_scale_dhcp_bindings(512)
