# Copyright 2016 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from oslo_config import cfg

from vmware_nsx.tests.unit.nsx_v import test_plugin

from neutron_lib.api.definitions import provider_net as pnet


class TestNsxvIpamSubnets(test_plugin.TestSubnetsV2):
    """Run the nsxv plugin subnets tests with the ipam driver"""
    def setUp(self):
        cfg.CONF.set_override(
            "ipam_driver",
            "vmware_nsx.services.ipam.nsx_v.driver.NsxvIpamDriver")
        super(TestNsxvIpamSubnets, self).setUp()

    def provider_net(self):
        name = 'dvs-provider-net'
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 43,
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
        return self.network(name=name, do_delete=False,
                            providernet_args=providernet_args,
                            arg_list=(pnet.NETWORK_TYPE,
                                      pnet.SEGMENTATION_ID,
                                      pnet.PHYSICAL_NETWORK))

    def test_provider_net_use_driver(self):
        with self.provider_net() as net:
            before = len(self.fc2._ipam_pools)
            with self.subnet(network=net, cidr='10.10.10.0/29',
                             enable_dhcp=False):
                self.assertEqual(before + 1, len(self.fc2._ipam_pools))

    def test_ext_net_use_driver(self):
        with self.network(router__external=True) as net:
            before = len(self.fc2._ipam_pools)
            with self.subnet(network=net, cidr='10.10.10.0/29',
                             enable_dhcp=False):
                self.assertEqual(before + 1, len(self.fc2._ipam_pools))

    def test_regular_net_dont_use_driver(self):
        with self.network() as net:
            before = len(self.fc2._ipam_pools)
            with self.subnet(network=net, cidr='10.10.10.0/29',
                             enable_dhcp=False):
                self.assertEqual(before, len(self.fc2._ipam_pools))

    def test_no_more_ips(self):
        # create a small provider network, and use all the IPs
        with self.provider_net() as net:
            with self.subnet(network=net, cidr='10.10.10.0/29',
                             enable_dhcp=False) as subnet:
                # create ports on this subnet until there are no more free ips
                # legal ips are 10.10.10.2 - 10.10.10.6
                fixed_ips = [{'subnet_id': subnet['subnet']['id']}]
                for counter in range(5):
                    port_res = self._create_port(
                        self.fmt, net['network']['id'], fixed_ips=fixed_ips)
                    port = self.deserialize('json', port_res)
                    self.assertIn('port', port)

                # try to create another one - should fail
                port_res = self._create_port(
                    self.fmt, net['network']['id'], fixed_ips=fixed_ips)
                port = self.deserialize('json', port_res)
                self.assertIn('NeutronError', port)
                self.assertIn('message', port['NeutronError'])
                self.assertTrue(('No more IP addresses available' in
                                 port['NeutronError']['message']))

    def test_use_same_ips(self):
        # create a provider network and try to allocate the same ip twice
        with self.provider_net() as net:
            with self.subnet(network=net, cidr='10.10.10.0/24',
                             enable_dhcp=False) as subnet:
                fixed_ips = [{'ip_address': '10.10.10.2',
                              'subnet_id': subnet['subnet']['id']}]
                # First port should succeed
                port_res = self._create_port(
                    self.fmt, net['network']['id'], fixed_ips=fixed_ips)
                port = self.deserialize('json', port_res)
                self.assertIn('port', port)

                # try to create another one - should fail
                port_res = self._create_port(
                    self.fmt, net['network']['id'], fixed_ips=fixed_ips)
                port = self.deserialize('json', port_res)
                self.assertIn('NeutronError', port)
                self.assertIn('message', port['NeutronError'])
                self.assertTrue(('already allocated in subnet' in
                                 port['NeutronError']['message']))


class TestNsxvIpamPorts(test_plugin.TestPortsV2):
    """Run the nsxv plugin ports tests with the ipam driver"""
    def setUp(self):
        cfg.CONF.set_override(
            "ipam_driver",
            "vmware_nsx.services.ipam.nsx_v.driver.NsxvIpamDriver")
        super(TestNsxvIpamPorts, self).setUp()
