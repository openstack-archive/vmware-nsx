# Copyright 2015 VMware, Inc.
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

import mock
from neutron.tests import base

from vmware_nsx.plugins.nsx_v.vshield import vcns_driver
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common


EDGE_ID = 'edge-x'
POOL_ID = 'b3dfb476-6fdf-4ddd-b6bd-e86ae78dc30b'


def firewall_section_maker(if_ip_list, vip_ip_list):
    return (
        '<section id="1132" name="LBaaS FW Rules"><rule><name>' + POOL_ID +
        '</name><action>allow</action><sources excluded="false"><source>'
        '<type>Ipv4Address</type><value>' + ','.join(if_ip_list) +
        '</value></source></sources><destinations excluded="false">'
        '<destination><type>Ipv4Address</type><value>' +
        ','.join(vip_ip_list) + '</value></destination></destinations></rule>'
        '</section>')


def if_maker(ip_list):
    intf = {
        'index': 1, 'name': 'internal1', 'addressGroups': {
            'addressGroups': [
                {'subnetPrefixLength': '24',
                 'secondaryAddresses': {
                     'ipAddress': ip_list,
                     'type': 'secondary_addresses'},
                 'primaryAddress': '10.0.0.1',
                 'subnetMask': '255.255.255.0'}]},
            'portgroupName': 'pg1234', 'label': 'vNic_1',
            'type': 'internal', 'portgroupId': 'virtualwire-31'}
    return intf


def if_list_maker(ip_list):
    if_list = {
        'vnics': [
            {'index': 0, 'name': 'external', 'addressGroups': {
                'addressGroups': [
                    {'subnetMask': '255.255.255.0',
                     'primaryAddress': '172.24.4.2',
                     'subnetPrefixLength': '24'}]},
             'portgroupName': 'VM Network', 'label': 'vNic_0',
             'type': 'uplink', 'portgroupId': 'network-13'},
            {'index': 1, 'name': 'internal1', 'addressGroups': {
                'addressGroups': [
                    {'subnetPrefixLength': '24',
                     'secondaryAddresses': {
                         'ipAddress': ip_list,
                         'type': 'secondary_addresses'},
                     'primaryAddress': '10.0.0.1',
                     'subnetMask': '255.255.255.0'}]},
             'portgroupName': 'pg1234',
             'label': 'vNic_1', 'type': 'internal',
             'portgroupId': 'virtualwire-31'},
            {'index': 2, 'name': 'vnic2',
             'addressGroups': {'addressGroups': []},
             'label': 'vNic_2', 'type': 'internal'},
            {'index': 3, 'name': 'vnic3',
             'addressGroups': {'addressGroups': []},
             'label': 'vNic_3', 'type': 'internal'}]}
    return if_list


class TestLbaasCommon(base.BaseTestCase):
    def setUp(self):
        super(TestLbaasCommon, self).setUp()
        callbacks = mock.Mock()
        callbacks.plugin = mock.Mock()
        self.edge_driver = vcns_driver.VcnsDriver(callbacks)
        self.edge_driver._lb_driver_prop = mock.Mock()

    def _mock_edge_driver_vcns(self, attr):
        return mock.patch.object(self.edge_driver.vcns, attr)

    def test_add_vip_as_secondary_ip(self):
        update_if = if_maker(['10.0.0.6', '10.0.0.8'])

        with self._mock_edge_driver_vcns('get_interfaces') as mock_get_if,\
                self._mock_edge_driver_vcns(
                    'update_interface') as mock_update_if:

            mock_get_if.return_value = (None, if_list_maker(['10.0.0.6']))

            lb_common.add_vip_as_secondary_ip(
                self.edge_driver.vcns, EDGE_ID, '10.0.0.8')
            mock_update_if.assert_called_with(EDGE_ID, update_if)

    def test_del_vip_as_secondary_ip(self):
        update_if = if_maker(['10.0.0.6'])

        with self._mock_edge_driver_vcns('get_interfaces') as mock_get_if,\
                self._mock_edge_driver_vcns(
                    'update_interface') as mock_update_if:

            mock_get_if.return_value = (None, if_list_maker(['10.0.0.6',
                                                             '10.0.0.8']))

            lb_common.del_vip_as_secondary_ip(
                self.edge_driver.vcns, EDGE_ID, '10.0.0.8')
            mock_update_if.assert_called_with(EDGE_ID, update_if)

    def test_get_edge_ip_addresses(self):
        get_if_list = if_list_maker(['10.0.0.6'])

        with mock.patch.object(self.edge_driver.vcns, 'get_interfaces',
                               return_value=(None, get_if_list)):
            ip_list = lb_common.get_edge_ip_addresses(self.edge_driver.vcns,
                                                      EDGE_ID)
            self.assertEqual(['172.24.4.2', '10.0.0.1'], ip_list)
