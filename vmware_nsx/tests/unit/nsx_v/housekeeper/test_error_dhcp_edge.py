# Copyright 2017 VMware, Inc.
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

import copy
import datetime

import mock
from neutron.tests import base
from neutron_lib.plugins import constants

from vmware_nsx.plugins.common.housekeeper import base_job
from vmware_nsx.plugins.nsx_v.housekeeper import error_dhcp_edge

FAKE_ROUTER_BINDINGS = [
    {
        'router_id': 'dhcp-16c224dd-7c2b-4241-a447-4fc07a3', 'status': 'ERROR',
        'availability_zone': 'default', 'edge_id': 'edge-752'},
    {
        'router_id': 'dhcp-31341032-6911-4596-8b64-afce92f', 'status': 'ERROR',
        'availability_zone': 'default', 'edge_id': 'edge-752'},
    {
        'router_id': 'dhcp-51c97abb-8ac9-4f24-b914-cc30cf8', 'status': 'ERROR',
        'availability_zone': 'default', 'edge_id': 'edge-752'},
    {
        'router_id': 'dhcp-5d01cea4-58f8-4a16-9be0-11012ca', 'status': 'ERROR',
        'availability_zone': 'default', 'edge_id': 'edge-752'},
    {
        'router_id': 'dhcp-65a5335c-4c72-4721-920e-5abdc9e', 'status': 'ERROR',
        'availability_zone': 'default', 'edge_id': 'edge-752'},
    {
        'router_id': 'dhcp-83bce421-b72c-4744-9285-a0fcc25', 'status': 'ERROR',
        'availability_zone': 'default', 'edge_id': 'edge-752'},
    {
        'router_id': 'dhcp-9d2f5b66-c252-4681-86af-9460484', 'status': 'ERROR',
        'availability_zone': 'default', 'edge_id': 'edge-752'},
    {
        'router_id': 'dhcp-aea44408-0448-42dd-9ae6-ed940da', 'status': 'ERROR',
        'availability_zone': 'default', 'edge_id': 'edge-752'}]

BAD_ROUTER_BINDING = {
    'router_id': 'dhcp-11111111-1111-1111-aaaa-aaaaaaa', 'status': 'ERROR',
    'availability_zone': 'default', 'edge_id': 'edge-752'}

FAKE_EDGE_VNIC_BINDS = [
    {
        'network_id': '7c0b6fb5-d86c-4e5e-a2af-9ce36971764b',
        'vnic_index': 1, 'edge_id': 'edge-752', 'tunnel_index': 1},
    {
        'network_id': '16c224dd-7c2b-4241-a447-4fc07a38dc80',
        'vnic_index': 2, 'edge_id': 'edge-752', 'tunnel_index': 4},
    {
        'network_id': '65a5335c-4c72-4721-920e-5abdc9e09ba4',
        'vnic_index': 2, 'edge_id': 'edge-752', 'tunnel_index': 6},
    {
        'network_id': 'aea44408-0448-42dd-9ae6-ed940dac564a',
        'vnic_index': 4, 'edge_id': 'edge-752', 'tunnel_index': 10},
    {
        'network_id': '5d01cea4-58f8-4a16-9be0-11012cadbf55',
        'vnic_index': 4, 'edge_id': 'edge-752', 'tunnel_index': 12},
    {
        'network_id': '51c97abb-8ac9-4f24-b914-cc30cf8e856a',
        'vnic_index': 6, 'edge_id': 'edge-752', 'tunnel_index': 16},
    {
        'network_id': '31341032-6911-4596-8b64-afce92f46bf4',
        'vnic_index': 6, 'edge_id': 'edge-752', 'tunnel_index': 18},
    {
        'network_id': '9d2f5b66-c252-4681-86af-946048414a1f',
        'vnic_index': 8, 'edge_id': 'edge-752', 'tunnel_index': 22},
    {
        'network_id': '83bce421-b72c-4744-9285-a0fcc25b001a',
        'vnic_index': 8, 'edge_id': 'edge-752', 'tunnel_index': 24}]

BAD_VNIC_BINDING = {
        'network_id': '11111111-1111-1111-aaaa-aaaaaaabbaac',
        'vnic_index': 8, 'edge_id': 'edge-752', 'tunnel_index': 21}

FAKE_INTERNAL_NETWORKS = [
    {'availability_zone': u'default',
     'network_id': u'7c0b6fb5-d86c-4e5e-a2af-9ce36971764b',
     'network_purpose': 'inter_edge_net', 'updated_at': None,
     '_rev_bumped': False,
     'created_at': datetime.datetime(2017, 12, 13, 12, 28, 18)}]

FAKE_NETWORK_RESULTS = [{'id': 'e3a02b46-b9c9-4f2f-bcea-7978355a7dca'},
                        {'id': '031eaf4b-49b8-4003-9369-8a0dd5d7a163'},
                        {'id': '16c224dd-7c2b-4241-a447-4fc07a38dc80'},
                        {'id': '1a3b570c-c8b5-411e-8e13-d4dc0b3e56b2'},
                        {'id': '24b31d2c-fcec-45e5-bdcb-aa089d3713ae'},
                        {'id': '31341032-6911-4596-8b64-afce92f46bf4'},
                        {'id': '51c97abb-8ac9-4f24-b914-cc30cf8e856a'},
                        {'id': '5484b39b-ec6e-43f4-b900-fc1b2c49c71a'},
                        {'id': '54eae237-3516-4f82-b46f-f955e91c989c'},
                        {'id': '5a859fa0-bea0-41be-843a-9f9bf39e2509'},
                        {'id': '5d01cea4-58f8-4a16-9be0-11012cadbf55'},
                        {'id': '65a5335c-4c72-4721-920e-5abdc9e09ba4'},
                        {'id': '708f11d4-00d0-48ea-836f-01273cbf36cc'},
                        {'id': '7c0b6fb5-d86c-4e5e-a2af-9ce36971764b'},
                        {'id': '83bce421-b72c-4744-9285-a0fcc25b001a'},
                        {'id': '9d2f5b66-c252-4681-86af-946048414a1f'},
                        {'id': 'aea44408-0448-42dd-9ae6-ed940dac564a'},
                        {'id': 'b0cee4e3-266b-48d3-a651-04f1985fe4b0'},
                        {'id': 'be82b8c5-96a9-4e08-a965-bb09d48ec161'},
                        {'id': 'e69279c6-9a1e-4f7b-b421-b8b3eb92c54b'}]

BACKEND_EDGE_VNICS = {'vnics': [
    {'label': 'vNic_0', 'name': 'external',
     'addressGroups': {'addressGroups': []}, 'mtu': 1500, 'type': 'uplink',
     'isConnected': True, 'index': 0, 'portgroupId': 'network-13',
     'fenceParameters': [], 'enableProxyArp': False,
     'enableSendRedirects': True},
    {'label': 'vNic_1', 'name': 'internal1', 'addressGroups': {
        'addressGroups': [
            {'primaryAddress': '169.254.128.14',
             'secondaryAddresses': {
                 'type': 'secondary_addresses',
                 'ipAddress': ['169.254.169.254']},
             'subnetMask': '255.255.128.0',
             'subnetPrefixLength': '17'}]}, 'mtu': 1500,
     'type': 'internal', 'isConnected': True, 'index': 1,
     'portgroupId': 'virtualwire-472',
     'fenceParameters': [], 'enableProxyArp': False,
     'enableSendRedirects': True},
    {'label': 'vNic_2', 'name': 'internal2',
     'addressGroups': {'addressGroups': []}, 'mtu': 1500, 'type': 'trunk',
     'subInterfaces': {'subInterfaces': [
         {'isConnected': True, 'label': 'vNic_10',
          'name': '1639ff40-8137-4803-a29f-dcf0efc35b34', 'index': 10,
          'tunnelId': 4, 'logicalSwitchId': 'virtualwire-497',
          'logicalSwitchName': '16c224dd-7c2b-4241-a447-4fc07a38dc80',
          'enableSendRedirects': True, 'mtu': 1500,
          'addressGroups': {'addressGroups': [{
                 'primaryAddress': '10.24.0.2', 'subnetMask': '255.255.255.0',
                 'subnetPrefixLength': '24'}]}, 'virtualNetworkId': 5025,
          'subInterfaceBackingType': 'NETWORK'},
         {'isConnected': True, 'label': 'vNic_12',
          'name': 'd1515746-a21a-442d-8347-62b36f5791d6', 'index': 12,
          'tunnelId': 6, 'logicalSwitchId': 'virtualwire-499',
          'logicalSwitchName': '65a5335c-4c72-4721-920e-5abdc9e09ba4',
          'enableSendRedirects': True, 'mtu': 1500,
          'addressGroups': {'addressGroups': [
                 {'primaryAddress': '10.26.0.2', 'subnetMask': '255.255.255.0',
                  'subnetPrefixLength': '24'}]}, 'virtualNetworkId': 5027,
          'subInterfaceBackingType': 'NETWORK'}]}, 'isConnected': True,
     'index': 2, 'portgroupId': 'dvportgroup-1550',
     'fenceParameters': [], 'enableProxyArp': False,
     'enableSendRedirects': True},
    {'label': 'vNic_3', 'name': 'vnic3',
     'addressGroups': {'addressGroups': []},
     'mtu': 1500, 'type': 'internal', 'isConnected': False, 'index': 3,
     'fenceParameters': [], 'enableProxyArp': False,
     'enableSendRedirects': True},
    {'label': 'vNic_4', 'name': 'internal4',
     'addressGroups': {'addressGroups': []}, 'mtu': 1500, 'type': 'trunk',
     'subInterfaces': {'subInterfaces': [
         {'isConnected': True, 'label': 'vNic_16',
          'name': 'e2405dc6-21d7-4421-a70c-3eecf675b286', 'index': 16,
          'tunnelId': 10, 'logicalSwitchId': 'virtualwire-503',
          'logicalSwitchName': 'aea44408-0448-42dd-9ae6-ed940dac564a',
          'enableSendRedirects': True, 'mtu': 1500,
          'addressGroups': {'addressGroups': [
                 {'primaryAddress': '10.30.0.2', 'subnetMask': '255.255.255.0',
                  'subnetPrefixLength': '24'}]}, 'virtualNetworkId': 5031,
          'subInterfaceBackingType': 'NETWORK'},
         {'isConnected': True, 'label': 'vNic_18',
          'name': 'a10fb348-30e4-477f-817f-bb3c9c9fd3f5', 'index': 18,
          'tunnelId': 12, 'logicalSwitchId': 'virtualwire-505',
          'logicalSwitchName': '5d01cea4-58f8-4a16-9be0-11012cadbf55',
          'enableSendRedirects': True, 'mtu': 1500,
          'addressGroups': {'addressGroups': [
                 {'primaryAddress': '10.32.0.2', 'subnetMask': '255.255.255.0',
                  'subnetPrefixLength': '24'}]}, 'virtualNetworkId': 5033,
          'subInterfaceBackingType': 'NETWORK'}]}, 'isConnected': True,
     'index': 4, 'portgroupId': 'dvportgroup-1559',
     'fenceParameters': [], 'enableProxyArp': False,
     'enableSendRedirects': True},
    {'label': 'vNic_5', 'name': 'vnic5',
     'addressGroups': {'addressGroups': []},
     'mtu': 1500, 'type': 'internal', 'isConnected': False, 'index': 5,
     'fenceParameters': [], 'enableProxyArp': False,
     'enableSendRedirects': True},
    {'label': 'vNic_6', 'name': 'internal6',
     'addressGroups': {'addressGroups': []}, 'mtu': 1500, 'type': 'trunk',
     'subInterfaces': {'subInterfaces': [
         {'isConnected': True, 'label': 'vNic_22',
          'name': '2da534c8-3d9b-4677-aa14-2e66efd09e3f', 'index': 22,
          'tunnelId': 16, 'logicalSwitchId': 'virtualwire-509',
          'logicalSwitchName': '51c97abb-8ac9-4f24-b914-cc30cf8e856a',
          'enableSendRedirects': True, 'mtu': 1500,
          'addressGroups': {'addressGroups': [
                 {'primaryAddress': '10.36.0.2', 'subnetMask': '255.255.255.0',
                  'subnetPrefixLength': '24'}]}, 'virtualNetworkId': 5037,
          'subInterfaceBackingType': 'NETWORK'},
         {'isConnected': True, 'label': 'vNic_24',
          'name': 'd25f00c2-eb82-455c-87b9-d2d510d42917', 'index': 24,
          'tunnelId': 18, 'logicalSwitchId': 'virtualwire-511',
          'logicalSwitchName': '31341032-6911-4596-8b64-afce92f46bf4',
          'enableSendRedirects': True, 'mtu': 1500,
          'addressGroups': {'addressGroups': [
                 {'primaryAddress': '10.38.0.2', 'subnetMask': '255.255.255.0',
                  'subnetPrefixLength': '24'}]}, 'virtualNetworkId': 5039,
          'subInterfaceBackingType': 'NETWORK'}]}, 'isConnected': True,
     'index': 6, 'portgroupId': 'dvportgroup-1567',

     'fenceParameters': [], 'enableProxyArp': False,
     'enableSendRedirects': True},
    {'label': 'vNic_7', 'name': 'vnic7',
     'addressGroups': {'addressGroups': []},
     'mtu': 1500, 'type': 'internal', 'isConnected': False, 'index': 7,
     'fenceParameters': [], 'enableProxyArp': False,
     'enableSendRedirects': True},
    {'label': 'vNic_8', 'name': 'internal8',
     'addressGroups': {'addressGroups': []}, 'mtu': 1500, 'type': 'trunk',
     'subInterfaces': {'subInterfaces': [
         {'isConnected': True, 'label': 'vNic_28',
          'name': 'cf4cc867-e958-4f86-acea-d8a52a4c26c8', 'index': 28,
          'tunnelId': 22, 'logicalSwitchId': 'virtualwire-515',
          'logicalSwitchName': '9d2f5b66-c252-4681-86af-946048414a1f',
          'enableSendRedirects': True, 'mtu': 1500,
          'addressGroups': {'addressGroups': [
                 {'primaryAddress': '10.42.0.2', 'subnetMask': '255.255.255.0',
                  'subnetPrefixLength': '24'}]}, 'virtualNetworkId': 5043,
          'subInterfaceBackingType': 'NETWORK'},
         {'isConnected': True, 'label': 'vNic_30',
          'name': 'ceab3d83-3ee2-4372-b5d7-f1d47be76e9d', 'index': 30,
          'tunnelId': 24, 'logicalSwitchId': 'virtualwire-517',
          'logicalSwitchName': '83bce421-b72c-4744-9285-a0fcc25b001a',
          'enableSendRedirects': True, 'mtu': 1500,
          'addressGroups': {'addressGroups': [
                 {'primaryAddress': '10.44.0.2', 'subnetMask': '255.255.255.0',
                  'subnetPrefixLength': '24'}]}, 'virtualNetworkId': 5045,
          'subInterfaceBackingType': 'NETWORK'}]}, 'isConnected': True,
     'index': 8, 'portgroupId': 'dvportgroup-1575',
     'fenceParameters': [], 'enableProxyArp': False,
     'enableSendRedirects': True},
    {'label': 'vNic_9', 'name': 'vnic9',
     'addressGroups': {'addressGroups': []},
     'mtu': 1500, 'type': 'internal', 'isConnected': False, 'index': 9,
     'fenceParameters': [], 'enableProxyArp': False,
     'enableSendRedirects': True}]}

BAD_SUBINTERFACE = {
    'isConnected': True, 'label': 'vNic_31',
    'name': '11111111-2222-3333-4444-555555555555', 'index': 31,
    'tunnelId': 25, 'logicalSwitchId': 'virtualwire-518',
    'logicalSwitchName': '55555555-4444-3333-2222-111111111111',
    'enableSendRedirects': True, 'mtu': 1500, 'addressGroups': {
        'addressGroups': [
            {'primaryAddress': '10.99.0.2', 'subnetMask': '255.255.255.0',
             'subnetPrefixLength': '24'}]}, 'virtualNetworkId': 5045,
    'subInterfaceBackingType': 'NETWORK'}

BAD_INTERFACE = {
    'label': 'vNic_8', 'name': 'vnic8',
    'addressGroups': {'addressGroups': []},
    'mtu': 1500, 'type': 'internal', 'isConnected': False, 'index': 8,
    'fenceParameters': [], 'enableProxyArp': False,
    'enableSendRedirects': True}


class ErrorDhcpEdgeTestCaseReadOnly(base.BaseTestCase):

    def setUp(self):
        def get_plugin_mock(alias=constants.CORE):
            if alias in (constants.CORE, constants.L3):
                return self.plugin

        super(ErrorDhcpEdgeTestCaseReadOnly, self).setUp()
        self.plugin = mock.Mock()
        self.context = mock.Mock()
        self.context.session = mock.Mock()
        mock.patch('neutron_lib.plugins.directory.get_plugin',
                   side_effect=get_plugin_mock).start()
        self.plugin.edge_manager = mock.Mock()
        self.plugin.nsx_v = mock.Mock()
        self.plugin.nsx_v.vcns = mock.Mock()
        mock.patch.object(self.plugin, 'get_availability_zone_name_by_edge',
                          return_value='default').start()
        self.log = mock.Mock()
        base_job.LOG = self.log
        self.job = error_dhcp_edge.ErrorDhcpEdgeJob(True, [])

    def run_job(self):
        self.job.run(self.context, readonly=True)

    def test_clean_run(self):
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_router_bindings',
                   return_value=[]).start()
        self.run_job()
        self.log.warning.assert_not_called()

    def test_invalid_router_binding(self):
        router_binds = copy.deepcopy(FAKE_ROUTER_BINDINGS)
        router_binds.append(BAD_ROUTER_BINDING)
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_router_bindings',
                   return_value=router_binds).start()
        mock.patch('vmware_nsx.db.nsxv_db.get_edge_vnic_bindings_by_edge',
                   return_value=FAKE_EDGE_VNIC_BINDS).start()
        mock.patch.object(self.plugin, 'get_networks',
                          return_value=FAKE_NETWORK_RESULTS).start()
        mock.patch.object(self.plugin.nsx_v.vcns, 'get_interfaces',
                          return_value=(None, BACKEND_EDGE_VNICS)).start()
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_internal_networks',
                   return_value=FAKE_INTERNAL_NETWORKS).start()
        self.run_job()
        self.log.warning.assert_called_once()

    def test_invalid_edge_vnic_bindings(self):
        def fake_vnic_bind(*args, **kwargs):
            # The DB content is manipulated by the housekeeper. Therefore
            # get_edge_vnic_bindings_by_edge() output should be altered
            if fake_vnic_bind.ctr < 2:
                ret = fake_vnic_bind.vnic_binds
            else:
                ret = FAKE_EDGE_VNIC_BINDS
            fake_vnic_bind.ctr += 1
            return ret

        fake_vnic_bind.ctr = 0
        fake_vnic_bind.vnic_binds = copy.deepcopy(FAKE_EDGE_VNIC_BINDS)
        fake_vnic_bind.vnic_binds.append(BAD_VNIC_BINDING)

        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_router_bindings',
                   return_value=FAKE_ROUTER_BINDINGS).start()
        mock.patch('vmware_nsx.db.nsxv_db.get_edge_vnic_bindings_by_edge',
                   side_effect=fake_vnic_bind).start()
        mock.patch.object(self.plugin, 'get_networks',
                          return_value=FAKE_NETWORK_RESULTS).start()
        mock.patch.object(self.plugin.nsx_v.vcns, 'get_interfaces',
                          return_value=(None, BACKEND_EDGE_VNICS)).start()
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_internal_networks',
                   return_value=FAKE_INTERNAL_NETWORKS).start()
        self.run_job()
        self.log.warning.assert_called_once()

    def test_invalid_edge_sub_if(self):
        backend_vnics = copy.deepcopy(BACKEND_EDGE_VNICS)
        backend_vnics['vnics'][8]['subInterfaces']['subInterfaces'].append(
            BAD_SUBINTERFACE)
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_router_bindings',
                   return_value=FAKE_ROUTER_BINDINGS).start()
        mock.patch('vmware_nsx.db.nsxv_db.get_edge_vnic_bindings_by_edge',
                   return_value=FAKE_EDGE_VNIC_BINDS).start()
        mock.patch.object(self.plugin, 'get_networks',
                          return_value=FAKE_NETWORK_RESULTS).start()
        mock.patch.object(self.plugin.nsx_v.vcns, 'get_interfaces',
                          return_value=(None, backend_vnics)).start()
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_internal_networks',
                   return_value=FAKE_INTERNAL_NETWORKS).start()
        self.run_job()
        self.log.warning.assert_called_once()

    def test_missing_edge_sub_if(self):
        backend_vnics = copy.deepcopy(BACKEND_EDGE_VNICS)
        del backend_vnics['vnics'][8]['subInterfaces']['subInterfaces'][1]
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_router_bindings',
                   return_value=FAKE_ROUTER_BINDINGS).start()
        mock.patch('vmware_nsx.db.nsxv_db.get_edge_vnic_bindings_by_edge',
                   return_value=FAKE_EDGE_VNIC_BINDS).start()
        mock.patch.object(self.plugin, 'get_networks',
                          return_value=FAKE_NETWORK_RESULTS).start()
        mock.patch.object(self.plugin.nsx_v.vcns, 'get_interfaces',
                          return_value=(None, backend_vnics)).start()
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_internal_networks',
                   return_value=FAKE_INTERNAL_NETWORKS).start()
        self.run_job()
        self.log.warning.assert_called_once()

    def test_missing_edge_interface(self):
        backend_vnics = copy.deepcopy(BACKEND_EDGE_VNICS)
        backend_vnics['vnics'][8] = BAD_INTERFACE
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_router_bindings',
                   return_value=FAKE_ROUTER_BINDINGS).start()
        mock.patch('vmware_nsx.db.nsxv_db.get_edge_vnic_bindings_by_edge',
                   return_value=FAKE_EDGE_VNIC_BINDS).start()
        mock.patch.object(self.plugin, 'get_networks',
                          return_value=FAKE_NETWORK_RESULTS).start()
        mock.patch.object(self.plugin.nsx_v.vcns, 'get_interfaces',
                          return_value=(None, backend_vnics)).start()
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_internal_networks',
                   return_value=FAKE_INTERNAL_NETWORKS).start()
        self.run_job()
        self.assertEqual(2, self.log.warning.call_count)


class ErrorDhcpEdgeTestCaseReadWrite(ErrorDhcpEdgeTestCaseReadOnly):

    def run_job(self):
        self.job.run(self.context, readonly=False)

    def test_invalid_router_binding(self):
        del_binding = mock.patch(
            'vmware_nsx.db.nsxv_db.delete_nsxv_router_binding').start()
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_router_bindings_by_edge',
                   return_value=FAKE_ROUTER_BINDINGS).start()
        upd_binding = mock.patch(
            'vmware_nsx.db.nsxv_db.update_nsxv_router_binding').start()
        super(ErrorDhcpEdgeTestCaseReadWrite, self
              ).test_invalid_router_binding()
        del_binding.assert_called_with(mock.ANY,
                                       BAD_ROUTER_BINDING['router_id'])
        upd_binding.assert_has_calls(
            [mock.call(mock.ANY, r['router_id'], status='ACTIVE')
             for r in FAKE_ROUTER_BINDINGS])

    def test_invalid_edge_vnic_bindings(self):
        del_binding = mock.patch(
            'vmware_nsx.db.nsxv_db.free_edge_vnic_by_network').start()
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_router_bindings_by_edge',
                   return_value=FAKE_ROUTER_BINDINGS).start()
        upd_binding = mock.patch(
            'vmware_nsx.db.nsxv_db.update_nsxv_router_binding').start()
        super(ErrorDhcpEdgeTestCaseReadWrite, self
              ).test_invalid_edge_vnic_bindings()
        del_binding.assert_called_with(mock.ANY, BAD_VNIC_BINDING['edge_id'],
                                       BAD_VNIC_BINDING['network_id'])
        upd_binding.assert_has_calls(
            [mock.call(mock.ANY, r['router_id'], status='ACTIVE')
             for r in FAKE_ROUTER_BINDINGS])

    def test_invalid_edge_sub_if(self):
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_router_bindings_by_edge',
                   return_value=FAKE_ROUTER_BINDINGS).start()
        upd_binding = mock.patch(
            'vmware_nsx.db.nsxv_db.update_nsxv_router_binding').start()
        upd_if = mock.patch.object(self.plugin.nsx_v.vcns,
                                   'update_interface').start()
        super(ErrorDhcpEdgeTestCaseReadWrite, self
              ).test_invalid_edge_sub_if()
        upd_binding.assert_has_calls(
            [mock.call(mock.ANY, r['router_id'], status='ACTIVE')
             for r in FAKE_ROUTER_BINDINGS])
        upd_if.assert_called_with('edge-752', BACKEND_EDGE_VNICS['vnics'][8])

    def test_missing_edge_sub_if(self):
        deleted_sub_if = BACKEND_EDGE_VNICS['vnics'][8]['subInterfaces'][
            'subInterfaces'][1]
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_router_bindings_by_edge',
                   return_value=FAKE_ROUTER_BINDINGS).start()
        mock.patch.object(
            self.plugin.edge_manager, '_create_sub_interface',
            return_value=('dvportgroup-1575', deleted_sub_if)).start()
        upd_binding = mock.patch(
            'vmware_nsx.db.nsxv_db.update_nsxv_router_binding').start()
        upd_if = mock.patch.object(self.plugin.nsx_v.vcns,
                                   'update_interface').start()
        super(ErrorDhcpEdgeTestCaseReadWrite, self
              ).test_missing_edge_sub_if()
        upd_binding.assert_has_calls(
            [mock.call(mock.ANY, r['router_id'], status='ACTIVE')
             for r in FAKE_ROUTER_BINDINGS])
        upd_if.assert_called_with('edge-752', BACKEND_EDGE_VNICS['vnics'][8])

    def test_missing_edge_interface(self):
        def fake_create_subif(*args, **kwargs):
            deleted_sub_if = BACKEND_EDGE_VNICS['vnics'][8]['subInterfaces'][
                'subInterfaces'][fake_create_subif.ctr]
            fake_create_subif.ctr += 1
            return (BACKEND_EDGE_VNICS['vnics'][8]['portgroupId'],
                    deleted_sub_if)

        fake_create_subif.ctr = 0

        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_router_bindings_by_edge',
                   return_value=FAKE_ROUTER_BINDINGS).start()
        mock.patch.object(
            self.plugin.edge_manager, '_create_sub_interface',
            side_effect=fake_create_subif).start()
        upd_binding = mock.patch(
            'vmware_nsx.db.nsxv_db.update_nsxv_router_binding').start()
        upd_if = mock.patch.object(self.plugin.nsx_v.vcns,
                                   'update_interface').start()
        super(ErrorDhcpEdgeTestCaseReadWrite, self
              ).test_missing_edge_interface()
        upd_binding.assert_has_calls(
            [mock.call(mock.ANY, r['router_id'], status='ACTIVE')
             for r in FAKE_ROUTER_BINDINGS])
        upd_if.assert_called_with('edge-752', BACKEND_EDGE_VNICS['vnics'][8])
