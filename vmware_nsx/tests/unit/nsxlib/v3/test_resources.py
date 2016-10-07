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
#
import copy

import mock

from oslo_serialization import jsonutils

from vmware_nsx.nsxlib.v3 import resources
from vmware_nsx.tests.unit.nsx_v3 import mocks
from vmware_nsx.tests.unit.nsx_v3 import test_constants as test_constants_v3
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase
from vmware_nsx.tests.unit.nsxlib.v3 import test_client


CLIENT_PKG = test_client.CLIENT_PKG
profile_types = resources.SwitchingProfileTypes


class TestSwitchingProfileTestCase(nsxlib_testcase.NsxClientTestCase):

    def _mocked_switching_profile(self, session_response=None):
        return self.mocked_resource(
            resources.SwitchingProfile, session_response=session_response)

    def test_switching_profile_create(self):
        mocked_resource = self._mocked_switching_profile()

        mocked_resource.create(profile_types.PORT_MIRRORING,
                               'pm-profile', 'port mirror prof')

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps({
                'resource_type': profile_types.PORT_MIRRORING,
                'display_name': 'pm-profile',
                'description': 'port mirror prof'
            }, sort_keys=True))

    def test_switching_profile_update(self):

        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'tenant-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]

        mocked_resource = self._mocked_switching_profile()

        mocked_resource.update(
            'a12bc1', profile_types.PORT_MIRRORING, tags=tags)

        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles/a12bc1',
            data=jsonutils.dumps({
                'resource_type': profile_types.PORT_MIRRORING,
                'tags': tags
            }, sort_keys=True))

    def test_spoofgaurd_profile_create(self):

        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'tenant-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]

        mocked_resource = self._mocked_switching_profile()

        mocked_resource.create_spoofguard_profile(
            'neutron-spoof', 'spoofguard-for-neutron',
            whitelist_ports=True, tags=tags)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps({
                'resource_type': profile_types.SPOOF_GUARD,
                'display_name': 'neutron-spoof',
                'description': 'spoofguard-for-neutron',
                'white_list_providers': ['LPORT_BINDINGS'],
                'tags': tags
            }, sort_keys=True))

    def test_create_dhcp_profile(self):

        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'tenant-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]

        mocked_resource = self._mocked_switching_profile()

        mocked_resource.create_dhcp_profile(
            'neutron-dhcp', 'dhcp-for-neutron',
            tags=tags)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps({
                'bpdu_filter': {
                    'enabled': True,
                    'white_list': []
                },
                'resource_type': profile_types.SWITCH_SECURITY,
                'display_name': 'neutron-dhcp',
                'description': 'dhcp-for-neutron',
                'tags': tags,
                'dhcp_filter': {
                    'client_block_enabled': True,
                    'server_block_enabled': False
                },
                'rate_limits': {
                    'enabled': False,
                    'rx_broadcast': 0,
                    'tx_broadcast': 0,
                    'rx_multicast': 0,
                    'tx_multicast': 0
                },
                'block_non_ip_traffic': True
            }, sort_keys=True))

    def test_create_mac_learning_profile(self):

        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'tenant-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]

        mocked_resource = self._mocked_switching_profile()

        mocked_resource.create_mac_learning_profile(
            'neutron-mac-learning', 'mac-learning-for-neutron',
            tags=tags)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps({
                'mac_learning': {
                    'enabled': True,
                },
                'resource_type': profile_types.MAC_LEARNING,
                'display_name': 'neutron-mac-learning',
                'description': 'mac-learning-for-neutron',
                'tags': tags,
                'mac_change_allowed': True,
            }, sort_keys=True))

    def test_find_by_display_name(self):
        resp_resources = {
            'results': [
                {'display_name': 'resource-1'},
                {'display_name': 'resource-2'},
                {'display_name': 'resource-3'}
            ]
        }
        session_response = mocks.MockRequestsResponse(
            200, jsonutils.dumps(resp_resources))
        mocked_resource = self._mocked_switching_profile(
            session_response=session_response)

        self.assertEqual([{'display_name': 'resource-1'}],
                         mocked_resource.find_by_display_name('resource-1'))
        self.assertEqual([{'display_name': 'resource-2'}],
                         mocked_resource.find_by_display_name('resource-2'))
        self.assertEqual([{'display_name': 'resource-3'}],
                         mocked_resource.find_by_display_name('resource-3'))

        resp_resources = {
            'results': [
                {'display_name': 'resource-1'},
                {'display_name': 'resource-1'},
                {'display_name': 'resource-1'}
            ]
        }
        session_response = mocks.MockRequestsResponse(
            200, jsonutils.dumps(resp_resources))
        mocked_resource = self._mocked_switching_profile(
            session_response=session_response)
        self.assertEqual(resp_resources['results'],
                         mocked_resource.find_by_display_name('resource-1'))

    def test_list_all_profiles(self):
        mocked_resource = self._mocked_switching_profile()
        mocked_resource.list()
        test_client.assert_json_call(
            'get', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles/'
            '?include_system_owned=True',
            data=None)


class LogicalPortTestCase(nsxlib_testcase.NsxClientTestCase):

    def _mocked_lport(self, session_response=None):
        return self.mocked_resource(
            resources.LogicalPort, session_response=session_response)

    def _get_profile_dicts(self, fake_port):
        fake_profile_dicts = []
        for profile_id in fake_port['switching_profile_ids']:
            fake_profile_dicts.append({'resource_type': profile_id['key'],
                                       'id': profile_id['value']})
        return fake_profile_dicts

    def _get_pktcls_bindings(self):
        fake_pkt_classifiers = []
        fake_binding_repr = []
        for i in range(0, 3):
            ip = "9.10.11.%s" % i
            mac = "00:0c:29:35:4a:%sc" % i
            fake_pkt_classifiers.append(resources.PacketAddressClassifier(
                ip, mac, None))
            fake_binding_repr.append({
                'ip_address': ip,
                'mac_address': mac
            })
        return fake_pkt_classifiers, fake_binding_repr

    def test_create_logical_port(self):
        """
        Test creating a port returns the correct response and 200 status
        """
        fake_port = test_constants_v3.FAKE_PORT.copy()

        profile_dicts = self._get_profile_dicts(fake_port)

        pkt_classifiers, binding_repr = self._get_pktcls_bindings()

        fake_port['address_bindings'] = binding_repr

        mocked_resource = self._mocked_lport()

        switch_profile = resources.SwitchingProfile
        mocked_resource.create(
            fake_port['logical_switch_id'],
            fake_port['attachment']['id'],
            address_bindings=pkt_classifiers,
            switch_profile_ids=switch_profile.build_switch_profile_ids(
                mock.Mock(), *profile_dicts))

        resp_body = {
            'logical_switch_id': fake_port['logical_switch_id'],
            'switching_profile_ids': fake_port['switching_profile_ids'],
            'attachment': {
                'attachment_type': 'VIF',
                'id': fake_port['attachment']['id']
            },
            'admin_state': 'UP',
            'address_bindings': fake_port['address_bindings']
        }

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/logical-ports',
            data=jsonutils.dumps(resp_body, sort_keys=True))

    def test_create_logical_port_with_attachtype_cif(self):
        """
        Test creating a port returns the correct response and 200 status
        """
        fake_port = test_constants_v3.FAKE_CONTAINER_PORT.copy()

        profile_dicts = self._get_profile_dicts(fake_port)

        pkt_classifiers, binding_repr = self._get_pktcls_bindings()

        fake_port['address_bindings'] = binding_repr

        mocked_resource = self._mocked_lport()
        switch_profile = resources.SwitchingProfile
        fake_port_ctx = fake_port['attachment']['context']

        fake_container_host_vif_id = fake_port_ctx['container_host_vif_id']

        mocked_resource.create(
            fake_port['logical_switch_id'],
            fake_port['attachment']['id'],
            parent_vif_id=fake_container_host_vif_id,
            parent_tag=fake_port_ctx['vlan_tag'],
            address_bindings=pkt_classifiers,
            switch_profile_ids=switch_profile.build_switch_profile_ids(
                mock.Mock(), *profile_dicts))

        resp_body = {
            'logical_switch_id': fake_port['logical_switch_id'],
            'switching_profile_ids': fake_port['switching_profile_ids'],
            'attachment': {
                'attachment_type': 'CIF',
                'id': fake_port['attachment']['id'],
                'context': {
                    'vlan_tag': fake_port_ctx['vlan_tag'],
                    'container_host_vif_id': fake_container_host_vif_id,
                    'resource_type': 'CifAttachmentContext'
                }
            },
            'admin_state': 'UP',
            'address_bindings': fake_port['address_bindings']
        }

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/logical-ports',
            data=jsonutils.dumps(resp_body, sort_keys=True))

    def test_create_logical_port_admin_down(self):
        """
        Test creating port with admin_state down
        """
        fake_port = test_constants_v3.FAKE_PORT
        fake_port['admin_state'] = "DOWN"

        mocked_resource = self._mocked_lport(
            session_response=mocks.MockRequestsResponse(
                200, jsonutils.dumps(fake_port)))

        result = mocked_resource.create(
            test_constants_v3.FAKE_PORT['logical_switch_id'],
            test_constants_v3.FAKE_PORT['attachment']['id'],
            tags={}, admin_state=False)

        self.assertEqual(fake_port, result)

    def test_delete_logical_port(self):
        """
        Test deleting port
        """
        mocked_resource = self._mocked_lport()

        uuid = test_constants_v3.FAKE_PORT['id']
        mocked_resource.delete(uuid)
        test_client.assert_json_call(
            'delete', mocked_resource,
            'https://1.2.3.4/api/v1/logical-ports/%s?detach=true' % uuid)

    def test_clear_port_bindings(self):
        fake_port = copy.copy(test_constants_v3.FAKE_PORT)
        fake_port['address_bindings'] = ['a', 'b']
        mocked_resource = self._mocked_lport()

        def get_fake_port(*args):
            return fake_port

        mocked_resource.get = get_fake_port
        mocked_resource.update(
                fake_port['id'], fake_port['id'], address_bindings=[])

        fake_port['address_bindings'] = []
        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/logical-ports/%s' % fake_port['id'],
            data=jsonutils.dumps(fake_port, sort_keys=True))


class LogicalRouterTestCase(nsxlib_testcase.NsxClientTestCase):

    def _mocked_lrouter(self, session_response=None):
        return self.mocked_resource(
            resources.LogicalRouter, session_response=session_response)

    def test_create_logical_router(self):
        """
        Test creating a router returns the correct response and 201 status
        """
        fake_router = test_constants_v3.FAKE_ROUTER.copy()

        router = self._mocked_lrouter()

        tier0_router = True
        router.create(fake_router['display_name'], None, None, tier0_router)

        data = {
            'display_name': fake_router['display_name'],
            'router_type': 'TIER0' if tier0_router else 'TIER1',
            'tags': None
        }

        test_client.assert_json_call(
            'post', router,
            'https://1.2.3.4/api/v1/logical-routers',
            data=jsonutils.dumps(data, sort_keys=True))

    def test_delete_logical_router(self):
        """
        Test deleting router
        """
        router = self._mocked_lrouter()
        uuid = test_constants_v3.FAKE_ROUTER['id']
        router.delete(uuid)
        test_client.assert_json_call(
            'delete', router,
            'https://1.2.3.4/api/v1/logical-routers/%s' % uuid)


class LogicalRouterPortTestCase(nsxlib_testcase.NsxClientTestCase):

    def _mocked_lrport(self, session_response=None):
        return self.mocked_resource(
            resources.LogicalRouterPort, session_response=session_response)

    def test_create_logical_router_port(self):
        """
        Test creating a router port returns the correct response and 201 status
        """
        fake_router_port = test_constants_v3.FAKE_ROUTER_PORT.copy()

        lrport = self._mocked_lrport()

        lrport.create(fake_router_port['logical_router_id'],
                      fake_router_port['display_name'],
                      None,
                      fake_router_port['resource_type'],
                      None, None, None)

        data = {
            'display_name': fake_router_port['display_name'],
            'logical_router_id': fake_router_port['logical_router_id'],
            'resource_type': fake_router_port['resource_type'],
            'tags': []
        }

        test_client.assert_json_call(
            'post', lrport,
            'https://1.2.3.4/api/v1/logical-router-ports',
            data=jsonutils.dumps(data, sort_keys=True))

    def test_delete_logical_router_port(self):
        """
        Test deleting router port
        """
        lrport = self._mocked_lrport()

        uuid = test_constants_v3.FAKE_ROUTER_PORT['id']
        lrport.delete(uuid)
        test_client.assert_json_call(
            'delete', lrport,
            'https://1.2.3.4/api/v1/logical-router-ports/%s' % uuid)

    def test_get_logical_router_port_by_router_id(self):
        """
        Test getting a router port by router id
        """
        fake_router_port = test_constants_v3.FAKE_ROUTER_PORT.copy()
        resp_resources = {'results': [fake_router_port]}

        lrport = self._mocked_lrport(
            session_response=mocks.MockRequestsResponse(
                200, jsonutils.dumps(resp_resources)))

        router_id = fake_router_port['logical_router_id']
        result = lrport.get_by_router_id(router_id)
        self.assertEqual(fake_router_port, result[0])
        test_client.assert_json_call(
            'get', lrport,
            'https://1.2.3.4/api/v1/logical-router-ports/?'
            'logical_router_id=%s' % router_id)

    def test_get_logical_router_port_by_switch_id(self):
        """
        Test getting a router port by switch id
        """
        fake_router_port = test_constants_v3.FAKE_ROUTER_PORT.copy()
        resp_resources = {
            'result_count': 1,
            'results': [fake_router_port]
        }

        lrport = self._mocked_lrport(
            session_response=mocks.MockRequestsResponse(
                200, jsonutils.dumps(resp_resources)))

        switch_id = test_constants_v3.FAKE_SWITCH_UUID
        lrport.get_by_lswitch_id(switch_id)
        test_client.assert_json_call(
            'get', lrport,
            'https://1.2.3.4/api/v1/logical-router-ports/?'
            'logical_switch_id=%s' % switch_id)
