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
import mock

from oslo_serialization import jsonutils

from vmware_nsx.nsxlib.v3 import client
from vmware_nsx.nsxlib.v3 import resources
from vmware_nsx.tests.unit.nsx_v3 import mocks
from vmware_nsx.tests.unit.nsx_v3 import test_constants as test_constants_v3
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase
from vmware_nsx.tests.unit.nsxlib.v3 import test_client


CLIENT_PKG = test_client.CLIENT_PKG
profile_types = resources.SwitchingProfileTypes


class TestSwitchingProfileTestCase(nsxlib_testcase.NsxClientTestCase):

    def test_switching_profile_create(self):
        api = resources.SwitchingProfile(client.NSX3Client())
        with self.mocked_resource(api) as mocked:
            api.create(profile_types.PORT_MIRRORING,
                       'pm-profile', 'port mirror prof')

            test_client.assert_session_call(
                mocked.get('post'),
                'https://1.2.3.4/api/v1/switching-profiles',
                False, jsonutils.dumps({
                    'resource_type': profile_types.PORT_MIRRORING,
                    'display_name': 'pm-profile',
                    'description': 'port mirror prof'
                }),
                client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)

    def test_switching_profile_update(self):

        tags = [
            {
                'scope': 'os-tid',
                'tag': 'tenant-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]

        api = resources.SwitchingProfile(client.NSX3Client())
        with self.mocked_resource(api) as mocked:
            api.update('a12bc1', profile_types.PORT_MIRRORING, tags=tags)

            test_client.assert_session_call(
                mocked.get('put'),
                'https://1.2.3.4/api/v1/switching-profiles/a12bc1',
                False, jsonutils.dumps({
                    'resource_type': profile_types.PORT_MIRRORING,
                    'tags': tags
                }),
                client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)

    def test_spoofgaurd_profile_create(self):

        tags = [
            {
                'scope': 'os-tid',
                'tag': 'tenant-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]

        api = resources.SwitchingProfile(client.NSX3Client())
        with self.mocked_resource(api) as mocked:
            api.create_spoofguard_profile(
                'neutron-spoof', 'spoofguard-for-neutron',
                whitelist_ports=True, tags=tags)

            test_client.assert_session_call(
                mocked.get('post'),
                'https://1.2.3.4/api/v1/switching-profiles',
                False,
                jsonutils.dumps({
                    'resource_type': profile_types.SPOOF_GUARD,
                    'display_name': 'neutron-spoof',
                    'description': 'spoofguard-for-neutron',
                    'white_list_providers': ['LPORT_BINDINGS'],
                    'tags': tags
                }),
                client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)

    def test_find_by_display_name(self):
        resp_resources = {
            'results': [
                {'display_name': 'resource-1'},
                {'display_name': 'resource-2'},
                {'display_name': 'resource-3'}
            ]
        }
        api = resources.SwitchingProfile(client.NSX3Client())
        with self.mocked_resource(api) as mocked:
            mock_get = mocked.get('get')
            mock_get.return_value = mocks.MockRequestsResponse(
                200, jsonutils.dumps(resp_resources))
            self.assertEqual([{'display_name': 'resource-1'}],
                             api.find_by_display_name('resource-1'))
            self.assertEqual([{'display_name': 'resource-2'}],
                             api.find_by_display_name('resource-2'))
            self.assertEqual([{'display_name': 'resource-3'}],
                             api.find_by_display_name('resource-3'))

            mock_get.reset_mock()

            resp_resources = {
                'results': [
                    {'display_name': 'resource-1'},
                    {'display_name': 'resource-1'},
                    {'display_name': 'resource-1'}
                ]
            }
            mock_get.return_value = mocks.MockRequestsResponse(
                200, jsonutils.dumps(resp_resources))
            self.assertEqual(resp_resources['results'],
                             api.find_by_display_name('resource-1'))


class LogicalPortTestCase(nsxlib_testcase.NsxClientTestCase):

    def test_create_logical_port(self):
        """
        Test creating a port returns the correct response and 200 status
        """
        fake_port = test_constants_v3.FAKE_PORT.copy()

        profile_dicts = []
        for profile_id in fake_port['switching_profile_ids']:
            profile_dicts.append({'resource_type': profile_id['key'],
                                  'id': profile_id['value']})

        pkt_classifiers = []
        binding_repr = []
        for i in range(0, 3):
            ip = "9.10.11.%s" % i
            mac = "00:0c:29:35:4a:%sc" % i
            pkt_classifiers.append(resources.PacketAddressClassifier(
                ip, mac, None))
            binding_repr.append({
                'ip_address': ip,
                'mac_address': mac
            })

        fake_port['address_bindings'] = binding_repr

        api = resources.LogicalPort(client.NSX3Client())
        with self.mocked_resource(api) as mocked:

            mocked.get('post').return_value = mocks.MockRequestsResponse(
                200, jsonutils.dumps(fake_port))

            switch_profile = resources.SwitchingProfile
            result = api.create(
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

            self.assertEqual(fake_port, result)
            test_client.assert_session_call(
                mocked.get('post'),
                'https://1.2.3.4/api/v1/logical-ports',
                False,
                jsonutils.dumps(resp_body),
                client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)

    def test_create_logical_port_admin_down(self):
        """
        Test creating port with admin_state down
        """
        fake_port = test_constants_v3.FAKE_PORT
        fake_port['admin_state'] = "DOWN"
        api = resources.LogicalPort(client.NSX3Client())
        with self.mocked_resource(api) as mocked:
            mocked.get('post').return_value = mocks.MockRequestsResponse(
                200, jsonutils.dumps(fake_port))

            result = api.create(
                test_constants_v3.FAKE_PORT['logical_switch_id'],
                test_constants_v3.FAKE_PORT['attachment']['id'],
                tags={}, admin_state=False)

            self.assertEqual(fake_port, result)

    def test_delete_logical_port(self):
        """
        Test deleting port
        """
        api = resources.LogicalPort(client.NSX3Client())
        with self.mocked_resource(api) as mocked:
            mocked.get('delete').return_value = mocks.MockRequestsResponse(
                200, None)

            uuid = test_constants_v3.FAKE_PORT['id']
            result = api.delete(uuid)
            self.assertIsNone(result.content)
            test_client.assert_session_call(
                mocked.get('delete'),
                'https://1.2.3.4/api/v1/logical-ports/%s?detach=true' % uuid,
                False,
                None,
                client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)


class LogicalRouterTestCase(nsxlib_testcase.NsxClientTestCase):

    def test_create_logical_router(self):
        """
        Test creating a router returns the correct response and 201 status
        """
        fake_router = test_constants_v3.FAKE_ROUTER.copy()

        api = resources.LogicalRouter(client.NSX3Client())
        with self.mocked_resource(api) as mocked:
            mocked.get('post').return_value = mocks.MockRequestsResponse(
                201, jsonutils.dumps(fake_router))

            tier0_router = True
            result = api.create(fake_router['display_name'], None, None,
                                tier0_router)

            data = {
                'display_name': fake_router['display_name'],
                'router_type': 'TIER0' if tier0_router else 'TIER1',
                'tags': None
            }

            self.assertEqual(fake_router, result)
            test_client.assert_session_call(
                mocked.get('post'),
                'https://1.2.3.4/api/v1/logical-routers',
                False,
                jsonutils.dumps(data),
                client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)

    def test_delete_logical_router(self):
        """
        Test deleting router
        """
        api = resources.LogicalRouter(client.NSX3Client())
        with self.mocked_resource(api) as mocked:
            mocked.get('delete').return_value = mocks.MockRequestsResponse(
                200, None)

            uuid = test_constants_v3.FAKE_ROUTER['id']
            result = api.delete(uuid)
            self.assertIsNone(result.content)
            test_client.assert_session_call(
                mocked.get('delete'),
                'https://1.2.3.4/api/v1/logical-routers/%s' % uuid,
                False,
                None,
                client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)


class LogicalRouterPortTestCase(nsxlib_testcase.NsxClientTestCase):

    def test_create_logical_router_port(self):
        """
        Test creating a router returns the correct response and 201 status
        """
        fake_router_port = test_constants_v3.FAKE_ROUTER_PORT.copy()

        api = resources.LogicalRouterPort(client.NSX3Client())
        with self.mocked_resource(api) as mocked:
            mocked.get('post').return_value = mocks.MockRequestsResponse(
                201, jsonutils.dumps(fake_router_port))

            result = api.create(fake_router_port['logical_router_id'],
                                fake_router_port['display_name'],
                                fake_router_port['resource_type'],
                                None, None, None)

            data = {
                'display_name': fake_router_port['display_name'],
                'logical_router_id': fake_router_port['logical_router_id'],
                'resource_type': fake_router_port['resource_type']
            }

            self.assertEqual(fake_router_port, result)
            test_client.assert_session_call(
                mocked.get('post'),
                'https://1.2.3.4/api/v1/logical-router-ports',
                False,
                jsonutils.dumps(data),
                client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)

    def test_delete_logical_router_port(self):
        """
        Test deleting router port
        """
        api = resources.LogicalRouterPort(client.NSX3Client())
        with self.mocked_resource(api) as mocked:
            mocked.get('delete').return_value = mocks.MockRequestsResponse(
                200, None)

            uuid = test_constants_v3.FAKE_ROUTER_PORT['id']
            result = api.delete(uuid)
            self.assertIsNone(result.content)
            test_client.assert_session_call(
                mocked.get('delete'),
                'https://1.2.3.4/api/v1/logical-router-ports/%s' % uuid,
                False,
                None,
                client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)
