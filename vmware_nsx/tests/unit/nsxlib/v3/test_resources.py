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
from vmware_nsx.tests.unit.nsxlib.v3 import test_client


CLIENT_PKG = test_client.CLIENT_PKG
profile_types = resources.SwitchingProfileTypes


class TestSwitchingProfileTestCase(test_client.BaseClientTestCase):

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.post'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_switching_profile_create(self, mock_validate, mock_post):
        api = resources.SwitchingProfile(client.NSX3Client())
        api.create(profile_types.PORT_MIRRORING,
                   'pm-profile', 'port mirror prof')

        test_client.assert_session_call(
            mock_post,
            'https://1.2.3.4/api/v1/switching-profiles',
            False, jsonutils.dumps({
                'resource_type': profile_types.PORT_MIRRORING,
                'display_name': 'pm-profile',
                'description': 'port mirror prof'
            }),
            client.JSONRESTClient._DEFAULT_HEADERS,
            test_client.BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.put'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_switching_profile_update(self, mock_validate, mock_put):

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
        api.update('a12bc1', profile_types.PORT_MIRRORING, tags=tags)

        test_client.assert_session_call(
            mock_put,
            'https://1.2.3.4/api/v1/switching-profiles/a12bc1',
            False, jsonutils.dumps({
                'resource_type': profile_types.PORT_MIRRORING,
                'tags': tags
            }),
            client.JSONRESTClient._DEFAULT_HEADERS,
            test_client.BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.post'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_spoofgaurd_profile_create(self, mock_validate, mock_post):

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
        api.create_spoofguard_profile(
            'neutron-spoof', 'spoofguard-for-neutron',
            whitelist_ports=True, tags=tags)

        test_client.assert_session_call(
            mock_post,
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
            test_client.BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.get'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_find_by_display_name(self, mock_validate, mock_get):
        resp_resources = {
            'results': [
                {'display_name': 'resource-1'},
                {'display_name': 'resource-2'},
                {'display_name': 'resource-3'}
            ]
        }
        mock_get.return_value = mocks.MockRequestsResponse(
            200, jsonutils.dumps(resp_resources))
        api = resources.SwitchingProfile(client.NSX3Client())
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
        api = resources.SwitchingProfile(client.NSX3Client())
        self.assertEqual(resp_resources['results'],
                         api.find_by_display_name('resource-1'))


class LogicalPortTestCase(test_client.BaseClientTestCase):

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.post'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_create_logical_port(self, mock_validate, mock_post):
        """
        Test creating a port returns the correct response and 200 status
        """
        fake_port = test_constants_v3.FAKE_PORT
        mock_post.return_value = mocks.MockRequestsResponse(
            200, jsonutils.dumps(fake_port))

        profile_client = resources.SwitchingProfile(client.NSX3Client())
        profile_dicts = []
        for profile_id in fake_port['switching_profile_ids']:
            profile_dicts.append({'resource_type': profile_id['key'],
                                  'id': profile_id['value']})

        # Reload resources because resources.LogicalPort.create is overridden
        # by tests/unit/nsx_v3/test_plugin.py. This is only needed when running
        # tox on multiple tests.
        reload(resources)
        result = resources.LogicalPort(client.NSX3Client()).create(
            fake_port['logical_switch_id'],
            fake_port['attachment']['id'],
            switch_profile_ids=profile_client.build_switch_profile_ids(
                *profile_dicts))

        resp_body = {
            'logical_switch_id': fake_port['logical_switch_id'],
            'attachment': {
                'attachment_type': 'VIF',
                'id': fake_port['attachment']['id']
            },
            'admin_state': 'UP',
            'switching_profile_ids': fake_port['switching_profile_ids']
        }

        self.assertEqual(fake_port, result)
        self.assertEqual(fake_port['switching_profile_ids'],
                         resp_body['switching_profile_ids'])
        test_client.assert_session_call(
            mock_post,
            'https://1.2.3.4/api/v1/logical-ports',
            False,
            jsonutils.dumps(resp_body),
            client.JSONRESTClient._DEFAULT_HEADERS,
            test_client.BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.post'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_create_logical_port_admin_down(self, mock_validate, mock_post):
        """
        Test creating port with admin_state down
        """
        fake_port = test_constants_v3.FAKE_PORT
        fake_port['admin_state'] = "DOWN"
        mock_post.return_value = mocks.MockRequestsResponse(
            200, jsonutils.dumps(fake_port))

        # Reload resources because resources.LogicalPort.create is overridden
        # by tests/unit/nsx_v3/test_plugin.py. This is only needed when running
        # tox on multiple tests.
        reload(resources)
        result = resources.LogicalPort(client.NSX3Client()).create(
            test_constants_v3.FAKE_PORT['logical_switch_id'],
            test_constants_v3.FAKE_PORT['attachment']['id'],
            tags={}, admin_state=False)

        self.assertEqual(fake_port, result)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.delete'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_delete_logical_port(self, mock_validate, mock_delete):
        """
        Test deleting port
        """
        mock_delete.return_value = mocks.MockRequestsResponse(
            200, None)

        uuid = test_constants_v3.FAKE_PORT['id']
        # Reload resources because resources.LogicalPort.delete is overridden
        # by tests/unit/nsx_v3/test_plugin.py. This is only needed when running
        # tox on multiple tests.
        reload(resources)
        result = resources.LogicalPort(client.NSX3Client()).delete(uuid)
        self.assertIsNone(result.content)
        test_client.assert_session_call(
            mock_delete,
            'https://1.2.3.4/api/v1/logical-ports/%s?detach=true' % uuid,
            False,
            None,
            client.JSONRESTClient._DEFAULT_HEADERS,
            test_client.BaseClientTestCase.ca_file)
