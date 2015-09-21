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
import vmware_nsx.tests.unit.vmware.nsx_v3_mocks as mocks

from oslo_serialization import jsonutils
from vmware_nsx.nsxlib.v3 import client
from vmware_nsx.nsxlib.v3 import resources
from vmware_nsx.tests.unit.vmware.nsxlib.v3 import test_client


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
