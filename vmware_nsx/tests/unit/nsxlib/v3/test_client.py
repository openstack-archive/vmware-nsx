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
from oslo_log import log
from oslo_serialization import jsonutils

from vmware_nsx.common import exceptions as exep
from vmware_nsx.nsxlib.v3 import client
from vmware_nsx.tests.unit.nsx_v3 import mocks
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase


LOG = log.getLogger(__name__)

CLIENT_PKG = 'vmware_nsx.nsxlib.v3.client'


def assert_session_call(mock_call, url, verify, data, headers, cert):
    mock_call.assert_called_once_with(
        url, verify=verify, data=data, headers=headers, cert=cert)


class NsxV3RESTClientTestCase(nsxlib_testcase.NsxClientTestCase):

    def test_client_conf_init(self):
        api = self.new_client(client.RESTClient)
        self.assertEqual((
            nsxlib_testcase.NSX_USER, nsxlib_testcase.NSX_PASSWORD),
            api._session.auth)
        self.assertEqual(nsxlib_testcase.NSX_MANAGER, api._host_ip)
        self.assertEqual(nsxlib_testcase.NSX_CERT, api._cert_file)

    def test_client_params_init(self):
        api = self.new_client(
            client.RESTClient, host_ip='11.12.13.14', password='mypass')
        self.assertEqual((
            nsxlib_testcase.NSX_USER, 'mypass'),
            api._session.auth)
        self.assertEqual('11.12.13.14', api._host_ip)
        self.assertEqual(nsxlib_testcase.NSX_CERT, api._cert_file)

    def test_client_url_prefix(self):
        api = self.new_client(client.RESTClient, url_prefix='/cloud/api')
        with self.mocked_client(api) as mocked:
            mock_get = mocked.get('get')
            mock_get.return_value = {}
            api.list()

            assert_session_call(
                mocked.get('get'),
                'https://1.2.3.4/cloud/api',
                False, None, {}, nsxlib_testcase.NSX_CERT)

            mock_get.reset_mock()

            api.url_list('v1/ports')
            assert_session_call(
                mock_get,
                'https://1.2.3.4/cloud/api/v1/ports', False, None, {},
                nsxlib_testcase.NSX_CERT)

    def test_client_headers(self):
        default_headers = {'Content-Type': 'application/golang'}
        api = self.new_client(
            client.RESTClient, default_headers=default_headers,
            url_prefix='/v1/api')

        with self.mocked_client(api) as mocked:
            mock_get = mocked.get('get')

            mock_get.return_value = {}

            api.list()

            assert_session_call(
                mock_get,
                'https://1.2.3.4/v1/api',
                False, None, default_headers, nsxlib_testcase.NSX_CERT)

            mock_get.reset_mock()

            method_headers = {'X-API-Key': 'strong-crypt'}
            api.url_list('ports/33', headers=method_headers)
            method_headers.update(default_headers)
            assert_session_call(
                mock_get,
                'https://1.2.3.4/v1/api/ports/33', False, None,
                method_headers,
                nsxlib_testcase.NSX_CERT)

    def test_client_for(self):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/')
        sub_api = api.new_client_for('switch/ports')

        with self.mocked_client(sub_api) as mocked:
            sub_api.get('11a2b')

            assert_session_call(
                mocked.get('get'),
                'https://1.2.3.4/api/v1/switch/ports/11a2b',
                False, None, {}, nsxlib_testcase.NSX_CERT)

    def test_client_list(self):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        with self.mocked_client(api) as mocked:
            api.list()

            assert_session_call(
                mocked.get('get'),
                'https://1.2.3.4/api/v1/ports',
                False, None, {}, nsxlib_testcase.NSX_CERT)

    def test_client_get(self):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        with self.mocked_client(api) as mocked:
            api.get('unique-id')

            assert_session_call(
                mocked.get('get'),
                'https://1.2.3.4/api/v1/ports/unique-id',
                False, None, {}, nsxlib_testcase.NSX_CERT)

    def test_client_delete(self):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        with self.mocked_client(api) as mocked:
            api.delete('unique-id')

            assert_session_call(
                mocked.get('delete'),
                'https://1.2.3.4/api/v1/ports/unique-id',
                False, None, {}, nsxlib_testcase.NSX_CERT)

    def test_client_update(self):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        with self.mocked_client(api) as mocked:
            api.update('unique-id', {'name': 'a-new-name'})

            assert_session_call(
                mocked.get('put'),
                'https://1.2.3.4/api/v1/ports/unique-id',
                False, {'name': 'a-new-name'},
                {}, nsxlib_testcase.NSX_CERT)

    def test_client_create(self):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        with self.mocked_client(api) as mocked:
            api.create({'resource-name': 'port1'})

            assert_session_call(
                mocked.get('post'),
                'https://1.2.3.4/api/v1/ports',
                False, {'resource-name': 'port1'},
                {}, nsxlib_testcase.NSX_CERT)

    def test_client_url_list(self):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        with self.mocked_client(api) as mocked:
            api.url_list('/connections', {'Content-Type': 'application/json'})

            assert_session_call(
                mocked.get('get'),
                'https://1.2.3.4/api/v1/ports/connections',
                False, None,
                {'Content-Type': 'application/json'},
                nsxlib_testcase.NSX_CERT)

    def test_client_url_get(self):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        with self.mocked_client(api) as mocked:
            api.url_get('connections/1')

            assert_session_call(
                mocked.get('get'),
                'https://1.2.3.4/api/v1/ports/connections/1',
                False, None, {}, nsxlib_testcase.NSX_CERT)

    def test_client_url_delete(self):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        with self.mocked_client(api) as mocked:
            api.url_delete('1')

            assert_session_call(
                mocked.get('delete'),
                'https://1.2.3.4/api/v1/ports/1',
                False, None, {}, nsxlib_testcase.NSX_CERT)

    def test_client_url_put(self):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        with self.mocked_client(api) as mocked:
            api.url_put('connections/1', {'name': 'conn1'})

            assert_session_call(
                mocked.get('put'),
                'https://1.2.3.4/api/v1/ports/connections/1',
                False, {'name': 'conn1'},
                {}, nsxlib_testcase.NSX_CERT)

    def test_client_url_post(self):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        with self.mocked_client(api) as mocked:
            api.url_post('1/connections', {'name': 'conn1'})

            assert_session_call(
                mocked.get('post'),
                'https://1.2.3.4/api/v1/ports/1/connections',
                False, {'name': 'conn1'},
                {}, nsxlib_testcase.NSX_CERT)

    def test_client_validate_result(self):

        api = self.new_client(client.RESTClient)
        with self.mocked_client(api, mock_validate=False) as mocked:
            def _verb_response_code(http_verb, status_code):
                response = mocks.MockRequestsResponse(
                    status_code, None)
                for _verb in ['get', 'post', 'put', 'delete']:
                    mocked.get(_verb).return_value = response
                client_call = getattr(api, "url_%s" % http_verb)
                client_call('', None)

            for verb in ['get', 'post', 'put', 'delete']:
                for code in client.RESTClient._VERB_RESP_CODES.get(
                        verb):
                    _verb_response_code(verb, code)
                self.assertRaises(
                    exep.ManagerError,
                    _verb_response_code, verb, 500)


class NsxV3JSONClientTestCase(nsxlib_testcase.NsxClientTestCase):

    def test_json_request(self):
        api = self.new_client(client.JSONRESTClient, url_prefix='api/v2/nat')
        with self.mocked_client(api) as mocked:
            mock_post = mocked.get('post')
            mock_post.return_value = mocks.MockRequestsResponse(
                200, jsonutils.dumps({'result': {'ok': 200}}))

            resp = api.create(body={'name': 'mgmt-egress'})

            assert_session_call(
                mock_post,
                'https://1.2.3.4/api/v2/nat',
                False, jsonutils.dumps({'name': 'mgmt-egress'}),
                client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)

            self.assertEqual(resp, {'result': {'ok': 200}})


class NsxV3APIClientTestCase(nsxlib_testcase.NsxClientTestCase):

    def test_api_call(self):
        api = self.new_client(client.NSX3Client)
        with self.mocked_client(api) as mocked:
            api.get('ports')

            assert_session_call(
                mocked.get('get'),
                'https://1.2.3.4/api/v1/ports',
                False, None,
                client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)


# NOTE(boden): remove this when tmp brigding removed
class NsxV3APIClientBridgeTestCase(nsxlib_testcase.NsxClientTestCase):

    def test_get_resource(self):
        api = self.new_client(client.NSX3Client)
        with self.mocked_client(api) as mocked:
            client.get_resource('ports', client=api)

            assert_session_call(
                mocked.get('get'),
                'https://1.2.3.4/api/v1/ports',
                False, None,
                client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)

    def test_create_resource(self):
        api = self.new_client(client.NSX3Client)
        with self.mocked_client(api) as mocked:
            client.create_resource(
                'ports', {'resource-name': 'port1'},
                client=api)

            assert_session_call(
                mocked.get('post'),
                'https://1.2.3.4/api/v1/ports',
                False, jsonutils.dumps({'resource-name': 'port1'}),
                client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)

    def test_update_resource(self):
        api = self.new_client(client.NSX3Client)
        with self.mocked_client(api) as mocked:
            client.update_resource(
                'ports/1', {'name': 'a-new-name'}, client=api)

            assert_session_call(
                mocked.get('put'),
                'https://1.2.3.4/api/v1/ports/1',
                False, jsonutils.dumps({'name': 'a-new-name'}),
                client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)

    def test_delete_resource(self):
        api = self.new_client(client.NSX3Client)
        with self.mocked_client(api) as mocked:
            client.delete_resource('ports/11', client=api)

            assert_session_call(
                mocked.get('delete'),
                'https://1.2.3.4/api/v1/ports/11',
                False, None, client.JSONRESTClient._DEFAULT_HEADERS,
                nsxlib_testcase.NSX_CERT)
