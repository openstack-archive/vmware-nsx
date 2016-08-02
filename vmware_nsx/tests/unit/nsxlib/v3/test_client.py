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

from oslo_log import log
from oslo_serialization import jsonutils

from vmware_nsx.nsxlib.v3 import client
from vmware_nsx.nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsx.tests.unit.nsx_v3 import mocks
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase


LOG = log.getLogger(__name__)

CLIENT_PKG = 'vmware_nsx.nsxlib.v3.client'

DFT_ACCEPT_HEADERS = {
    'Accept': '*/*'
}


def _headers(**kwargs):
    headers = copy.copy(DFT_ACCEPT_HEADERS)
    headers.update(kwargs)
    return headers


def assert_call(verb, client_or_resource,
                url, verify=nsxlib_testcase.NSX_CERT,
                data=None, headers=DFT_ACCEPT_HEADERS,
                timeout=(nsxlib_testcase.NSX_HTTP_TIMEOUT,
                         nsxlib_testcase.NSX_HTTP_READ_TIMEOUT)):
    nsx_client = client_or_resource
    if getattr(nsx_client, '_client', None) is not None:
        nsx_client = nsx_client._client
    cluster = nsx_client._conn
    cluster.assert_called_once(
        verb,
        **{'url': url, 'verify': verify, 'body': data,
           'headers': headers, 'cert': None, 'timeout': timeout})


def assert_json_call(verb, client_or_resource, url,
                     verify=nsxlib_testcase.NSX_CERT,
                     data=None,
                     headers=client.JSONRESTClient._DEFAULT_HEADERS):
    return assert_call(verb, client_or_resource, url,
                       verify=verify, data=data,
                       headers=headers)


class NsxV3RESTClientTestCase(nsxlib_testcase.NsxClientTestCase):

    def test_client_url_prefix(self):
        api = self.new_mocked_client(client.RESTClient,
                                     url_prefix='/cloud/api')

        api.list()

        assert_call(
            'get', api,
            'https://1.2.3.4/cloud/api')

        api = self.new_mocked_client(client.RESTClient,
                                     url_prefix='/cloud/api')

        api.url_list('v1/ports')

        assert_call(
            'get', api,
            'https://1.2.3.4/cloud/api/v1/ports')

    def test_client_headers(self):
        default_headers = {'Content-Type': 'application/golang'}
        api = self.new_mocked_client(
            client.RESTClient, default_headers=default_headers,
            url_prefix='/v1/api')

        api.list()

        assert_call(
            'get', api,
            'https://1.2.3.4/v1/api',
            headers=_headers(**default_headers))

        api = self.new_mocked_client(
            client.RESTClient,
            default_headers=default_headers,
            url_prefix='/v1/api')

        method_headers = {'X-API-Key': 'strong-crypt'}
        api.url_list('ports/33', headers=method_headers)
        method_headers.update(default_headers)
        assert_call(
            'get', api,
            'https://1.2.3.4/v1/api/ports/33',
            headers=_headers(**method_headers))

    def test_client_for(self):
        api = self.new_mocked_client(client.RESTClient, url_prefix='api/v1/')
        sub_api = api.new_client_for('switch/ports')

        sub_api.get('11a2b')

        assert_call(
            'get', sub_api,
            'https://1.2.3.4/api/v1/switch/ports/11a2b')

    def test_client_list(self):
        api = self.new_mocked_client(client.RESTClient,
                                     url_prefix='api/v1/ports')
        api.list()

        assert_call(
            'get', api,
            'https://1.2.3.4/api/v1/ports')

    def test_client_get(self):
        api = self.new_mocked_client(client.RESTClient,
                                     url_prefix='api/v1/ports')
        api.get('unique-id')

        assert_call(
            'get', api,
            'https://1.2.3.4/api/v1/ports/unique-id')

    def test_client_delete(self):
        api = self.new_mocked_client(client.RESTClient,
                                     url_prefix='api/v1/ports')
        api.delete('unique-id')

        assert_call(
            'delete', api,
            'https://1.2.3.4/api/v1/ports/unique-id')

    def test_client_update(self):
        api = self.new_mocked_client(client.RESTClient,
                                     url_prefix='api/v1/ports')
        api.update('unique-id', jsonutils.dumps({'name': 'a-new-name'}))

        assert_call(
            'put', api,
            'https://1.2.3.4/api/v1/ports/unique-id',
            data=jsonutils.dumps({'name': 'a-new-name'}))

    def test_client_create(self):
        api = self.new_mocked_client(client.RESTClient,
                                     url_prefix='api/v1/ports')
        api.create(body=jsonutils.dumps({'resource-name': 'port1'}))

        assert_call(
            'post', api,
            'https://1.2.3.4/api/v1/ports',
            data=jsonutils.dumps({'resource-name': 'port1'}))

    def test_client_url_list(self):
        api = self.new_mocked_client(client.RESTClient,
                                     url_prefix='api/v1/ports')

        json_headers = {'Content-Type': 'application/json'}

        api.url_list('/connections', json_headers)

        assert_call(
            'get', api,
            'https://1.2.3.4/api/v1/ports/connections',
            headers=_headers(**json_headers))

    def test_client_url_get(self):
        api = self.new_mocked_client(client.RESTClient,
                                     url_prefix='api/v1/ports')
        api.url_get('connections/1')

        assert_call(
            'get', api,
            'https://1.2.3.4/api/v1/ports/connections/1')

    def test_client_url_delete(self):
        api = self.new_mocked_client(client.RESTClient,
                                     url_prefix='api/v1/ports')
        api.url_delete('1')

        assert_call(
            'delete', api,
            'https://1.2.3.4/api/v1/ports/1')

    def test_client_url_put(self):
        api = self.new_mocked_client(client.RESTClient,
                                     url_prefix='api/v1/ports')
        api.url_put('connections/1', jsonutils.dumps({'name': 'conn1'}))

        assert_call(
            'put', api,
            'https://1.2.3.4/api/v1/ports/connections/1',
            data=jsonutils.dumps({'name': 'conn1'}))

    def test_client_url_post(self):
        api = self.new_mocked_client(client.RESTClient,
                                     url_prefix='api/v1/ports')
        api.url_post('1/connections', jsonutils.dumps({'name': 'conn1'}))

        assert_call(
            'post', api,
            'https://1.2.3.4/api/v1/ports/1/connections',
            data=jsonutils.dumps({'name': 'conn1'}))

    def test_client_validate_result(self):

        def _verb_response_code(http_verb, status_code):
            response = mocks.MockRequestsResponse(
                status_code, None)

            client_api = self.new_mocked_client(
                client.RESTClient, mock_validate=False,
                session_response=response)

            client_call = getattr(client_api, "url_%s" % http_verb)
            client_call('', None)

        for verb in ['get', 'post', 'put', 'delete']:
            for code in client.RESTClient._VERB_RESP_CODES.get(verb):
                _verb_response_code(verb, code)
            self.assertRaises(
                nsxlib_exc.ManagerError,
                _verb_response_code, verb, 500)


class NsxV3JSONClientTestCase(nsxlib_testcase.NsxClientTestCase):

    def test_json_request(self):
        resp = mocks.MockRequestsResponse(
            200, jsonutils.dumps({'result': {'ok': 200}}))

        api = self.new_mocked_client(client.JSONRESTClient,
                                     session_response=resp,
                                     url_prefix='api/v2/nat')

        resp = api.create(body={'name': 'mgmt-egress'})

        assert_json_call(
            'post', api,
            'https://1.2.3.4/api/v2/nat',
            data=jsonutils.dumps({'name': 'mgmt-egress'}))

        self.assertEqual(resp, {'result': {'ok': 200}})


class NsxV3APIClientTestCase(nsxlib_testcase.NsxClientTestCase):

    def test_api_call(self):
        api = self.new_mocked_client(client.NSX3Client)
        api.get('ports')

        assert_json_call(
            'get', api,
            'https://1.2.3.4/api/v1/ports')


# NOTE(boden): remove this when tmp brigding removed
class NsxV3APIClientBridgeTestCase(nsxlib_testcase.NsxClientTestCase):

    def test_get_resource(self):
        api = self.new_mocked_client(client.NSX3Client)
        client.get_resource('ports', client=api)

        assert_json_call(
            'get', api,
            'https://1.2.3.4/api/v1/ports')

    def test_create_resource(self):
        api = self.new_mocked_client(client.NSX3Client)
        client.create_resource(
            'ports', {'resource-name': 'port1'},
            client=api)

        assert_json_call(
            'post', api,
            'https://1.2.3.4/api/v1/ports',
            data=jsonutils.dumps({'resource-name': 'port1'}))

    def test_update_resource(self):
        api = self.new_mocked_client(client.NSX3Client)
        client.update_resource(
            'ports/1', {'name': 'a-new-name'}, client=api)

        assert_json_call(
            'put', api,
            'https://1.2.3.4/api/v1/ports/1',
            data=jsonutils.dumps({'name': 'a-new-name'}))

    def test_delete_resource(self):
        api = self.new_mocked_client(client.NSX3Client)
        client.delete_resource('ports/11', client=api)

        assert_json_call(
            'delete', api,
            'https://1.2.3.4/api/v1/ports/11')
