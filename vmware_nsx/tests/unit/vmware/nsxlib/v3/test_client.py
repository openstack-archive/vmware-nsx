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

import vmware_nsx.common.exceptions as exep
import vmware_nsx.tests.unit.vmware.nsx_v3_mocks as mocks

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from vmware_nsx.nsxlib.v3 import client
from vmware_nsx.tests.unit.vmware.nsxlib.v3 import nsxlib_testcase

LOG = log.getLogger(__name__)

CLIENT_PKG = 'vmware_nsx.nsxlib.v3.client'


def assert_session_call(mock_call, url, verify, data, headers, cert):
    mock_call.assert_called_once_with(
        url, verify=verify, data=data, headers=headers, cert=cert)


class BaseClientTestCase(nsxlib_testcase.NsxLibTestCase):
    nsx_manager = '1.2.3.4'
    nsx_user = 'testuser'
    nsx_password = 'pass123'
    ca_file = '/path/to/ca.pem'
    insecure = True

    def setUp(self):
        cfg.CONF.set_override(
            'nsx_manager', BaseClientTestCase.nsx_manager, 'nsx_v3')
        cfg.CONF.set_override(
            'nsx_user', BaseClientTestCase.nsx_user, 'nsx_v3')
        cfg.CONF.set_override(
            'nsx_password', BaseClientTestCase.nsx_password, 'nsx_v3')
        cfg.CONF.set_override(
            'ca_file', BaseClientTestCase.ca_file, 'nsx_v3')
        cfg.CONF.set_override(
            'insecure', BaseClientTestCase.insecure, 'nsx_v3')
        super(BaseClientTestCase, self).setUp()

    def new_client(
            self, clazz, host_ip=nsx_manager,
            user_name=nsx_user, password=nsx_password,
            insecure=insecure, url_prefix=None,
            default_headers=None, cert_file=ca_file):

        return clazz(host_ip=host_ip, user_name=user_name,
                     password=password, insecure=insecure,
                     url_prefix=url_prefix, default_headers=default_headers,
                     cert_file=cert_file)


class NsxV3RESTClientTestCase(BaseClientTestCase):

    def test_client_conf_init(self):
        api = self.new_client(client.RESTClient)
        self.assertEqual((
            BaseClientTestCase.nsx_user, BaseClientTestCase.nsx_password),
            api._session.auth)
        self.assertEqual(BaseClientTestCase.nsx_manager, api._host_ip)
        self.assertEqual(BaseClientTestCase.ca_file, api._cert_file)

    def test_client_params_init(self):
        api = self.new_client(
            client.RESTClient, host_ip='11.12.13.14', password='mypass')
        self.assertEqual((
            BaseClientTestCase.nsx_user, 'mypass'),
            api._session.auth)
        self.assertEqual('11.12.13.14', api._host_ip)
        self.assertEqual(BaseClientTestCase.ca_file, api._cert_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.get'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_client_url_prefix(self, mock_validate, mock_get):
        mock_get.return_value = {}
        api = self.new_client(client.RESTClient, url_prefix='/cloud/api')
        api.list()

        assert_session_call(
            mock_get,
            'https://1.2.3.4/cloud/api',
            False, None, {}, BaseClientTestCase.ca_file)

        mock_get.reset_mock()

        api.url_list('v1/ports')
        assert_session_call(
            mock_get,
            'https://1.2.3.4/cloud/api/v1/ports', False, None, {},
            BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.get'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_client_headers(self, mock_validate, mock_get):
        default_headers = {'Content-Type': 'application/golang'}

        mock_get.return_value = {}
        api = self.new_client(
            client.RESTClient, default_headers=default_headers,
            url_prefix='/v1/api')
        api.list()

        assert_session_call(
            mock_get,
            'https://1.2.3.4/v1/api',
            False, None, default_headers, BaseClientTestCase.ca_file)

        mock_get.reset_mock()

        method_headers = {'X-API-Key': 'strong-crypt'}
        api.url_list('ports/33', headers=method_headers)
        method_headers.update(default_headers)
        assert_session_call(
            mock_get,
            'https://1.2.3.4/v1/api/ports/33', False, None,
            method_headers,
            BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.get'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_client_for(self, mock_validate, mock_get):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/')
        sub_api = api.new_client_for('switch/ports')
        sub_api.get('11a2b')

        assert_session_call(
            mock_get,
            'https://1.2.3.4/api/v1/switch/ports/11a2b',
            False, None, {}, BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.get'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_client_list(self, mock_validate, mock_get):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        api.list()

        assert_session_call(
            mock_get,
            'https://1.2.3.4/api/v1/ports',
            False, None, {}, BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.get'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_client_get(self, mock_validate, mock_get):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        api.get('unique-id')

        assert_session_call(
            mock_get,
            'https://1.2.3.4/api/v1/ports/unique-id',
            False, None, {}, BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.delete'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_client_delete(self, mock_validate, mock_delete):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        api.delete('unique-id')

        assert_session_call(
            mock_delete,
            'https://1.2.3.4/api/v1/ports/unique-id',
            False, None, {}, BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.put'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_client_update(self, mock_validate, mock_put):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        api.update('unique-id', {'name': 'a-new-name'})

        assert_session_call(
            mock_put,
            'https://1.2.3.4/api/v1/ports/unique-id',
            False, {'name': 'a-new-name'},
            {}, BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.post'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_client_create(self, mock_validate, mock_post):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        api.create({'resource-name': 'port1'})

        assert_session_call(
            mock_post,
            'https://1.2.3.4/api/v1/ports',
            False, {'resource-name': 'port1'},
            {}, BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.get'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_client_url_list(self, mock_validate, mock_get):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        api.url_list('/connections', {'Content-Type': 'application/json'})

        assert_session_call(
            mock_get,
            'https://1.2.3.4/api/v1/ports/connections',
            False, None,
            {'Content-Type': 'application/json'},
            BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.get'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_client_url_get(self, mock_validate, mock_get):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        api.url_get('connections/1')

        assert_session_call(
            mock_get,
            'https://1.2.3.4/api/v1/ports/connections/1',
            False, None, {}, BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.delete'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_client_url_delete(self, mock_validate, mock_delete):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        api.url_delete('1')

        assert_session_call(
            mock_delete,
            'https://1.2.3.4/api/v1/ports/1',
            False, None, {}, BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.put'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_client_url_put(self, mock_validate, mock_put):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        api.url_put('connections/1', {'name': 'conn1'})

        assert_session_call(
            mock_put,
            'https://1.2.3.4/api/v1/ports/connections/1',
            False, {'name': 'conn1'},
            {}, BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.post'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_client_url_post(self, mock_validate, mock_post):
        api = self.new_client(client.RESTClient, url_prefix='api/v1/ports')
        api.url_post('1/connections', {'name': 'conn1'})

        assert_session_call(
            mock_post,
            'https://1.2.3.4/api/v1/ports/1/connections',
            False, {'name': 'conn1'},
            {}, BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.get'))
    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.put'))
    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.post'))
    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.delete'))
    def test_client_validate_result(self, *args):

        def _verb_response_code(http_verb, status_code):
            response = mocks.MockRequestsResponse(status_code, None)
            api = self.new_client(client.RESTClient)
            for mocked in args:
                mocked.return_value = response
            client_call = getattr(api, "url_%s" % http_verb)
            client_call('', None)

        for verb in ['get', 'post', 'put', 'delete']:
            for code in client.RESTClient._VERB_RESP_CODES.get(verb):
                _verb_response_code(verb, code)
            self.assertRaises(
                exep.ManagerError, _verb_response_code, verb, 500)


class NsxV3JSONClientTestCase(BaseClientTestCase):

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.post'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_json_request(self, mock_validate, mock_post):
        mock_post.return_value = mocks.MockRequestsResponse(
            200, jsonutils.dumps({'result': {'ok': 200}}))

        api = self.new_client(client.JSONRESTClient, url_prefix='api/v2/nat')
        resp = api.create(body={'name': 'mgmt-egress'})

        assert_session_call(
            mock_post,
            'https://1.2.3.4/api/v2/nat',
            False, jsonutils.dumps({'name': 'mgmt-egress'}),
            client.JSONRESTClient._DEFAULT_HEADERS,
            BaseClientTestCase.ca_file)

        self.assertEqual(resp, {'result': {'ok': 200}})


class NsxV3APIClientTestCase(BaseClientTestCase):

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.get'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_api_call(self, mock_validate, mock_get):
        api = self.new_client(client.NSX3Client)
        api.get('ports')

        assert_session_call(
            mock_get,
            'https://1.2.3.4/api/v1/ports',
            False, None,
            client.JSONRESTClient._DEFAULT_HEADERS,
            NsxV3APIClientTestCase.ca_file)


# NOTE(boden): remove this when tmp brigding removed
class NsxV3APIClientBridgeTestCase(BaseClientTestCase):

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.get'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_get_resource(self, mock_validate, mock_get):
        client.get_resource('ports')

        assert_session_call(
            mock_get,
            'https://1.2.3.4/api/v1/ports',
            False, None,
            client.JSONRESTClient._DEFAULT_HEADERS,
            NsxV3APIClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.post'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_create_resource(self, mock_validate, mock_post):
        client.create_resource('ports', {'resource-name': 'port1'})

        assert_session_call(
            mock_post,
            'https://1.2.3.4/api/v1/ports',
            False, jsonutils.dumps({'resource-name': 'port1'}),
            client.JSONRESTClient._DEFAULT_HEADERS,
            BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.put'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_update_resource(self, mock_validate, mock_put):
        client.update_resource('ports/1', {'name': 'a-new-name'})

        assert_session_call(
            mock_put,
            'https://1.2.3.4/api/v1/ports/1',
            False, jsonutils.dumps({'name': 'a-new-name'}),
            client.JSONRESTClient._DEFAULT_HEADERS,
            BaseClientTestCase.ca_file)

    @mock.patch("%s.%s" % (CLIENT_PKG, 'requests.Session.delete'))
    @mock.patch(CLIENT_PKG + '.RESTClient._validate_result')
    def test_delete_resource(self, mock_validate, mock_delete):
        client.delete_resource('ports/11')

        assert_session_call(
            mock_delete,
            'https://1.2.3.4/api/v1/ports/11',
            False, None, client.JSONRESTClient._DEFAULT_HEADERS,
            BaseClientTestCase.ca_file)
