# Copyright (c) 2015 VMware, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import copy
import mock
import unittest

from oslo_utils import uuidutils
from requests import exceptions as requests_exceptions

from vmware_nsx.nsxlib import v3
from vmware_nsx.nsxlib.v3 import client as nsx_client
from vmware_nsx.nsxlib.v3 import cluster as nsx_cluster
from vmware_nsx.nsxlib.v3 import config

NSX_USER = 'admin'
NSX_PASSWORD = 'default'
NSX_MANAGER = '1.2.3.4'
NSX_INSECURE = False
NSX_CERT = '/opt/stack/certs/nsx.pem'
NSX_HTTP_RETRIES = 10
NSX_HTTP_TIMEOUT = 10
NSX_HTTP_READ_TIMEOUT = 180
NSX_CONCURENT_CONN = 10
NSX_CONN_IDLE_TIME = 10

PLUGIN_SCOPE = "plugin scope"
PLUGIN_TAG = "plugin tag"
PLUGIN_VER = "plugin ver"


def _mock_nsxlib():
    def _return_id_key(*args, **kwargs):
        return {'id': uuidutils.generate_uuid()}

    def _mock_add_rules_in_section(*args):
        # NOTE(arosen): the code in the neutron plugin expects the
        # neutron rule id as the display_name.
        rules = args[0]
        return {
            'rules': [
                {'display_name': rule['display_name'],
                 'id': uuidutils.generate_uuid()}
                for rule in rules
            ]}

    mock.patch(
        "vmware_nsx.nsxlib.v3.cluster.NSXRequestsHTTPProvider"
        ".validate_connection").start()

    mock.patch(
        "vmware_nsx.nsxlib.v3.security.NsxLibNsGroup.create",
        side_effect=_return_id_key
    ).start()

    mock.patch(
        "vmware_nsx.nsxlib.v3.security.NsxLibFirewallSection.create_empty",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsx.nsxlib.v3.security.NsxLibFirewallSection.init_default",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsx.nsxlib.v3.security.NsxLibNsGroup.list").start()

    mock.patch(
        "vmware_nsx.nsxlib.v3.security.NsxLibFirewallSection.add_rules",
        side_effect=_mock_add_rules_in_section).start()

    mock.patch(
        "vmware_nsx.nsxlib.v3.NsxLibTransportZone.get_id_by_name_or_id",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsx.nsxlib.v3.NsxLib.get_version",
        return_value='1.1.0').start()


def get_default_nsxlib_config():
    return config.NsxLibConfig(
        username=NSX_USER,
        password=NSX_PASSWORD,
        retries=NSX_HTTP_RETRIES,
        insecure=NSX_INSECURE,
        ca_file=NSX_CERT,
        concurrent_connections=NSX_CONCURENT_CONN,
        http_timeout=NSX_HTTP_TIMEOUT,
        http_read_timeout=NSX_HTTP_READ_TIMEOUT,
        conn_idle_timeout=NSX_CONN_IDLE_TIME,
        http_provider=None,
        nsx_api_managers=[],
        plugin_scope=PLUGIN_SCOPE,
        plugin_tag=PLUGIN_TAG,
        plugin_ver=PLUGIN_VER)


class NsxLibTestCase(unittest.TestCase):

    def setUp(self, *args, **kwargs):
        super(NsxLibTestCase, self).setUp()
        _mock_nsxlib()

        nsxlib_config = get_default_nsxlib_config()
        self.nsxlib = v3.NsxLib(nsxlib_config)

        # print diffs when assert comparisons fail
        self.maxDiff = None


class MemoryMockAPIProvider(nsx_cluster.AbstractHTTPProvider):
    """Acts as a HTTP provider for mocking which is backed
    by a MockRequestSessionApi.
    """

    def __init__(self, mock_session_api):
        self._store = mock_session_api

    @property
    def provider_id(self):
        return "Memory mock API"

    def validate_connection(self, cluster_api, endpoint, conn):
        return

    def new_connection(self, cluster_api, provider):
        # all callers use the same backing
        return self._store

    def is_connection_exception(self, exception):
        return isinstance(exception, requests_exceptions.ConnectionError)


class NsxClientTestCase(NsxLibTestCase):

    class MockNSXClusteredAPI(nsx_cluster.NSXClusteredAPI):

        def __init__(
            self, session_response=None,
            username=None,
            password=None,
            retries=None,
            insecure=None,
            ca_file=None,
            concurrent_connections=None,
            http_timeout=None,
            http_read_timeout=None,
            conn_idle_timeout=None,
            nsx_api_managers=None):

            nsxlib_config = config.NsxLibConfig(
                username=username or NSX_USER,
                password=password or NSX_PASSWORD,
                retries=retries or NSX_HTTP_RETRIES,
                insecure=insecure if insecure is not None else NSX_INSECURE,
                ca_file=ca_file or NSX_CERT,
                concurrent_connections=(concurrent_connections or
                                        NSX_CONCURENT_CONN),
                http_timeout=http_timeout or NSX_HTTP_TIMEOUT,
                http_read_timeout=http_read_timeout or NSX_HTTP_READ_TIMEOUT,
                conn_idle_timeout=conn_idle_timeout or NSX_CONN_IDLE_TIME,
                http_provider=NsxClientTestCase.MockHTTPProvider(
                    session_response=session_response),
                nsx_api_managers=nsx_api_managers or [NSX_MANAGER],
                plugin_scope=PLUGIN_SCOPE,
                plugin_tag=PLUGIN_TAG,
                plugin_ver=PLUGIN_VER)

            super(NsxClientTestCase.MockNSXClusteredAPI, self).__init__(
                nsxlib_config)
            self._record = mock.Mock()

        def record_call(self, request, **kwargs):
            verb = request.method.lower()

            # filter out requests specific attributes
            checked_kwargs = copy.copy(kwargs)
            del checked_kwargs['proxies']
            del checked_kwargs['stream']
            if 'allow_redirects' in checked_kwargs:
                del checked_kwargs['allow_redirects']

            for attr in ['url', 'body']:
                checked_kwargs[attr] = getattr(request, attr, None)

            # remove headers we don't need to verify
            checked_kwargs['headers'] = copy.copy(request.headers)
            for header in ['Accept-Encoding', 'User-Agent',
                           'Connection', 'Authorization',
                           'Content-Length']:
                if header in checked_kwargs['headers']:
                    del checked_kwargs['headers'][header]

            checked_kwargs['headers'] = request.headers

            # record the call in the mock object
            method = getattr(self._record, verb)
            method(**checked_kwargs)

        def assert_called_once(self, verb, **kwargs):
            mock_call = getattr(self._record, verb.lower())
            mock_call.assert_called_once_with(**kwargs)

        @property
        def recorded_calls(self):
            return self._record

    class MockHTTPProvider(nsx_cluster.NSXRequestsHTTPProvider):

        def __init__(self, session_response=None):
            super(NsxClientTestCase.MockHTTPProvider, self).__init__()
            self._session_response = session_response

        def new_connection(self, cluster_api, provider):
            # wrapper the session so we can intercept and record calls
            session = super(NsxClientTestCase.MockHTTPProvider,
                            self).new_connection(cluster_api, provider)

            mock_adapter = mock.Mock()
            session_send = session.send

            def _adapter_send(request, **kwargs):
                # record calls at the requests HTTP adapter level
                mock_response = mock.Mock()
                mock_response.history = None
                # needed to bypass requests internal checks for mock
                mock_response.raw._original_response = {}

                # record the request for later verification
                cluster_api.record_call(request, **kwargs)
                return mock_response

            def _session_send(request, **kwargs):
                # calls at the Session level
                if self._session_response:
                    # consumer has setup a response for the session
                    cluster_api.record_call(request, **kwargs)
                    return (self._session_response()
                            if hasattr(self._session_response, '__call__')
                            else self._session_response)

                # bypass requests redirect handling for mock
                kwargs['allow_redirects'] = False

                # session send will end up calling adapter send
                return session_send(request, **kwargs)

            mock_adapter.send = _adapter_send
            session.send = _session_send

            def _mock_adapter(*args, **kwargs):
                # use our mock adapter rather than requests adapter
                return mock_adapter

            session.get_adapter = _mock_adapter
            return session

        def validate_connection(self, cluster_api, endpoint, conn):
            assert conn is not None

    def mock_nsx_clustered_api(self, session_response=None, **kwargs):
        return NsxClientTestCase.MockNSXClusteredAPI(
            session_response=session_response, **kwargs)

    def mocked_resource(self, resource_class, mock_validate=True,
                        session_response=None):
        mocked = resource_class(nsx_client.NSX3Client(
            self.mock_nsx_clustered_api(session_response=session_response)))
        if mock_validate:
            mock.patch.object(mocked._client, '_validate_result').start()

        return mocked

    def new_mocked_client(self, client_class, mock_validate=True,
                          session_response=None, mock_cluster=None,
                          **kwargs):
        client = client_class(mock_cluster or self.mock_nsx_clustered_api(
            session_response=session_response), **kwargs)

        if mock_validate:
            mock.patch.object(client, '_validate_result').start()

        new_client_for = client.new_client_for

        def _new_client_for(*args, **kwargs):
            sub_client = new_client_for(*args, **kwargs)
            if mock_validate:
                mock.patch.object(sub_client, '_validate_result').start()
            return sub_client

        client.new_client_for = _new_client_for

        return client

    def new_mocked_cluster(self, conf_managers, validate_conn_func,
                           concurrent_connections=None):
        mock_provider = mock.Mock()
        mock_provider.default_scheme = 'https'
        mock_provider.validate_connection = validate_conn_func

        nsxlib_config = get_default_nsxlib_config()
        if concurrent_connections:
            nsxlib_config.concurrent_connections = concurrent_connections
        nsxlib_config.http_provider = mock_provider
        nsxlib_config.nsx_api_managers = conf_managers

        return nsx_cluster.NSXClusteredAPI(nsxlib_config)
