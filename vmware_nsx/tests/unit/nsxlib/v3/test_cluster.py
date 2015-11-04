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
import urlparse

from oslo_config import cfg
from oslo_serialization import jsonutils
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.nsxlib.v3 import client
from vmware_nsx.nsxlib.v3 import cluster
from vmware_nsx.tests.unit.nsx_v3 import mocks
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase


def _validate_conn_up(*args, **kwargs):
    return


def _validate_conn_down(*args, **kwargs):
    raise Exception()


class RequestsHTTPProviderTestCase(nsxlib_testcase.NsxClientTestCase):

    def test_new_connection(self):
        mock_api = mock.Mock()
        mock_api.username = 'nsxuser'
        mock_api.password = 'nsxpassword'
        mock_api.retries = 100
        mock_api.insecure = True
        mock_api.ca_file = None
        mock_api.http_timeout = 99
        mock_api.conn_idle_timeout = 39
        provider = cluster.NSXRequestsHTTPProvider()
        session = provider.new_connection(
            mock_api, cluster.Provider('9.8.7.6', 'https://9.8.7.6'))

        self.assertEqual(session.auth, ('nsxuser', 'nsxpassword'))
        self.assertEqual(session.verify, False)
        self.assertEqual(session.cert, None)
        self.assertEqual(session.adapters['https://'].max_retries.total, 100)
        self.assertEqual(session.timeout, 99)

    def test_validate_connection(self):
        mock_conn = mocks.MockRequestSessionApi()
        mock_ep = mock.Mock()
        mock_ep.provider.url = 'https://1.2.3.4'
        provider = cluster.NSXRequestsHTTPProvider()
        self.assertRaises(nsx_exc.ResourceNotFound,
                          provider.validate_connection,
                          mock.Mock(), mock_ep, mock_conn)

        mock_conn.post('api/v1/transport-zones',
                       data=jsonutils.dumps({'id': 'dummy-tz'}),
                       headers=client.JSONRESTClient._DEFAULT_HEADERS)
        provider.validate_connection(mock.Mock(), mock_ep, mock_conn)


class NsxV3ClusteredAPITestCase(nsxlib_testcase.NsxClientTestCase):

    def _assert_providers(self, cluster_api, provider_tuples):
        self.assertEqual(len(cluster_api.providers), len(provider_tuples))

        def _assert_provider(pid, purl):
            for provider in cluster_api.providers:
                if provider.id == pid and provider.url == purl:
                    return
            self.fail("Provider: %s not found" % pid)

        for provider_tuple in provider_tuples:
            _assert_provider(provider_tuple[0], provider_tuple[1])

    def test_conf_providers_no_scheme(self):
        conf_managers = ['8.9.10.11', '9.10.11.12:4433']
        cfg.CONF.set_override(
            'nsx_managers', conf_managers, 'nsx_v3')

        mock_provider = mock.Mock()
        mock_provider.default_scheme = 'https'
        mock_provider.validate_connection = _validate_conn_up

        api = cluster.NSXClusteredAPI(http_provider=mock_provider)

        self._assert_providers(
            api, [(p, "https://%s" % p) for p in conf_managers])

    def test_conf_providers_with_scheme(self):
        conf_managers = ['http://8.9.10.11:8080', 'https://9.10.11.12:4433']
        cfg.CONF.set_override(
            'nsx_managers', conf_managers, 'nsx_v3')

        mock_provider = mock.Mock()
        mock_provider.default_scheme = 'https'
        mock_provider.validate_connection = _validate_conn_up

        api = cluster.NSXClusteredAPI(http_provider=mock_provider)

        self._assert_providers(
            api, [(urlparse.urlparse(p).netloc, p) for p in conf_managers])

    def test_conns_per_pool(self):
        cfg.CONF.set_override(
            'concurrent_connections', 11, 'nsx_v3')
        conf_managers = ['8.9.10.11', '9.10.11.12:4433']
        cfg.CONF.set_override(
            'nsx_managers', conf_managers, 'nsx_v3')

        mock_provider = mock.Mock()
        mock_provider.default_scheme = 'https'
        mock_provider.validate_connection = _validate_conn_up

        api = cluster.NSXClusteredAPI(http_provider=mock_provider)

        for ep_id, ep in api.endpoints.items():
            self.assertEqual(ep.pool.max_size, 11)


class ClusteredAPITestCase(nsxlib_testcase.NsxClientTestCase):

    def _test_health(self, validate_fn, expected_health):
        conf_managers = ['8.9.10.11', '9.10.11.12']
        cfg.CONF.set_override(
            'nsx_managers', conf_managers, 'nsx_v3')

        mock_provider = mock.Mock()
        mock_provider.default_scheme = 'https'

        mock_provider.validate_connection = validate_fn
        api = cluster.NSXClusteredAPI(http_provider=mock_provider)
        self.assertEqual(api.health, expected_health)

    def test_orange_health(self):

        def _validate(cluster_api, endpoint, conn):
            if endpoint.provider.id == '8.9.10.11':
                raise Exception()

        self._test_health(_validate, cluster.ClusterHealth.ORANGE)

    def test_green_health(self):
        self._test_health(_validate_conn_up, cluster.ClusterHealth.GREEN)

    def test_red_health(self):
        self._test_health(_validate_conn_down, cluster.ClusterHealth.RED)

    def test_cluster_unavailable(self):
        conf_managers = ['8.9.10.11', '9.10.11.12', '10.11.12.13']
        cfg.CONF.set_override(
            'nsx_managers', conf_managers, 'nsx_v3')

        mock_provider = mock.Mock()
        mock_provider.default_scheme = 'https'

        mock_provider.validate_connection = _validate_conn_down
        api = cluster.NSXClusteredAPI(http_provider=mock_provider)

        self.assertEqual(len(api.endpoints), 3)
        self.assertRaises(nsx_exc.ServiceClusterUnavailable,
                          api.get, 'api/v1/transport-zones')
