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
import contextlib
import mock
import types
import unittest

from oslo_config import cfg
from oslo_utils import uuidutils
from vmware_nsx.nsxlib.v3 import client as nsx_client
from vmware_nsx.tests.unit.nsx_v3 import mocks

NSX_USER = 'admin'
NSX_PASSWORD = 'default'
NSX_MANAGER = '1.2.3.4'
NSX_INSECURE = True
NSX_CERT = '/opt/stack/certs/nsx.pem'

V3_CLIENT_PKG = 'vmware_nsx.nsxlib.v3.client'
BRIDGE_FNS = ['create_resource', 'delete_resource',
              'update_resource', 'get_resource']


class NsxLibTestCase(unittest.TestCase):
    def setUp(self, *args, **kwargs):
        super(NsxLibTestCase, self).setUp()
        cfg.CONF.set_override('nsx_user', NSX_USER)
        cfg.CONF.set_override('nsx_password', NSX_PASSWORD)
        cfg.CONF.set_override('default_tz_uuid',
                              uuidutils.generate_uuid())
        cfg.CONF.set_override('nsx_controllers', ['11.9.8.7', '11.9.8.77'])

        cfg.CONF.set_override('nsx_user', NSX_USER, 'nsx_v3')
        cfg.CONF.set_override('nsx_password', NSX_PASSWORD, 'nsx_v3')
        cfg.CONF.set_override('nsx_manager', NSX_MANAGER, 'nsx_v3')
        cfg.CONF.set_override('insecure', NSX_INSECURE, 'nsx_v3')
        cfg.CONF.set_override('ca_file', NSX_CERT, 'nsx_v3')

        # print diffs when assert comparisons fail
        self.maxDiff = None


# NOTE(boden): a lot of the hackery and magic below can be removed
# once we move all v3 rest function calls to OO based on rest resource
class NsxClientTestCase(NsxLibTestCase):

    class MockBridge(object):
        def __init__(self, api_client):
            self._client = api_client

        def get_resource(self, resource):
            return nsx_client.get_resource(
                resource, client=self._client)

        def create_resource(self, resource, data):
            return nsx_client.create_resource(
                resource, data, client=self._client)

        def delete_resource(self, resource):
            return nsx_client.delete_resource(
                resource, client=self._client)

        def update_resource(self, resource, data):
            return nsx_client.create_resource(
                resource, data, client=self._client)

    def new_client(
            self, clazz, host_ip=NSX_MANAGER,
            user_name=NSX_USER,
            password=NSX_PASSWORD,
            insecure=NSX_INSECURE,
            url_prefix=None,
            default_headers=None,
            cert_file=NSX_CERT):

        return clazz(host_ip=host_ip, user_name=user_name,
                     password=password, insecure=insecure,
                     url_prefix=url_prefix, default_headers=default_headers,
                     cert_file=cert_file)

    @contextlib.contextmanager
    def mocked_client(self, client, mock_validate=True):
        session = client._session
        with mock.patch.object(session, 'get')as _get:
            with mock.patch.object(session, 'post')as _post:
                with mock.patch.object(session, 'delete')as _delete:
                    with mock.patch.object(session, 'put')as _put:
                        rep = {
                            'get': _get,
                            'put': _put,
                            'delete': _delete,
                            'post': _post
                        }
                        if mock_validate:
                            with mock.patch.object(client, '_validate_result'):
                                yield rep
                        else:
                            yield rep

    @contextlib.contextmanager
    def mocked_resource(self, resource, mock_validate=True):
        with self.mocked_client(resource._client,
                                mock_validate=mock_validate) as _client:
            yield _client

    @contextlib.contextmanager
    def mocked_client_bridge(self, client, module, attr, mock_validate=True):
        mocked_bridge = NsxClientTestCase.MockBridge(client)
        mocked_bridge.JSONRESTClient = nsx_client.JSONRESTClient
        with self.mocked_client(client, mock_validate=mock_validate) as mocked:
            with mock.patch.object(module, attr, new=mocked_bridge):
                yield mocked

    @classmethod
    def patch_client_module(cls, in_module, fn_map):
        mock_client = mock.Mock()
        for name, clazz in in_module.__dict__.items():
            if (isinstance(clazz, types.ModuleType) and
                    clazz.__name__ == V3_CLIENT_PKG):
                for fn_name in BRIDGE_FNS:
                    mock_call = fn_map.get(fn_name, getattr(mocks, fn_name))
                    setattr(mock_client, fn_name, mock_call)
                for fn_name, fn_call in fn_map.items():
                    if fn_name not in BRIDGE_FNS:
                        setattr(mock_client, fn_name, fn_call)
                return mock.patch.object(in_module, name, new=mock_client)
        return None

    @classmethod
    def mocked_session_module(cls, in_module, with_client,
                              mock_session=None):
        mock_session = mock_session or mocks.MockRequestSessionApi()
        with_client._session = mock_session

        def _call_client(fn_name):
            def _client(*args, **kwargs):
                client_fn = getattr(nsx_client, fn_name)
                kwargs['client'] = with_client
                return client_fn(*args, **kwargs)
            return _client

        def _mock_client_init(*args, **kwargs):
            return with_client

        fn_map = {}
        for fn in BRIDGE_FNS:
            fn_map[fn] = _call_client(fn)

        fn_map['NSX3Client'] = _mock_client_init
        fn_map['JSONRESTClient'] = _mock_client_init
        fn_map['RESTClient'] = _mock_client_init

        with_client.new_client_for = _mock_client_init

        return cls.patch_client_module(in_module, fn_map)
