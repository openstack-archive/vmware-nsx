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
from oslo_log import log
from oslo_serialization import jsonutils

from vmware_nsx.nsxlib import v3 as nsxlib
from vmware_nsx.nsxlib.v3 import client
from vmware_nsx.tests.unit.nsx_v3 import test_constants as test_constants_v3
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase
from vmware_nsx.tests.unit.nsxlib.v3 import test_client

LOG = log.getLogger(__name__)
_JSON_HEADERS = client.JSONRESTClient._DEFAULT_HEADERS


class NsxLibQosTestCase(nsxlib_testcase.NsxClientTestCase):

    def _body(self, qos_marking=None, dscp=None):
        body = {
            "resource_type": "QosSwitchingProfile",
            "tags": []
        }
        if qos_marking:
            body["dscp"] = {}
            body["dscp"]["mode"] = qos_marking.upper()
            if dscp:
                body["dscp"]["priority"] = dscp
        body["display_name"] = test_constants_v3.FAKE_NAME
        body["description"] = test_constants_v3.FAKE_NAME

        return body

    def test_create_qos_switching_profile_untrusted(self):
        """
        Test creating a qos-switching profile returns the correct response
        """
        api = self.new_client(client.NSX3Client)
        with self.mocked_client_bridge(api, nsxlib, 'client') as mocked:
            nsxlib.create_qos_switching_profile(
                qos_marking="untrusted", dscp=25, tags=[],
                name=test_constants_v3.FAKE_NAME,
                description=test_constants_v3.FAKE_NAME)

            test_client.assert_session_call(
                mocked.get('post'),
                'https://1.2.3.4/api/v1/switching-profiles',
                False,
                jsonutils.dumps(self._body(qos_marking='UNTRUSTED', dscp=25),
                                sort_keys=True),
                _JSON_HEADERS,
                nsxlib_testcase.NSX_CERT)

    def test_create_qos_switching_profile_trusted(self):
        """
        Test creating a qos-switching profile returns the correct response
        """
        api = self.new_client(client.NSX3Client)
        with self.mocked_client_bridge(api, nsxlib, 'client') as mocked:
            nsxlib.create_qos_switching_profile(
                qos_marking="trusted", dscp=0, tags=[],
                name=test_constants_v3.FAKE_NAME,
                description=test_constants_v3.FAKE_NAME)

            test_client.assert_session_call(
                mocked.get('post'),
                'https://1.2.3.4/api/v1/switching-profiles',
                False,
                jsonutils.dumps(self._body(qos_marking='trusted', dscp=0),
                                sort_keys=True),
                _JSON_HEADERS,
                nsxlib_testcase.NSX_CERT)

    def test_delete_qos_switching_profile(self):
        """
        Test deleting qos-switching-profile
        """
        api = self.new_client(client.NSX3Client)
        with self.mocked_client_bridge(api, nsxlib, 'client') as mocked:
            nsxlib.delete_qos_switching_profile(
                test_constants_v3.FAKE_QOS_PROFILE['id'])
            test_client.assert_session_call(
                mocked.get('delete'),
                'https://1.2.3.4/api/v1/switching-profiles/%s'
                % test_constants_v3.FAKE_QOS_PROFILE['id'],
                False, None,
                _JSON_HEADERS,
                nsxlib_testcase.NSX_CERT)
