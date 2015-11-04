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
from vmware_nsx.tests.unit.nsx_v3 import test_constants as test_constants_v3
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase
from vmware_nsx.tests.unit.nsxlib.v3 import test_client

LOG = log.getLogger(__name__)


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
        api = self.mocked_rest_fns(nsxlib, 'client')

        nsxlib.create_qos_switching_profile(
            qos_marking="untrusted", dscp=25, tags=[],
            name=test_constants_v3.FAKE_NAME,
            description=test_constants_v3.FAKE_NAME)

        test_client.assert_json_call(
            'post', api,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps(self._body(qos_marking='UNTRUSTED', dscp=25),
                                 sort_keys=True))

    def test_create_qos_switching_profile_trusted(self):
        """
        Test creating a qos-switching profile returns the correct response
        """
        api = self.mocked_rest_fns(nsxlib, 'client')

        nsxlib.create_qos_switching_profile(
            qos_marking="trusted", dscp=0, tags=[],
            name=test_constants_v3.FAKE_NAME,
            description=test_constants_v3.FAKE_NAME)

        test_client.assert_json_call(
            'post', api,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps(self._body(qos_marking='trusted', dscp=0),
                                 sort_keys=True))

    def test_delete_qos_switching_profile(self):
        """
        Test deleting qos-switching-profile
        """
        api = self.mocked_rest_fns(nsxlib, 'client')

        nsxlib.delete_qos_switching_profile(
            test_constants_v3.FAKE_QOS_PROFILE['id'])

        test_client.assert_json_call(
            'delete', api,
            'https://1.2.3.4/api/v1/switching-profiles/%s'
            % test_constants_v3.FAKE_QOS_PROFILE['id'])
