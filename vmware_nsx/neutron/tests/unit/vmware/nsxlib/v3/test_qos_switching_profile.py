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

import mock

from oslo_log import log

from vmware_nsx.neutron.plugins.vmware.nsxlib import v3 as nsxlib
from vmware_nsx.neutron.tests.unit.vmware.nsxlib.v3 import nsxlib_testcase
from vmware_nsx.neutron.tests.unit.vmware import test_constants_v3

LOG = log.getLogger(__name__)


class NsxLibQosTestCase(nsxlib_testcase.NsxLibTestCase):

    @mock.patch("vmware_nsx.neutron.plugins.vmware.nsxlib.v3"
                ".client.create_resource")
    def test_create_qos_switching_profile_untrusted(
        self, mock_create_resource):
        """
        Test creating a qos-switching profile returns the correct response
        """
        fake_qos_profile = test_constants_v3.FAKE_QOS_PROFILE
        fake_qos_profile["dscp"]["mode"] = "UNTRUSTED"
        fake_qos_profile["dscp"]["priority"] = 25
        mock_create_resource.return_value = fake_qos_profile

        result = nsxlib.create_qos_switching_profile(
                     qos_marking="untrusted", dscp=25, tags=[],
                     name=test_constants_v3.FAKE_NAME,
                     description=test_constants_v3.FAKE_NAME)
        self.assertEqual(fake_qos_profile, result)

    @mock.patch("vmware_nsx.neutron.plugins.vmware.nsxlib.v3"
                ".client.create_resource")
    def test_create_qos_switching_profile_trusted(
        self, mock_create_resource):
        """
        Test creating a qos-switching profile returns the correct response
        """
        fake_qos_profile = test_constants_v3.FAKE_QOS_PROFILE
        fake_qos_profile["dscp"]["mode"] = "TRUSTED"
        fake_qos_profile["dscp"]["priority"] = 0
        mock_create_resource.return_value = fake_qos_profile

        result = nsxlib.create_qos_switching_profile(
                     qos_marking="trusted", dscp=0, tags=[],
                     name=test_constants_v3.FAKE_NAME,
                     description=test_constants_v3.FAKE_NAME)
        self.assertEqual(fake_qos_profile, result)

    @mock.patch("vmware_nsx.neutron.plugins.vmware.nsxlib.v3"
                ".client.delete_resource")
    def test_delete_qos_switching_profile(self, mock_delete_resource):
        """
        Test deleting qos-switching-profile
        """
        mock_delete_resource.return_value = None
        result = nsxlib.delete_qos_switching_profile(
                     test_constants_v3.FAKE_QOS_PROFILE['id'])
        self.assertIsNone(result)
