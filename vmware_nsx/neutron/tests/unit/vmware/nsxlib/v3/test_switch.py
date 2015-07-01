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
import requests

from oslo_log import log

from vmware_nsx.neutron.plugins.vmware.nsxlib import v3 as nsxlib
from vmware_nsx.neutron.tests.unit.vmware.nsxlib.v3 import nsxlib_testcase
from vmware_nsx.neutron.tests.unit.vmware import test_constants_v3

LOG = log.getLogger(__name__)


class NsxLibSwitchTestCase(nsxlib_testcase.NsxLibTestCase):

    def _create_mock_object(self, fake_object):
        """Construct mock response object"""
        mock_response = mock.Mock()
        mock_response.json.return_value = fake_object
        return mock_response

    @mock.patch("vmware_nsx.neutron.plugins.vmware.nsxlib.v3.requests.post")
    def test_create_logical_switch(self, mock_post):
        """
        Test creating a switch returns the correct response and 200 status
        """
        mock_post.return_value = self._create_mock_object(
                                     test_constants_v3.FAKE_SWITCH)
        mock_post.return_value.status_code = requests.codes.created

        result = nsxlib.create_logical_switch(
                    test_constants_v3.FAKE_NAME,
                    test_constants_v3.FAKE_TZ_UUID, tags={})
        self.assertEqual(test_constants_v3.FAKE_SWITCH, result)
