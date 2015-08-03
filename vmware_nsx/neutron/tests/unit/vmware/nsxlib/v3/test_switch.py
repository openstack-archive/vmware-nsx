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


class NsxLibSwitchTestCase(nsxlib_testcase.NsxLibTestCase):

    @mock.patch("vmware_nsx.neutron.plugins.vmware.nsxlib.v3"
                ".client.create_resource")
    def test_create_logical_switch(self, mock_create_resource):
        """
        Test creating a switch returns the correct response and 200 status
        """
        mock_create_resource.return_value = test_constants_v3.FAKE_SWITCH

        result = nsxlib.create_logical_switch(test_constants_v3.FAKE_NAME,
                                              test_constants_v3.FAKE_TZ_UUID,
                                              tags={})
        self.assertEqual(test_constants_v3.FAKE_SWITCH, result)
