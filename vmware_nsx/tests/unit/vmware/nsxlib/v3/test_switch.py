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
from oslo_utils import uuidutils

from vmware_nsx.common import nsx_constants
from vmware_nsx.nsxlib import v3 as nsxlib
from vmware_nsx.tests.unit.vmware import nsx_v3_mocks
from vmware_nsx.tests.unit.vmware.nsxlib.v3 import nsxlib_testcase

LOG = log.getLogger(__name__)


class NsxLibSwitchTestCase(nsxlib_testcase.NsxLibTestCase):

    @mock.patch("vmware_nsx.nsxlib.v3"
                ".client.create_resource")
    def test_create_logical_switch(self, mock_create_resource):
        """
        Test creating a switch returns the correct response and 200 status
        """
        tz_uuid = uuidutils.generate_uuid()
        fake_switch = nsx_v3_mocks.make_fake_switch(tz_uuid=tz_uuid)
        mock_create_resource.return_value = fake_switch

        result = nsxlib.create_logical_switch(nsx_v3_mocks.FAKE_NAME, tz_uuid,
                                              [])
        self.assertEqual(fake_switch, result)

    @mock.patch("vmware_nsx.nsxlib.v3"
                ".client.create_resource")
    def test_create_logical_switch_admin_down(self, mock_create_resource):
        """
        Test creating switch with admin_state down
        """
        tz_uuid = uuidutils.generate_uuid()
        fake_switch = nsx_v3_mocks.make_fake_switch(tz_uuid=tz_uuid)
        fake_switch['admin_state'] = nsx_constants.ADMIN_STATE_DOWN
        mock_create_resource.return_value = fake_switch

        result = nsxlib.create_logical_switch(nsx_v3_mocks.FAKE_NAME, tz_uuid,
                                              [], admin_state=False)
        self.assertEqual(fake_switch, result)

    @mock.patch("vmware_nsx.nsxlib.v3"
                ".client.create_resource")
    def test_create_logical_switch_vlan(self, mock_create_resource):
        """
        Test creating switch with provider:network_type VLAN
        """
        tz_uuid = uuidutils.generate_uuid()
        fake_switch = nsx_v3_mocks.make_fake_switch()
        fake_switch['vlan_id'] = '123'
        mock_create_resource.return_value = fake_switch

        result = nsxlib.create_logical_switch(nsx_v3_mocks.FAKE_NAME, tz_uuid,
                                              [])
        self.assertEqual(fake_switch, result)

    @mock.patch("vmware_nsx.nsxlib.v3"
                ".client.delete_resource")
    def test_delete_logical_switch(self, mock_delete_resource):
        """
        Test deleting switch
        """
        mock_delete_resource.return_value = None

        fake_switch = nsx_v3_mocks.make_fake_switch()
        result = nsxlib.delete_logical_switch(fake_switch['id'])
        self.assertIsNone(result)
