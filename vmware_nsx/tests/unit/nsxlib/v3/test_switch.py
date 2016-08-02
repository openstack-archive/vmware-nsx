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

from vmware_nsx.common import nsx_constants
from vmware_nsx.tests.unit.nsx_v3 import mocks as nsx_v3_mocks
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase


LOG = log.getLogger(__name__)


class NsxLibSwitchTestCase(nsxlib_testcase.NsxClientTestCase):
    _tz_id = "8f602f97-ee3e-46b0-9d9f-358955f03608"

    def _create_body(self, admin_state=nsx_constants.ADMIN_STATE_UP,
                     vlan_id=None):
        body = {
            "transport_zone_id": NsxLibSwitchTestCase._tz_id,
            "replication_mode": "MTEP",
            "display_name": "fake_name",
            "tags": [],
            "admin_state": admin_state
        }
        if vlan_id:
            body['vlan'] = vlan_id
        return body

    def test_create_logical_switch(self):
        """
        Test creating a switch returns the correct response and 200 status
        """

        with mock.patch.object(self.nsxlib.client, 'create') as create:
            self.nsxlib.create_logical_switch(
                nsx_v3_mocks.FAKE_NAME, NsxLibSwitchTestCase._tz_id, [])
            create.assert_called_with('logical-switches', self._create_body())

    def test_create_logical_switch_admin_down(self):
        """
        Test creating switch with admin_state down
        """

        with mock.patch.object(self.nsxlib.client, 'create') as create:
            self.nsxlib.create_logical_switch(
                nsx_v3_mocks.FAKE_NAME, NsxLibSwitchTestCase._tz_id,
                [], admin_state=False)

            create.assert_called_with(
                'logical-switches',
                self._create_body(
                    admin_state=nsx_constants.ADMIN_STATE_DOWN))

    def test_create_logical_switch_vlan(self):
        """
        Test creating switch with provider:network_type VLAN
        """

        with mock.patch.object(self.nsxlib.client, 'create') as create:
            self.nsxlib.create_logical_switch(
                nsx_v3_mocks.FAKE_NAME, NsxLibSwitchTestCase._tz_id,
                [], vlan_id='123')

            create.assert_called_with(
                'logical-switches',
                self._create_body(vlan_id='123'))

    def test_delete_logical_switch(self):
        """
        Test deleting switch
        """

        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            fake_switch = nsx_v3_mocks.make_fake_switch()
            self.nsxlib.delete_logical_switch(fake_switch['id'])
            delete.assert_called_with(
                'logical-switches/%s'
                '?detach=true&cascade=true' % fake_switch['id'])
