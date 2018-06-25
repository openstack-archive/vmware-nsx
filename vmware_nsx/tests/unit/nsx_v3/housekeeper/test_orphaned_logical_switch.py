# Copyright 2018 VMware, Inc.
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

import mock
from neutron.tests import base
from neutron_lib.plugins import constants
from oslo_utils import uuidutils

from vmware_nsx.plugins.common.housekeeper import base_job
from vmware_nsx.plugins.nsx_v3.housekeeper import orphaned_logical_switch

DUMMY_LS = {
    "resource_type": "LogicalSwitch",
    "id": uuidutils.generate_uuid(),
    "display_name": "test",
    "tags": [{
        "scope": "os-neutron-net-id",
        "tag": uuidutils.generate_uuid()
    }, {
        "scope": "os-project-id",
        "tag": uuidutils.generate_uuid()
    }, {
        "scope": "os-project-name",
        "tag": "admin"
    }, {
        "scope": "os-api-version",
        "tag": "13.0.0.0b3.dev90"
    }],
    "transport_zone_id": uuidutils.generate_uuid(),
    "address_bindings": []}


class OrphanedLogicalSwitchTestCaseReadOnly(base.BaseTestCase):

    def setUp(self):
        def get_plugin_mock(alias=constants.CORE):
            if alias in (constants.CORE, constants.L3):
                return self.plugin

        super(OrphanedLogicalSwitchTestCaseReadOnly, self).setUp()
        self.plugin = mock.Mock()
        self.plugin.nsxlib = mock.Mock()
        self.context = mock.Mock()
        self.context.session = mock.Mock()
        mock.patch('neutron_lib.plugins.directory.get_plugin',
                   side_effect=get_plugin_mock).start()
        self.log = mock.Mock()
        base_job.LOG = self.log
        self.job = orphaned_logical_switch.OrphanedLogicalSwitchJob(True, [])

    def run_job(self):
        self.job.run(self.context, readonly=True)

    def test_clean_run(self):
        with mock.patch.object(self.plugin.nsxlib.logical_switch, 'list',
                               return_value={'results': []}):
            self.run_job()
            self.log.warning.assert_not_called()

    def test_with_orphaned_ls(self):
        with mock.patch.object(self.plugin.nsxlib.logical_switch, 'list',
                               return_value={'results': [DUMMY_LS]}),\
            mock.patch("vmware_nsx.db.db.get_net_ids", return_value=None):
            self.run_job()
            self.log.warning.assert_called()


class OrphanedLogicalSwitchTestCaseReadWrite(
    OrphanedLogicalSwitchTestCaseReadOnly):

    def run_job(self):
        self.job.run(self.context, readonly=False)
