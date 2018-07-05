# Copyright 2017 VMware, Inc.
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

from vmware_nsx.plugins.common.housekeeper import base_job
from vmware_nsx.plugins.nsx_v.housekeeper import error_backup_edge

FAKE_ROUTER_BINDINGS = [
    {
        'router_id': 'backup-3b0b1fe1-c984', 'status': 'ERROR',
        'availability_zone': 'default', 'edge_id': 'edge-782',
        'edge_type': 'service', 'appliance_size': 'compact'}]


class ErrorBackupEdgeTestCaseReadOnly(base.BaseTestCase):

    def setUp(self):
        def get_plugin_mock(alias=constants.CORE):
            if alias in (constants.CORE, constants.L3):
                return self.plugin

        super(ErrorBackupEdgeTestCaseReadOnly, self).setUp()
        self.plugin = mock.Mock()
        self.context = mock.Mock()
        self.context.session = mock.Mock()
        mock.patch('neutron_lib.plugins.directory.get_plugin',
                   side_effect=get_plugin_mock).start()
        self.log = mock.Mock()
        base_job.LOG = self.log
        self.job = error_backup_edge.ErrorBackupEdgeJob(True, [])

    def run_job(self):
        self.job.run(self.context, readonly=True)

    def test_clean_run(self):
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_router_bindings',
                   return_value=[]).start()
        self.run_job()
        self.log.warning.assert_not_called()

    def test_broken_backup_edge(self):
        mock.patch('vmware_nsx.db.nsxv_db.get_nsxv_router_bindings',
                   return_value=FAKE_ROUTER_BINDINGS).start()

        self.run_job()
        self.log.warning.assert_called_once()


class ErrorBackupEdgeTestCaseReadWrite(ErrorBackupEdgeTestCaseReadOnly):
    def run_job(self):
        self.job.run(self.context, readonly=False)

    def test_broken_backup_edge(self):
        upd_binding = mock.patch(
            'vmware_nsx.db.nsxv_db.update_nsxv_router_binding').start()
        upd_edge = mock.patch.object(self.plugin.nsx_v, 'update_edge').start()
        self.job.azs = mock.Mock()
        az = mock.Mock()
        mock.patch.object(self.job.azs, 'get_availability_zone',
                          return_value=az).start()
        super(ErrorBackupEdgeTestCaseReadWrite, self
              ).test_broken_backup_edge()
        upd_binding.assert_has_calls(
            [mock.call(mock.ANY, r['router_id'], status='ACTIVE')
             for r in FAKE_ROUTER_BINDINGS])
        upd_edge.assert_called_with(
            self.context, 'backup-3b0b1fe1-c984', 'edge-782',
            'backup-3b0b1fe1-c984', None, appliance_size='compact',
            availability_zone=az, dist=False)
