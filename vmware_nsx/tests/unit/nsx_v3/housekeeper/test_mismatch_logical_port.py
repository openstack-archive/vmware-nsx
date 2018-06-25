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
from vmware_nsx.plugins.nsx_v3.housekeeper import mismatch_logical_port
from vmware_nsxlib.v3 import exceptions as nsxlib_exc

DUMMY_PORT = {
    "resource_type": "LogicalPort",
    "id": uuidutils.generate_uuid(),
    "display_name": "test",
    "tags": [{
        "scope": "os-neutron-dport-id",
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
    "logical_switch_id": uuidutils.generate_uuid(),
    "admin_state": "UP",
    "switching_profile_ids": []}


class MismatchLogicalPortTestCaseReadOnly(base.BaseTestCase):

    def setUp(self):
        def get_plugin_mock(alias=constants.CORE):
            if alias in (constants.CORE, constants.L3):
                return self.plugin

        super(MismatchLogicalPortTestCaseReadOnly, self).setUp()
        self.plugin = mock.Mock()
        self.plugin.nsxlib = mock.Mock()
        self.plugin.nsxlib.switching_profile.find_by_display_name = mock.Mock(
            return_value=[{'id': 'Dummy'}])
        self.context = mock.Mock()
        self.context.session = mock.Mock()
        mock.patch('neutron_lib.plugins.directory.get_plugin',
                   side_effect=get_plugin_mock).start()
        self.log = mock.Mock()
        base_job.LOG = self.log
        self.job = mismatch_logical_port.MismatchLogicalportJob(True, [])

    def run_job(self):
        self.job.run(self.context, readonly=True)

    def test_clean_run(self):
        with mock.patch.object(self.plugin, 'get_ports', return_value=[]):
            self.run_job()
            self.log.warning.assert_not_called()

    def test_with_mismatched_ls(self):
        with mock.patch.object(
                self.plugin, 'get_ports',
                return_value=[{'id': uuidutils.generate_uuid()}]),\
            mock.patch("vmware_nsx.plugins.nsx_v3.utils.get_port_nsx_id",
                       return_value=uuidutils.generate_uuid()),\
            mock.patch.object(self.plugin.nsxlib.logical_port, 'get',
                              side_effect=nsxlib_exc.ResourceNotFound):
            self.run_job()
            self.log.warning.assert_called()


class MismatchLogicalPortTestCaseReadWrite(
    MismatchLogicalPortTestCaseReadOnly):

    def run_job(self):
        self.job.run(self.context, readonly=False)
