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
from vmware_nsx.plugins.nsx_v3.housekeeper import orphaned_logical_router

DUMMY_ROUTER = {
    "resource_type": "LogicalRouter",
    "id": uuidutils.generate_uuid(),
    "display_name": "test",
    "tags": [{
        "scope": "os-neutron-router-id",
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
    "edge_cluster_id": uuidutils.generate_uuid(),
    "router_type": "TIER1"}


class OrphanedLogicalRouterTestCaseReadOnly(base.BaseTestCase):

    def setUp(self):
        def get_plugin_mock(alias=constants.CORE):
            if alias in (constants.CORE, constants.L3):
                return self.plugin

        super(OrphanedLogicalRouterTestCaseReadOnly, self).setUp()
        self.plugin = mock.Mock()
        self.plugin.nsxlib = mock.Mock()
        self.context = mock.Mock()
        self.context.session = mock.Mock()
        mock.patch('neutron_lib.plugins.directory.get_plugin',
                   side_effect=get_plugin_mock).start()
        self.log = mock.Mock()
        base_job.LOG = self.log
        self.job = orphaned_logical_router.OrphanedLogicalRouterJob(True, [])

    def run_job(self):
        self.job.run(self.context, readonly=True)

    def test_clean_run(self):
        with mock.patch.object(self.plugin.nsxlib.logical_router, 'list',
                               return_value={'results': []}):
            self.run_job()
            self.log.warning.assert_not_called()

    def test_with_orphaned_ls(self):
        with mock.patch.object(self.plugin.nsxlib.logical_router, 'list',
                               return_value={'results': [DUMMY_ROUTER]}),\
            mock.patch("vmware_nsx.db.db.get_neutron_from_nsx_router_id",
                       return_value=None):
            self.run_job()
            self.log.warning.assert_called()


class OrphanedLogicalRouterTestCaseReadWrite(
    OrphanedLogicalRouterTestCaseReadOnly):

    def run_job(self):
        self.job.run(self.context, readonly=False)
