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
from neutron_lib import exceptions as n_exc

from vmware_nsx.plugins.common.housekeeper import base_job
from vmware_nsx.plugins.common.housekeeper import housekeeper


class TestJob1(base_job.BaseJob):
    def __init__(self, global_readonly, readonly_jobs):
        super(TestJob1, self).__init__(global_readonly, readonly_jobs)

    def get_name(self):
        return 'test_job1'

    def get_project_plugin(self, plugin):
        return 'Dummy'

    def get_description(self):
        return 'test'

    def run(self, context, readonly=False):
        pass


class TestJob2(TestJob1):
    def get_name(self):
        return 'test_job2'


class TestHousekeeper(base.BaseTestCase):

    def setUp(self):
        self.jobs = ['test_job1', 'test_job2']
        self.readonly_jobs = ['test_job1']
        self.readonly = False
        self.housekeeper = housekeeper.NsxHousekeeper(
            hk_ns='stevedore.test.extension',
            hk_jobs=self.jobs,
            hk_readonly=self.readonly,
            hk_readonly_jobs=self.readonly_jobs)

        self.job1 = TestJob1(self.readonly, self.readonly_jobs)
        self.job2 = TestJob2(self.readonly, self.readonly_jobs)
        self.housekeeper.jobs = {'test_job1': self.job1,
                                 'test_job2': self.job2}
        self.context = mock.Mock()
        self.context.session = mock.Mock()

        super(TestHousekeeper, self).setUp()

    def test_run_job_readonly(self):
        with mock.patch.object(self.job1, 'run') as run1,\
            mock.patch.object(self.job2, 'run') as run2:
            self.housekeeper.run(self.context, 'test_job1', readonly=True)
            run1.assert_called_with(mock.ANY, readonly=True)

            self.housekeeper.run(self.context, 'test_job2', readonly=True)
            run2.assert_called_with(mock.ANY, readonly=True)

    def test_run_job_readwrite(self):
        with mock.patch.object(self.job1, 'run') as run1,\
            mock.patch.object(self.job2, 'run') as run2:
            # job1 is configured as a readonly job so this should fail
            self.assertRaises(
                n_exc.ObjectNotFound,
                self.housekeeper.run, self.context, 'test_job1',
                readonly=False)
            self.assertFalse(run1.called)

            # job2 should run
            self.housekeeper.run(self.context, 'test_job2', readonly=False)
            run2.assert_called_with(mock.ANY, readonly=False)

    def test_run_all_readonly(self):
        with mock.patch.object(self.job1, 'run') as run1,\
            mock.patch.object(self.job2, 'run') as run2:
            self.housekeeper.run(self.context, 'all', readonly=True)
            run1.assert_called_with(mock.ANY, readonly=True)
            run2.assert_called_with(mock.ANY, readonly=True)

    def test_run_all_readwrite(self):
        with mock.patch.object(self.job1, 'run') as run1,\
            mock.patch.object(self.job2, 'run') as run2:
            self.housekeeper.run(self.context, 'all', readonly=False)
            # job1 is configured as a readonly job so it was not called
            self.assertFalse(run1.called)
            # job2 should run
            run2.assert_called_with(mock.ANY, readonly=False)


class TestHousekeeperReadOnly(TestHousekeeper):

    def setUp(self):
        super(TestHousekeeperReadOnly, self).setUp()
        self.housekeeper.global_readonly = True

    def test_run_job_readonly(self):
        with mock.patch.object(self.job1, 'run') as run1,\
            mock.patch.object(self.job2, 'run') as run2:
            self.housekeeper.run(self.context, 'test_job1', readonly=True)
            run1.assert_called_with(mock.ANY, readonly=True)

            self.housekeeper.run(self.context, 'test_job2', readonly=True)
            run2.assert_called_with(mock.ANY, readonly=True)

    def test_run_job_readwrite(self):
        with mock.patch.object(self.job1, 'run') as run1,\
            mock.patch.object(self.job2, 'run') as run2:

            # job1 is configured as a readonly job so this should fail
            self.assertRaises(
                n_exc.ObjectNotFound,
                self.housekeeper.run, self.context, 'test_job1',
                readonly=False)
            self.assertFalse(run1.called)

            # global readonly flag so job2 should also fail
            self.assertRaises(
                n_exc.ObjectNotFound,
                self.housekeeper.run, self.context, 'test_job2',
                readonly=False)
            self.assertFalse(run2.called)

    def test_run_all_readonly(self):
        with mock.patch.object(self.job1, 'run') as run1,\
            mock.patch.object(self.job2, 'run') as run2:
            self.housekeeper.run(self.context, 'all', readonly=True)
            run1.assert_called_with(mock.ANY, readonly=True)
            run2.assert_called_with(mock.ANY, readonly=True)

    def test_run_all_readwrite(self):
        with mock.patch.object(self.job1, 'run') as run1,\
            mock.patch.object(self.job2, 'run') as run2:
            # global readonly flag so 'all' should fail
            self.assertRaises(
                n_exc.ObjectNotFound,
                self.housekeeper.run, self.context, 'all',
                readonly=False)
            self.assertFalse(run1.called)
            self.assertFalse(run2.called)
