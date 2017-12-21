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

from oslo_config import cfg
from oslo_log import log
import stevedore

from neutron_lib import exceptions as n_exc
from vmware_nsx.common import locking

LOG = log.getLogger(__name__)
ALL_DUMMY_JOB = {
    'name': 'all',
    'description': 'Execute all housekeepers',
    'enabled': True}


class NsxvHousekeeper(stevedore.named.NamedExtensionManager):
    def __init__(self, hk_ns, hk_jobs):
        self.readonly = cfg.CONF.nsxv.housekeeping_readonly
        if self.readonly:
            LOG.info('Housekeeper initialized in readonly mode')
        else:
            LOG.info('Housekeeper initialized')

        self.jobs = {}
        super(NsxvHousekeeper, self).__init__(
            hk_ns, hk_jobs, invoke_on_load=True, invoke_args=(self.readonly,))

        LOG.info("Loaded housekeeping job names: %s", self.names())
        for job in self:
            if job.obj.get_name() in cfg.CONF.nsxv.housekeeping_jobs:
                self.jobs[job.obj.get_name()] = job.obj

    def get(self, job_name):
        if job_name == ALL_DUMMY_JOB.get('name'):
            return ALL_DUMMY_JOB

        for job in self:
            name = job.obj.get_name()
            if job_name == name:
                return {'name': job_name,
                        'description': job.obj.get_description(),
                        'enabled': job_name in self.jobs}

        raise n_exc.ObjectNotFound(id=job_name)

    def list(self):
        results = [ALL_DUMMY_JOB]

        for job in self:
            job_name = job.obj.get_name()
            results.append({'name': job_name,
                            'description': job.obj.get_description(),
                            'enabled': job_name in self.jobs})

        return results

    def run(self, context, job_name):
        if context.is_admin:
            with locking.LockManager.get_lock('nsx-housekeeper'):
                if job_name == ALL_DUMMY_JOB.get('name'):
                    for job in self.jobs.values():
                        job.run(context)
                else:
                    job = self.jobs.get(job_name)
                    if job:
                        job.run(context)
                    else:
                        raise n_exc.ObjectNotFound(id=job_name)
        else:
            raise n_exc.AdminRequired()
