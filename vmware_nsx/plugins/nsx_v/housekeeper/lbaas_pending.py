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

import time

from neutron_lbaas.db.loadbalancer import models
from neutron_lib import constants
from oslo_log import log

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.common.housekeeper import base_job

LOG = log.getLogger(__name__)

ELEMENT_LIFETIME = 3 * 60 * 60  # Three hours lifetime


class LbaasPendingJob(base_job.BaseJob):
    lbaas_objects = {}
    lbaas_models = [models.LoadBalancer,
                    models.Listener,
                    models.L7Policy,
                    models.L7Rule,
                    models.PoolV2,
                    models.MemberV2,
                    models.HealthMonitorV2]

    def get_project_plugin(self, plugin):
        return plugin.get_plugin_by_type(projectpluginmap.NsxPlugins.NSX_V)

    def get_name(self):
        return 'lbaas_pending'

    def get_description(self):
        return 'Monitor LBaaS objects in pending states'

    def run(self, context, readonly=False):
        super(LbaasPendingJob, self).run(context)
        curr_time = time.time()
        error_count = 0
        fixed_count = 0
        error_info = ''

        for model in self.lbaas_models:
            sess = context.session
            elements = sess.query(model).filter(
                model.provisioning_status.in_(
                    [constants.PENDING_CREATE,
                     constants.PENDING_UPDATE,
                     constants.PENDING_DELETE])).all()

            for element in elements:
                if element['id'] in self.lbaas_objects:
                    obj = self.lbaas_objects[element['id']]
                    lifetime = curr_time - obj['time_added']
                    if lifetime > ELEMENT_LIFETIME:
                        # Entry has been pending for more than lifetime.
                        # Report and remove when in R/W mode
                        error_count += 1
                        error_info = base_job.housekeeper_warning(
                            error_info,
                            'LBaaS %s %s is stuck in pending state',
                            model.NAME, element['id'])

                        if not readonly:
                            element['provisioning_status'] = constants.ERROR
                            fixed_count += 1
                        del self.lbaas_objects[element['id']]
                    else:
                        # Entry is still pending but haven't reached lifetime
                        LOG.debug('Housekeeping: LBaaS object %s %s in '
                                  'PENDING state for %d seconds', model.NAME,
                                  element['id'], lifetime)
                        obj['time_seen'] = curr_time
                else:
                    # Entry wasn't seen before this iteration - add to dict
                    LOG.debug('Housekeeping: monitoring PENDING state for '
                              'LBaaS object %s %s', model.NAME, element['id'])
                    self.lbaas_objects[element.id] = {
                        'model': model,
                        'time_added': curr_time,
                        'time_seen': curr_time}

        # Look for dictionary entries which weren't seen in this iteration.
        # Such entries were either removed from DB or their state was changed.
        for obj_id in self.lbaas_objects.keys():
            if self.lbaas_objects[obj_id]['time_seen'] != curr_time:
                LOG.debug('Housekeeping: LBaaS %s %s is back to normal',
                          self.lbaas_objects[obj_id]['model'].NAME, obj_id)
                del self.lbaas_objects[obj_id]

        if error_count == 0:
            error_info = 'No LBaaS objects in pending state'
        return {'error_count': error_count,
                'fixed_count': fixed_count,
                'error_info': error_info}
