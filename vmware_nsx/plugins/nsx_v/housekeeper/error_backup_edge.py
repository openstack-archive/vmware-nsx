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

from neutron_lib import constants
from oslo_log import log
from sqlalchemy.orm import exc as sa_exc

from vmware_nsx.common import locking
from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import nsxv_db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.common.housekeeper import base_job
from vmware_nsx.plugins.nsx_v import availability_zones as nsx_az
from vmware_nsx.plugins.nsx_v.vshield.common import constants as vcns_const

LOG = log.getLogger(__name__)


class ErrorBackupEdgeJob(base_job.BaseJob):
    def __init__(self, global_readonly, readonly_jobs):
        super(ErrorBackupEdgeJob, self).__init__(
            global_readonly, readonly_jobs)
        self.azs = nsx_az.NsxVAvailabilityZones()

    def get_project_plugin(self, plugin):
        return plugin.get_plugin_by_type(projectpluginmap.NsxPlugins.NSX_V)

    def get_name(self):
        return 'error_backup_edge'

    def get_description(self):
        return 'revalidate backup Edge appliances in ERROR state'

    def run(self, context, readonly=False):
        super(ErrorBackupEdgeJob, self).run(context)
        error_count = 0
        fixed_count = 0
        error_info = ''

        # Gather ERROR state backup edges into dict
        filters = {'status': [constants.ERROR]}
        like_filters = {'router_id': vcns_const.BACKUP_ROUTER_PREFIX + "%"}
        with locking.LockManager.get_lock('nsx-edge-backup-pool'):
            error_edge_bindings = nsxv_db.get_nsxv_router_bindings(
                context.session, filters=filters, like_filters=like_filters)

        if not error_edge_bindings:
            LOG.debug('Housekeeping: no backup edges in ERROR state detected')
            return {'error_count': 0,
                    'fixed_count': 0,
                    'error_info': 'No backup edges in ERROR state detected'}

        # Keep list of current broken backup edges - as it may change while
        # HK is running
        for binding in error_edge_bindings:
            error_count += 1
            error_info = base_job.housekeeper_warning(
                error_info, 'Backup Edge appliance %s is in ERROR state',
                binding['edge_id'])

            if not readonly:
                with locking.LockManager.get_lock(binding['edge_id']):
                    if self._handle_backup_edge(context, binding):
                        fixed_count += 1

        return {'error_count': error_count,
                'fixed_count': fixed_count,
                'error_info': error_info}

    def _handle_backup_edge(self, context, binding):
        dist = (binding['edge_type'] == nsxv_constants.VDR_EDGE)
        result = True
        az = self.azs.get_availability_zone(
            binding['availability_zone'])
        try:
            update_result = self.plugin.nsx_v.update_edge(
                context, binding['router_id'], binding['edge_id'],
                binding['router_id'], None,
                appliance_size=binding['appliance_size'],
                dist=dist, availability_zone=az)

            if update_result:
                nsxv_db.update_nsxv_router_binding(
                    context.session, binding['router_id'],
                    status=constants.ACTIVE)
        except Exception as e:
            LOG.error('Housekeeping: failed to recover Edge '
                      'appliance %s with exception %s',
                      binding['edge_id'], e)
            update_result = False

        if not update_result:
            LOG.warning('Housekeeping: failed to recover Edge '
                        'appliance %s, trying to delete', binding['edge_id'])
            result = self._delete_edge(context, binding, dist)

        return result

    def _delete_edge(self, context, binding, dist):
        try:
            nsxv_db.update_nsxv_router_binding(
                context.session, binding['router_id'],
                status=constants.PENDING_DELETE)
        except sa_exc.NoResultFound:
            LOG.debug("Housekeeping: Router binding %s does not exist.",
                      binding['router_id'])

        try:
            self.plugin.nsx_v.delete_edge(context, binding['router_id'],
                                          binding['edge_id'], dist=dist)
            return True

        except Exception as e:
            LOG.warning('Housekeeping: Failed to delete edge %s with '
                        'exception %s', binding['edge_id'], e)
