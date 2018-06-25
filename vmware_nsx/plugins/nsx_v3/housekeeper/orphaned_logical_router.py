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

from oslo_log import log

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.common.housekeeper import base_job
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils

LOG = log.getLogger(__name__)


class OrphanedLogicalRouterJob(base_job.BaseJob):

    def __init__(self, global_readonly, readonly_jobs):
        super(OrphanedLogicalRouterJob, self).__init__(
            global_readonly, readonly_jobs)

    def get_project_plugin(self, plugin):
        return plugin.get_plugin_by_type(projectpluginmap.NsxPlugins.NSX_T)

    def get_name(self):
        return 'orphaned_logical_router'

    def get_description(self):
        return 'Detect orphaned logical routers'

    def run(self, context, readonly=False):
        super(OrphanedLogicalRouterJob, self).run(context)

        # get all orphaned DHCP servers
        orphaned_routers = v3_utils.get_orphaned_routers(
            context, self.plugin.nsxlib)

        info = ""
        if not orphaned_routers:
            msg = 'No orphaned logical routers detected.'
            info = base_job.housekeeper_info(info, msg)
            return {'error_count': 0, 'fixed_count': 0, 'error_info': info}

        msg = ("Found %(len)s orphaned logical router%(plural)s:" %
               {'len': len(orphaned_routers),
                'plural': 's' if len(orphaned_routers) > 1 else ''})
        info = base_job.housekeeper_warning(info, msg)
        fixed_count = 0
        for router in orphaned_routers:
            msg = ("Logical router %(name)s [id: %(id)s] "
                   "(neutron router: %(rtr)s)" %
                   {'name': router['display_name'],
                    'id': router['id'],
                    'rtr': router['neutron_router_id']
                    if router['neutron_router_id'] else 'Unknown'})
            if not readonly:
                success, error = v3_utils.delete_orphaned_router(
                    self.plugin.nsxlib, router['id'])
                if success:
                    fixed_count = fixed_count + 1
                    msg = "%s was removed." % msg
                else:
                    msg = "%s failed to be removed: %s." % (msg, error)
            info = base_job.housekeeper_warning(info, msg)

        return {'error_count': len(orphaned_routers),
                'error_info': info,
                'fixed_count': fixed_count}
