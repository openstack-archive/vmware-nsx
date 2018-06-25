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


class OrphanedDhcpServerJob(base_job.BaseJob):

    def __init__(self, global_readonly, readonly_jobs):
        super(OrphanedDhcpServerJob, self).__init__(
            global_readonly, readonly_jobs)

    def get_project_plugin(self, plugin):
        return plugin.get_plugin_by_type(projectpluginmap.NsxPlugins.NSX_T)

    def get_name(self):
        return 'orphaned_dhcp_server'

    def get_description(self):
        return 'Detect orphaned DHCP server'

    def run(self, context, readonly=False):
        super(OrphanedDhcpServerJob, self).run(context)

        # get all orphaned DHCP servers
        orphaned_servers = v3_utils.get_orphaned_dhcp_servers(
            context, self.plugin, self.plugin.nsxlib)

        info = ""
        if not orphaned_servers:
            msg = 'No orphaned DHCP servers detected.'
            info = base_job.housekeeper_info(info, msg)
            return {'error_count': 0, 'fixed_count': 0, 'error_info': msg}

        msg = ("Found %(len)s orphaned DHCP server%(plural)s:" %
               {'len': len(orphaned_servers),
                'plural': 's' if len(orphaned_servers) > 1 else ''})
        info = base_job.housekeeper_warning(info, msg)
        fixed_count = 0
        for server in orphaned_servers:
            msg = ("DHCP server %(name)s [id: %(id)s] "
                   "(neutron network: %(net)s)" %
                   {'name': server['display_name'],
                    'id': server['id'],
                    'net': server['neutron_net_id']
                    if server.get('neutron_net_id') else 'Unknown'})
            if not readonly:
                success, error = v3_utils.delete_orphaned_dhcp_server(
                    context, self.plugin.nsxlib, server)
                if success:
                    msg = "%s was removed." % msg
                    fixed_count = fixed_count + 1
                else:
                    msg = "%s failed to be removed: %s." % (msg, error)
            info = base_job.housekeeper_warning(info, msg)

        return {'error_count': len(orphaned_servers),
                'error_info': info,
                'fixed_count': fixed_count}
