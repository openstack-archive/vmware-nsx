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


class MismatchLogicalportJob(base_job.BaseJob):

    def __init__(self, global_readonly, readonly_jobs):
        super(MismatchLogicalportJob, self).__init__(
            global_readonly, readonly_jobs)

    def get_project_plugin(self, plugin):
        return plugin.get_plugin_by_type(projectpluginmap.NsxPlugins.NSX_T)

    def get_name(self):
        return 'mismatch_logical_port'

    def get_description(self):
        return 'Detect mismatched configuration on NSX logical ports'

    def run(self, context, readonly=False):
        super(MismatchLogicalportJob, self).run(context)

        # get all orphaned DHCP servers
        mismatch_ports = v3_utils.get_mismatch_logical_ports(
            context, self.plugin.nsxlib, self.plugin)
        info = ""
        if not mismatch_ports:
            msg = 'No mismatched logical ports detected.'
            info = base_job.housekeeper_info(info, msg)
            return {'error_count': 0, 'fixed_count': 0, 'error_info': info}

        msg = ("Found %(len)s mismatched logical port%(plural)s:" %
               {'len': len(mismatch_ports),
                'plural': 's' if len(mismatch_ports) > 1 else ''})
        info = base_job.housekeeper_warning(info, msg)

        fixed_count = 0
        for port_problem in mismatch_ports:
            msg = ("Logical port %(nsx_id)s "
                   "[neutron id: %(id)s] error: %(err)s" %
                   {'nsx_id': port_problem['nsx_id'],
                    'id': port_problem['neutron_id'],
                    'err': port_problem['error']})
            if not readonly:
                # currently we mitigate only address bindings mismatches
                err_type = port_problem['error_type']
                if err_type == v3_utils.PORT_ERROR_TYPE_BINDINGS:
                    # Create missing address bindings on backend
                    port = port_problem['port']
                    try:
                        address_bindings = self.plugin._build_address_bindings(
                            port)
                        self.plugin.nsxlib.logical_port.update(
                            port_problem['nsx_id'], port_problem['neutron_id'],
                            address_bindings=address_bindings)
                    except Exception as e:
                        msg = "%s failed to be fixed: %s" % (msg, e)
                    else:
                        fixed_count = fixed_count + 1
                        msg = "%s was fixed." % msg
                else:
                    msg = "%s cannot be fixed automatically." % msg
            info = base_job.housekeeper_warning(info, msg)

        return {'error_count': len(mismatch_ports),
                'error_info': info,
                'fixed_count': fixed_count}
