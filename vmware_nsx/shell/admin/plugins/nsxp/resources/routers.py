# Copyright 2018 VMware, Inc.  All rights reserved.
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

from neutron_lib import context

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxp.resources import utils as p_utils


@admin_utils.list_handler(constants.ROUTERS)
@admin_utils.output_header
def list_routers(resource, event, trigger, **kwargs):
    """List neutron routers

    With the NSX policy resources and realization state.
    """
    mappings = []
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    ctx = context.get_admin_context()
    with p_utils.NsxPolicyPluginWrapper() as plugin:
        routers = plugin.get_routers(ctx, fields=['id', 'name', 'tenant_id'])
        for rtr in routers:
            status = p_utils.get_realization_info(
                nsxpolicy.tier1, rtr['id'])
            mappings.append({'ID': rtr['id'],
                             'Name': rtr.get('name'),
                             'Project': rtr.get('tenant_id'),
                             'NSX status': status})
    p_utils.log_info(constants.ROUTERS,
                     mappings,
                     attrs=['Project', 'Name', 'ID', 'NSX status'])
    return bool(mappings)
