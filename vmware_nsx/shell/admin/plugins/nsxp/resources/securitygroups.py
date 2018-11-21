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

from neutron.db import securitygroups_db
from neutron_lib import context

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxp.resources import utils as p_utils

neutron_client = securitygroups_db.SecurityGroupDbMixin()


@admin_utils.list_handler(constants.SECURITY_GROUPS)
@admin_utils.output_header
def list_security_groups(resource, event, trigger, **kwargs):
    """List neutron security groups

    With the NSX policy resources and realization state.
    """
    mappings = []
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    ctx = context.get_admin_context()
    sgs = neutron_client.get_security_groups(ctx)
    for sg in sgs:
        domain_id = sg['tenant_id']
        map_status = p_utils.get_realization_info(
            nsxpolicy.comm_map, domain_id, sg['id'])
        group_status = p_utils.get_realization_info(
            nsxpolicy.group, domain_id, sg['id'])
        mappings.append({'ID': sg['id'],
                         'Name': sg.get('name'),
                         'Project': domain_id,
                         'NSX Group': group_status,
                         'NSX Map': map_status})
    p_utils.log_info(constants.SECURITY_GROUPS,
                     mappings,
                     attrs=['Project', 'Name', 'ID', 'NSX Group', 'NSX Map'])
    return bool(mappings)
