# Copyright 2017 VMware, Inc.  All rights reserved.
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

from oslo_log import log as logging

from neutron_lib.callbacks import registry
from neutron_lib import context

from vmware_nsx.db import db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell import resources as shell

LOG = logging.getLogger(__name__)


@admin_utils.output_header
def migrate_projects(resource, event, trigger, **kwargs):
    """Import existing openstack projects to the current plugin"""
    # TODO(asarfaty): get the projects list from keystone

    # get the plugin name from the user
    if not kwargs.get('property'):
        LOG.error("Need to specify plugin and project parameters")
        return
    else:
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        plugin = properties.get('plugin')
        project = properties.get('project')
        if not plugin or not project:
            LOG.error("Need to specify plugin and project parameters")
            return
    if plugin not in projectpluginmap.VALID_TYPES:
        LOG.error("The supported plugins are %s", projectpluginmap.VALID_TYPES)
        return

    ctx = context.get_admin_context()
    if not db.get_project_plugin_mapping(ctx.session, project):
        db.add_project_plugin_mapping(ctx.session, project, plugin)


registry.subscribe(migrate_projects,
                   constants.PROJECTS,
                   shell.Operations.IMPORT.value)
