# Copyright 2014 VMware, Inc.
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

from neutron_lib import context as n_context
from neutron_lib.plugins import directory


def is_tvd_core_plugin():
    core_plugin = cfg.CONF.core_plugin
    if (core_plugin.endswith('NsxTVDPlugin') or
        core_plugin.endswith('vmware_nsxtvd')):
        return True
    return False


def get_tvd_plugin_type_for_project(project_id, context=None):
    """Get the plugin type used by a project

    Raise an exception if not found or the plugin is not in use
    """
    if not context:
        context = n_context.get_admin_context()
    core_plugin = directory.get_plugin()
    return core_plugin.get_plugin_type_from_project(context, project_id)
