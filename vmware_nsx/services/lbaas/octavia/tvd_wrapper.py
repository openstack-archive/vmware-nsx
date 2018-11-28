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

from oslo_log import log as logging

from neutron_lib import exceptions as n_exc

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.nsx import utils as tvd_utils

LOG = logging.getLogger(__name__)


class OctaviaTVDWrapper(object):

    def __init__(self, v_manager, t_manager):
        self.managers = {}
        if v_manager:
            self.managers[projectpluginmap.NsxPlugins.NSX_V] = v_manager
        if t_manager:
            self.managers[projectpluginmap.NsxPlugins.NSX_T] = t_manager

    def _get_manager_by_project(self, context, project_id):
        plugin_type = tvd_utils.get_tvd_plugin_type_for_project(
            project_id, context=context)
        if not self.managers.get(plugin_type):
            LOG.error("Project %(project)s with plugin %(plugin)s has no "
                      "support for Octavia", {'project': project_id,
                                              'plugin': plugin_type})
            raise n_exc.ServiceUnavailable()
        return self.managers[plugin_type]

    def create(self, context, obj, completor, **args):
        manager = self._get_manager_by_project(context, obj['project_id'])
        return manager.create(context, obj, completor, **args)

    def update(self, context, old_obj, new_obj, completor, **args):
        manager = self._get_manager_by_project(context, old_obj['project_id'])
        return manager.update(context, old_obj, new_obj, completor, **args)

    def delete(self, context, obj, completor, **args):
        manager = self._get_manager_by_project(context, obj['project_id'])
        return manager.delete(context, obj, completor, **args)


def stats_getter(context, core_plugin, ignore_list=None):
    """Call stats of both plugins"""
    for plugin_type in [projectpluginmap.NsxPlugins.NSX_V,
                        projectpluginmap.NsxPlugins.NSX_T]:
        plugin = core_plugin.get_plugin_by_type(plugin_type)
        if plugin:
            stats_getter_func = plugin._get_octavia_stats_getter()
            return stats_getter_func(context, plugin)
