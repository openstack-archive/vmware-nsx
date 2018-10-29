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
from oslo_log import log

from neutron_lib import context as n_context
from neutron_lib import exceptions
from neutron_lib.plugins import directory

from vmware_nsx.db import db as nsx_db

LOG = log.getLogger(__name__)


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


def filter_plugins(cls):
    """
    Class decorator to separate the results of each of the given methods
    by plugin
    """
    def get_project_mapping(context, project_id):
        """Return the plugin associated with this project"""
        mapping = nsx_db.get_project_plugin_mapping(
                context.session, project_id)
        if mapping:
            return mapping['plugin']
        else:
            raise exceptions.ObjectNotFound(id=project_id)

    def add_separate_plugin_hook(name):
        orig_method = getattr(cls, name, None)

        def filter_results_by_plugin(self, context, **kwargs):
            """Run the original get-list method, and filter the results
            by the project id of the context
            """
            entries = orig_method(self, context, **kwargs)
            if not context.project_id or not entries:
                return entries
            req_p = get_project_mapping(context, context.project_id)
            for entry in entries[:]:
                if entry.get('tenant_id'):
                    try:
                        p = get_project_mapping(context, entry['tenant_id'])
                    except exceptions.ObjectNotFound:
                        # This could be a project that was already deleted
                        LOG.info("Project %s is not associated with any "
                                 "plugin and will be ignored",
                                 entry['tenant_id'])
                        entries.remove(entry)
                    else:
                        if p != req_p:
                            entries.remove(entry)

            return entries

        setattr(cls, name, filter_results_by_plugin)

    for method in cls.methods_to_separate:
        add_separate_plugin_hook(method)

    return cls
