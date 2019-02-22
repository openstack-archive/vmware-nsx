# Copyright 2017 VMware.  All rights reserved.
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
#

import abc

from neutron.api.v2 import resource_helper
from neutron_lib.api import extensions
from neutron_lib.db import constants as db_const
from neutron_lib import exceptions as nexception

from vmware_nsx._i18n import _

PROJECT_PLUGIN_RESOURCE_NAME = "project_plugin_map"
# Use dash for alias and collection name
ALIAS = PROJECT_PLUGIN_RESOURCE_NAME.replace('_', '-')
PROJECT_PLUGINS = "project_plugin_maps"


class NsxPlugins(object):
    NSX_V = 'nsx-v'
    NSX_T = 'nsx-t'
    DVS = 'dvs'
    NSX_P = 'nsx-p'  # Note(asarfaty) this option is missing from the DB enum


VALID_TYPES = [NsxPlugins.NSX_V,
               NsxPlugins.NSX_T,
               NsxPlugins.DVS]

RESOURCE_ATTRIBUTE_MAP = {
    PROJECT_PLUGINS: {
        'id': {
            'allow_post': False, 'allow_put': False,
            'validate': {'type:uuid': None},
            'is_visible': True},
        # project is the id of the project mapped by this entry
        'project': {
            'allow_post': True, 'allow_put': False, 'is_visible': True},
        'plugin': {
            'allow_post': True, 'allow_put': False, 'is_visible': True,
            'validate': {'type:values': VALID_TYPES}},
        # tenant id is the id of tenant/project owning this entry
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {
                          'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                      'required_by_policy': True,
                      'is_visible': True},
    }
}


class Projectpluginmap(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Project Plugin Mapping"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return "Per Project Core Plugin."

    @classmethod
    def get_updated(cls):
        return "2017-12-05T00:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        member_actions = {}
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   None,
                                                   action_map=member_actions,
                                                   register_quota=True,
                                                   translate_name=True)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


class ProjectPluginReadOnly(nexception.NotAuthorized):
    message = _("Project Plugin map entries cannot be modified.")


class ProjectPluginAlreadyExists(nexception.Conflict):
    message = _("Project Plugin map already exists for project "
                "%(project_id)s.")


class ProjectPluginAdminOnly(nexception.NotAuthorized):
    message = _("Project Plugin map can be added only by an admin user.")


class ProjectPluginIllegalId(nexception.Conflict):
    message = _("Project ID %(project_id)s is illegal.")


class ProjectPluginNotAvailable(nexception.NotAuthorized):
    message = _("Plugin %(plugin)s is not available.")


class ProjectPluginMapPluginBase(object):

    @abc.abstractmethod
    def create_project_plugin_map(self, context, project_plugin_map):
        pass

    @abc.abstractmethod
    def update_project_plugin_map(self, context, id, project_plugin_map):
        raise ProjectPluginReadOnly()

    @abc.abstractmethod
    def get_project_plugin_map(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def delete_project_plugin_map(self, context, id):
        # TODO(asarfaty): delete when the project is deleted?
        raise ProjectPluginReadOnly()

    @abc.abstractmethod
    def get_project_plugin_maps(self, context, filters=None, fields=None,
                                sorts=None, limit=None, marker=None,
                                page_reverse=False):
        pass
