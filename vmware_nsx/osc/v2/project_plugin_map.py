#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#

"""Project Plugin mapping action implementations"""

import six

from openstack import exceptions as os_exceptions
from openstack import resource
from openstackclient.i18n import _
from osc_lib.command import command
from osc_lib import exceptions as osc_exceptions
from osc_lib import utils

project_plugin_maps_path = "/project-plugin-maps"


class ProjectPluginMap(resource.Resource):
    resource_key = 'project_plugin_map'
    resources_key = 'project_plugin_maps'
    base_path = '/project-plugin-maps'

    # capabilities
    allow_create = True
    allow_get = True
    allow_update = False
    allow_delete = False
    allow_list = True

    _query_mapping = resource.QueryParameters(
        'plugin', 'project', 'tenant_id')

    # Properties
    id = resource.Body('id')
    project = resource.Body('project')
    plugin = resource.Body('plugin')
    tenant_id = resource.Body('tenant_id')


def _get_columns(item):
    columns = ['project', 'plugin']
    return columns, columns


def _get_attrs(parsed_args):
    attrs = {}
    if parsed_args.project is not None:
        attrs['project'] = parsed_args.project

    if parsed_args.plugin is not None:
        attrs['plugin'] = parsed_args.plugin
    return attrs


class CreateProjectPluginMap(command.ShowOne):
    _description = _("Create project plugin map")

    def get_parser(self, prog_name):
        parser = super(CreateProjectPluginMap, self).get_parser(prog_name)
        parser.add_argument(
            'project',
            metavar="<project>",
            help=_("project")
        )
        parser.add_argument(
            '--plugin',
            metavar="<plugin>",
            required=True,
            help=_('Plugin.)')
        )

        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.network
        attrs = _get_attrs(parsed_args)
        try:
            obj = client._create(ProjectPluginMap, **attrs)
        except os_exceptions.HttpException as exc:
            msg = _("Error while executing command: %s") % exc.message
            if exc.details:
                msg += ", " + six.text_type(exc.details)
            raise osc_exceptions.CommandError(msg)
        display_columns, columns = _get_columns(obj)
        data = utils.get_item_properties(obj, columns, formatters={})
        return (display_columns, data)


class ListProjectPluginMap(command.Lister):
    _description = _("List project plugin mappings")

    def take_action(self, parsed_args):
        client = self.app.client_manager.network

        columns = (
            'project',
            'plugin'
        )
        column_headers = (
            'Project ID',
            'Plugin',
        )

        client = self.app.client_manager.network
        data = client._list(ProjectPluginMap)
        return (column_headers,
                (utils.get_item_properties(
                    s, columns,
                ) for s in data))


class ShowProjectPluginMap(command.ShowOne):
    _description = _("Display project plugins mapping")

    def get_parser(self, prog_name):
        parser = super(ShowProjectPluginMap, self).get_parser(prog_name)
        parser.add_argument(
            'id',
            metavar='<id>',
            help=_('id')
        )
        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.network
        obj = client._get(ProjectPluginMap, parsed_args.id)
        display_columns, columns = _get_columns(obj)
        data = utils.get_item_properties(obj, columns)
        return display_columns, data
