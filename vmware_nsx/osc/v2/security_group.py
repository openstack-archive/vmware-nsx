# Copyright 2016 VMware, Inc.
# All rights reserved.
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

"""Security group action implementations with nsx extensions"""

from osc_lib import utils as osc_utils

from openstackclient.identity import common as identity_common
from openstackclient.network.v2 import _tag
from openstackclient.network.v2 import security_group

from vmware_nsx._i18n import _
from vmware_nsx.osc.v2 import utils


def add_nsx_extensions_to_parser(parser, client_manager, for_create=True):
    if 'security-group-logging' in utils.get_extensions(client_manager):
        # logging
        logging_enable_group = parser.add_mutually_exclusive_group()
        logging_enable_group.add_argument(
            '--logging',
            action='store_true',
            help=_("Enable logging")
        )
        logging_enable_group.add_argument(
            '--no-logging',
            action='store_true',
            help=_("Disable logging (default)")
        )
    if ('provider-security-group' in utils.get_extensions(client_manager) and
        for_create):
        # provider
        parser.add_argument(
            '--provider',
            action='store_true',
            help=_("Provider security group")
        )
    if 'security-group-policy' in utils.get_extensions(client_manager):
        # policy
        parser.add_argument(
            '--policy',
            metavar='<policy>',
            help=_("NSX Policy Id")
        )


def _get_plugin_attrs(attrs, parsed_args, client_manager):
    if 'security-group-logging' in utils.get_extensions(client_manager):
        # logging
        if parsed_args.logging:
            attrs['logging'] = True
        if parsed_args.no_logging:
            attrs['logging'] = False
    if 'provider-security-group' in utils.get_extensions(client_manager):
        # provider
        if hasattr(parsed_args, 'provider') and parsed_args.provider:
            attrs['provider'] = True
    if 'security-group-policy' in utils.get_extensions(client_manager):
        # policy
        if parsed_args.policy is not None:
            attrs['policy'] = parsed_args.policy

    return attrs


class NsxCreateSecurityGroup(security_group.CreateSecurityGroup):
    """Create a new security_group with vmware nsx extensions """

    def take_action_network(self, client, parsed_args):
        #TODO(asarfaty): Better to change the neutron client code of
        # CreateSecurityGroup:take_action_network to use an internal
        # get_attributes, and override only this

        # Build the create attributes.
        attrs = {}
        attrs['name'] = parsed_args.name
        attrs['description'] = self._get_description(parsed_args)
        if parsed_args.project is not None:
            identity_client = self.app.client_manager.identity
            project_id = identity_common.find_project(
                identity_client,
                parsed_args.project,
                parsed_args.project_domain,
            ).id
            attrs['tenant_id'] = project_id

        # add the plugin attributes
        attrs = _get_plugin_attrs(attrs, parsed_args, self.app.client_manager)

        # Create the security group and display the results.
        obj = client.create_security_group(**attrs)
        # tags cannot be set when created, so tags need to be set later.
        _tag.update_tags_for_set(client, obj, parsed_args)
        display_columns, property_columns = security_group._get_columns(obj)
        data = osc_utils.get_item_properties(
            obj,
            property_columns,
            formatters=security_group._formatters_network
        )
        return (display_columns, data)

    def update_parser_common(self, parser):
        parser = super(NsxCreateSecurityGroup, self).update_parser_common(
            parser)

        # Add the nsx attributes to the neutron security group attributes
        add_nsx_extensions_to_parser(
            parser, self.app.client_manager, for_create=True)
        return parser


class NsxSetSecurityGroup(security_group.SetSecurityGroup):
    """Set security group properties with vmware nsx extensions """

    def take_action_network(self, client, parsed_args):
        #TODO(asarfaty): Better to change the neutron client code of
        # CreateSecurityGroup:take_action_network to use an internal
        # get_attributes, and override only this

        obj = client.find_security_group(parsed_args.group,
                                         ignore_missing=False)
        attrs = {}
        if parsed_args.name is not None:
            attrs['name'] = parsed_args.name
        if parsed_args.description is not None:
            attrs['description'] = parsed_args.description

        # add the plugin attributes
        attrs = _get_plugin_attrs(attrs, parsed_args, self.app.client_manager)

        client.update_security_group(obj, **attrs)

        # tags is a subresource and it needs to be updated separately.
        _tag.update_tags_for_set(client, obj, parsed_args)

    def update_parser_common(self, parser):
        parser = super(NsxSetSecurityGroup, self).update_parser_common(parser)

        # Add the nsx attributes to the neutron security group attributes
        add_nsx_extensions_to_parser(
            parser, self.app.client_manager, for_create=False)
        return parser
