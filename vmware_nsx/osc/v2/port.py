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

"""Port action implementations with nsx extensions"""

from openstackclient.network.v2 import port
from osc_lib import utils as osc_utils

from vmware_nsx._i18n import _
from vmware_nsx.osc.v2 import utils


def add_nsx_extensions_to_parser(parser, client_manager, is_create=True):
    allowed_extensions = utils.get_extensions(client_manager)
    # Provider security group (only for create action)
    if (is_create and
        'provider-security-group' in allowed_extensions):
        parser.add_argument(
            '--provider-security-group',
            metavar='<provider-security-group>',
            action='append',
            dest='provider_security_groups',
            help=_("Provider Security group to associate with this port "
                   "(name or ID) "
                   "(repeat option to set multiple security groups)")
        )
    if 'vnic-index' in allowed_extensions:
        # vnic index
        parser.add_argument(
            '--vnic-index',
            type=int,
            metavar='<vnic-index>',
            help=_("Vnic index")
        )
    if 'mac-learning' in allowed_extensions:
        # mac-learning-enabled
        mac_learning_group = parser.add_mutually_exclusive_group()
        mac_learning_group.add_argument(
            '--enable-mac-learning',
            action='store_true',
            help=_("Enable MAC learning")
        )
        mac_learning_group.add_argument(
            '--disable-mac-learning',
            action='store_true',
            help=_("Disable MAC learning (Default")
        )


# overriding the port module global method, to add the nsx extensions
super_get_attrs = port._get_attrs


def _get_plugin_attrs(client_manager, parsed_args):
    allowed_extensions = utils.get_extensions(client_manager)
    attrs = super_get_attrs(client_manager, parsed_args)
    # Provider security groups
    if 'provider-security-group' in allowed_extensions:
        if (hasattr(parsed_args, 'provider_security_groups') and
            parsed_args.provider_security_groups is not None):
            attrs['provider_security_groups'] = [
                client_manager.network.find_security_group(
                    sg, ignore_missing=False).id
                for sg in parsed_args.provider_security_groups]

    if 'vnic-index' in allowed_extensions:
        # Vnic index
        if parsed_args.vnic_index is not None:
            attrs['vnic_index'] = parsed_args.vnic_index
            parsed_args.vnic_index = None
    if 'mac-learning' in allowed_extensions:
        # mac-learning-enabled
        if parsed_args.enable_mac_learning:
            attrs['mac_learning_enabled'] = True
        if parsed_args.disable_mac_learning:
            attrs['mac_learning_enabled'] = False

    return attrs


port._get_attrs = _get_plugin_attrs


# Update the port module global _formatters, to format provider security
# groups too
port._formatters['provider_security_groups'] = osc_utils.format_list


class NsxCreatePort(port.CreatePort):
    """Create a new port with vmware nsx extensions """

    def get_parser(self, prog_name):
        # Add the nsx attributes to the neutron port attributes
        parser = super(NsxCreatePort, self).get_parser(prog_name)
        add_nsx_extensions_to_parser(parser, self.app.client_manager,
                                     is_create=True)
        return parser


class NsxSetPort(port.SetPort):
    """Set port properties with vmware nsx extensions """

    def get_parser(self, prog_name):
        # Add the nsx attributes to the neutron port attributes
        parser = super(NsxSetPort, self).get_parser(prog_name)
        add_nsx_extensions_to_parser(parser, self.app.client_manager,
                                     is_create=False)
        return parser
