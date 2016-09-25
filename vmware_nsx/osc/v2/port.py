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

from vmware_nsx._i18n import _
from vmware_nsx.osc.v2 import utils


def add_nsx_extensions_to_parser(parser, client_manager):
    # Provider security group
    if 'provider-security-group' in utils.get_extensions(client_manager):
        parser.add_argument(
            '--provider-security-groups',
            metavar='<provider-security-groups>',
            action='append',
            dest='provider_security_groups',
            help=_("Provider security groups")
        )
    if 'vnic-index' in utils.get_extensions(client_manager):
        # vnic index
        parser.add_argument(
            '--vnic-index',
            type=int,
            metavar='<vnic-index>',
            help=_("Vnic index")
        )


# overriding the port module global method, to add the nsx extensions
super_get_attrs = port._get_attrs


def _get_plugin_attrs(client_manager, parsed_args):
    attrs = super_get_attrs(client_manager, parsed_args)
    # Provider security groups
    if 'provider-security-group' in utils.get_extensions(client_manager):
        if parsed_args.provider_security_groups is not None:
            attrs['provider_security_groups'] = (
                parsed_args.provider_security_groups)
            parsed_args.provider_security_groups = None
    if 'vnic-index' in utils.get_extensions(client_manager):
        # Vnic index
        if parsed_args.vnic_index is not None:
            attrs['vnic_index'] = parsed_args.vnic_index
            parsed_args.vnic_index = None

    return attrs


port._get_attrs = _get_plugin_attrs


class NsxCreatePort(port.CreatePort):
    """Create a new port with vmware nsx extensions """

    def get_parser(self, prog_name):
        # Add the nsx attributes to the neutron port attributes
        parser = super(NsxCreatePort, self).get_parser(prog_name)
        add_nsx_extensions_to_parser(parser, self.app.client_manager)
        return parser


class NsxSetPort(port.SetPort):
    """Set port properties with vmware nsx extensions """

    def get_parser(self, prog_name):
        # Add the nsx attributes to the neutron port attributes
        parser = super(NsxSetPort, self).get_parser(prog_name)
        add_nsx_extensions_to_parser(parser, self.app.client_manager)
        return parser
