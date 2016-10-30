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

"""Subnet extensions action implementations"""

from openstackclient.network.v2 import subnet

from vmware_nsx._i18n import _
from vmware_nsx.osc.v2 import utils


def add_nsx_extensions_to_parser(parser, client_manager):
    if 'dhcp-mtu' in utils.get_extensions(client_manager):
        # DHCP MTU
        parser.add_argument(
            '--dhcp-mtu',
            type=int,
            metavar='<dhcp-mtu>',
            help=_("DHCP MTU")
        )
    if 'dns-search-domain' in utils.get_extensions(client_manager):
        # DNS search domain
        parser.add_argument(
            '--dns-search-domain',
            metavar='<domain-name>',
            help=_("DNS search Domain")
        )


# overriding the subnet module global method, to add the nsx extensions
super_get_attrs = subnet._get_attrs


def _get_plugin_attrs(client_manager, parsed_args, is_create=True):
    attrs = super_get_attrs(client_manager, parsed_args, is_create)

    if 'dhcp-mtu' in utils.get_extensions(client_manager):
        # DHCP MTU
        if parsed_args.dhcp_mtu is not None:
            attrs['dhcp_mtu'] = int(parsed_args.dhcp_mtu)
            parsed_args.dhcp_mtu = None
    if 'dns-search-domain' in utils.get_extensions(client_manager):
        # DNS search domain
        if parsed_args.dns_search_domain is not None:
            attrs['dns_search_domain'] = parsed_args.dns_search_domain
            parsed_args.dns_search_domain = None

    return attrs


subnet._get_attrs = _get_plugin_attrs


class NsxCreateSubnet(subnet.CreateSubnet):
    """Create a new subnet with vmware nsx extensions """

    def get_parser(self, prog_name):
        # Add the nsx attributes to the neutron subnet attributes
        parser = super(NsxCreateSubnet, self).get_parser(prog_name)
        add_nsx_extensions_to_parser(parser, self.app.client_manager)
        return parser


class NsxSetSubnet(subnet.SetSubnet):
    """Set subnet properties with vmware nsx extensions """

    def get_parser(self, prog_name):
        # Add the nsx attributes to the neutron subnet attributes
        parser = super(NsxSetSubnet, self).get_parser(prog_name)
        add_nsx_extensions_to_parser(parser, self.app.client_manager)
        return parser
