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

"""Router action implementations with nsx extensions"""

from openstackclient.network.v2 import router

from vmware_nsx._i18n import _
from vmware_nsx.extensions import routersize
from vmware_nsx.extensions import routertype
from vmware_nsx.osc.v2 import utils


def add_nsx_extensions_to_parser(parser, client_manager):
    if 'nsxv-router-size' in utils.get_extensions(client_manager):
        # router-size
        parser.add_argument(
            '--router-size',
            metavar='<router-size>',
            choices=routersize.VALID_EDGE_SIZES,
            help=_("Router Size")
        )
    if 'nsxv-router-type' in utils.get_extensions(client_manager):
        # router-type
        parser.add_argument(
            '--router-type',
            metavar='<router-type>',
            choices=routertype.VALID_TYPES,
            help=_("Router Type")
        )


# overriding the router module global method, to add the nsx extensions
super_get_attrs = router._get_attrs


def _get_plugin_attrs(client_manager, parsed_args):
    attrs = super_get_attrs(client_manager, parsed_args)

    if 'nsxv-router-type' in utils.get_extensions(client_manager):
        # Router type
        if parsed_args.router_type is not None:
            attrs['router_type'] = parsed_args.router_type
            parsed_args.router_type = None
    if 'nsxv-router-size' in utils.get_extensions(client_manager):
        # Router size
        if parsed_args.router_size is not None:
            attrs['router_size'] = parsed_args.router_size
            parsed_args.router_size = None

    return attrs


router._get_attrs = _get_plugin_attrs


class NsxCreateRouter(router.CreateRouter):
    """Create a new router with vmware nsx extensions """

    def get_parser(self, prog_name):
        # Add the nsx attributes to the neutron router attributes
        parser = super(NsxCreateRouter, self).get_parser(prog_name)
        add_nsx_extensions_to_parser(parser, self.app.client_manager)
        return parser


class NsxSetRouter(router.SetRouter):
    """Set router properties with vmware nsx extensions """

    def get_parser(self, prog_name):
        # Add the nsx attributes to the neutron router attributes
        parser = super(NsxSetRouter, self).get_parser(prog_name)
        add_nsx_extensions_to_parser(parser, self.app.client_manager)
        return parser
