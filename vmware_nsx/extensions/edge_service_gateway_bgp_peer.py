# Copyright 2017 VMware, Inc.  All rights reserved.
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

import re

from neutron_lib.api import extensions
from neutron_lib.api import validators
from neutron_lib import exceptions as nexception

from vmware_nsx._i18n import _

EDGE_SERVICE_GW = 'esg_id'
EDGE_ID_MAX_LEN = 15
ALIAS = 'edge-service-gateway-bgp-peer'


def _validate_edge_service_gw_id(esg_id, valid_values=None):
    if esg_id is None:
        return
    msg = validators.validate_string(esg_id, max_len=EDGE_ID_MAX_LEN)
    if msg:
        return msg
    if re.match(r'^edge-[1-9]+[0-9]*$', esg_id) is None:
        msg = _("'%s' is not a valid edge service gateway id.") % esg_id
        return msg


validators.add_validator('validate_edge_service_gw_id',
                         _validate_edge_service_gw_id)


RESOURCE_ATTRIBUTE_MAP = {
    'bgp-peers': {
        EDGE_SERVICE_GW: {
            'allow_post': True,
            'allow_put': False,
            'default': None,
            'validate': {'type:validate_edge_service_gw_id': None},
            'enforce_policy': True,
            'is_visible': True,
            'required_by_policy': False
        }
    }
}


class BgpDisabledOnEsgPeer(nexception.InvalidInput):
    message = _("To add this peer to BGP speaker you must first enable BGP on "
                "the associated ESG - '%(esg_id)s'.")


class EsgRemoteASDoNotMatch(nexception.InvalidInput):
    message = _("Specified remote AS is '%(remote_as)s', but ESG '%(esg_id)s' "
                "is configured on AS %(esg_as)s.")


class ExternalSubnetHasGW(nexception.InvalidInput):
    message = _("Subnet '%(subnet_id)s' on external network '%(network_id)s' "
                "is configured with gateway IP, set to None before enabling "
                "BGP on the network.")


class EsgInternalIfaceDoesNotMatch(nexception.InvalidInput):
    message = _("Given BGP peer IP address doesn't match "
                "any interface on ESG '%(esg_id)s'")


class Edge_service_gateway_bgp_peer(extensions.ExtensionDescriptor):
    """Extension class to allow identifying of-peer with specificN SXv edge
    service gateway.
    """

    @classmethod
    def get_name(cls):
        return "Edge service gateway bgp peer"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return ("Adding a new (optional) attribute 'esg_id' to bgp-peer "
                "resource, where esg_id is a valid NSXv Edge service gateway "
                "id.")

    @classmethod
    def get_updated(cls):
        return "2017-04-01T10:00:00-00:00"

    def get_required_extensions(self):
        return ["bgp"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
