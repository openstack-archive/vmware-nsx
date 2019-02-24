# Copyright 2016 VMware, Inc.  All rights reserved.
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

from neutron_lib.api import extensions
from neutron_lib import constants

DHCP_MTU = 'dhcp_mtu'
ALIAS = 'dhcp-mtu'
EXTENDED_ATTRIBUTES_2_0 = {
    'subnets': {
        DHCP_MTU: {
            'allow_post': True, 'allow_put': True,
            'default': constants.ATTR_NOT_SPECIFIED,
            # This is the legal range for the backend MTU
            'validate': {'type:range': (68, 65535)},
            'is_visible': True},
    }
}


class Dhcp_mtu(extensions.ExtensionDescriptor):
    """Extension class supporting DHCP MTU for subnets."""

    @classmethod
    def get_name(cls):
        return "DHCP MTU"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return "Enable the ability to add DHCP MTU for Subnets"

    @classmethod
    def get_updated(cls):
        return "2016-7-21T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        return {}
