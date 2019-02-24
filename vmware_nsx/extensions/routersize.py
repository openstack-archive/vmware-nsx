# Copyright 2015 VMware, Inc.  All rights reserved.
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


ALIAS = 'nsxv-router-size'
ROUTER_SIZE = 'router_size'
VALID_EDGE_SIZES = ['compact', 'large', 'xlarge', 'quadlarge']
EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        ROUTER_SIZE: {'allow_post': True, 'allow_put': True,
                      'validate': {'type:values': VALID_EDGE_SIZES},
                      'default': constants.ATTR_NOT_SPECIFIED,
                      'is_visible': True},
    }
}


class Routersize(extensions.ExtensionDescriptor):
    """Extension class supporting router size."""

    @classmethod
    def get_name(cls):
        return "Router Size"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return "Enables configuration of NSXv Edge Size"

    @classmethod
    def get_updated(cls):
        return "2015-9-22T10:00:00-00:00"

    def get_required_extensions(self):
        return ["router"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        return {}
