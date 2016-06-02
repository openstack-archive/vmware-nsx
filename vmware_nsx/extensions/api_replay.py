# Copyright 2016 VMware, Inc.
#
# All Rights Reserved
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

from neutron.api import extensions


RESOURCE_ATTRIBUTE_MAP = {
    'ports': {
        'id': {'allow_post': True, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
    },
    'networks': {
        'id': {'allow_post': True, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
    },
    'security_groups': {
        'id': {'allow_post': True, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
    },
    'security_group_rules': {
        'id': {'allow_post': True, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
    },
    'routers': {
        'id': {'allow_post': True, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
    },
}


class Api_replay(extensions.ExtensionDescriptor):
    """Extension for api replay which allows us to specify ids of resources."""

    @classmethod
    def get_name(cls):
        return "Api Replay"

    @classmethod
    def get_alias(cls):
        return 'api-replay'

    @classmethod
    def get_description(cls):
        return "Enables mode to allow api to be replayed"

    @classmethod
    def get_updated(cls):
        return "2016-05-05T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
