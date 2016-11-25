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

from neutron_lib.api import extensions
from neutron_lib.db import constants as db_const

# The attributes map is here for 2 reasons:
# 1) allow posting id for the different objects we are importing
# 2) make sure security-group named 'default' is also copied

ID_WITH_POST = {'allow_post': True, 'allow_put': False,
                'validate': {'type:uuid': None},
                'is_visible': True,
                'primary_key': True}

RESOURCE_ATTRIBUTE_MAP = {
    'ports': {
        'id': ID_WITH_POST,
    },
    'networks': {
        'id': ID_WITH_POST,
    },
    'security_groups': {
        'id': ID_WITH_POST,
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': '',
                 'validate': {'type:string': db_const.NAME_FIELD_SIZE}},
    },
    'security_group_rules': {
        'id': ID_WITH_POST,
    },
    'routers': {
        'id': ID_WITH_POST,
    },
    'policies': {  # QoS policies
        'id': ID_WITH_POST,
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

    def get_required_extensions(self):
        # make sure this extension is called after those, so our change
        # will not be overridden
        return ["security-group", "router"]

    def get_optional_extensions(self):
        # QoS is optional since it is not always enabled
        return ["qos"]
