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

from neutron_lib.api import converters
from neutron_lib.api import extensions

ALIAS = 'security-group-logging'
LOGGING = 'logging'

RESOURCE_ATTRIBUTE_MAP = {
    'security_groups': {
        LOGGING: {
            'allow_post': True,
            'allow_put': True,
            'convert_to': converters.convert_to_boolean,
            'default': False,
            'enforce_policy': True,
            'is_visible': True}
    }
}


class Securitygrouplogging(extensions.ExtensionDescriptor):
    """Security group logging extension."""

    @classmethod
    def get_name(cls):
        return "Security group logging"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return "Security group logging extension."

    @classmethod
    def get_namespace(cls):
        # todo
        return "https://docs.openstack.org/ext/security_group_logging/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2015-04-13T10:00:00-00:00"

    def get_required_extensions(self):
        return ["security-group"]

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        return []

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
