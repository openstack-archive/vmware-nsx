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

from neutron.extensions import securitygroup

from neutron_lib.api import extensions
from neutron_lib import constants


ALIAS = 'secgroup-rule-local-ip-prefix'
LOCAL_IP_PREFIX = 'local_ip_prefix'

RESOURCE_ATTRIBUTE_MAP = {
    'security_group_rules': {
        LOCAL_IP_PREFIX: {
            'allow_post': True,
            'allow_put': False,
            'convert_to': securitygroup.convert_ip_prefix_to_cidr,
            'default': constants.ATTR_NOT_SPECIFIED,
            'enforce_policy': True,
            'is_visible': True}
    }
}


class Secgroup_rule_local_ip_prefix(extensions.ExtensionDescriptor):
    """Extension class to add support for specifying local-ip-prefix in a
    security-group rule.
    """

    @classmethod
    def get_name(cls):
        return "Security Group rule local ip prefix"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return ("Enable to specify the 'local-ip-prefix' when creating a "
                "security-group rule.")

    @classmethod
    def get_updated(cls):
        return "2016-03-01T10:00:00-00:00"

    def get_required_extensions(self):
        return ["security-group"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
