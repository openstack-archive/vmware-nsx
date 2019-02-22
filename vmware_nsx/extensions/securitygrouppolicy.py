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
from neutron_lib import exceptions as nexception

from vmware_nsx._i18n import _


ALIAS = 'security-group-policy'
POLICY = 'policy'

RESOURCE_ATTRIBUTE_MAP = {
    'security_groups': {
        POLICY: {
            'allow_post': True,
            'allow_put': True,
            'enforce_policy': True,
            'is_visible': True,
            'default': None}
    }
}


class PolicySecurityGroupDeleteNotAdmin(nexception.NotAuthorized):
    message = _("Security group %(id)s is a policy security group and "
                "requires an admin to delete it.")


class Securitygrouppolicy(extensions.ExtensionDescriptor):
    """Security group policy extension."""

    @classmethod
    def get_name(cls):
        return "Security group policy"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return "Security group policy extension."

    @classmethod
    def get_updated(cls):
        return "2016-10-06T10:00:00-00:00"

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
