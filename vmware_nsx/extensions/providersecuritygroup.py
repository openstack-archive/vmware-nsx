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
from neutron_lib import constants
from neutron_lib import exceptions as nexception

from vmware_nsx._i18n import _


ALIAS = 'provider-security-group'
PROVIDER = 'provider'
PROVIDER_SECURITYGROUPS = 'provider_security_groups'

EXTENDED_ATTRIBUTES_2_0 = {
    'security_groups': {
        PROVIDER: {
            'allow_post': True,
            'allow_put': False,
            'convert_to': converters.convert_to_boolean,
            'default': False,
            'enforce_policy': True,
            'is_visible': True}
    },
    'ports': {PROVIDER_SECURITYGROUPS: {
        'allow_post': True,
        'allow_put': True,
        'is_visible': True,
        'convert_to': converters.convert_none_to_empty_list,
        'validate': {'type:uuid_list': None},
        'default': constants.ATTR_NOT_SPECIFIED}
    }
}


NUM_PROVIDER_SGS_ON_PORT = 1


class SecurityGroupNotProvider(nexception.InvalidInput):
    message = _("Security group %(id)s is not a provider security group.")


class SecurityGroupIsProvider(nexception.InvalidInput):
    message = _("Security group %(id)s is a provider security group and "
                "cannot be specified via the security group field.")


class DefaultSecurityGroupIsNotProvider(nexception.InvalidInput):
    message = _("Can't create default security-group as a provider "
                "security-group.")


class ProviderSecurityGroupEditNotAdmin(nexception.NotAuthorized):
    message = _("Security group %(id)s is a provider security group and "
                "requires an admin to modify it.")


class Providersecuritygroup(extensions.ExtensionDescriptor):
    """Provider security-group extension."""

    @classmethod
    def get_name(cls):
        return "Provider security group"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return "Admin controlled security groups with blocking rules."

    @classmethod
    def get_updated(cls):
        return "2016-07-13T10:00:00-00:00"

    def get_required_extensions(self):
        return ["security-group"]

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        return []

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
