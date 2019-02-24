# Copyright 2016 VMware.  All rights reserved.
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

import abc

from neutron.api.v2 import resource_helper
from neutron_lib.api import extensions
from neutron_lib import exceptions as nexception

from vmware_nsx._i18n import _

POLICY_RESOURCE_NAME = "nsx_policy"
# Use dash for alias and collection name
ALIAS = POLICY_RESOURCE_NAME.replace('_', '-')
NSX_POLICIES = "nsx_policies"

# The nsx-policies table is read only
RESOURCE_ATTRIBUTE_MAP = {
    NSX_POLICIES: {
        'id': {
            'allow_post': False, 'allow_put': False, 'is_visible': True},
        'name': {
            'allow_post': False, 'allow_put': False, 'is_visible': True},
        'description': {
            'allow_post': False, 'allow_put': False, 'is_visible': True},
    }
}


class Nsxpolicy(extensions.ExtensionDescriptor):
    """API extension for NSX policies."""

    @classmethod
    def get_name(cls):
        return "NSX Policy"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return "NSX security policies."

    @classmethod
    def get_updated(cls):
        return "2016-11-20T00:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        member_actions = {}
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   None,
                                                   action_map=member_actions,
                                                   register_quota=True,
                                                   translate_name=True)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


class NsxPolicyReadOnly(nexception.NotAuthorized):
    message = _("NSX policies are read-only.")


class NsxPolicyPluginBase(object):

    @abc.abstractmethod
    def create_nsx_policy(self, context, nsx_policy):
        raise NsxPolicyReadOnly()

    @abc.abstractmethod
    def update_nsx_policy(self, context, id, nsx_policy):
        raise NsxPolicyReadOnly()

    @abc.abstractmethod
    def get_nsx_policy(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def delete_nsx_policy(self, context, id):
        raise NsxPolicyReadOnly()

    @abc.abstractmethod
    def get_nsx_policies(self, context, filters=None, fields=None,
                         sorts=None, limit=None, marker=None,
                         page_reverse=False):
        pass
