# Copyright 2017 VMware, Inc.
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

import abc

from neutron.api.v2 import resource_helper
from neutron_lib.api import extensions
from neutron_lib import exceptions as nexception

from vmware_nsx._i18n import _


HOUSEKEEPER_RESOURCE_NAME = "housekeeper"
HOUSEKEEPERS = "housekeepers"
ALIAS = 'housekeeper'

# The housekeeper tasks table is read only
RESOURCE_ATTRIBUTE_MAP = {
    HOUSEKEEPERS: {
        'name': {
            'allow_post': False, 'allow_put': False, 'is_visible': True},
        'description': {
            'allow_post': False, 'allow_put': False, 'is_visible': True},
        'enabled': {
            'allow_post': False, 'allow_put': False, 'is_visible': True},
        'error_count': {
            'allow_post': False, 'allow_put': False, 'is_visible': True},
        'fixed_count': {
            'allow_post': False, 'allow_put': False, 'is_visible': True},
        'error_info': {
            'allow_post': False, 'allow_put': False, 'is_visible': True},
    }
}


class Housekeeper(extensions.ExtensionDescriptor):
    """API extension for NSX housekeeper jobs."""

    @classmethod
    def get_name(cls):
        return "Housekeeper"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return "NSX plugin housekeeping services."

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


class HousekeeperReadOnly(nexception.NotAuthorized):
    message = _("NSX housekeeper tasks are read-only.")


class HousekeeperPluginBase(object):

    @abc.abstractmethod
    def create_housekeeper(self, context, housekeeper):
        raise HousekeeperReadOnly()

    @abc.abstractmethod
    def update_housekeeper(self, context, name, housekeeper):
        pass

    @abc.abstractmethod
    def get_housekeeper(self, context, name, fields=None):
        pass

    @abc.abstractmethod
    def delete_housekeeper(self, context, name):
        raise HousekeeperReadOnly()

    @abc.abstractmethod
    def get_housekeepers(self, context, filters=None, fields=None,
                         sorts=None, limit=None, marker=None,
                         page_reverse=False):
        pass

    @abc.abstractmethod
    def get_housekeeper_count(self, context, filters=None):
        pass
