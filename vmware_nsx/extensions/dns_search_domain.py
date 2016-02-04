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

from neutron.api import extensions
from neutron.api.v2 import attributes


DNS_SEARCH_DOMAIN = 'dns_search_domain'
EXTENDED_ATTRIBUTES_2_0 = {
    'subnets': {
        DNS_SEARCH_DOMAIN: {'allow_post': True, 'allow_put': True,
                            'default': attributes.ATTR_NOT_SPECIFIED,
                            'validate': {'type:string': None},
                            'is_visible': True},
    }
}


class Dns_search_domain(extensions.ExtensionDescriptor):
    """Extension class supporting dns search domains for subnets."""

    @classmethod
    def get_name(cls):
        return "DNS search Domains"

    @classmethod
    def get_alias(cls):
        return "dns-search-domain"

    @classmethod
    def get_description(cls):
        return "Enable the ability to add DNS search domain name for Subnets"

    @classmethod
    def get_updated(cls):
        return "2016-1-22T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        return {}
