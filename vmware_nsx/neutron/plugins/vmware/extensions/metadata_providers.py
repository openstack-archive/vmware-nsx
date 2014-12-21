# Copyright 2014 VMware, Inc.  All rights reserved.
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


# Attribute Map
METADATA_PROVIDERS = 'metadata_providers'


EXTENDED_ATTRIBUTES_2_0 = {
    'subnets': {
        METADATA_PROVIDERS:
        {'allow_post': False,
         'allow_put': False,
         'is_visible': True,
         'default': None}}}


class Metadata_providers(object):
    @classmethod
    def get_name(cls):
        return "Metadata Providers"

    @classmethod
    def get_alias(cls):
        return "metadata-providers"

    @classmethod
    def get_description(cls):
        return ("Id of the metadata providers attached to the subnet")

    @classmethod
    def get_namespace(cls):
        return(
            "http://docs.openstack.org/ext/neutron/metadata_providers/api/v1.0"
        )

    @classmethod
    def get_updated(cls):
        return "2014-12-11T12:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
