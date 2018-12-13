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

from oslo_config import cfg

from vmware_nsx.common import availability_zones as common_az
from vmware_nsx.plugins.common_v3 import availability_zones as v3_az


DEFAULT_NAME = common_az.DEFAULT_NAME + 'v3'


class NsxPAvailabilityZone(v3_az.NsxV3AvailabilityZone):

    def init_defaults(self):
        # use the default configuration
        self.metadata_proxy = cfg.CONF.nsx_p.metadata_proxy
        self.dhcp_profile = cfg.CONF.nsx_p.dhcp_profile
        self.native_metadata_route = cfg.CONF.nsx_p.native_metadata_route
        self.default_overlay_tz = cfg.CONF.nsx_p.default_overlay_tz
        self.default_vlan_tz = cfg.CONF.nsx_p.default_vlan_tz
        self.default_tier0_router = cfg.CONF.nsx_p.default_tier0_router


class NsxPAvailabilityZones(common_az.ConfiguredAvailabilityZones):

    default_name = DEFAULT_NAME

    def __init__(self):
        default_azs = cfg.CONF.default_availability_zones
        super(NsxPAvailabilityZones, self).__init__(
            cfg.CONF.nsx_p.availability_zones,
            NsxPAvailabilityZone,
            default_availability_zones=default_azs)
