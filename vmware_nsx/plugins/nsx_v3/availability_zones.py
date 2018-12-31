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
from vmware_nsx.common import config
from vmware_nsx.plugins.common_v3 import availability_zones as v3_az

from vmware_nsxlib.v3 import core_resources
from vmware_nsxlib.v3 import nsx_constants as nsxlib_consts

DEFAULT_NAME = common_az.DEFAULT_NAME + 'v3'


class NsxV3AvailabilityZone(v3_az.NsxV3AvailabilityZone):

    def get_az_opts(self):
        return config.get_nsxv3_az_opts(self.name)

    def _has_native_dhcp_metadata(self):
        return cfg.CONF.nsx_v3.native_dhcp_metadata

    def init_from_config_section(self, az_name):
        super(NsxV3AvailabilityZone, self).init_from_config_section(az_name)

        az_info = self.get_az_opts()

        switching_profiles = az_info.get('switching_profiles')
        if switching_profiles:
            self.switching_profiles = switching_profiles

        edge_cluster = az_info.get('edge_cluster')
        if edge_cluster:
            self.edge_cluster = edge_cluster

        dhcp_relay_service = az_info.get('dhcp_relay_service')
        if dhcp_relay_service:
            self.dhcp_relay_service = dhcp_relay_service

    def init_defaults(self):
        # use the default configuration
        self.metadata_proxy = cfg.CONF.nsx_v3.metadata_proxy
        self.dhcp_profile = cfg.CONF.nsx_v3.dhcp_profile
        self.native_metadata_route = cfg.CONF.nsx_v3.native_metadata_route
        self.dns_domain = cfg.CONF.nsx_v3.dns_domain
        self.nameservers = cfg.CONF.nsx_v3.nameservers
        self.default_overlay_tz = cfg.CONF.nsx_v3.default_overlay_tz
        self.default_vlan_tz = cfg.CONF.nsx_v3.default_vlan_tz
        self.switching_profiles = cfg.CONF.nsx_v3.switching_profiles
        self.dhcp_relay_service = cfg.CONF.nsx_v3.dhcp_relay_service
        self.default_tier0_router = cfg.CONF.nsx_v3.default_tier0_router
        self.edge_cluster = cfg.CONF.nsx_v3.edge_cluster

    def translate_configured_names_to_uuids(self, nsxlib, search_scope=None):
        # Mandatory configurations (in AZ or inherited from global values)
        # Unless this is the default AZ, and metadata is disabled.
        if self.edge_cluster:
            edge_cluster_uuid = None
            if cfg.CONF.nsx_v3.init_objects_by_tags:
                # Find the edge cluster by its tag
                edge_cluster_uuid = nsxlib.get_id_by_resource_and_tag(
                    nsxlib.edge_cluster.resource_type,
                    cfg.CONF.nsx_v3.search_objects_scope,
                    self.edge_cluster)
            if not edge_cluster_uuid:
                edge_cluster_uuid = (nsxlib.edge_cluster
                                     .get_id_by_name_or_id(self.edge_cluster))
            self._edge_cluster_uuid = edge_cluster_uuid
        else:
            self._edge_cluster_uuid = None

        if self.default_overlay_tz:
            tz_id = None
            if search_scope:
                # Find the TZ by its tag
                resource_type = (nsxlib.transport_zone.resource_type +
                                 ' AND transport_type:OVERLAY')
                tz_id = nsxlib.get_id_by_resource_and_tag(
                    resource_type,
                    search_scope,
                    self.default_overlay_tz)
            if not tz_id:
                # Find the TZ by its name or id
                tz_id = nsxlib.transport_zone.get_id_by_name_or_id(
                    self.default_overlay_tz)
            self._default_overlay_tz_uuid = tz_id
        else:
            self._default_overlay_tz_uuid = None

        self._translate_dhcp_profile(nsxlib, search_scope=search_scope)
        self._translate_metadata_proxy(nsxlib, search_scope=search_scope)

        # Optional configurations (may be None)
        if self.default_vlan_tz:
            tz_id = None
            if search_scope:
                # Find the TZ by its tag
                resource_type = (nsxlib.transport_zone.resource_type +
                                 ' AND transport_type:VLAN')
                tz_id = nsxlib.get_id_by_resource_and_tag(
                    resource_type,
                    search_scope,
                    self.default_vlan_tz)
            if not tz_id:
                # Find the TZ by its name or id
                tz_id = nsxlib.transport_zone.get_id_by_name_or_id(
                    self.default_vlan_tz)
            self._default_vlan_tz_uuid = tz_id
        else:
            self._default_vlan_tz_uuid = None

        # switching profiles are already uuids, but we need to translate
        # those to objects
        profiles = []
        if self.switching_profiles:
            for profile in self.switching_profiles:
                nsx_profile = nsxlib.switching_profile.get(profile)
                # TODO(asarfaty): skip or alert on unsupported types
                profiles.append(core_resources.SwitchingProfileTypeId(
                        nsx_profile.get('resource_type'),
                        nsx_profile.get('id')))
        self.switching_profiles_objs = profiles

        if (self.dhcp_relay_service and
            nsxlib.feature_supported(nsxlib_consts.FEATURE_DHCP_RELAY)):
            relay_id = None
            if search_scope:
                # Find the relay service by its tag
                relay_id = nsxlib.get_id_by_resource_and_tag(
                    nsxlib.relay_service.resource_type,
                    search_scope,
                    self.dhcp_relay_service)
            if not relay_id:
                # Find the service by its name or id
                relay_id = nsxlib.relay_service.get_id_by_name_or_id(
                    self.dhcp_relay_service)
            self.dhcp_relay_service = relay_id
            # if there is a relay service - also find the server ips
            if self.dhcp_relay_service:
                self.dhcp_relay_servers = nsxlib.relay_service.get_server_ips(
                    self.dhcp_relay_service)
        else:
            self.dhcp_relay_service = None
            self.dhcp_relay_servers = None

        if self.default_tier0_router:
            rtr_id = None
            if search_scope:
                # Find the router by its tag
                resource_type = (nsxlib.logical_router.resource_type +
                                 ' AND router_type:TIER0')
                rtr_id = nsxlib.get_id_by_resource_and_tag(
                    resource_type,
                    search_scope,
                    self.default_tier0_router)
            if not rtr_id:
                # find the router by name or id
                rtr_id = nsxlib.logical_router.get_id_by_name_or_id(
                    self.default_tier0_router)
            self._default_tier0_router = rtr_id
        else:
            self._default_tier0_router = None


class NsxV3AvailabilityZones(common_az.ConfiguredAvailabilityZones):

    default_name = DEFAULT_NAME

    def __init__(self, use_tvd_config=False):
        if use_tvd_config:
            default_azs = cfg.CONF.nsx_tvd.nsx_v3_default_availability_zones
        else:
            default_azs = cfg.CONF.default_availability_zones
        super(NsxV3AvailabilityZones, self).__init__(
            cfg.CONF.nsx_v3.availability_zones,
            NsxV3AvailabilityZone,
            default_availability_zones=default_azs)

    def dhcp_relay_configured(self):
        for az in self.availability_zones.values():
            if az.dhcp_relay_service:
                return True
        return False
