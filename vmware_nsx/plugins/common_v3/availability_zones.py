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

from vmware_nsx._i18n import _
from vmware_nsx.common import availability_zones as common_az
from vmware_nsx.common import exceptions as nsx_exc


class NsxV3AvailabilityZone(common_az.ConfiguredAvailabilityZone):

    def init_from_config_line(self, config_line):
        # Not supported for nsx_v3 (old configuration)
        raise nsx_exc.NsxInvalidConfiguration(
            opt_name="availability_zones",
            opt_value=config_line,
            reason=_("Expected a list of names"))

    def _has_native_dhcp_metadata(self):
        # May be overriden by children
        return True

    def get_az_opts(self):
        # Should be implemented by children
        pass

    def init_from_config_section(self, az_name):
        az_info = self.get_az_opts()

        if self._has_native_dhcp_metadata():
            # The optional parameters will get the global values if not
            # defined for this AZ
            self.metadata_proxy = az_info.get('metadata_proxy')
            if not self.metadata_proxy:
                raise nsx_exc.NsxInvalidConfiguration(
                    opt_name="metadata_proxy",
                    opt_value='None',
                    reason=(_("metadata_proxy for availability zone %s "
                              "must be defined") % az_name))

            self.dhcp_profile = az_info.get('dhcp_profile')
            if not self.dhcp_profile:
                raise nsx_exc.NsxInvalidConfiguration(
                    opt_name="dhcp_profile",
                    opt_value='None',
                    reason=(_("dhcp_profile for availability zone %s "
                              "must be defined") % az_name))

            native_metadata_route = az_info.get('native_metadata_route')
            if native_metadata_route:
                self.native_metadata_route = native_metadata_route
        else:
            self.metadata_proxy = None
            self.dhcp_profile = None
            self.native_metadata_route = None

        default_overlay_tz = az_info.get('default_overlay_tz')
        if default_overlay_tz:
            self.default_overlay_tz = default_overlay_tz

        default_vlan_tz = az_info.get('default_vlan_tz')
        if default_vlan_tz:
            self.default_vlan_tz = default_vlan_tz

        default_tier0_router = az_info.get('default_tier0_router')
        if default_tier0_router:
            self.default_tier0_router = default_tier0_router

        dns_domain = az_info.get('dns_domain')
        if dns_domain:
            self.dns_domain = dns_domain

        nameservers = az_info.get('nameservers')
        if nameservers:
            self.nameservers = nameservers

        edge_cluster = az_info.get('edge_cluster')
        if edge_cluster:
            self.edge_cluster = edge_cluster

    def init_defaults(self):
        # Should be implemented by children
        pass

    def _translate_dhcp_profile(self, nsxlib, search_scope=None):
        if self.dhcp_profile:
            dhcp_id = None
            if search_scope:
                # Find the TZ by its tag
                dhcp_id = nsxlib.get_id_by_resource_and_tag(
                    nsxlib.native_dhcp_profile.resource_type,
                    search_scope,
                    self.dhcp_profile)
            if not dhcp_id:
                dhcp_id = nsxlib.native_dhcp_profile.get_id_by_name_or_id(
                    self.dhcp_profile)
            self._native_dhcp_profile_uuid = dhcp_id
        else:
            self._native_dhcp_profile_uuid = None

    def _translate_metadata_proxy(self, nsxlib, search_scope=None):
        if self.metadata_proxy:
            proxy_id = None
            if search_scope:
                # Find the TZ by its tag
                proxy_id = nsxlib.get_id_by_resource_and_tag(
                    nsxlib.native_md_proxy.resource_type,
                    search_scope,
                    self.metadata_proxy)
            if not proxy_id:
                proxy_id = nsxlib.native_md_proxy.get_id_by_name_or_id(
                    self.metadata_proxy)
            self._native_md_proxy_uuid = proxy_id
        else:
            self._native_md_proxy_uuid = None

    def translate_configured_names_to_uuids(self, nsxlib):
        # May be overriden by children
        # Default implementation assumes UUID is provided in config
        # TODO(annak): refine this when we have a better picture
        # what az config is relevant for policy
        self._default_overlay_tz_uuid = self.default_overlay_tz
        self._default_vlan_tz_uuid = self.default_vlan_tz
        self._default_tier0_router = self.default_tier0_router
        self._native_dhcp_profile_uuid = self.dhcp_profile
        self._native_md_proxy_uuid = self.metadata_proxy
