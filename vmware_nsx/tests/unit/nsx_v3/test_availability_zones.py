# Copyright 2017 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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
from oslo_utils import uuidutils

from neutron.tests import base

from vmware_nsx.common import config
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.plugins.nsx_v3 import availability_zones as nsx_az


class Nsxv3AvailabilityZonesTestCase(base.BaseTestCase):

    def setUp(self):
        super(Nsxv3AvailabilityZonesTestCase, self).setUp()
        self.az_name = "zone1"
        self.group_name = "az:%s" % self.az_name
        config.register_nsxv3_azs(cfg.CONF, [self.az_name])
        self.global_md_proxy = uuidutils.generate_uuid()
        cfg.CONF.set_override(
            "metadata_proxy", self.global_md_proxy, group="nsx_v3")
        self.global_dhcp_profile = uuidutils.generate_uuid()
        cfg.CONF.set_override(
            "dhcp_profile", self.global_dhcp_profile, group="nsx_v3")
        cfg.CONF.set_override(
            "native_metadata_route", "1.1.1.1", group="nsx_v3")
        cfg.CONF.set_override("dns_domain", "xxx.com", group="nsx_v3")
        cfg.CONF.set_override("nameservers", ["10.1.1.1"], group="nsx_v3")
        cfg.CONF.set_override("switching_profiles", ["uuid1"], group="nsx_v3")
        cfg.CONF.set_override("dhcp_relay_service", "service1", group="nsx_v3")
        cfg.CONF.set_override(
            "default_tier0_router", "uuidrtr1", group="nsx_v3")

    def _config_az(self,
                   metadata_proxy="metadata_proxy1",
                   dhcp_profile="dhcp_profile1",
                   native_metadata_route="2.2.2.2",
                   dns_domain="aaa.com",
                   nameservers=["20.1.1.1"],
                   default_overlay_tz='otz',
                   default_vlan_tz='vtz',
                   switching_profiles=["uuid2"],
                   dhcp_relay_service="service2",
                   default_tier0_router="uuidrtr2"):
        if metadata_proxy is not None:
            cfg.CONF.set_override("metadata_proxy", metadata_proxy,
                                  group=self.group_name)
        if dhcp_profile is not None:
            cfg.CONF.set_override("dhcp_profile", dhcp_profile,
                                  group=self.group_name)
        if native_metadata_route is not None:
            cfg.CONF.set_override("native_metadata_route",
                                  native_metadata_route,
                                  group=self.group_name)
        if dns_domain is not None:
            cfg.CONF.set_override("dns_domain", dns_domain,
                                  group=self.group_name)
        if nameservers is not None:
            cfg.CONF.set_override("nameservers", nameservers,
                                  group=self.group_name)
        if default_overlay_tz is not None:
            cfg.CONF.set_override("default_overlay_tz", default_overlay_tz,
                                  group=self.group_name)
        if default_vlan_tz is not None:
            cfg.CONF.set_override("default_vlan_tz", default_vlan_tz,
                                  group=self.group_name)
        if switching_profiles is not None:
            cfg.CONF.set_override("switching_profiles", switching_profiles,
                                  group=self.group_name)
        if dhcp_relay_service is not None:
            cfg.CONF.set_override("dhcp_relay_service", dhcp_relay_service,
                                  group=self.group_name)
        if default_tier0_router is not None:
            cfg.CONF.set_override("default_tier0_router", default_tier0_router,
                                  group=self.group_name)

    def test_simple_availability_zone(self):
        self._config_az()
        az = nsx_az.NsxV3AvailabilityZone(self.az_name)
        self.assertEqual(self.az_name, az.name)
        self.assertEqual("metadata_proxy1", az.metadata_proxy)
        self.assertEqual("dhcp_profile1", az.dhcp_profile)
        self.assertEqual("2.2.2.2", az.native_metadata_route)
        self.assertEqual("aaa.com", az.dns_domain)
        self.assertEqual(["20.1.1.1"], az.nameservers)
        self.assertEqual("otz", az.default_overlay_tz)
        self.assertEqual("vtz", az.default_vlan_tz)
        self.assertEqual(["uuid2"], az.switching_profiles)
        self.assertEqual("service2", az.dhcp_relay_service)
        self.assertEqual("uuidrtr2", az.default_tier0_router)

    def test_missing_group_section(self):
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.NsxV3AvailabilityZone,
            "doesnt_exist")

    def test_availability_zone_missing_metadata_proxy(self):
        # Mandatory parameter
        self._config_az(metadata_proxy=None)
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.NsxV3AvailabilityZone,
            self.az_name)

    def test_availability_zone_missing_dhcp_profile(self):
        # Mandatory parameter
        self._config_az(dhcp_profile=None)
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.NsxV3AvailabilityZone,
            self.az_name)

    def test_availability_zone_missing_md_route(self):
        self._config_az(native_metadata_route=None)
        az = nsx_az.NsxV3AvailabilityZone(self.az_name)
        self.assertEqual("1.1.1.1", az.native_metadata_route)

    def test_availability_zone_missing_dns_domain(self):
        self._config_az(dns_domain=None)
        az = nsx_az.NsxV3AvailabilityZone(self.az_name)
        self.assertEqual("xxx.com", az.dns_domain)

    def test_availability_zone_missing_nameservers(self):
        self._config_az(nameservers=None)
        az = nsx_az.NsxV3AvailabilityZone(self.az_name)
        self.assertEqual(["10.1.1.1"], az.nameservers)

    def test_availability_zone_missing_profiles(self):
        self._config_az(switching_profiles=None)
        az = nsx_az.NsxV3AvailabilityZone(self.az_name)
        self.assertEqual(["uuid1"], az.switching_profiles)
