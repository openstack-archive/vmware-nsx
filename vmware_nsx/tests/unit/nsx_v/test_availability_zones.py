# Copyright 2016 VMware, Inc.
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

from neutron.tests import base

from vmware_nsx.common import config
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.plugins.nsx_v import availability_zones as nsx_az


DEF_AZ_POOL = ['service:compact:1:2', 'vdr:compact:1:2']
DEF_GLOBAL_POOL = ['service:compact:4:10', 'vdr:compact:4:10']


class NsxvAvailabilityZonesTestCase(base.BaseTestCase):

    def setUp(self):
        super(NsxvAvailabilityZonesTestCase, self).setUp()
        self.az_name = 'zone1'
        self.group_name = 'az:%s' % self.az_name
        config.register_nsxv_azs(cfg.CONF, [self.az_name])
        cfg.CONF.set_override("ha_placement_random", True, group="nsxv")
        cfg.CONF.set_override("mgt_net_proxy_ips", ["2.2.2.2"], group="nsxv")
        cfg.CONF.set_override("dvs_id", "dvs-1", group="nsxv")

    def _config_az(self,
                   resource_pool_id="respool",
                   datastore_id="datastore",
                   edge_ha=True,
                   ha_datastore_id="hastore",
                   backup_edge_pool=DEF_AZ_POOL,
                   ha_placement_random=False,
                   datacenter_moid="datacenter",
                   mgt_net_moid="portgroup-407",
                   mgt_net_proxy_ips=["1.1.1.1"],
                   mgt_net_proxy_netmask="255.255.255.0",
                   mgt_net_default_gateway="2.2.2.2",
                   external_network="network-17",
                   vdn_scope_id="vdnscope-1",
                   dvs_id="dvs-2"):
        cfg.CONF.set_override("resource_pool_id", resource_pool_id,
                              group=self.group_name)
        cfg.CONF.set_override("datastore_id", datastore_id,
                              group=self.group_name)
        if edge_ha is not None:
            cfg.CONF.set_override("edge_ha", edge_ha,
                                  group=self.group_name)
        cfg.CONF.set_override("ha_datastore_id", ha_datastore_id,
                              group=self.group_name)
        if ha_placement_random is not None:
            cfg.CONF.set_override("ha_placement_random",
                                  ha_placement_random,
                                  group=self.group_name)
        if datacenter_moid is not None:
            cfg.CONF.set_override("datacenter_moid",
                                  datacenter_moid,
                                  group=self.group_name)
        if backup_edge_pool is not None:
            cfg.CONF.set_override("backup_edge_pool", backup_edge_pool,
                                  group=self.group_name)
        if mgt_net_moid is not None:
            cfg.CONF.set_override("mgt_net_moid", mgt_net_moid,
                                  group=self.group_name)
        if mgt_net_proxy_ips is not None:
            cfg.CONF.set_override("mgt_net_proxy_ips", mgt_net_proxy_ips,
                                  group=self.group_name)
        if mgt_net_proxy_netmask is not None:
            cfg.CONF.set_override("mgt_net_proxy_netmask",
                                  mgt_net_proxy_netmask,
                                  group=self.group_name)
        if mgt_net_default_gateway is not None:
            cfg.CONF.set_override("mgt_net_default_gateway",
                                  mgt_net_default_gateway,
                                  group=self.group_name)
        if external_network is not None:
            cfg.CONF.set_override("external_network", external_network,
                                  group=self.group_name)
        if vdn_scope_id is not None:
            cfg.CONF.set_override("vdn_scope_id", vdn_scope_id,
                                  group=self.group_name)
        if dvs_id is not None:
            cfg.CONF.set_override("dvs_id", dvs_id,
                                  group=self.group_name)

    def test_simple_availability_zone(self):
        self._config_az()
        az = nsx_az.NsxVAvailabilityZone(self.az_name)
        self.assertEqual(self.az_name, az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertTrue(az.edge_ha)
        self.assertEqual("hastore", az.ha_datastore_id)
        self.assertFalse(az.ha_placement_random)
        self.assertEqual("datacenter", az.datacenter_moid)
        self.assertEqual(DEF_AZ_POOL, az.backup_edge_pool)
        self.assertEqual("portgroup-407", az.mgt_net_moid)
        self.assertEqual(["1.1.1.1"], az.mgt_net_proxy_ips)
        self.assertEqual("255.255.255.0", az.mgt_net_proxy_netmask)
        self.assertEqual("2.2.2.2", az.mgt_net_default_gateway)
        self.assertEqual("network-17", az.external_network)
        self.assertEqual("vdnscope-1", az.vdn_scope_id)
        self.assertEqual("dvs-2", az.dvs_id)
        self.assertTrue(az.az_metadata_support)

    def test_availability_zone_no_edge_ha(self):
        self._config_az(edge_ha=False)
        az = nsx_az.NsxVAvailabilityZone(self.az_name)
        self.assertEqual(self.az_name, az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertFalse(az.edge_ha)
        self.assertIsNone(az.ha_datastore_id)
        self.assertFalse(az.ha_placement_random)

    def test_availability_zone_no_ha_datastore(self):
        self._config_az(ha_datastore_id=None)
        az = nsx_az.NsxVAvailabilityZone(self.az_name)
        self.assertEqual(self.az_name, az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertTrue(az.edge_ha)
        self.assertIsNone(az.ha_datastore_id)
        self.assertFalse(az.ha_placement_random)

    def test_missing_group_section(self):
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.NsxVAvailabilityZone,
            "doesnt_exist")

    def test_availability_zone_missing_respool(self):
        self._config_az(resource_pool_id=None)
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.NsxVAvailabilityZone,
            self.az_name)

    def test_availability_zone_missing_datastore(self):
        self._config_az(datastore_id=None)
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.NsxVAvailabilityZone,
            self.az_name)

    def test_availability_zone_missing_edge_ha(self):
        self._config_az(edge_ha=None)
        az = nsx_az.NsxVAvailabilityZone(self.az_name)
        self.assertEqual(self.az_name, az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertFalse(az.edge_ha)
        self.assertIsNone(az.ha_datastore_id)
        self.assertFalse(az.ha_placement_random)

    def test_availability_zone_missing_edge_placement(self):
        self._config_az(ha_placement_random=None)
        az = nsx_az.NsxVAvailabilityZone(self.az_name)
        self.assertEqual(self.az_name, az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertTrue(az.edge_ha)
        self.assertEqual("hastore", az.ha_datastore_id)
        # ha_placement_random should have the global value
        self.assertTrue(az.ha_placement_random)

    def test_availability_zone_missing_backup_pool(self):
        self._config_az(backup_edge_pool=None)
        az = nsx_az.NsxVAvailabilityZone(self.az_name)
        self.assertEqual(self.az_name, az.name)
        # Should use the global configuration instead
        self.assertEqual(DEF_GLOBAL_POOL, az.backup_edge_pool)

    def test_availability_zone_missing_metadata(self):
        self._config_az(mgt_net_proxy_ips=None)
        az = nsx_az.NsxVAvailabilityZone(self.az_name)
        self.assertIsNone(az.mgt_net_moid)
        self.assertEqual([], az.mgt_net_proxy_ips)
        self.assertIsNone(az.mgt_net_proxy_netmask)
        self.assertIsNone(az.mgt_net_default_gateway)
        self.assertFalse(az.az_metadata_support)

    def test_availability_zone_same_metadata(self):
        self._config_az(mgt_net_proxy_ips=["2.2.2.2"])
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.NsxVAvailabilityZone,
            self.az_name)

        self._config_az(mgt_net_proxy_ips=["2.2.2.2", "3.3.3.3"])
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.NsxVAvailabilityZone,
            self.az_name)


class NsxvAvailabilityZonesOldTestCase(base.BaseTestCase):
    """Test old way of configuring the availability zones

    using a one-line configuration instead of different dynamic sections
    """

    def setUp(self):
        super(NsxvAvailabilityZonesOldTestCase, self).setUp()
        cfg.CONF.set_override("mgt_net_proxy_ips", ["2.2.2.2"], group="nsxv")
        cfg.CONF.set_override("dvs_id", "dvs-1", group="nsxv")

    def test_simple_availability_zone(self):
        az = nsx_az.NsxVAvailabilityZone(
            "name:respool:datastore:true:hastore")
        self.assertEqual("name", az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertTrue(az.edge_ha)
        self.assertEqual("hastore", az.ha_datastore_id)
        self.assertFalse(az.ha_placement_random)
        self.assertEqual(DEF_GLOBAL_POOL, az.backup_edge_pool)
        # should get the global configuration (which is empty now)
        self.assertIsNone(az.external_network)
        self.assertIsNone(az.vdn_scope_id)
        self.assertEqual("dvs-1", az.dvs_id)
        # no metadata per az support
        self.assertFalse(az.az_metadata_support)
        self.assertIsNone(az.mgt_net_moid)
        self.assertEqual([], az.mgt_net_proxy_ips)
        self.assertIsNone(az.mgt_net_proxy_netmask)
        self.assertIsNone(az.mgt_net_default_gateway)

    def test_availability_zone_without_ha_datastore(self):
        az = nsx_az.NsxVAvailabilityZone(
            "name:respool:datastore:true")
        self.assertEqual("name", az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertTrue(az.edge_ha)
        self.assertIsNone(az.ha_datastore_id)

    def test_availability_zone_without_edge_ha(self):
        az = nsx_az.NsxVAvailabilityZone(
            "name:respool:datastore:FALSE")
        self.assertEqual("name", az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertFalse(az.edge_ha)
        self.assertIsNone(az.ha_datastore_id)

    def test_availability_fail_long_name(self):
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.NsxVAvailabilityZone,
            "very-very-very-very-very-longest-name:respool:da:true:ha")

    def test_availability_fail_few_args(self):
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.NsxVAvailabilityZone,
            "name:respool")

    def test_availability_fail_many_args(self):
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.NsxVAvailabilityZone,
            "name:1:2:3:4:5:6")

    def test_availability_fail_bad_edge_ha(self):
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.NsxVAvailabilityZone,
            "name:respool:datastore:truex:hastore")

    def test_availability_fail_no_ha_datastore(self):
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.NsxVAvailabilityZone,
            "name:respool:datastore:false:hastore")
