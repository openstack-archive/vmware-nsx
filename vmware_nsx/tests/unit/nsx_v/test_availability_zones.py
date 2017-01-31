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

    def _config_az(self, resource_pool_id="respool", datastore_id="datastore",
                   edge_ha=True, ha_datastore_id="hastore",
                   ha_placement_random=False,
                   backup_edge_pool=DEF_AZ_POOL):
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
        if backup_edge_pool is not None:
            cfg.CONF.set_override("backup_edge_pool", backup_edge_pool,
                                  group=self.group_name)

    def test_simple_availability_zone(self):
        self._config_az()
        az = nsx_az.ConfiguredAvailabilityZone(self.az_name)
        self.assertEqual(self.az_name, az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertEqual(True, az.edge_ha)
        self.assertEqual("hastore", az.ha_datastore_id)
        self.assertEqual(False, az.ha_placement_random)
        self.assertEqual(DEF_AZ_POOL, az.backup_edge_pool)

    def test_availability_zone_no_edge_ha(self):
        self._config_az(edge_ha=False)
        az = nsx_az.ConfiguredAvailabilityZone(self.az_name)
        self.assertEqual(self.az_name, az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertEqual(False, az.edge_ha)
        self.assertEqual(None, az.ha_datastore_id)
        self.assertEqual(False, az.ha_placement_random)

    def test_availability_zone_no_ha_datastore(self):
        self._config_az(ha_datastore_id=None)
        az = nsx_az.ConfiguredAvailabilityZone(self.az_name)
        self.assertEqual(self.az_name, az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertEqual(True, az.edge_ha)
        self.assertEqual(None, az.ha_datastore_id)
        self.assertEqual(False, az.ha_placement_random)

    def test_missing_group_section(self):
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.ConfiguredAvailabilityZone,
            "doesnt_exist")

    def test_availability_zone_missing_respool(self):
        self._config_az(resource_pool_id=None)
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.ConfiguredAvailabilityZone,
            self.az_name)

    def test_availability_zone_missing_datastore(self):
        self._config_az(datastore_id=None)
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.ConfiguredAvailabilityZone,
            self.az_name)

    def test_availability_zone_missing_edge_ha(self):
        self._config_az(edge_ha=None)
        az = nsx_az.ConfiguredAvailabilityZone(self.az_name)
        self.assertEqual(self.az_name, az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertEqual(False, az.edge_ha)
        self.assertEqual(None, az.ha_datastore_id)
        self.assertEqual(False, az.ha_placement_random)

    def test_availability_zone_missing_edge_placement(self):
        self._config_az(ha_placement_random=None)
        az = nsx_az.ConfiguredAvailabilityZone(self.az_name)
        self.assertEqual(self.az_name, az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertEqual(True, az.edge_ha)
        self.assertEqual("hastore", az.ha_datastore_id)
        # ha_placement_random should have the global value
        self.assertEqual(True, az.ha_placement_random)

    def test_availability_zone_missing_backup_pool(self):
        self._config_az(backup_edge_pool=None)
        az = nsx_az.ConfiguredAvailabilityZone(self.az_name)
        self.assertEqual(self.az_name, az.name)
        # Should use the global configuration instead
        self.assertEqual(DEF_GLOBAL_POOL, az.backup_edge_pool)


class NsxvAvailabilityZonesOldTestCase(base.BaseTestCase):
    """Test old way of configuring the availability zones

    using a one-line configuration instead of different dynamic sections
    """

    def test_simple_availability_zone(self):
        az = nsx_az.ConfiguredAvailabilityZone(
            "name:respool:datastore:true:hastore")
        self.assertEqual("name", az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertEqual(True, az.edge_ha)
        self.assertEqual("hastore", az.ha_datastore_id)
        self.assertEqual(False, az.ha_placement_random)
        self.assertEqual(DEF_GLOBAL_POOL, az.backup_edge_pool)

    def test_availability_zone_without_ha_datastore(self):
        az = nsx_az.ConfiguredAvailabilityZone(
            "name:respool:datastore:true")
        self.assertEqual("name", az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertEqual(True, az.edge_ha)
        self.assertIsNone(az.ha_datastore_id)

    def test_availability_zone_without_edge_ha(self):
        az = nsx_az.ConfiguredAvailabilityZone(
            "name:respool:datastore:FALSE")
        self.assertEqual("name", az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertEqual(False, az.edge_ha)
        self.assertIsNone(az.ha_datastore_id)

    def test_availability_fail_long_name(self):
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.ConfiguredAvailabilityZone,
            "very-very-very-very-very-longest-name:respool:da:true:ha")

    def test_availability_fail_few_args(self):
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.ConfiguredAvailabilityZone,
            "name:respool")

    def test_availability_fail_many_args(self):
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.ConfiguredAvailabilityZone,
            "name:1:2:3:4:5:6")

    def test_availability_fail_bad_edge_ha(self):
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.ConfiguredAvailabilityZone,
            "name:respool:datastore:truex:hastore")

    def test_availability_fail_no_ha_datastore(self):
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.ConfiguredAvailabilityZone,
            "name:respool:datastore:false:hastore")
