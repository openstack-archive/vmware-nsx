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

from neutron.tests import base

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.plugins.nsx_v import availability_zones as nsx_az


class NsxvAvailabilityZonesTestCase(base.BaseTestCase):

    def test_simple_availability_zone(self):
        az = nsx_az.ConfiguredAvailabilityZone(
            "name:respool:datastore:true:hastore")
        self.assertEqual("name", az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertEqual(True, az.edge_ha)
        self.assertEqual("hastore", az.ha_datastore_id)

    def test_availability_zone_without_ha_datastore(self):
        az = nsx_az.ConfiguredAvailabilityZone(
            "name:respool:datastore:true")
        self.assertEqual("name", az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertEqual(True, az.edge_ha)
        self.assertEqual(None, az.ha_datastore_id)

    def test_availability_zone_without_edge_ha(self):
        az = nsx_az.ConfiguredAvailabilityZone(
            "name:respool:datastore:FALSE")
        self.assertEqual("name", az.name)
        self.assertEqual("respool", az.resource_pool)
        self.assertEqual("datastore", az.datastore_id)
        self.assertEqual(False, az.edge_ha)
        self.assertEqual(None, az.ha_datastore_id)

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
