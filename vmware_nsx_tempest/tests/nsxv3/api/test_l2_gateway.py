# Copyright 2016 VMware Inc
# All Rights Reserved.
#
# Copyright 2015 OpenStack Foundation
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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest import test

from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.services import base_l2gw

LOG = constants.log.getLogger(__name__)

CONF = config.CONF


class L2GatewayTest(base_l2gw.BaseL2GatewayTest):
    """
    Test l2 gateway operations.
    """

    @test.attr(type="nsxv3")
    @test.idempotent_id("e5e3a089-602c-496e-8c17-4ef613266924")
    def test_l2_gateway_create_without_vlan(self):
        """
        Create l2gw based on UUID and bridge cluster name. It creates l2gw.
        To create l2gw we need bridge cluster name (interface name) and
        bridge cluster UUID (device name) from NSX manager.
        """
        LOG.info(_LI("Testing l2_gateway_create api"))
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        rsp, requested_devices = self.create_l2gw(l2gw_name, l2gw_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        self.assertEqual(requested_devices[0]["device_name"],
                         rsp[constants.L2GW]["devices"][0]["device_name"],
                         "Device name is not the same as expected")
        self.resource_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id("9968a529-e785-472f-8705-9b394a912e43")
    def test_l2_gateway_with_single_vlan(self):
        """
        Create l2gw based on UUID and bridge cluster name. It creates l2gw.
        To create l2gw we need bridge cluster name (interface name) and
        bridge cluster UUID (device name) from NSX manager and vlan id.
        """
        LOG.info(_LI("Testing l2_gateway_create api with segmentation ID"))
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [self.VLAN_1]}
        l2gw_param = [device_1]
        rsp, requested_devices = self.create_l2gw(l2gw_name, l2gw_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        self.assertEqual(requested_devices[0]["device_name"],
                         rsp[constants.L2GW]["devices"][0]["device_name"],
                         "Device name is not the same as expected")
        self.assertEqual(requested_devices[0]["interfaces"][0][
                             "name"],
                         rsp[constants.L2GW]["devices"][0]["interfaces"][0][
                             "name"],
                         "Interface name is not the same as expected")
        requested_vlans = \
            requested_devices[0]["interfaces"][0]["segmentation_id"]
        response_vlans = rsp[constants.L2GW]["devices"][0]["interfaces"][0][
            "segmentation_id"]
        for id in requested_vlans:
            self.assertIn(id, response_vlans)
        self.resource_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id("3861aab0-4f76-4472-ad0e-a255e6e42193")
    def test_l2_gateway_with_multiple_vlans(self):
        """
        Create l2gw based on UUID and bridge cluster name. It creates l2gw.
        To create l2gw we need bridge cluster name (interface name) and
        bridge cluster UUID (device name) from NSX manager and vlan id.
        """
        LOG.info(_LI("Testing l2_gateway_create api with segmentation ID"))
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [self.VLAN_1, self.VLAN_2]}
        l2gw_param = [device_1]
        rsp, requested_devices = self.create_l2gw(l2gw_name, l2gw_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        self.assertEqual(requested_devices[0]["device_name"],
                         rsp[constants.L2GW]["devices"][0]["device_name"],
                         "Device name is not the same as expected")
        self.assertEqual(requested_devices[0]["interfaces"][0][
                             "name"],
                         rsp[constants.L2GW]["devices"][0]["interfaces"][0][
                             "name"],
                         "Interface name is not the same as expected")
        requested_vlans = \
            requested_devices[0]["interfaces"][0]["segmentation_id"]
        response_vlans = rsp[constants.L2GW]["devices"][0]["interfaces"][0][
            "segmentation_id"]
        for id in requested_vlans:
            self.assertIn(id, response_vlans)
        self.resource_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id("670cbcb5-134e-467d-ba41-0d7cdbcf3903")
    def test_l2_gateway_delete(self):
        """
        Delete l2gw will create l2gw and delete recently created l2gw. To
        delete l2gw we need l2gw id.
        """
        LOG.info(_LI("Testing l2_gateway_delete api"))
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        # Create l2gw to delete it.
        rsp, requested_devices = self.create_l2gw(l2gw_name, l2gw_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code":
                                 constants.EXPECTED_HTTP_RESPONSE_201})
        l2gw_id = rsp[constants.L2GW]["id"]
        # Delete l2gw.
        rsp = self.delete_l2gw(l2gw_id)
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_204,
                         rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_204})
        self.l2gw_created.pop(l2gw_id)
        self.resource_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id("fa76f6e6-8aa7-46d8-9af4-2206d0773dc3")
    def test_l2_gateway_update_l2gw_name(self):
        """
        Update l2gw will update info in already created l2gw. To
        update l2gw we need l2gw id and payload to update.
        """
        LOG.info(_LI("Testing l2_gateway_update api"))
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        # Create l2gw to update l2gw name.
        rsp, requested_devices = self.create_l2gw(l2gw_name, l2gw_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code":
                                 constants.EXPECTED_HTTP_RESPONSE_201})
        devices = {"devices": [{"device_name": device_name,
                                "interfaces": [{"name": interface_name}]}]
                   }
        l2gw_id = rsp[constants.L2GW]["id"]
        l2gw_new_name = "updated_name"
        # Update l2gw name.
        update_rsp = self.update_l2gw(l2gw_id, l2gw_new_name, devices)
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_200,
                         update_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code":
                                 constants.EXPECTED_HTTP_RESPONSE_200})
        rsp_l2gw = update_rsp[constants.L2GW]
        LOG.info(_LI("response : %(rsp_l2gw)s") % {"rsp_l2gw": rsp_l2gw})
        # Assert if name is not updated.
        self.assertEqual(l2gw_new_name, rsp_l2gw["name"],
                         "l2gw name=%(rsp_name)s is not the same as "
                         "requested=%(name)s" % {"rsp_name": rsp_l2gw["name"],
                                                 "name": l2gw_new_name})
        self.resource_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id("c4977df8-8e3a-4b7e-a8d2-5aa757117658")
    def test_l2_gateway_update_interface(self):
        """
        Update l2gw will update info in already created l2gw. To
        update l2gw we need l2gw id and payload to update.
        """
        LOG.info(_LI("Testing l2_gateway_update api"))
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        # Create l2gw to update l2gw name.
        rsp, requested_devices = self.create_l2gw(l2gw_name, l2gw_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code":
                                 constants.EXPECTED_HTTP_RESPONSE_201})
        devices = {"devices": [
            {"device_name": device_name,

             "interfaces": [{"name": "new_name",
                             "segmentation_id": [self.VLAN_1]}],
             "deleted_interfaces": [{"name": interface_name}]}
        ]}
        l2gw_id = rsp[constants.L2GW]["id"]
        update_rsp = self.update_l2gw(l2gw_id, l2gw_name, devices)
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_200,
                         update_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code":
                                 constants.EXPECTED_HTTP_RESPONSE_200})
        rsp_l2gw = update_rsp[constants.L2GW]
        self.l2gw_created[rsp_l2gw["id"]] = rsp_l2gw
        LOG.info(_LI("response : %(rsp_l2gw)s") % {"rsp_l2gw": rsp_l2gw})
        if "segmentation_id" in devices["devices"][0]["interfaces"][0]:
            self.assertEqual(devices["devices"][0]["interfaces"][0][
                                 "segmentation_id"][0],
                             rsp_l2gw["devices"][0]["interfaces"][0][
                                 "segmentation_id"][0],
                             "L2GW segmentation id update failed!!!")
        self.resource_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id("5a3cef97-c91c-4e03-92c8-d180f9269f27")
    def test_l2_gateway_show(self):
        """
        show l2gw based on UUID. To see l2gw info we need l2gw id.
        """
        LOG.info(_LI("Testing l2_gateway_show api"))
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [self.VLAN_1, self.VLAN_2]}
        l2gw_param = [device_1]
        rsp, requested_devices = self.create_l2gw(l2gw_name, l2gw_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        l2gw_id = rsp[constants.L2GW]["id"]
        l2gw_id = str(l2gw_id)
        show_rsp = self.l2gw_client.show_l2_gateway(l2gw_id)
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_200,
                         show_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code":
                                 constants.EXPECTED_HTTP_RESPONSE_200})
        show_rsp = show_rsp[constants.L2GW]["devices"]
        rsp = rsp[constants.L2GW]["devices"]
        self.assertEqual(rsp[0]["device_name"],
                         show_rsp[0]["device_name"],
                         "Device name is not the same as expected")
        self.assertEqual(
            rsp[0]["interfaces"][0]["name"],
            show_rsp[0]["interfaces"][0]["name"],
            "Interface name is not the same as expected")
        requested_vlans = \
            rsp[0]["interfaces"][0]["segmentation_id"]
        response_vlans = show_rsp[0]["interfaces"][0]["segmentation_id"]
        for id in requested_vlans:
            self.assertIn(id, response_vlans)
        self.resource_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id("d4a7d3af-e637-45c5-a967-d179153a6e58")
    def test_l2_gateway_list(self):
        """
        list created l2gw.
        """
        LOG.info(_LI("Testing l2_gateway_list api"))
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [self.VLAN_1]}
        l2gw_param = [device_1]
        l2gw_rsp, requested_devices = self.create_l2gw(l2gw_name, l2gw_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gw_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        list_rsp = self.l2gw_client.list_l2_gateways()
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_200,
                         list_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code":
                                 constants.EXPECTED_HTTP_RESPONSE_200})
        for l2gw in list_rsp[constants.L2GWS]:
            if l2gw["id"] == l2gw_rsp[constants.L2GW]["id"]:
                list_rsp = l2gw
                l2gw_rsp = l2gw_rsp[constants.L2GW]
                break
        self.assertEqual(l2gw_rsp, list_rsp, "L2GW create response and L2GW "
                                             "list response does not match.")
        self.resource_cleanup()
