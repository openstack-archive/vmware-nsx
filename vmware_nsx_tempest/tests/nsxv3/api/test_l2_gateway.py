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
import netaddr

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
from tempest import test

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.lib import feature_manager

LOG = constants.log.getLogger(__name__)

CONF = config.CONF
NON_EXIST_UUID = "12341234-0000-1111-2222-000000000000"


class L2GatewayBase(feature_manager.FeatureManager):
    @classmethod
    def skip_checks(cls):
        """
        Skip running test if we do not meet criteria to run the tests.
        """
        super(L2GatewayBase, cls).skip_checks()
        if not test.is_extension_enabled("l2-gateway", "network"):
            raise cls.skipException("l2-gateway extension not enabled.")

    @classmethod
    def resource_setup(cls):
        """
        Setting up the resources for the test.
        """
        super(L2GatewayBase, cls).resource_setup()
        cls.VLAN_1 = CONF.l2gw.vlan_1
        cls.VLAN_2 = CONF.l2gw.vlan_2
        # Create subnet on the network just created.
        cls.SUBNET_1_NETWORK_CIDR = CONF.l2gw.subnet_1_cidr
        cls.SUBNET_1_MASK = cls.SUBNET_1_NETWORK_CIDR.split("/")[1]

    def deploy_l2gateway_topology(self):
        network_l2gateway = self.create_topology_network("network_l2gateway")
        # cidr must be presented & in IPNetwork structure.
        self.CIDR = netaddr.IPNetwork(self.SUBNET_1_NETWORK_CIDR)
        self.create_topology_subnet(
            "subnet1_l2gateway", network_l2gateway, cidr=self.CIDR,
            mask_bits=int(self.SUBNET_1_MASK))


class L2GatewayTest(L2GatewayBase):
    """
    Test l2 gateway operations.
    """

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("e5e3a089-602c-496e-8c17-4ef613266924")
    def test_l2_gateway_create_without_vlan(self):
        """
        Create l2gw based on UUID and bridge cluster name. It creates l2gw.
        To create l2gw we need bridge cluster name (interface name) and
        bridge cluster UUID (device name) from NSX manager.
        """
        LOG.info("Testing l2_gateway_create api")
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

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("9968a529-e785-472f-8705-9b394a912e43")
    def test_l2_gateway_with_single_vlan(self):
        """
        Create l2gw based on UUID and bridge cluster name. It creates l2gw.
        To create l2gw we need bridge cluster name (interface name) and
        bridge cluster UUID (device name) from NSX manager and vlan id.
        """
        LOG.info("Testing l2_gateway_create api with segmentation ID")
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

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("3861aab0-4f76-4472-ad0e-a255e6e42193")
    def test_l2_gateway_with_multiple_vlans(self):
        """
        Create l2gw based on UUID and bridge cluster name. It creates l2gw.
        To create l2gw we need bridge cluster name (interface name) and
        bridge cluster UUID (device name) from NSX manager and vlan id.
        """
        LOG.info("Testing l2_gateway_create api with segmentation ID")
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

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("670cbcb5-134e-467d-ba41-0d7cdbcf3903")
    def test_l2_gateway_delete(self):
        """
        Delete l2gw will create l2gw and delete recently created l2gw. To
        delete l2gw we need l2gw id.
        """
        LOG.info("Testing l2_gateway_delete api")
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

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("fa76f6e6-8aa7-46d8-9af4-2206d0773dc3")
    def test_l2_gateway_update_l2gw_name(self):
        """
        Update l2gw will update info in already created l2gw. To
        update l2gw we need l2gw id and payload to update.
        """
        LOG.info("Testing l2_gateway_update api")
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
        LOG.info("response : %(rsp_l2gw)s", {"rsp_l2gw": rsp_l2gw})
        # Assert if name is not updated.
        self.assertEqual(l2gw_new_name, rsp_l2gw["name"],
                         "l2gw name=%(rsp_name)s is not the same as "
                         "requested=%(name)s" % {"rsp_name": rsp_l2gw["name"],
                                                 "name": l2gw_new_name})

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("c4977df8-8e3a-4b7e-a8d2-5aa757117658")
    def test_l2_gateway_update_interface(self):
        """
        Update l2gw will update info in already created l2gw. To
        update l2gw we need l2gw id and payload to update.
        """
        LOG.info("Testing l2_gateway_update api")
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
        LOG.info("response : %(rsp_l2gw)s", {"rsp_l2gw": rsp_l2gw})
        if "segmentation_id" in devices["devices"][0]["interfaces"][0]:
            self.assertEqual(devices["devices"][0]["interfaces"][0][
                                 "segmentation_id"][0],
                             rsp_l2gw["devices"][0]["interfaces"][0][
                                 "segmentation_id"][0],
                             "L2GW segmentation id update failed!!!")

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("5a3cef97-c91c-4e03-92c8-d180f9269f27")
    def test_l2_gateway_show(self):
        """
        show l2gw based on UUID. To see l2gw info we need l2gw id.
        """
        LOG.info("Testing l2_gateway_show api")
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

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("d4a7d3af-e637-45c5-a967-d179153a6e58")
    def test_l2_gateway_list(self):
        """
        list created l2gw.
        """
        LOG.info("Testing l2_gateway_list api")
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


class L2GatewayConnectionTest(L2GatewayBase):
    """
    Test l2 gateway connection operations.
    """
    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("81edfb9e-4722-4565-939c-6593b8405ff4")
    def test_l2_gateway_connection_create(self):
        """
        Create l2 gateway connection using one vlan. Vlan parameter is
        passed into L2GW create.
        """
        LOG.info("Testing test_l2_gateway_connection_create api")
        self.deploy_l2gateway_topology()
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [self.VLAN_1]}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id":
                           self.topology_networks["network_l2gateway"]["id"]}
        l2gwc_rsp = self.create_l2gw_connection(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        self.assertEqual(l2gwc_param["l2_gateway_id"],
                         l2gwc_rsp[constants.L2GWC]["l2_gateway_id"],
                         "l2gw id is not same as expected in "
                         "create l2gw connection response")
        self.assertEqual(l2gwc_param["network_id"],
                         l2gwc_rsp[constants.L2GWC]["network_id"],
                         "network id is not same as expected in "
                         "create l2gw connection response")

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("7db4f6c9-18c5-4a99-93c1-68bc2ecb48a7")
    def test_l2_gateway_connection_create_with_multiple_vlans(self):
        """
        Create l2 gateway connection using multiple vlans. Vlan parameter is
        passed into L2GW create.
        """
        LOG.info("Testing test_l2_gateway_connection_create api")
        self.deploy_l2gateway_topology()
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [self.VLAN_1, self.VLAN_2]}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id":
                           self.topology_networks["network_l2gateway"]["id"]}
        l2gwc_rsp = self.create_l2gw_connection(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        self.assertEqual(l2gwc_param["l2_gateway_id"],
                         l2gwc_rsp[constants.L2GWC]["l2_gateway_id"],
                         "l2gw id is not same as expected in "
                         "create l2gw connection response")
        self.assertEqual(l2gwc_param["network_id"],
                         l2gwc_rsp[constants.L2GWC]["network_id"],
                         "network id is not same as expected in "
                         "create l2gw connection response")

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("de70d6a2-d454-4a09-b06b-8f39be67b635")
    def test_l2_gateway_connection_with_seg_id_create(self):
        """
        Create l2 gateway connection using one vlan. Vlan parameter is
        passed into L2GW connection create.
        """
        LOG.info("Testing test_l2_gateway_connection_create api")
        self.deploy_l2gateway_topology()
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id":
                           self.topology_networks["network_l2gateway"]["id"],
                       "segmentation_id": self.VLAN_1}
        l2gwc_rsp = self.create_l2gw_connection(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        self.assertEqual(l2gwc_param["l2_gateway_id"],
                         l2gwc_rsp[constants.L2GWC]["l2_gateway_id"],
                         "l2gw id is not same as expected in "
                         "create l2gw connection response")
        self.assertEqual(l2gwc_param["network_id"],
                         l2gwc_rsp[constants.L2GWC]["network_id"],
                         "network id is not same as expected in "
                         "create l2gw connection response")
        self.assertEqual(l2gwc_param["segmentation_id"],
                         l2gwc_rsp[constants.L2GWC]["segmentation_id"],
                         "segmentation id is not same as expected in "
                         "create l2gw connection response")

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("819d9b50-9159-48d0-be2a-493ec686534c")
    def test_l2_gateway_connection_show(self):
        """
        Create l2 gateway connection using one vlan and tes l2 gateway
        connection show api
        """
        LOG.info("Testing test_l2_gateway_connection_create api")
        self.deploy_l2gateway_topology()
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id":
                           self.topology_networks["network_l2gateway"]["id"],
                       "segmentation_id": self.VLAN_1}
        l2gwc_rsp = self.create_l2gw_connection(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        l2gwc_id = l2gwc_rsp[constants.L2GWC]["id"]
        show_rsp = self.l2gwc_client.show_l2_gateway_connection(l2gwc_id)
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_200,
                         show_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_200})
        self.assertEqual(l2gwc_param["l2_gateway_id"],
                         show_rsp[constants.L2GWC]["l2_gateway_id"],
                         "l2gw id is not same as expected in "
                         "show l2gw connection response")
        self.assertEqual(l2gwc_param["network_id"],
                         show_rsp[constants.L2GWC]["network_id"],
                         "network id is not same as expected in "
                         "show l2gw connection response")
        show_rsp_seg_id = str(show_rsp[constants.L2GWC][
                                  "segmentation_id"])
        self.assertEqual(l2gwc_param["segmentation_id"],
                         show_rsp_seg_id,
                         "segmentation id is not same as expected in "
                         "show l2gw connection response")

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("4188f8e7-cd65-427e-92b8-2a9e0492ab21")
    def test_l2_gateway_connection_list(self):
        """
        Create l2 gateway connection using one vlan and test l2 gateway
        connection list api.
        """
        LOG.info("Testing test_l2_gateway_connection_create api")
        self.deploy_l2gateway_topology()
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        # Create 2 l2 gateways.
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        # Create 2 l2 gateway connections.
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id":
                           self.topology_networks["network_l2gateway"]["id"],
                       "segmentation_id": self.VLAN_1}
        l2gwc_rsp = self.create_l2gw_connection(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        list_rsp = self.l2gwc_client.list_l2_gateway_connections()
        LOG.info("l2gw connection list response: %s", list_rsp)
        # Assert in case of failure.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_200,
                         list_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_200})
        self.assertEqual(l2gwc_rsp["l2_gateway_connection"]["id"],
                         list_rsp["l2_gateway_connections"][0]["id"],
                         "l2gw connection list does not show proper id")
        self.assertEqual(l2gwc_rsp["l2_gateway_connection"]["l2_gateway_id"],
                         list_rsp["l2_gateway_connections"][0][
                             "l2_gateway_id"],
                         "l2gw connection list does not show proper "
                         "l2_gateway_id")
        self.assertEqual(l2gwc_rsp["l2_gateway_connection"]["network_id"],
                         list_rsp["l2_gateway_connections"][0]["network_id"],
                         "l2gw connection list does not show proper "
                         "network_id")
        self.assertEqual(l2gwc_rsp["l2_gateway_connection"]["tenant_id"],
                         list_rsp["l2_gateway_connections"][0]["tenant_id"],
                         "l2gw connection list does not show proper tenant_id")
        self.assertEqual(l2gwc_rsp["l2_gateway_connection"]["segmentation_id"],
                         str(list_rsp["l2_gateway_connections"][0][
                                 "segmentation_id"]),
                         "l2gw connection list does not show proper "
                         "segmentation_id")

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("4d71111f-3d2b-4557-97c7-2e149a6f41fb")
    def test_l2_gateway_connection_recreate(self):
        """
        Recreate l2 gateway connection.
        - Create l2GW.
        - Create l2gw connection.
        - delete l2gw connection.
        - Recreate l2gw connection
        - verify with l2gw connection list API.
        """
        LOG.info("Testing test_l2_gateway_connection_create api")
        self.deploy_l2gateway_topology()
        # List all the L2GW connection.
        list_rsp = self.l2gwc_client.list_l2_gateway_connections()
        LOG.info("l2gw connection list response: %s", list_rsp)
        # Assert in case of failure.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_200,
                         list_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_200})
        list_rsp = list_rsp["l2_gateway_connections"]
        l2gwc_ids = [item.get("id") for item in list_rsp if "id"
                     in item]
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id":
                           self.topology_networks["network_l2gateway"]["id"],
                       "segmentation_id": self.VLAN_1}
        l2gwc_rsp = self.create_l2gw_connection(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        l2gwc_id = l2gwc_rsp[constants.L2GWC]["id"]
        # Delete l2gw.
        rsp = self.delete_l2gw_connection(l2gwc_id)
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_204,
                         rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_204})
        l2gwc_rsp = self.create_l2gw_connection(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        # List all the L2GW connection.
        list_rsp = self.l2gwc_client.list_l2_gateway_connections()
        LOG.info("l2gw connection list response: %s", list_rsp)
        # Assert in case of failure.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_200,
                         list_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_200})
        list_rsp = list_rsp["l2_gateway_connections"]
        l2gwc_ids = l2gwc_ids + [item.get("id") for item in list_rsp if
                                 "id" in item]
        self.assertNotIn(l2gwc_id, l2gwc_ids, "l2gwc list api shows hanging "
                                              "l2gwc id")

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("671cacb5-134e-467d-ba41-0d7cdbcf3903")
    def test_l2_gateway_connection_delete(self):
        """
        Delete l2gw will create l2gw and delete recently created l2gw. To
        delete l2gw we need l2gw id.
        """
        LOG.info("Testing l2_gateway_connection_delete api")
        self.deploy_l2gateway_topology()
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id":
                           self.topology_networks["network_l2gateway"]["id"],
                       "segmentation_id": self.VLAN_1}
        l2gwc_rsp = self.create_l2gw_connection(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        l2gwc_id = l2gwc_rsp[constants.L2GWC]["id"]
        # Delete l2gw.
        rsp = self.delete_l2gw_connection(l2gwc_id)
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_204,
                         rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_204})


class L2GatewayConnectionNegative(L2GatewayBase):
    """
    Negative L2GW tests.
    """
    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("e86bd8e9-b32b-425d-86fa-cd866138d028")
    def test_active_l2_gateway_delete(self):
        """
        Delete l2 gateway with active mapping.
        """
        LOG.info("Testing test_l2_gateway_create api")
        self.deploy_l2gateway_topology()
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id":
                           self.topology_networks["network_l2gateway"]["id"],
                       "segmentation_id": self.VLAN_1}
        l2gwc_rsp = self.create_l2gw_connection(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        l2gw_id = l2gw_rsp[constants.L2GW]["id"]
        # Delete l2gw must raise Conflict exception.
        self.assertRaises(lib_exc.Conflict, self.delete_l2gw, l2gw_id)

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("488faaae-180a-4c48-8b7a-44c3a243369f")
    def test_recreate_l2_gateway_connection(self):
        """
        Recreate l2 gateway connection using same parameters.
        """
        LOG.info("Testing test_l2_gateway_connection_create api")
        self.deploy_l2gateway_topology()
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [self.VLAN_1]}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id":
                           self.topology_networks["network_l2gateway"]["id"]}
        l2gwc_rsp = self.create_l2gw_connection(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        self.assertRaises(lib_exc.Conflict, self.create_l2gw_connection,
                          l2gwc_param)

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("14606e74-4f65-402e-ae50-a0adcd877a83")
    def test_create_l2gwc_with_nonexist_l2gw(self):
        """
        Create l2 gateway connection using non exist l2gw uuid.
        """
        LOG.info("Testing test_l2_gateway_connection_create api")
        self.deploy_l2gateway_topology()
        non_exist_l2gw_uuid = NON_EXIST_UUID
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": non_exist_l2gw_uuid,
                       "network_id":
                           self.topology_networks["network_l2gateway"]["id"],
                       "segmentation_id": self.VLAN_1}
        # Delete l2gw must raise Conflict exception.
        self.assertRaises(lib_exc.NotFound, self.create_l2gw_connection,
                          l2gwc_param)

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("e6cb8973-fcbc-443e-a3cb-c6a82ae58b63")
    def test_create_l2gwc_with_nonexist_network(self):
        """
        Create l2 gateway connection using non exist l2gw uuid.
        """
        LOG.info("Testing test_l2_gateway_connection_create api")
        non_exist_network_uuid = NON_EXIST_UUID
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": non_exist_network_uuid,
                       "segmentation_id": self.VLAN_1}
        # Delete l2gw must raise Conflict exception.
        self.assertRaises(lib_exc.NotFound, self.create_l2gw_connection,
                          l2gwc_param)

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("27c7c64f-511f-421e-8b62-dfed143fc00b")
    def test_create_l2gw_with_invalid_seg_id(self):
        """
        Create l2 gateway connection using invalid seg id.
        """
        LOG.info("Testing l2_gateway_create api with segmentation ID")
        invalid_seg_id = 20000
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [invalid_seg_id]}
        l2gw_param = [device_1]
        self.assertRaises(lib_exc.BadRequest, self.create_l2gw, l2gw_name,
                          l2gw_param)

    @decorators.skip_because(bug="1640033")
    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("000cc597-bcea-4539-af07-bd70357e8d82")
    def test_create_l2gw_with_non_int_seg_id(self):
        """
        Create l2 gateway connection using invalid seg id.
        """
        LOG.info("Testing l2_gateway_create api with segmentation ID")
        invalid_seg_id = 2.45
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [invalid_seg_id]}
        l2gw_param = [device_1]
        self.assertRaises(lib_exc.BadRequest, self.create_l2gw, l2gw_name,
                          l2gw_param)
