# Copyright 2015 OpenStack Foundation
# Copyright 2016 VMware Inc
# All Rights Reserved.
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
from tempest.lib.common.utils import test_utils
from tempest import test

from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.services import base_l2gw

CONF = config.CONF

LOG = constants.log.getLogger(__name__)


class L2GatewayConnectionTest(base_l2gw.BaseL2GatewayTest):
    """
    Test l2 gateway connection operations.
    """

    @classmethod
    def resource_setup(cls):
        """
        Setting up the resources for the test.
        """
        super(L2GatewayConnectionTest, cls).resource_setup()
        # Create a network.
        cls.network = cls.create_network()
        # Create subnet on the network just created.
        cls.SUBNET_1_NETWORK_CIDR = CONF.l2gw.subnet_1_cidr
        network_cidr = cls.SUBNET_1_NETWORK_CIDR.split("/")
        cls.SUBNET_1_MASK = network_cidr[1]
        subnet_info = {}
        # cidr must be presented & in IPNetwork structure.
        cls.CIDR = netaddr.IPNetwork(cls.SUBNET_1_NETWORK_CIDR)
        cls.subnet = cls.create_subnet(cls.network, cidr=cls.CIDR,
                                       mask_bits=int(cls.SUBNET_1_MASK),
                                       **subnet_info)

    @classmethod
    def resource_cleanup(cls):
        """
        Clean all the resources used during the test.
        """
        super(L2GatewayConnectionTest, cls).resource_cleanup()
        test_utils.call_and_ignore_notfound_exc(
            cls.networks_client.delete_network, cls.network["id"])

    @classmethod
    def l2gw_cleanup(cls):
        """
        Delete created L2GWs and L2GWCs.
        """
        for l2gwc_id in cls.l2gwc_created.keys():
            cls.l2gwc_client.delete_l2_gateway_connection(l2gwc_id)
            cls.l2gwc_created.pop(l2gwc_id)
        for l2gw_id in cls.l2gw_created.keys():
            cls.l2gw_client.delete_l2_gateway(l2gw_id)
            cls.l2gw_created.pop(l2gw_id)

    @test.attr(type="nsxv3")
    @test.idempotent_id("81edfb9e-4722-4565-939c-6593b8405ff4")
    def test_l2_gateway_connection_create(self):
        """
        Create l2 gateway connection using one vlan. Vlan parameter is
        passed into L2GW create.
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [self.VLAN_1]}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": self.network["id"]}
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
        self.addCleanup(self.l2gw_cleanup)

    @test.attr(type="nsxv3")
    @test.idempotent_id("7db4f6c9-18c5-4a99-93c1-68bc2ecb48a7")
    def test_l2_gateway_connection_create_with_multiple_vlans(self):
        """
        Create l2 gateway connection using multiple vlans. Vlan parameter is
        passed into L2GW create.
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [self.VLAN_1, self.VLAN_2]}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": self.network["id"]}
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
        self.addCleanup(self.l2gw_cleanup)

    @test.attr(type="nsxv3")
    @test.idempotent_id("de70d6a2-d454-4a09-b06b-8f39be67b635")
    def test_l2_gateway_connection_with_seg_id_create(self):
        """
        Create l2 gateway connection using one vlan. Vlan parameter is
        passed into L2GW connection create.
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": self.network["id"],
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
        self.addCleanup(self.l2gw_cleanup)

    @test.attr(type="nsxv3")
    @test.idempotent_id("819d9b50-9159-48d0-be2a-493ec686534c")
    def test_l2_gateway_connection_show(self):
        """
        Create l2 gateway connection using one vlan and tes l2 gateway
        connection show api
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": self.network["id"],
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
        self.addCleanup(self.l2gw_cleanup)

    @test.attr(type="nsxv3")
    @test.idempotent_id("4188f8e7-cd65-427e-92b8-2a9e0492ab21")
    def test_l2_gateway_connection_list(self):
        """
        Create l2 gateway connection using one vlan and test l2 gateway
        connection list api.
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        # Create 2 l2 gateways.
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        # Create 2 l2 gateway connections.
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": self.network["id"],
                       "segmentation_id": self.VLAN_1}
        l2gwc_rsp = self.create_l2gw_connection(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        list_rsp = self.l2gwc_client.list_l2_gateway_connections()
        LOG.info(_LI("l2gw connection list response: %s") % list_rsp)
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
        self.addCleanup(self.l2gw_cleanup)

    @test.attr(type="nsxv3")
    @test.idempotent_id("4d71111f-3d2b-4557-97c7-2e149a6f41fb")
    def test_l2_gateway_connection_recreate(self):
        """
        Recreate l2 gateway connection.
        - Create l2GW.
        - Create l2gw connection.
        - delete l2gw connection.
        - Recreate l2gw connection
        - verify with l2gw connection list API.
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
        # List all the L2GW connection.
        list_rsp = self.l2gwc_client.list_l2_gateway_connections()
        LOG.info(_LI("l2gw connection list response: %s") % list_rsp)
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
                       "network_id": self.network["id"],
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
        # Since we delete l2gwc pop that id from list.
        self.l2gwc_created.pop(l2gwc_id)
        l2gwc_rsp = self.create_l2gw_connection(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        # List all the L2GW connection.
        list_rsp = self.l2gwc_client.list_l2_gateway_connections()
        LOG.info(_LI("l2gw connection list response: %s") % list_rsp)
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
        self.addCleanup(self.l2gw_cleanup)

    @test.attr(type="nsxv3")
    @test.idempotent_id("671cacb5-134e-467d-ba41-0d7cdbcf3903")
    def test_l2_gateway_connection_delete(self):
        """
        Delete l2gw will create l2gw and delete recently created l2gw. To
        delete l2gw we need l2gw id.
        """
        LOG.info(_LI("Testing l2_gateway_connection_delete api"))
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": self.network["id"],
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
        # Since we delete l2gwc pop that id from list.
        self.l2gwc_created.pop(l2gwc_id)
        self.addCleanup(self.l2gw_cleanup)
