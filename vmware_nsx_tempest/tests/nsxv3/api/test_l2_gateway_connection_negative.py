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
from tempest import test

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.services import base_l2gw

CONF = config.CONF
NON_EXIST_UUID = "12341234-0000-1111-2222-000000000000"

LOG = constants.log.getLogger(__name__)


class L2GatewayConnectionNegative(base_l2gw.BaseL2GatewayTest):
    """
    Negative L2GW tests.
    """

    @classmethod
    def resource_setup(cls):
        """
        Setting up the resources for the test.
        """
        super(L2GatewayConnectionNegative, cls).resource_setup()
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
        super(L2GatewayConnectionNegative, cls).resource_cleanup()
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
    @test.idempotent_id("e86bd8e9-b32b-425d-86fa-cd866138d028")
    def test_active_l2_gateway_delete(self):
        """
        Delete l2 gateway with active mapping.
        """
        LOG.info(_LI("Testing test_l2_gateway_create api"))
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
        l2gw_id = l2gw_rsp[constants.L2GW]["id"]
        # Delete l2gw must raise Conflict exception.
        self.assertRaises(lib_exc.Conflict, self.delete_l2gw, l2gw_id)
        self.addCleanup(self.l2gw_cleanup)

    @test.attr(type="nsxv3")
    @test.idempotent_id("488faaae-180a-4c48-8b7a-44c3a243369f")
    def test_recreate_l2_gateway_connection(self):
        """
        Recreate l2 gateway connection using same parameters.
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
        self.assertRaises(lib_exc.Conflict, self.create_l2gw_connection,
                          l2gwc_param)
        self.addCleanup(self.l2gw_cleanup)

    @test.attr(type="nsxv3")
    @test.idempotent_id("14606e74-4f65-402e-ae50-a0adcd877a83")
    def test_create_l2gwc_with_nonexist_l2gw(self):
        """
        Create l2 gateway connection using non exist l2gw uuid.
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
        non_exist_l2gw_uuid = NON_EXIST_UUID
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": non_exist_l2gw_uuid,
                       "network_id": self.network["id"],
                       "segmentation_id": self.VLAN_1}
        # Delete l2gw must raise Conflict exception.
        self.assertRaises(lib_exc.NotFound, self.create_l2gw_connection,
                          l2gwc_param)
        self.addCleanup(self.l2gw_cleanup)

    @test.attr(type="nsxv3")
    @test.idempotent_id("e6cb8973-fcbc-443e-a3cb-c6a82ae58b63")
    def test_create_l2gwc_with_nonexist_network(self):
        """
        Create l2 gateway connection using non exist l2gw uuid.
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
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
        self.addCleanup(self.l2gw_cleanup)

    @test.attr(type="nsxv3")
    @test.idempotent_id("27c7c64f-511f-421e-8b62-dfed143fc00b")
    def test_create_l2gw_with_invalid_seg_id(self):
        """
        Create l2 gateway connection using invalid seg id.
        """
        LOG.info(_LI("Testing l2_gateway_create api with segmentation ID"))
        invalid_seg_id = 20000
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [invalid_seg_id]}
        l2gw_param = [device_1]
        self.assertRaises(lib_exc.BadRequest, self.create_l2gw, l2gw_name,
                          l2gw_param)
        self.addCleanup(self.l2gw_cleanup)

    @decorators.skip_because(bug="1640033")
    @test.attr(type="nsxv3")
    @test.idempotent_id("000cc597-bcea-4539-af07-bd70357e8d82")
    def test_create_l2gw_with_non_int_seg_id(self):
        """
        Create l2 gateway connection using invalid seg id.
        """
        LOG.info(_LI("Testing l2_gateway_create api with segmentation ID"))
        invalid_seg_id = 2.45
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [invalid_seg_id]}
        l2gw_param = [device_1]
        self.assertRaises(lib_exc.BadRequest, self.create_l2gw, l2gw_name,
                          l2gw_param)
        self.addCleanup(self.l2gw_cleanup)
