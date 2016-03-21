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

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest import test

from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest._i18n import _LW
from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.services import l2_gateway_client
from vmware_nsx_tempest.services import nsxv3_client

LOG = constants.log.getLogger(__name__)

CONF = config.CONF


class L2GatewayTest(base.BaseAdminNetworkTest):
    """
    Test l2 gateway operations.
    """

    credentials = ["primary", "admin"]

    @classmethod
    def skip_checks(cls):
        """
        Skip running test if we do not meet crietria to run the tests.
        """
        super(L2GatewayTest, cls).skip_checks()
        if not test.is_extension_enabled("l2-gateway", "network"):
            raise cls.skipException("l2-gateway extension not enabled.")

    @classmethod
    def setup_clients(cls):
        """
        Create various client connections. Such as NSXv3 and L2 Gateway.
        """
        super(L2GatewayTest, cls).setup_clients()
        cls.l2gw_created = {}
        try:
            manager = getattr(cls.os_adm, "manager", cls.os_adm)
            net_client = getattr(manager, "networks_client")
            _params = manager.default_params_withy_timeout_values.copy()
        except AttributeError as attribute_err:
            LOG.warning(
                _LW("Failed to locate the attribute, Error: %(err_msg)s") %
                {"err_msg": attribute_err.__str__()})
            _params = {}
        cls.l2gw_client = l2_gateway_client.L2GatewayClient(
            net_client.auth_provider,
            net_client.service,
            net_client.region,
            net_client.endpoint_type,
            **_params)
        cls.nsxv3_client_obj = nsxv3_client.NSXV3Client(
            CONF.nsxv3.nsx_manager,
            CONF.nsxv3.nsx_user,
            CONF.nsxv3.nsx_password)

    @classmethod
    def resource_setup(cls):
        """
        Setting up the resources for the test.
        """
        super(L2GatewayTest, cls).resource_setup()
        cls.VLAN_1 = getattr(CONF.l2gw, "vlan_1", None)
        cls.VLAN_2 = getattr(CONF.l2gw, "vlan_2", None)

    @classmethod
    def resource_cleanup(cls):
        """
        Clean all the resources used during the test.
        """
        for l2gw_id in cls.l2gw_created.keys():
            cls.l2gw_client.delete_l2_gateway(l2gw_id)
            cls.l2gw_created.pop(l2gw_id)

    def operate_l2gw(self, name, devices, task):
        """
        l2gw operations such create, delete, update and show.

        :param name: l2gw name.
        :param devices: l2gw parameters information.
        :param task: Operation to perform.
        """
        LOG.info(_LI("name: %(name)s, devices: %(devices)s, "
                     "task: %(task)s") %
                 {"name": name, "devices": devices, "task": task})
        if task == "create":
            rsp = self.l2gw_client.create_l2_gateway(
                name=name, **devices)
            self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                             rsp.response["status"],
                             "Response code is not %(code)s" % {
                                 "code":
                                     constants.EXPECTED_HTTP_RESPONSE_201})
            rsp_l2gw = rsp[constants.L2GW]
            self.l2gw_created[rsp_l2gw["id"]] = rsp_l2gw
            LOG.info(_LI("response : %(rsp_l2gw)s") % {"rsp_l2gw": rsp_l2gw})
            self.assertEqual(name, rsp_l2gw["name"],
                             "l2gw name=%(rsp_name)s is not the same as "
                             "requested=%(name)s" % {"rsp_name": rsp_l2gw[
                                 "name"], "name": name})
        elif task == "delete":
            l2gw_id, _ = self.l2gw_created.popitem()
            rsp = self.l2gw_client.delete_l2_gateway(l2gw_id)
            LOG.info(_LI("response : %(rsp)s") % {"rsp": rsp})
            self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_204,
                             rsp.response["status"],
                             "Response code is not %(code)s" % {
                                 "code":
                                     constants.EXPECTED_HTTP_RESPONSE_204})
        elif task == "update":
            l2gw_id, _ = self.l2gw_created.popitem()
            rsp = self.l2gw_client.update_l2_gateway(l2gw_id,
                                                     name=name, **devices)
            self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_200,
                             rsp.response["status"],
                             "Response code is not %(code)s" % {
                                 "code":
                                     constants.EXPECTED_HTTP_RESPONSE_200})
            rsp_l2gw = rsp[constants.L2GW]
            self.l2gw_created[rsp_l2gw["id"]] = rsp_l2gw
            LOG.info(_LI("response : %(rsp_l2gw)s") % {"rsp_l2gw": rsp_l2gw})
            self.assertEqual(name, rsp_l2gw["name"],
                             "l2gw name=%(rsp_name)s is not the same as "
                             "requested=%(name)s" % {
                                 "rsp_name": rsp_l2gw["name"], "name": name})
            if "name" in devices["devices"][0]["interfaces"][0]:
                self.assertEqual(
                    devices["devices"][0]["interfaces"][0]["name"],
                    rsp_l2gw["devices"][0]["interfaces"][0][
                        "name"], "L2GW interface name update "
                                 "failed!!!")
            if "segmentation_id" in devices["devices"][0]["interfaces"][0]:
                self.assertEqual(devices["devices"][0]["interfaces"][0][
                                     "segmentation_id"][0],
                                 rsp_l2gw["devices"][0]["interfaces"][0][
                                     "segmentation_id"][0],
                                 "L2GW segmentation id update failed!!!")
        elif task == "show":
            l2gw_id, l2gw_parameters = self.l2gw_created.popitem()
            rsp = self.l2gw_client.show_l2_gateway(l2gw_id)
            self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_200,
                             rsp.response["status"],
                             "Response code is not %(code)s" % {
                                 "code":
                                     constants.EXPECTED_HTTP_RESPONSE_200})
            rsp_l2gw = rsp[constants.L2GW]
            constants.LOG.info(
                _LI("response : %(rsp_l2gw)s") % {"rsp_l2gw": rsp_l2gw})
            self.assertEqual(name, rsp_l2gw["name"],
                             "l2gw name=%(rsp_name)s is not the same as "
                             "requested=%(name)s" % {
                                 "rsp_name": rsp_l2gw["name"],
                                 "name": name})
            self.assertEqual(l2gw_parameters, rsp_l2gw,
                             "l2-gateway-show does not show parameter as it "
                             "was created.")
            self.l2gw_created[l2gw_id] = l2gw_parameters

    def nsx_bridge_cluster_info(self):
        """
        Collect the device and interface name of the nsx brdige cluster.

        :return: nsx bridge id and display name.
        """
        response = self.nsxv3_client_obj.get_bridge_cluster_info()
        if len(response) == 0:
            raise RuntimeError("NSX bridge cluster information is null")
        return response[0]["id"], response[0]["display_name"]

    @test.attr(type="nsxv3")
    @test.idempotent_id("e5e3a089-602c-496e-8c17-4ef613266924")
    def test_l2_gateway_create(self):
        """
        Create l2gw based on UUID and bridge cluster name. It creates l2gw.
        To create l2gw we need bridge cluster name (interface name) and
        bridge cluster UUID (device name) from NSX manager.
        """
        LOG.info(_LI("Testing l2_gateway_create api"))
        device_name, interface_name = self.nsx_bridge_cluster_info()
        l2gw_name = data_utils.rand_name(constants.L2GW)
        devices = {"devices": [{"device_name": device_name,
                                "interfaces": [{"name": interface_name}]}]
                   }
        self.operate_l2gw(name=l2gw_name, devices=devices, task="create")
        self.resource_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id("9968a529-e785-472f-8705-9b394a912e43")
    def test_l2_gateway_create_with_segmentation_id(self):
        """
        Create l2gw based on UUID and bridge cluster name. It creates l2gw.
        To create l2gw we need bridge cluster name (interface name) and
        bridge cluster UUID (device name) from NSX manager and vlan id.
        """
        LOG.info(_LI("Testing l2_gateway_create api"))
        device_name, interface_name = self.nsx_bridge_cluster_info()
        l2gw_name = data_utils.rand_name(constants.L2GW)
        devices = {"devices": [
            {"device_name": device_name,
             "interfaces": [{"name": interface_name,
                             "segmentation_id": [
                                 self.VLAN_1,
                                 self.VLAN_2
                             ]
                             }]
             }]
        }
        self.operate_l2gw(name=l2gw_name, devices=devices, task="create")
        self.resource_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id("670cacb5-134e-467d-ba41-0d7cdbcf3903")
    def test_l2_gateway_delete(self):
        """
        Delete l2gw will create l2gw and delete recently created l2gw. To
        delete l2gw we need l2gw id.
        """
        LOG.info(_LI("Testing l2_gateway_delete api"))
        device_name, interface_name = self.nsx_bridge_cluster_info()
        l2gw_name = data_utils.rand_name(constants.L2GW)
        devices = {"devices": [{"device_name": device_name,
                                "interfaces": [{"name": interface_name}]}]
                   }
        # Creating l2gw.
        self.operate_l2gw(name=l2gw_name, devices=devices, task="create")
        # Deleting already created l2gw.
        self.operate_l2gw(name=l2gw_name, devices=devices, task="delete")
        self.resource_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id("fa76f6e6-8aa7-46d8-9af4-2206d0773dc3")
    def test_l2_gateway_update_l2gw_name(self):
        """
        Update l2gw will update info in already created l2gw. To
        update l2gw we need l2gw id and payload to update.
        """
        LOG.info(_LI("Testing l2_gateway_update api"))
        device_name, interface_name = self.nsx_bridge_cluster_info()
        l2gw_name = data_utils.rand_name(constants.L2GW)
        devices = {"devices": [{"device_name": device_name,
                                "interfaces": [{"name": interface_name}]}]
                   }
        # Creating l2gw.
        self.operate_l2gw(name=l2gw_name, devices=devices, task="create")
        # Updating already created l2gw with new l2gw name.
        self.operate_l2gw(name=l2gw_name + "_updated", devices=devices,
                          task="update")
        self.resource_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id("c4977df8-8e3a-4b7e-a8d2-5aa757117658")
    def test_l2_gateway_update_interface(self):
        """
        Update l2gw will update info in already created l2gw. To
        update l2gw we need l2gw id and payload to update.
        """
        LOG.info(_LI("Testing l2_gateway_update api"))
        device_name, interface_name = self.nsx_bridge_cluster_info()
        l2gw_name = data_utils.rand_name(constants.L2GW)
        devices = {"devices": [{"device_name": device_name,
                                "interfaces": [{"name": interface_name}]}]
                   }
        # Creating l2gw.
        self.operate_l2gw(name=l2gw_name, devices=devices, task="create")
        # Updating Interfaces.
        devices = {"devices": [
            {"device_name": device_name,

             "interfaces": [{"name": "new_name",
                             "segmentation_id": [
                                 self.VLAN_1]}],
             "deleted_interfaces": [
                 {"name": interface_name}]}
        ]
        }
        # Updating already created l2gw with new interface.
        self.operate_l2gw(name=l2gw_name, devices=devices, task="update")
        self.resource_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id("5a3cef97-c91c-4e03-92c8-d180f9269f27")
    def test_l2_gateway_show(self):
        """
        show l2gw based on UUID. To see l2gw info we need l2gw id.
        """
        LOG.info(_LI("Testing l2_gateway_show api"))
        device_name, interface_name = self.nsx_bridge_cluster_info()
        l2gw_name = data_utils.rand_name(constants.L2GW)
        devices = {"devices": [
            {"device_name": device_name,
             "interfaces": [{"name": interface_name,
                             "segmentation_id": [
                                 self.VLAN_1,
                                 self.VLAN_2]}]
             }]
        }
        # Creating l2gw.
        self.operate_l2gw(name=l2gw_name, devices=devices, task="create")
        # Show already created l2gw with l2gw id.
        self.operate_l2gw(name=l2gw_name, devices=devices, task="show")
        self.resource_cleanup()
