# Copyright 2016 VMware Inc
# All Rights Reserved.
#
# Copyright 2015 Hewlett-Packard Development Company, L.P.
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
from tempest import test

from vmware_nsx_tempest._i18n import _
from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest._i18n import _LW
from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.services import l2_gateway_client
from vmware_nsx_tempest.services import l2_gateway_connection_client
from vmware_nsx_tempest.services import nsxv3_client

LOG = constants.log.getLogger(__name__)

CONF = config.CONF
SEGMENTATION_ID_DELIMITER = "#"
INTERFACE_SEG_ID_DELIMITER = "|"
DEVICE_INTERFACE_DELIMITER = "::"
DEVICE_DELIMITER = ","
INTERFACE_DELIMITER = ";"
"""
  Sample for providing input for gateway creation in config is noted below
  Options provide flexibility to user to create l2gateway
  For single device ,single interface with single vlan
    l2gw_switch = device_name1::int_name1|vlan1
  For single device multiple interfaces with single or multiple vlans
    l2gw_switch = device_name1::int_name1|vlan1#vlan2;int_name2|vlan3
  For multiple devices with mutiple interfaces having single or mutiple vlan
    l2gw_switch = device_n1::int_n1|vlan1,device_n2::int_n2|vlan2#vlan3
"""


def get_interface(interfaces):
    interface_dict = []
    for interface in interfaces:
        if INTERFACE_SEG_ID_DELIMITER in interface:
            int_name = interface.split(INTERFACE_SEG_ID_DELIMITER)[0]
            segid = interface.split(INTERFACE_SEG_ID_DELIMITER)[1]
            if SEGMENTATION_ID_DELIMITER in segid:
                segid = segid.split(SEGMENTATION_ID_DELIMITER)
            else:
                segid = [segid]
            interface_detail = {'name': int_name, 'segmentation_id': segid}
        else:
            interface_detail = {'name': interface}
        interface_dict.append(interface_detail)
    return interface_dict


def get_device_interface(device_name, interface):
    if INTERFACE_DELIMITER in interface:
        interface_dict = interface.split(INTERFACE_DELIMITER)
        interfaces = get_interface(interface_dict)
    else:
        interfaces = get_interface([interface])
    device = {'device_name': device_name,
              'interfaces': interfaces}
    return device


def get_l2gw_body(l2gw_conf):
    device_dict = []
    devices = l2gw_conf.split(DEVICE_DELIMITER)
    for device in devices:
        if DEVICE_INTERFACE_DELIMITER in device:
            device_name = device.split(DEVICE_INTERFACE_DELIMITER)[0]
            interface = device.split(DEVICE_INTERFACE_DELIMITER)[1]
            device = get_device_interface(device_name, interface)
        device_dict.append(device)
    body = {'devices': device_dict}
    return body


def form_dict_devices(devices):
    seg_ids = []
    devices1 = dict()
    int_seg = []
    for device in devices:
        device_name = device['device_name']
        interfaces = device['interfaces']
        for interface in interfaces:
            interface_name = interface['name']
            int_seg.append(interface_name)
            seg_id = interface['segmentation_id']
            if type(seg_id) is list:
                for segid in seg_id:
                    seg_ids.append(segid)
            else:
                seg_ids.append(seg_id)
            int_seg.append(seg_id)
            devices1.setdefault(device_name, []).append(int_seg)
            int_seg = []
    return devices1


class BaseL2GatewayTest(base.BaseAdminNetworkTest):
    """
    L2Gateway base class. Extend this class to get basics of L2GW.
    """
    credentials = ["primary", "admin"]

    @classmethod
    def skip_checks(cls):
        """
        Skip running test if we do not meet criteria to run the tests.
        """
        super(BaseL2GatewayTest, cls).skip_checks()
        if not test.is_extension_enabled("l2-gateway", "network"):
            raise cls.skipException("l2-gateway extension not enabled.")

    @classmethod
    def setup_clients(cls):
        """
        Create various client connections. Such as NSXv3 and L2 Gateway.
        """
        super(BaseL2GatewayTest, cls).setup_clients()
        cls.l2gw_created = {}
        cls.l2gwc_created = {}
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
        cls.l2gwc_client = \
            l2_gateway_connection_client.L2GatewayConnectionClient(
                net_client.auth_provider,
                net_client.service,
                net_client.region,
                net_client.endpoint_type,
                **_params)

    @classmethod
    def resource_setup(cls):
        """
        Setting up the resources for the test.
        """
        super(BaseL2GatewayTest, cls).resource_setup()
        cls.VLAN_1 = CONF.l2gw.vlan_1
        cls.VLAN_2 = CONF.l2gw.vlan_2

    @classmethod
    def resource_cleanup(cls):
        """
        Clean all the resources used during the test.
        """
        for l2gw_id in cls.l2gw_created.keys():
            cls.l2gw_client.delete_l2_gateway(l2gw_id)
            cls.l2gw_created.pop(l2gw_id)
        for l2gwc_id in cls.l2gwc_created.keys():
            cls.l2gwc_client.delete_l2_gateway_connection(l2gwc_id)
            cls.l2gwc_created.pop(l2gwc_id)

    def create_l2gw(self, l2gw_name, l2gw_param):
        """
        Creates L2GW and return the response.

        :param l2gw_name: name of the L2GW
        :param l2gw_param: L2GW parameters

        :return: response of L2GW create API
        """
        LOG.info(_LI("l2gw name: %(name)s, l2gw_param: %(devices)s ") %
                 {"name": l2gw_name, "devices": l2gw_param})
        devices = []
        for device_dict in l2gw_param:
            interface = [{"name": device_dict["iname"],
                          "segmentation_id": device_dict[
                              "vlans"]}] if "vlans" in device_dict else [
                {"name": device_dict["iname"]}]
            device = {"device_name": device_dict["dname"],
                      "interfaces": interface}
            devices.append(device)
        l2gw_request_body = {"devices": devices}
        LOG.info(_LI(" l2gw_request_body: %s") % l2gw_request_body)
        rsp = self.l2gw_client.create_l2_gateway(
            name=l2gw_name, **l2gw_request_body)
        LOG.info(_LI(" l2gw response: %s") % rsp)
        self.l2gw_created[rsp[constants.L2GW]["id"]] = rsp[constants.L2GW]
        return rsp, devices

    def delete_l2gw(self, l2gw_id):
        """
        Delete L2gw.

        :param l2gw_id: L2GW id to delete l2gw.

        :return: response of the l2gw delete API.
        """
        LOG.info(_LI("L2GW id: %(id)s to be deleted.") % {"id": l2gw_id})
        rsp = self.l2gw_client.delete_l2_gateway(l2gw_id)
        LOG.info(_LI("response : %(rsp)s") % {"rsp": rsp})
        return rsp

    def update_l2gw(self, l2gw_id, l2gw_new_name, devices):
        """
        Update existing L2GW.

        :param l2gw_id: L2GW id to update its parameters.
        :param l2gw_new_name: name of the L2GW.
        :param devices: L2GW parameters.

        :return: Response of the L2GW update API.
        """
        rsp = self.l2gw_client.update_l2_gateway(l2gw_id,
                                                 name=l2gw_new_name, **devices)
        return rsp

    def nsx_bridge_cluster_info(self):
        """
        Collect the device and interface name of the nsx brdige cluster.

        :return: nsx bridge id and display name.
        """
        response = self.nsxv3_client_obj.get_bridge_cluster_info()
        if len(response) == 0:
            raise RuntimeError(_("NSX bridge cluster information is null"))
        return [(x.get("id"), x.get("display_name")) for x in response]

    def create_l2gw_connection(self, l2gwc_param):
        """
        Creates L2GWC and return the response.

        :param l2gwc_param: L2GWC parameters.

        :return: response of L2GWC create API.
        """
        LOG.info(_LI("l2gwc param: %(param)s ") % {"param": l2gwc_param})
        l2gwc_request_body = {"l2_gateway_id": l2gwc_param["l2_gateway_id"],
                              "network_id": l2gwc_param["network_id"]}
        if "segmentation_id" in l2gwc_param:
            l2gwc_request_body["segmentation_id"] = l2gwc_param[
                "segmentation_id"]
        LOG.info(_LI("l2gwc_request_body: %s") % l2gwc_request_body)
        rsp = self.l2gwc_client.create_l2_gateway_connection(
            **l2gwc_request_body)
        LOG.info(_LI("l2gwc response: %s") % rsp)
        self.l2gwc_created[rsp[constants.L2GWC]["id"]] = rsp[constants.L2GWC]
        return rsp

    def delete_l2gw_connection(self, l2gwc_id):
        """
        Delete L2GWC and returns the response.

        :param l2gwc_id: L2GWC id to delete L2GWC.

        :return: response of the l2gwc delete API.
        """
        LOG.info(_LI("L2GW connection id: %(id)s to be deleted")
                 % {"id": l2gwc_id})
        rsp = self.l2gwc_client.delete_l2_gateway_connection(l2gwc_id)
        LOG.info(_LI("response : %(rsp)s") % {"rsp": rsp})
        return rsp
