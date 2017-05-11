# Copyright 2017 VMware Inc
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

from tempest import config
from tempest.lib.common.utils import test_utils

from vmware_nsx_tempest._i18n import _
from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.lib import traffic_manager
from vmware_nsx_tempest.services import nsx_client
from vmware_nsx_tempest.services import openstack_network_clients

LOG = constants.log.getLogger(__name__)

CONF = config.CONF


# It includes feature related function such CRUD Mdproxy, L2GW or QoS
class FeatureManager(traffic_manager.TrafficManager):
    @classmethod
    def setup_clients(cls):
        """
        Create various client connections. Such as NSXv3 and L2 Gateway.
        """
        super(FeatureManager, cls).setup_clients()
        try:
            manager = getattr(cls.os_admin, "manager", cls.os_admin)
            net_client = getattr(manager, "networks_client")
            _params = manager.default_params_withy_timeout_values.copy()
        except AttributeError as attribute_err:
            LOG.warning(
                "Failed to locate the attribute, Error: %(err_msg)s",
                {"err_msg": attribute_err.__str__()})
            _params = {}
        cls.l2gw_client = openstack_network_clients.L2GatewayClient(
            net_client.auth_provider,
            net_client.service,
            net_client.region,
            net_client.endpoint_type,
            **_params)
        cls.nsx_client = nsx_client.NSXClient(
            CONF.network.backend,
            CONF.nsxv3.nsx_manager,
            CONF.nsxv3.nsx_user,
            CONF.nsxv3.nsx_password)
        cls.l2gwc_client = openstack_network_clients.L2GatewayConnectionClient(
            net_client.auth_provider,
            net_client.service,
            net_client.region,
            net_client.endpoint_type,
            **_params)

    #
    # L2Gateway base class. To get basics of L2GW.
    #
    def create_l2gw(self, l2gw_name, l2gw_param):
        """
        Creates L2GW and returns the response.

        :param l2gw_name: name of the L2GW
        :param l2gw_param: L2GW parameters

        :return: response of L2GW create API
        """
        LOG.info("l2gw name: %(name)s, l2gw_param: %(devices)s ",
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
        LOG.info(" l2gw_request_body: %s", l2gw_request_body)
        rsp = self.l2gw_client.create_l2_gateway(
            name=l2gw_name, **l2gw_request_body)
        LOG.info(" l2gw response: %s", rsp)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.l2gw_client.delete_l2_gateway, rsp[constants.L2GW]["id"])
        return rsp, devices

    def delete_l2gw(self, l2gw_id):
        """
        Delete L2gw.

        :param l2gw_id: L2GW id to delete l2gw.

        :return: response of the l2gw delete API.
        """
        LOG.info("L2GW id: %(id)s to be deleted.", {"id": l2gw_id})
        rsp = self.l2gw_client.delete_l2_gateway(l2gw_id)
        LOG.info("response : %(rsp)s", {"rsp": rsp})
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
        response = self.nsx_client.get_bridge_cluster_info()
        if len(response) == 0:
            raise RuntimeError(_("NSX bridge cluster information is null"))
        return [(x.get("id"), x.get("display_name")) for x in response]

    def create_l2gw_connection(self, l2gwc_param):
        """
        Creates L2GWC and return the response.

        :param l2gwc_param: L2GWC parameters.

        :return: response of L2GWC create API.
        """
        LOG.info("l2gwc param: %(param)s ", {"param": l2gwc_param})
        l2gwc_request_body = {"l2_gateway_id": l2gwc_param["l2_gateway_id"],
                              "network_id": l2gwc_param["network_id"]}
        if "segmentation_id" in l2gwc_param:
            l2gwc_request_body["segmentation_id"] = l2gwc_param[
                "segmentation_id"]
        LOG.info("l2gwc_request_body: %s", l2gwc_request_body)
        rsp = self.l2gwc_client.create_l2_gateway_connection(
            **l2gwc_request_body)
        LOG.info("l2gwc response: %s", rsp)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.l2gwc_client.delete_l2_gateway_connection,
            rsp[constants.L2GWC]["id"])
        return rsp

    def delete_l2gw_connection(self, l2gwc_id):
        """
        Delete L2GWC and returns the response.

        :param l2gwc_id: L2GWC id to delete L2GWC.

        :return: response of the l2gwc delete API.
        """
        LOG.info("L2GW connection id: %(id)s to be deleted",
                 {"id": l2gwc_id})
        rsp = self.l2gwc_client.delete_l2_gateway_connection(l2gwc_id)
        LOG.info("response : %(rsp)s", {"rsp": rsp})
        return rsp
