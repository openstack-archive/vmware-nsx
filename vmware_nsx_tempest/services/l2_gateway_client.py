# Copyright 2016 VMware, Inc.
# All Rights Reserved
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
from oslo_log import log

from tempest.lib.services.network import base

from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest._i18n import _LW
from vmware_nsx_tempest.common import constants

LOG = log.getLogger(__name__)


class L2GatewayClient(base.BaseNetworkClient):
    """
    Request resources via API for L2GatewayClient
        l2 gateway create request
        l2 gateway update request
        l2 gateway show request
        l2 gateway delete request
        l2 gateway list all request
    """

    def create_l2_gateway(self, **kwargs):
        uri = constants.L2_GWS_BASE_URI
        post_data = {constants.L2GW: kwargs}
        LOG.info(_LI("URI : %(uri)s, posting data : %(post_data)s") % {
            "uri": uri, "post_data": post_data})
        return self.create_resource(uri, post_data)

    def update_l2_gateway(self, l2_gateway_id, **kwargs):
        uri = constants.L2_GWS_BASE_URI + "/" + l2_gateway_id
        post_data = {constants.L2GW: kwargs}
        constants.LOG.info(
            _LI("URI : %(uri)s, posting data : %(post_data)s") % {
                "uri": uri, "post_data": post_data})
        return self.update_resource(uri, post_data)

    def show_l2_gateway(self, l2_gateway_id, **fields):
        uri = constants.L2_GWS_BASE_URI + "/" + l2_gateway_id
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.show_resource(uri, **fields)

    def delete_l2_gateway(self, l2_gateway_id):
        uri = constants.L2_GWS_BASE_URI + "/" + l2_gateway_id
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.delete_resource(uri)

    def list_l2_gateways(self, **filters):
        uri = constants.L2_GWS_BASE_URI
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.list_resources(uri, **filters)


def get_client(client_mgr):
    """
    Create a l2-gateway client from manager or networks_client
    """
    try:
        manager = getattr(client_mgr, "manager", client_mgr)
        net_client = getattr(manager, "networks_client")
        _params = manager.default_params_withy_timeout_values.copy()
    except AttributeError as attribute_err:
        LOG.warning(_LW("Failed to locate the attribute, Error: %(err_msg)s") %
                    {"err_msg": attribute_err.__str__()})
        _params = {}
    client = L2GatewayClient(net_client.auth_provider,
                             net_client.service,
                             net_client.region,
                             net_client.endpoint_type,
                             **_params)
    return client
