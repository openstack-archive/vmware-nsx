# Copyright 2016 VMware Inc
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
from vmware_nsx_tempest.services import network_client_base as base_client

LOG = log.getLogger(__name__)


class TaaSClient(base.BaseNetworkClient):

    """
    Request resources via API for TapService and TapFlow

         create request
         show request
         delete request
         list all request

    """

    # Tap Service

    def create_tap_service(self, **kwargs):
        uri = '/taas/tap_services'
        post_data = {'tap_service': kwargs}
        LOG.info(_LI("URI : %(uri)s, posting data : %(post_data)s") % {
            "uri": uri, "post_data": post_data})
        return self.create_resource(uri, post_data)

    def list_tap_service(self, **filters):
        uri = '/taas/tap_services'
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.list_resources(uri, **filters)

    def show_tap_service(self, ts_id, **fields):
        uri = '/taas/tap_services' + "/" + ts_id
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.show_resource(uri, **fields)

    def delete_tap_service(self, ts_id):
        uri = '/taas/tap_services' + "/" + ts_id
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.delete_resource(uri)

    #  Tap Flow

    def create_tap_flow(self, **kwargs):
        uri = '/taas/tap_flows'
        post_data = {'tap_flow': kwargs}
        LOG.info(_LI("URI : %(uri)s, posting data : %(post_data)s") % {
            "uri": uri, "post_data": post_data})
        return self.create_resource(uri, post_data)

    def list_tap_flow(self, **filters):
        uri = '/taas/tap_flows'
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.list_resources(uri, **filters)

    def show_tap_flow(self, tf_id, **fields):
        uri = '/taas/tap_flows' + "/" + tf_id
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.show_resource(uri, **fields)

    def delete_tap_flow(self, tf_id):
        uri = '/taas/tap_flows' + "/" + tf_id
        LOG.info(_LI("URI : %(uri)s") % {"uri": uri})
        return self.delete_resource(uri)


def get_client(client_mgr):

    """
    Create a TaaS client from manager or networks_client

    """

    try:
        manager = getattr(client_mgr, "manager", client_mgr)
        net_client = getattr(manager, "networks_client")
        _params = base_client.default_params_with_timeout_values.copy()
    except AttributeError as attribute_err:
        LOG.warning(_LW("Failed to locate the attribute, Error: %(err_msg)s") %
                    {"err_msg": attribute_err.__str__()})
        _params = {}
    client = TaaSClient(net_client.auth_provider,
                        net_client.service,
                        net_client.region,
                        net_client.endpoint_type,
                        **_params)
    return client
