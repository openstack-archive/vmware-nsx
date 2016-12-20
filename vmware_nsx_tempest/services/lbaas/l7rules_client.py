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

from tempest.lib.services.network import base

from vmware_nsx_tempest.services import network_client_base as base_client


class L7RulesClient(base.BaseNetworkClient):
    resource = 'rule'
    resource_plural = 'rules'
    resource_base_path = '/lbaas/l7policies/%s/rules'
    resource_object_path = '/lbaas/l7policies/%s/rules/%s'

    def create_l7rule(self, policy_id, **kwargs):
        uri = self.resource_base_path % policy_id
        post_data = {self.resource: kwargs}
        return self.create_resource(uri, post_data)

    def update_l7rule(self, policy_id, rule_id, **kwargs):
        uri = self.resource_object_path % (policy_id, rule_id)
        post_data = {self.resource: kwargs}
        return self.update_resource(uri, post_data)

    def show_l7rule(self, policy_id, rule_id, **fields):
        uri = self.resource_object_path % (policy_id, rule_id)
        return self.show_resource(uri, **fields)

    def delete_l7rule(self, policy_id, rule_id):
        uri = self.resource_object_path % (policy_id, rule_id)
        return self.delete_resource(uri)

    def list_l7rules(self, policy_id, **filters):
        uri = self.resource_base_path % policy_id
        return self.list_resources(uri, **filters)


def get_client(client_mgr):
    """create a lbaas l7rules client from manager or networks_client"""
    manager = getattr(client_mgr, 'manager', client_mgr)
    net_client = getattr(manager, 'networks_client')
    try:
        _params = base_client.default_params_with_timeout_values.copy()
    except Exception:
        _params = {}
    client = L7RulesClient(net_client.auth_provider,
                           net_client.service,
                           net_client.region,
                           net_client.endpoint_type,
                           **_params)
    return client
