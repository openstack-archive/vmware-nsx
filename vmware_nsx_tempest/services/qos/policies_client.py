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


class PoliciesClient(base.BaseNetworkClient):
    resource = 'policy'
    resource_plural = 'policies'
    path = 'qos/policies'
    resource_base_path = '/%s' % path
    resource_object_path = '/%s/%%s' % path

    def create_policy(self, **kwargs):
        uri = self.resource_base_path
        post_data = {self.resource: kwargs}
        return self.create_resource(uri, post_data)

    def update_policy(self, policy_id, **kwargs):
        uri = self.resource_object_path % policy_id
        post_data = {self.resource: kwargs}
        return self.update_resource(uri, post_data)

    def show_policy(self, policy_id, **fields):
        uri = self.resource_object_path % policy_id
        return self.show_resource(uri, **fields)

    def delete_policy(self, policy_id):
        uri = self.resource_object_path % policy_id
        return self.delete_resource(uri)

    def list_policies(self, **filters):
        uri = self.resource_base_path
        return self.list_resources(uri, **filters)

    # utility
    def get_policy_id(self, policy_id_or_name):
        policies = self.list_policies(name=policy_id_or_name)
        policy_list = policies[self.resource_plural]
        if len(policy_list) > 0:
            return policy_list[0]['id']
        return policy_id_or_name


def get_client(client_mgr,
               set_property=False,
               with_name="qos_policies_client"):
    """create a qos policies client from manager or networks_client

    For tempest user:
        client = policies_client.get_client(osn.adm)
    """
    manager = getattr(client_mgr, 'manager', client_mgr)
    net_client = getattr(manager, 'networks_client')
    try:
        _params = manager.default_params_with_timeout_values.copy()
    except Exception:
        _params = {}
    client = PoliciesClient(net_client.auth_provider,
                            net_client.service,
                            net_client.region,
                            net_client.endpoint_type,
                            **_params)
    if set_property:
        setattr(manager, with_name, client)
    return client
