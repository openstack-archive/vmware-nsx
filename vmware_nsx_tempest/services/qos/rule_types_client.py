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


class RuleTypesClient(base.BaseNetworkClient):
    resource = 'rule_type'
    resource_plural = 'rule_types'
    path = 'qos/rule-types'
    resource_base_path = '/%s' % path
    resource_object_path = '/%s/%%s' % path

    def list_rule_types(self):
        uri = self.resource_base_path
        return self.list_resources(uri)


def get_client(client_mgr,
               set_property=False,
               with_name="qos_rule_types_client"):
    """create a qos rule_types client from manager or networks_client

    For tempest user:
        client = rule_types_client.get_client(osn.adm)
    """
    manager = getattr(client_mgr, 'manager', client_mgr)
    net_client = getattr(manager, 'networks_client')
    try:
        _params = manager.default_params_with_timeout_values.copy()
    except Exception:
        _params = {}
    client = RuleTypesClient(net_client.auth_provider,
                             net_client.service,
                             net_client.region,
                             net_client.endpoint_type,
                             **_params)
    if set_property:
        setattr(manager, with_name, client)
    return client
