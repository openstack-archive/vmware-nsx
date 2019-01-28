#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from oslo_policy import policy

from vmware_nsx.policies import base


rules = [
    policy.DocumentedRuleDefault(
        'create_network_gateway',
        base.RULE_ADMIN_OR_OWNER,
        'Create a network gateway',
        [
            {
                'method': 'POST',
                'path': '/network-gateways',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_network_gateway',
        base.RULE_ADMIN_OR_OWNER,
        'Update a network gateway',
        [
            {
                'method': 'PUT',
                'path': '/network-gateways/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_network_gateway',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a network gateway',
        [
            {
                'method': 'DELETE',
                'path': '/network-gateways/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_network_gateway',
        base.RULE_ADMIN_OR_OWNER,
        'Get network gateways',
        [
            {
                'method': 'GET',
                'path': '/network-gateways',
            },
            {
                'method': 'GET',
                'path': '/network-gateways/{id}',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'connect_network',
        base.RULE_ADMIN_OR_OWNER,
        'Connect a network to a network gateway',
        [
            {
                'method': 'PUT',
                'path': '/network-gateways/{id}/connect_network',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'disconnect_network',
        base.RULE_ADMIN_OR_OWNER,
        'Disconnect a network from a network gateway',
        [
            {
                'method': 'PUT',
                'path': '/network-gateways/{id}/disconnect_network',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'create_gateway_device',
        base.RULE_ADMIN_OR_OWNER,
        'Create a gateway device',
        [
            {
                'method': 'POST',
                'path': '/gateway-devices',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_gateway_device',
        base.RULE_ADMIN_OR_OWNER,
        'Update a gateway device',
        [
            {
                'method': 'PUT',
                'path': '/gateway-devices/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_gateway_device',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a gateway device',
        [
            {
                'method': 'DELETE',
                'path': '/gateway-devices/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_gateway_device',
        base.RULE_ADMIN_OR_OWNER,
        'Get gateway devices',
        [
            {
                'method': 'GET',
                'path': '/gateway-devices',
            },
            {
                'method': 'GET',
                'path': '/gateway-devices/{id}',
            },
        ]
    ),
]


def list_rules():
    return rules
