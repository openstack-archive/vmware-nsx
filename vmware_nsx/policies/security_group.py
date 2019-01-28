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
        'create_security_group:logging',
        base.RULE_ADMIN_ONLY,
        'Create a security group with ``logging`` attribute',
        [
            {
                'method': 'POST',
                'path': '/security-groups',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_security_group:logging',
        base.RULE_ADMIN_ONLY,
        'Update ``logging`` attribute of a security group',
        [
            {
                'method': 'PUT',
                'path': '/security-groups/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_security_group:logging',
        base.RULE_ADMIN_ONLY,
        'Get ``logging`` attributes of security groups',
        [
            {
                'method': 'GET',
                'path': '/security-groups',
            },
            {
                'method': 'GET',
                'path': '/security-groups/{id}',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'create_security_group:provider',
        base.RULE_ADMIN_ONLY,
        'Create a security group with ``provider`` attribute',
        [
            {
                'method': 'POST',
                'path': '/security-groups',
            },
        ]
    ),

    policy.DocumentedRuleDefault(
        'create_security_group:policy',
        base.RULE_ADMIN_ONLY,
        'Create a security group with ``policy`` attribute',
        [
            {
                'method': 'POST',
                'path': '/security-groups',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_security_group:policy',
        base.RULE_ADMIN_ONLY,
        'Update ``policy`` attribute of a security group',
        [
            {
                'method': 'PUT',
                'path': '/security-groups/{id}',
            },
        ]
    ),
]


def list_rules():
    return rules
