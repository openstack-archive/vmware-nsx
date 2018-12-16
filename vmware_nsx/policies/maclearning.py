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
        'create_port:mac_learning_enabled',
        base.RULE_ADMIN_OR_NET_OWNER_OR_ADVSVC,
        'Create a port with ``mac_learning_enabled`` attribute',
        [
            {
                'method': 'POST',
                'path': '/ports',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_port:mac_learning_enabled',
        base.RULE_ADMIN_OR_NET_OWNER_OR_ADVSVC,
        'Update ``mac_learning_enabled`` attribute of a port',
        [
            {
                'method': 'PUT',
                'path': '/ports/{id}',
            },
        ]
    ),
]


def list_rules():
    return rules
