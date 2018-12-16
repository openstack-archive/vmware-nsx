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

import itertools

from vmware_nsx.policies import housekeeper
from vmware_nsx.policies import lsn
from vmware_nsx.policies import maclearning
from vmware_nsx.policies import network_gateway
from vmware_nsx.policies import nsxpolicy
from vmware_nsx.policies import providersecuritygroup
from vmware_nsx.policies import qos_queue
from vmware_nsx.policies import security_group


def list_rules():
    return itertools.chain(
        lsn.list_rules(),
        maclearning.list_rules(),
        network_gateway.list_rules(),
        providersecuritygroup.list_rules(),
        qos_queue.list_rules(),
        security_group.list_rules(),
        nsxpolicy.list_rules(),
        housekeeper.list_rules(),
    )
