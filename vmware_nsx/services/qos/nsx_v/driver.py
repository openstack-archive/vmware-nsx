# Copyright 2017 VMware, Inc.
#
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

from oslo_log import log as logging

from neutron.services.qos.drivers import base
from neutron.services.qos import qos_consts

LOG = logging.getLogger(__name__)
DRIVER = None
SUPPORTED_RULES = [qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                   qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH]


class NSXvQosDriver(base.DriverBase):

    @staticmethod
    def create(core_plugin):
        return NSXvQosDriver(
            core_plugin,
            name='NSXvQosDriver',
            vif_types=None,
            vnic_types=None,
            supported_rules=SUPPORTED_RULES,
            requires_rpc_notifications=False)

    def __init__(self, core_plugin, **kwargs):
        super(NSXvQosDriver, self).__init__(**kwargs)
        self.core_plugin = core_plugin
        self.requires_rpc_notifications = False

    def is_vif_type_compatible(self, vif_type):
        return True

    def is_vnic_compatible(self, vnic_type):
        return True

    def create_policy(self, context, policy):
        pass

    def update_policy(self, context, policy):
        # get all the bound networks of this policy
        networks = policy.get_bound_networks()
        for net_id in networks:
            # update the new bw limitations for this network
            self.core_plugin._update_qos_on_backend_network(
                context, net_id, policy.id)

    def delete_policy(self, context, policy):
        pass


def register(core_plugin):
    """Register the NSX-V QoS driver."""
    global DRIVER
    if not DRIVER:
        DRIVER = NSXvQosDriver.create(core_plugin)
    LOG.debug('NSXvQosDriver QoS driver registered')
