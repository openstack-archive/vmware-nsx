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

from neutron_lib.services.qos import base
from neutron_lib.services.qos import constants as qos_consts
from oslo_log import log as logging

from neutron.common import constants as n_consts

from vmware_nsx.services.qos.nsx_v3 import utils as qos_utils

LOG = logging.getLogger(__name__)

DRIVER = None

SUPPORTED_RULES = {
    qos_consts.RULE_TYPE_BANDWIDTH_LIMIT: {
        qos_consts.MAX_KBPS: {
            'type:range': [0, n_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.MAX_BURST: {
            'type:range': [0, n_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.DIRECTION: {
            'type:values': [n_consts.EGRESS_DIRECTION,
                            n_consts.INGRESS_DIRECTION]}
    },
    qos_consts.RULE_TYPE_DSCP_MARKING: {
        qos_consts.DSCP_MARK: {'type:values': n_consts.VALID_DSCP_MARKS}
    }
}


class NSXv3QosDriver(base.DriverBase):

    @staticmethod
    def create():
        return NSXv3QosDriver(
            name='NSXv3QosDriver',
            vif_types=None,
            vnic_types=None,
            supported_rules=SUPPORTED_RULES,
            requires_rpc_notifications=False)

    def __init__(self, **kwargs):
        self.handler = qos_utils.QosNotificationsHandler()
        super(NSXv3QosDriver, self).__init__(**kwargs)

    def is_vif_type_compatible(self, vif_type):
        return True

    def is_vnic_compatible(self, vnic_type):
        return True

    def create_policy(self, context, policy):
        self.handler.create_policy(context, policy)

    def update_policy(self, context, policy):
        if (hasattr(policy, "rules")):
            self.handler.update_policy_rules(
                context, policy.id, policy["rules"])

        # May also need to update name / description
        self.handler.update_policy(context, policy.id, policy)

    def delete_policy(self, context, policy):
        self.handler.delete_policy(context, policy.id)

    def update_policy_precommit(self, context, policy):
        """Validate rules values, before creation"""
        if (hasattr(policy, "rules")):
            for rule in policy["rules"]:
                self.handler.validate_policy_rule(context, policy.id, rule)


def register():
    """Register the NSX-V3 QoS driver."""
    global DRIVER
    if not DRIVER:
        DRIVER = NSXv3QosDriver.create()
    LOG.debug('NSXv3QosDriver QoS driver registered')
