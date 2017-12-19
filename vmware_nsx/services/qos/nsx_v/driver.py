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

from neutron_lib import constants
from neutron_lib.db import constants as db_constants
from neutron_lib.services.qos import base
from neutron_lib.services.qos import constants as qos_consts
from oslo_log import log as logging

from vmware_nsx.extensions import projectpluginmap

LOG = logging.getLogger(__name__)
DRIVER = None
SUPPORTED_RULES = {
    qos_consts.RULE_TYPE_BANDWIDTH_LIMIT: {
        qos_consts.MAX_KBPS: {
            'type:range': [0, db_constants.DB_INTEGER_MAX_VALUE]},
        qos_consts.MAX_BURST: {
            'type:range': [0, db_constants.DB_INTEGER_MAX_VALUE]},
        qos_consts.DIRECTION: {
            'type:values': [constants.EGRESS_DIRECTION,
                            constants.INGRESS_DIRECTION]}
    },
    qos_consts.RULE_TYPE_DSCP_MARKING: {
        qos_consts.DSCP_MARK: {'type:values': constants.VALID_DSCP_MARKS}
    }
}


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
        if self.core_plugin.is_tvd_plugin():
            # get the plugin that match this driver
            self.core_plugin = self.core_plugin.get_plugin_by_type(
                projectpluginmap.NsxPlugins.NSX_V)
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
