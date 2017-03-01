# Copyright 2016 VMware, Inc.
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

from neutron.api.rpc.callbacks import events as callbacks_events
from neutron.objects.qos import policy as qos_policy
from neutron.plugins.common import constants
from neutron.services.qos import qos_consts
from neutron_lib import context as n_context
from neutron_lib.plugins import directory

from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class NsxVQosRule(object):

    def __init__(self, context=None, qos_policy_id=None):
        super(NsxVQosRule, self).__init__()

        self._qos_plugin = None

        # Data structure to hold the NSX-V representation
        # of the neutron QoS Bandwidth rule
        self.bandwidthEnabled = False
        self.averageBandwidth = 0
        self.peakBandwidth = 0
        self.burstSize = 0

        # And data for the DSCP marking rule
        self.dscpMarkEnabled = False
        self.dscpMarkValue = 0

        if qos_policy_id is not None:
            self._init_from_policy_id(context, qos_policy_id)

    def _get_qos_plugin(self):
        if not self._qos_plugin:
            self._qos_plugin = directory.get_plugin(constants.QOS)
        return self._qos_plugin

    # init the nsx_v qos data (outShapingPolicy) from a neutron qos policy
    def _init_from_policy_id(self, context, qos_policy_id):
        self.bandwidthEnabled = False
        self.dscpMarkEnabled = False

        # read the neutron policy restrictions
        if qos_policy_id is not None:
            plugin = self._get_qos_plugin()
            policy_obj = plugin.get_policy(context, qos_policy_id)
            if 'rules' in policy_obj and len(policy_obj['rules']) > 0:
                for rule_obj in policy_obj['rules']:
                    # TODO(asarfaty): for now we support one rule of each type
                    # This code should be fixed in order to support rules of
                    # different directions
                    if (rule_obj['type'] ==
                        qos_consts.RULE_TYPE_BANDWIDTH_LIMIT):
                        self.bandwidthEnabled = True
                        # averageBandwidth: kbps (neutron) -> bps (nsxv)
                        self.averageBandwidth = rule_obj['max_kbps'] * 1024
                        # peakBandwidth: a Multiplying on the average BW
                        # because the neutron qos configuration supports
                        # only 1 value
                        self.peakBandwidth = int(round(
                            self.averageBandwidth *
                            cfg.CONF.NSX.qos_peak_bw_multiplier))
                        # burstSize: kbps (neutron) -> Bytes (nsxv)
                        self.burstSize = rule_obj['max_burst_kbps'] * 128
                    if rule_obj['type'] == qos_consts.RULE_TYPE_DSCP_MARKING:
                        self.dscpMarkEnabled = True
                        self.dscpMarkValue = rule_obj['dscp_mark']

        return self


def handle_qos_notification(policies_list, event_type, core_plugin):
    # Check if QoS policy rule was created/deleted/updated
    # Only if the policy rule was updated, we need to update the dvs
    if event_type != callbacks_events.UPDATED:
        return

    for policy_obj in policies_list:
        if hasattr(policy_obj, "rules"):
            handle_qos_policy_notification(policy_obj, core_plugin)


def handle_qos_policy_notification(policy_obj, core_plugin):
    # Reload the policy as admin so we will have a context
    context = n_context.get_admin_context()
    admin_policy = qos_policy.QosPolicy.get_object(
        context, id=policy_obj.id)
    # get all the bound networks of this policy
    networks = admin_policy.get_bound_networks()
    for net_id in networks:
        # update the new bw limitations for this network
        core_plugin._update_qos_on_backend_network(
            context, net_id, policy_obj.id)
