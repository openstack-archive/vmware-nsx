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
from neutron import context as n_context
from neutron import manager
from neutron.objects.qos import policy as qos_policy
from neutron.services.qos import qos_consts
from neutron_lib.api import validators
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx._i18n import _, _LW
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db

LOG = logging.getLogger(__name__)

MAX_KBPS_MIN_VALUE = 1024
# The max limit is calculated so that the value sent to the backed will
# be smaller than 2**31
MAX_BURST_MAX_VALUE = int((2 ** 31 - 1) / 128)


def handle_qos_notification(policies_list, event_type):
    for policy_obj in policies_list:
        handle_qos_policy_notification(policy_obj, event_type)


def handle_qos_policy_notification(policy_obj, event_type):
    handler = QosNotificationsHandler()
    context = n_context.get_admin_context()

    # Reload the policy as admin so we will have a context
    if (event_type != callbacks_events.DELETED):
        policy = qos_policy.QosPolicy.get_object(context, id=policy_obj.id)

    # Check if QoS policy rule was created/deleted/updated
    if (event_type == callbacks_events.CREATED):
        handler.create_policy(context, policy)

    elif (event_type == callbacks_events.UPDATED):
        if (hasattr(policy_obj, "rules")):
            # Rebuild the QoS data of this policy
            # we may have up to 1 rule of each type
            bw_rule = None
            dscp_rule = None
            for rule in policy_obj["rules"]:
                if rule.rule_type == qos_consts.RULE_TYPE_BANDWIDTH_LIMIT:
                    bw_rule = rule
                else:
                    dscp_rule = rule

            handler.update_policy_rules(
                context, policy_obj.id, bw_rule, dscp_rule)
        else:
            # Without rules - need to update only name / description
            handler.update_policy(context, policy_obj.id, policy)

    elif (event_type == callbacks_events.DELETED):
        handler.delete_policy(context, policy_obj.id)

    else:
        msg = _("Unknown QoS notification event %s") % event_type
        raise nsx_exc.NsxPluginException(err_msg=msg)


class QosNotificationsHandler(object):

    def __init__(self):
        super(QosNotificationsHandler, self).__init__()

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_tags(self, context, policy):
        policy_dict = {'id': policy.id, 'tenant_id': policy.tenant_id}
        return utils.build_v3_tags_payload(
            policy_dict, resource_type='os-neutron-qos-id',
            project_name=context.tenant_name)

    def create_policy(self, context, policy):
        policy_id = policy.id
        tags = self._get_tags(context, policy)
        result = self._core_plugin.nsxlib.create_qos_switching_profile(
            tags=tags, name=policy.name,
            description=policy.description)
        if not result or not validators.is_attr_set(result.get('id')):
            msg = _("Unable to create QoS switching profile on the backend")
            raise nsx_exc.NsxPluginException(err_msg=msg)
        profile_id = result['id']

        # Add the mapping entry of the policy_id <-> profile_id
        nsx_db.add_qos_policy_profile_mapping(context.session,
                                              policy_id,
                                              profile_id)

    def delete_policy(self, context, policy_id):
        profile_id = nsx_db.get_switch_profile_by_qos_policy(
            context.session, policy_id)
        self._core_plugin.nsxlib.delete_qos_switching_profile(profile_id)

    def update_policy(self, context, policy_id, policy):
        profile_id = nsx_db.get_switch_profile_by_qos_policy(
            context.session, policy_id)
        tags = self._get_tags(context, policy)
        self._core_plugin.nsxlib.update_qos_switching_profile(
            profile_id,
            tags=tags,
            name=policy.name,
            description=policy.description)

    def _validate_bw_values(self, bw_rule):
        """Validate that the configured values are allowed by the NSX backend.

        Since failing the action from the notification callback
        is not possible, just log the warning and use the minimal/maximal
        values.
        """
        # Validate the max bandwidth value minimum value
        # (max value is above what neutron allows so no need to check it)
        if (bw_rule.max_kbps < MAX_KBPS_MIN_VALUE):
            LOG.warning(_LW("Invalid input for max_kbps. "
                            "The minimal legal value is %s"),
                        MAX_KBPS_MIN_VALUE)
            bw_rule.max_kbps = MAX_KBPS_MIN_VALUE

        # validate the burst size value max value
        # (max value is 0, and neutron already validates this)
        if (bw_rule.max_burst_kbps > MAX_BURST_MAX_VALUE):
            LOG.warning(_LW("Invalid input for burst_size. "
                            "The maximal legal value is %s"),
                        MAX_BURST_MAX_VALUE)
            bw_rule.max_burst_kbps = MAX_BURST_MAX_VALUE

    def _get_bw_values_from_rule(self, bw_rule):
        """Translate the neutron bandwidth_limit_rule values, into the
        values expected by the NSX-v3 QoS switch profile,
        and validate that those are legal
        """
        if bw_rule:
            shaping_enabled = True
            self._validate_bw_values(bw_rule)

            # translate kbps -> bytes
            burst_size = int(bw_rule.max_burst_kbps) * 128

            # translate kbps -> Mbps
            average_bandwidth = int(round(float(bw_rule.max_kbps) / 1024))

            # peakBandwidth: a Multiplying on the average BW
            # because the neutron qos configuration supports
            # only 1 value
            peak_bandwidth = int(round(average_bandwidth *
                                       cfg.CONF.NSX.qos_peak_bw_multiplier))
        else:
            shaping_enabled = False
            burst_size = None
            peak_bandwidth = None
            average_bandwidth = None

        return shaping_enabled, burst_size, peak_bandwidth, average_bandwidth

    def _get_dscp_values_from_rule(self, dscp_rule):
        """Translate the neutron DSCP marking rule values, into the
        values expected by the NSX-v3 QoS switch profile
        """
        if dscp_rule:
            qos_marking = 'untrusted'
            dscp = dscp_rule.dscp_mark
        else:
            qos_marking = 'trusted'
            dscp = 0

        return qos_marking, dscp

    def update_policy_rules(self, context, policy_id, bw_rule, dscp_rule):
        """Update the QoS switch profile with the BW limitations and
        DSCP marking configuration
        """
        profile_id = nsx_db.get_switch_profile_by_qos_policy(
            context.session, policy_id)

        (shaping_enabled, burst_size, peak_bw,
            average_bw) = self._get_bw_values_from_rule(bw_rule)

        qos_marking, dscp = self._get_dscp_values_from_rule(dscp_rule)
        self._core_plugin.nsxlib.update_qos_switching_profile_shaping(
            profile_id,
            shaping_enabled=shaping_enabled,
            burst_size=burst_size,
            peak_bandwidth=peak_bw,
            average_bandwidth=average_bw,
            qos_marking=qos_marking,
            dscp=dscp)
