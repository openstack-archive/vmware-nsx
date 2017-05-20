# Copyright 2017 VMware, Inc.
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

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx.common import locking
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas.nsx_v.v2 import l7policy_mgr

LOG = logging.getLogger(__name__)


class EdgeL7RuleManager(base_mgr.EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeL7RuleManager, self).__init__(vcns_driver)

    def _handle_l7policy_rules_change(self, context, rule, delete=False):
        # Get the nsx application rule id and edge id
        edge_id, app_rule_id = l7policy_mgr.policy_to_edge_and_rule_id(
            context, rule.l7policy_id)

        # Create the script for the new policy data.
        # The policy obj on the rule is already updated with the
        # created/updated/deleted rule.
        app_rule = l7policy_mgr.policy_to_application_rule(rule.policy)
        try:
            with locking.LockManager.get_lock(edge_id):
                # update the backend application rule for the updated policy
                self.vcns.update_app_rule(edge_id, app_rule_id, app_rule)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.l7rule.failed_completion(context, rule)
                LOG.error('Failed to update L7rules on edge %(edge)s: '
                          '%(err)s',
                          {'edge': edge_id, 'err': e})

        # complete the transaction
        self.lbv2_driver.l7rule.successful_completion(context, rule,
                                                      delete=delete)

    @log_helpers.log_method_call
    def create(self, context, rule):
        self._handle_l7policy_rules_change(context, rule)

    @log_helpers.log_method_call
    def update(self, context, old_rule, new_rule):
        self._handle_l7policy_rules_change(context, new_rule)

    @log_helpers.log_method_call
    def delete(self, context, rule):
        self._handle_l7policy_rules_change(context, rule, delete=True)
