# Copyright 2018 VMware, Inc.
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

from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import lb_utils
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeL7RuleManagerFromDict(base_mgr.NsxpLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def _update_l7rule_change(self, rule, completor, delete=False):
        vs_client = self.core_plugin.nsxpolicy.load_balancer.virtual_server
        policy = rule['policy']
        policy_name = utils.get_name_and_uuid(policy['name'] or 'policy',
                                              policy['id'])
        if delete:
            lb_utils.remove_rule_from_policy(rule)
        else:
            lb_utils.update_rule_in_policy(rule)
        rule_body = lb_utils.convert_l7policy_to_lb_rule(rule['policy'])
        try:
            vs_client.update_lb_rule(policy['listener_id'],
                                     name=policy_name,
                                     position=policy.get('position', 0) - 1,
                                     **rule_body)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to update L7policy %(policy)s: '
                          '%(err)s', {'policy': policy['id'], 'err': e})

        completor(success=True)

    @log_helpers.log_method_call
    def create(self, context, rule, completor):
        self._update_l7rule_change(rule, completor)

    @log_helpers.log_method_call
    def update(self, context, old_rule, new_rule, completor):
        self._update_l7rule_change(new_rule, completor)

    @log_helpers.log_method_call
    def delete(self, context, rule, completor):
        self._update_l7rule_change(rule, completor, delete=True)

    @log_helpers.log_method_call
    def delete_cascade(self, context, rule, completor):
        # No action should be taken on rules delete cascade
        pass
