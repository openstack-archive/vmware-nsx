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

from neutron_lib import exceptions as n_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3 import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc

LOG = logging.getLogger(__name__)


class EdgeL7RuleManager(base_mgr.Nsxv3LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeL7RuleManager, self).__init__()

    @staticmethod
    def _validate_rule_in_policy(policy):
        # Only one l7rule is allowed for each l7policy in pike release.
        # This validation is to allow only one l7rule per l7policy.
        if len(policy.rules) > 1:
            msg = (_('Only one l7rule is allowed on l7policy'
                     '%(policy)s') % {'policy': policy.id})
            raise n_exc.BadRequest(resource='lbaas-l7rule-create',
                                   msg=msg)

    @log_helpers.log_method_call
    def _get_rule_match_conditions(self, rule):
        match_conditions = []
        # values in rule have already been validated in LBaaS API,
        # we won't need to valid anymore in driver, and just get
        # the LB rule mapping from the dict.
        match_type = lb_const.LB_RULE_MATCH_TYPE[rule.compare_type]
        if rule.type == lb_const.L7_RULE_TYPE_COOKIE:
            header_value = rule.key + '=' + rule.value
            match_conditions.append(
                {'type': 'LbHttpRequestHeaderCondition',
                 'match_type': match_type,
                 'header_name': 'Cookie',
                 'header_value': header_value})
        elif rule.type == lb_const.L7_RULE_TYPE_FILE_TYPE:
            match_conditions.append(
                {'type': 'LbHttpRequestUriCondition',
                 'match_type': match_type,
                 'uri': '*.' + rule.value})
        elif rule.type == lb_const.L7_RULE_TYPE_HEADER:
            match_conditions.append(
                {'type': 'LbHttpRequestHeaderCondition',
                 'match_type': match_type,
                 'header_name': rule.key,
                 'header_value': rule.value})
        elif rule.type == lb_const.L7_RULE_TYPE_HOST_NAME:
            match_conditions.append(
                {'type': 'LbHttpRequestHeaderCondition',
                 'match_type': match_type,
                 'header_name': 'Host',
                 'header_value': rule.value})
        elif rule.type == lb_const.L7_RULE_TYPE_PATH:
            match_conditions.append(
                {'type': 'LbHttpRequestUriCondition',
                 'match_type': match_type,
                 'uri': rule.value})
        else:
            msg = (_('l7rule type %(type)s is not supported in LBaaS') %
                   {'type': rule.type})
            LOG.error(msg)
            raise n_exc.BadRequest(resource='lbaas-l7rule', msg=msg)
        return match_conditions

    @log_helpers.log_method_call
    def _get_rule_actions(self, context, rule):
        lb_id = rule.policy.listener.loadbalancer_id
        l7policy = rule.policy
        if l7policy.action == lb_const.L7_POLICY_ACTION_REDIRECT_TO_POOL:
            pool_binding = nsx_db.get_nsx_lbaas_pool_binding(
                context.session, lb_id, l7policy.redirect_pool_id)
            if pool_binding:
                lb_pool_id = pool_binding['lb_pool_id']
                actions = [{'type': lb_const.LB_SELECT_POOL_ACTION,
                            'pool_id': lb_pool_id}]
            else:
                msg = _('Failed to get LB pool binding from nsx db')
                raise n_exc.BadRequest(resource='lbaas-l7rule-create',
                                       msg=msg)
        elif l7policy.action == lb_const.L7_POLICY_ACTION_REDIRECT_TO_URL:
            actions = [{'type': lb_const.LB_HTTP_REDIRECT_ACTION,
                        'redirect_status': lb_const.LB_HTTP_REDIRECT_STATUS,
                        'redirect_url': l7policy.redirect_url}]
        elif l7policy.action == lb_const.L7_POLICY_ACTION_REJECT:
            actions = [{'type': lb_const.LB_REJECT_ACTION,
                        'reply_status': lb_const.LB_HTTP_REJECT_STATUS}]
        else:
            msg = (_('Invalid l7policy action: %(action)s') %
                   {'action': l7policy.action})
            raise n_exc.BadRequest(resource='lbaas-l7rule-create',
                                   msg=msg)
        return actions

    @log_helpers.log_method_call
    def _convert_l7policy_to_lb_rule(self, context, rule):
        body = {}
        body['match_conditions'] = self._get_rule_match_conditions(rule)
        body['actions'] = self._get_rule_actions(context, rule)
        body['phase'] = lb_const.LB_RULE_HTTP_FORWARDING
        body['match_strategy'] = 'ANY'

        return body

    @log_helpers.log_method_call
    def create(self, context, rule):
        self._validate_rule_in_policy(rule.policy)

        lb_id = rule.policy.listener.loadbalancer_id
        listener_id = rule.policy.listener_id
        vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server
        rule_client = self.core_plugin.nsxlib.load_balancer.rule
        tags = lb_utils.get_tags(self.core_plugin, rule.id,
                                 lb_const.LB_L7RULE_TYPE,
                                 rule.tenant_id, context.project_name)

        binding = nsx_db.get_nsx_lbaas_listener_binding(
            context.session, lb_id, listener_id)
        if not binding:
            msg = _('Cannot find nsx lbaas binding for listener '
                    '%(listener_id)s') % {'listener_id': listener_id}
            raise n_exc.BadRequest(resource='lbaas-l7rule-create', msg=msg)

        vs_id = binding['lb_vs_id']
        rule_body = self._convert_l7policy_to_lb_rule(context, rule)
        try:
            lb_rule = rule_client.create(tags=tags, **rule_body)
        except nsxlib_exc.ManagerError:
            self.lbv2_driver.l7rule.failed_completion(context, rule)
            msg = _('Failed to create lb rule at NSX backend')
            raise n_exc.BadRequest(resource='lbaas-l7rule-create',
                                   msg=msg)
        try:
            vs_client.add_rule(vs_id, lb_rule['id'])
        except nsxlib_exc.ManagerError:
            self.lbv2_driver.l7rule.failed_completion(context, rule)
            msg = (_('Failed to add rule %(rule)% to virtual server '
                     '%(vs)s at NSX backend') %
                   {'rule': lb_rule['id'], 'vs': vs_id})
            raise n_exc.BadRequest(resource='lbaas-l7rule-create',
                                   msg=msg)

        nsx_db.add_nsx_lbaas_l7rule_binding(
            context.session, lb_id, rule.l7policy_id, rule.id,
            lb_rule['id'], vs_id)
        self.lbv2_driver.l7rule.successful_completion(context, rule)

    @log_helpers.log_method_call
    def update(self, context, old_rule, new_rule):
        self.lbv2_driver.l7rule.successful_completion(context, new_rule)

    @log_helpers.log_method_call
    def delete(self, context, rule):
        lb_id = rule.policy.listener.loadbalancer_id
        vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server
        rule_client = self.core_plugin.nsxlib.load_balancer.rule

        binding = nsx_db.get_nsx_lbaas_l7rule_binding(
            context.session, lb_id, rule.l7policy_id, rule.id)
        if binding:
            vs_id = binding['lb_vs_id']
            rule_id = binding['lb_rule_id']
            try:
                vs_client.remove_rule(vs_id, rule_id)
            except nsx_exc.NsxResourceNotFound:
                msg = (_("virtual server cannot be found on nsx: %(vs)s") %
                       {'vs': vs_id})
                raise n_exc.BadRequest(resource='lbaas-l7rule-delete',
                                       msg=msg)
            except nsxlib_exc.ManagerError:
                self.lbv2_driver.l7rule.failed_completion(context,
                                                          rule)
                msg = (_('Failed to update rule %(rule)s on virtual server '
                         '%(vs)s') % {'rule': rule_id, 'vs': vs_id})
                raise n_exc.BadRequest(resource='lbaas-l7rule-delete',
                                       msg=msg)
            try:
                rule_client.delete(rule_id)
            except nsx_exc.NsxResourceNotFound:
                LOG.warning("LB rule cannot be found on nsx: %(rule)s",
                            {'rule': rule_id})
            except nsxlib_exc.ManagerError:
                self.lbv2_driver.l7rule.failed_completion(context,
                                                          rule)
                msg = (_('Failed to delete lb rule: %(rule)s') %
                       {'rule': rule.id})
                raise n_exc.BadRequest(resource='lbaas-l7rule-delete',
                                       msg=msg)
            nsx_db.delete_nsx_lbaas_l7rule_binding(
                context.session, lb_id, rule.l7policy_id, rule.id)
        self.lbv2_driver.l7rule.successful_completion(context, rule,
                                                      delete=True)
