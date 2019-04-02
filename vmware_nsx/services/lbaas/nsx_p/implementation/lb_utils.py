# Copyright 2019 VMware, Inc.
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
from oslo_config import cfg
from oslo_log import helpers as log_helpers

from vmware_nsx._i18n import _
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_p.implementation import lb_const as p_const
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils

ADV_RULE_NAME = 'LB external VIP advertisement'


@log_helpers.log_method_call
def get_rule_match_conditions(policy):
    match_conditions = []
    # values in rule have already been validated in LBaaS API,
    # we won't need to valid anymore in driver, and just get
    # the LB rule mapping from the dict.
    for rule in policy['rules']:
        match_type = lb_const.LB_RULE_MATCH_TYPE[rule['compare_type']]
        if rule['type'] == lb_const.L7_RULE_TYPE_COOKIE:
            header_value = rule['key'] + '=' + rule['value']
            match_conditions.append(
                {'type': 'LBHttpRequestHeaderCondition',
                 'match_type': match_type,
                 'header_name': 'Cookie',
                 'header_value': header_value})
        elif rule['type'] == lb_const.L7_RULE_TYPE_FILE_TYPE:
            match_conditions.append(
                {'type': 'LBHttpRequestUriCondition',
                 'match_type': match_type,
                 'uri': '*.' + rule['value']})
        elif rule['type'] == lb_const.L7_RULE_TYPE_HEADER:
            match_conditions.append(
                {'type': 'LBHttpRequestHeaderCondition',
                 'match_type': match_type,
                 'header_name': rule['key'],
                 'header_value': rule['value']})
        elif rule['type'] == lb_const.L7_RULE_TYPE_HOST_NAME:
            match_conditions.append(
                {'type': 'LBHttpRequestHeaderCondition',
                 'match_type': match_type,
                 'header_name': 'Host',
                 'header_value': rule['value']})
        elif rule['type'] == lb_const.L7_RULE_TYPE_PATH:
            match_conditions.append(
                {'type': 'LBHttpRequestUriCondition',
                 'match_type': match_type,
                 'uri': rule['value']})
        else:
            msg = (_('l7rule type %(type)s is not supported in LBaaS') %
                   {'type': rule['type']})
            raise n_exc.BadRequest(resource='lbaas-l7rule', msg=msg)
    return match_conditions


@log_helpers.log_method_call
def get_rule_actions(l7policy):
    if l7policy['action'] == lb_const.L7_POLICY_ACTION_REDIRECT_TO_POOL:
        if l7policy['redirect_pool_id']:
            lb_pool_id = l7policy['redirect_pool_id']
            actions = [{'type': p_const.LB_SELECT_POOL_ACTION,
                        'pool_id': lb_pool_id}]
        else:
            msg = _('Failed to get LB pool binding from nsx db')
            raise n_exc.BadRequest(resource='lbaas-l7rule-create',
                                   msg=msg)
    elif l7policy['action'] == lb_const.L7_POLICY_ACTION_REDIRECT_TO_URL:
        actions = [{'type': p_const.LB_HTTP_REDIRECT_ACTION,
                    'redirect_status': lb_const.LB_HTTP_REDIRECT_STATUS,
                    'redirect_url': l7policy['redirect_url']}]
    elif l7policy['action'] == lb_const.L7_POLICY_ACTION_REJECT:
        actions = [{'type': p_const.LB_REJECT_ACTION,
                    'reply_status': lb_const.LB_HTTP_REJECT_STATUS}]
    else:
        msg = (_('Invalid l7policy action: %(action)s') %
               {'action': l7policy['action']})
        raise n_exc.BadRequest(resource='lbaas-l7rule-create',
                               msg=msg)
    return actions


@log_helpers.log_method_call
def convert_l7policy_to_lb_rule(policy):
    return {
        'match_conditions': get_rule_match_conditions(policy),
        'actions': get_rule_actions(policy),
        'phase': lb_const.LB_RULE_HTTP_FORWARDING,
        'match_strategy': 'ALL'
    }


@log_helpers.log_method_call
def remove_rule_from_policy(rule):
    l7rules = rule['policy']['rules']
    rule['policy']['rules'] = [r for r in l7rules if r['id'] != rule['id']]


@log_helpers.log_method_call
def update_rule_in_policy(rule):
    remove_rule_from_policy(rule)
    rule['policy']['rules'].append(rule)


@log_helpers.log_method_call
def update_router_lb_vip_advertisement(context, core_plugin, router_id):
    router = core_plugin.get_router(context, router_id)

    # Add a rule to advertise external vips on the router

    # TODO(kobis): Code below should be executed when platform supports
    #
    #     external_subnets = core_plugin._find_router_gw_subnets(
    #         context.elevated(), router)
    #     external_cidrs = [s['cidr'] for s in external_subnets]
    #     if external_cidrs:
    #         core_plugin.nsxpolicy.tier1.add_advertisement_rule(
    #             router_id,
    #             ADV_RULE_NAME,
    #             p_constants.ADV_RULE_PERMIT,
    #             p_constants.ADV_RULE_OPERATOR_GE,
    #             [p_constants.ADV_RULE_TIER1_LB_VIP],
    #             external_cidrs)
    if cfg.CONF.nsx_p.allow_passthrough:
        lb_utils.update_router_lb_vip_advertisement(
            context, core_plugin, router,
            core_plugin.nsxpolicy.tier1.get_realized_id(
                router_id, entity_type='RealizedLogicalRouter'))
    else:
        msg = (_('Failed to set loadbalancer advertisement rule for router %s')
               % router_id)
        raise n_exc.BadRequest(resource='lbaas-loadbalancer', msg=msg)
