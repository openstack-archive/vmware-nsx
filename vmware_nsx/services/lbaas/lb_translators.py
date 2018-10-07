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

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def lb_hm_obj_to_dict(hm):
    # Translate the LBaaS HM to a dictionary skipping the pool object to avoid
    # recursions
    hm_dict = hm.to_dict(pool=False)
    # Translate the pool separately without it's internal objects
    if hm.pool:
        hm_dict['pool'] = lb_pool_obj_to_dict(hm.pool, with_listeners=False)
    return hm_dict


def lb_listener_obj_to_dict(listener):
    # Translate the LBaaS listener to a dictionary skipping the some objects
    # to avoid recursions
    listener_dict = listener.to_dict(loadbalancer=False, default_pool=False)

    # Translate the default pool separately without it's internal objects
    if listener.default_pool:
        listener_dict['default_pool'] = lb_pool_obj_to_dict(
            listener.default_pool, with_listeners=False)
    else:
        listener_dict['default_pool'] = None

    if listener.loadbalancer:
        listener_dict['loadbalancer'] = lb_loadbalancer_obj_to_dict(
            listener.loadbalancer)
    else:
        listener_dict['loadbalancer'] = None
    return listener_dict


def lb_pool_obj_to_dict(pool, with_listeners=True):
    # Translate the LBaaS pool to a dictionary skipping the some objects
    # to avoid recursions
    pool_dict = pool.to_dict(listeners=False, listener=False)
    if with_listeners:
        # Translate the listener/s separately without it's internal objects
        if pool.listener:
            pool_dict['listener'] = lb_listener_obj_to_dict(pool.listener)
        else:
            pool_dict['listener'] = None
        pool_dict['listeners'] = []
        if pool.listeners:
            for listener in pool.listeners:
                pool_dict['listeners'].append(
                    lb_listener_obj_to_dict(listener))
    return pool_dict


def lb_loadbalancer_obj_to_dict(loadbalancer):
    return loadbalancer.to_dict()


def lb_member_obj_to_dict(member):
    # Translate the LBaaS member to a dictionary skipping the some objects
    # to avoid recursions
    member_dict = member.to_dict(pool=False)
    # Add the pool dictionary (with its listeners and loadbalancer)
    if member.pool:
        member_dict['pool'] = lb_pool_obj_to_dict(member.pool)
    else:
        member_dict['pool'] = None
    return member_dict


def lb_l7policy_obj_to_dict(l7policy):
    # Translate the LBaaS L7 policy to a dictionary skipping the some objects
    # to avoid recursions
    l7policy_dict = l7policy.to_dict(listener=False, rules=False)
    # Add the listener dictionary
    if l7policy.listener:
        l7policy_dict['listener'] = lb_listener_obj_to_dict(l7policy.listener)
    else:
        l7policy_dict['listener'] = None
    # Add the rules
    l7policy_dict['rules'] = []
    if l7policy.rules:
        for rule in l7policy.rules:
            l7policy_dict['rules'].append(
                lb_l7rule_obj_to_dict(rule, with_policy=False))

    return l7policy_dict


def lb_l7rule_obj_to_dict(l7rule, with_policy=True):
    # Translate the LBaaS L7 rule to a dictionary skipping the some objects
    # to avoid recursions
    l7rule_dict = l7rule.to_dict(policy=False)
    # Add the policy dictionary
    if with_policy:
        l7rule_dict['policy'] = lb_l7policy_obj_to_dict(l7rule.policy)
    else:
        l7rule_dict['policy'] = None
    return l7rule_dict
