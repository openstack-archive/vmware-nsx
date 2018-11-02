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

from neutron_lib import exceptions as n_exc

from vmware_nsx.services.lbaas import base_mgr

LOG = logging.getLogger(__name__)


class EdgeLoadbalancerDriverV2(object):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeLoadbalancerDriverV2, self).__init__()

        self.loadbalancer = EdgeLoadBalancerManager()
        self.listener = EdgeListenerManager()
        self.pool = EdgePoolManager()
        self.member = EdgeMemberManager()
        self.healthmonitor = EdgeHealthMonitorManager()
        self.l7policy = EdgeL7PolicyManager()
        self.l7rule = EdgeL7RuleManager()


class EdgeLoadBalancerManager(base_mgr.LoadbalancerBaseManager):

    @log_helpers.log_method_call
    def create(self, context, lb):
        # verify that the subnet belongs to the same plugin as the lb
        lb_p = self.core_plugin._get_plugin_from_project(context,
                                                         lb.tenant_id)
        subnet_p = self.core_plugin._get_subnet_plugin_by_id(
            context, lb.vip_subnet_id)
        if lb_p.plugin_type() != subnet_p.plugin_type():
            self.lbv2_driver.load_balancer.failed_completion(context, lb)
            msg = (_('Subnet must belong to the plugin %s, as the '
                     'loadbalancer') % lb_p.plugin_type())
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
        return lb_p.lbv2_driver.loadbalancer.create(context, lb)

    @log_helpers.log_method_call
    def update(self, context, old_lb, new_lb):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      new_lb.tenant_id)
        return p.lbv2_driver.loadbalancer.update(context, old_lb, new_lb)

    @log_helpers.log_method_call
    def delete(self, context, lb):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      lb.tenant_id)
        return p.lbv2_driver.loadbalancer.delete(context, lb)

    @log_helpers.log_method_call
    def refresh(self, context, lb):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      lb.tenant_id)
        return p.lbv2_driver.loadbalancer.refresh(context, lb)

    @log_helpers.log_method_call
    def stats(self, context, lb):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      lb.tenant_id)
        return p.lbv2_driver.loadbalancer.stats(context, lb)

    @log_helpers.log_method_call
    def get_operating_status(self, context, id, with_members=False):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      context.project_id)
        return p.lbv2_driver.loadbalancer.get_operating_status(
            context, id, with_members=with_members)


class EdgeListenerManager(base_mgr.LoadbalancerBaseManager):

    @log_helpers.log_method_call
    def create(self, context, listener, certificate=None):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      listener.tenant_id)
        if listener.loadbalancer:
            # Verify that this is the same plugin as the loadbalancer
            lb_p = self.core_plugin._get_plugin_from_project(
                context, listener.loadbalancer.tenant_id)
            if lb_p != p:
                msg = (_('Listener must belong to the plugin %s, as the '
                         'loadbalancer') % lb_p.plugin_type())
                raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

        return p.lbv2_driver.listener.create(context, listener,
                                             certificate=certificate)

    @log_helpers.log_method_call
    def update(self, context, old_listener, new_listener, certificate=None):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      new_listener.tenant_id)
        return p.lbv2_driver.listener.update(context,
                                             old_listener,
                                             new_listener,
                                             certificate=certificate)

    @log_helpers.log_method_call
    def delete(self, context, listener):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      listener.tenant_id)
        return p.lbv2_driver.listener.delete(context, listener)


class EdgePoolManager(base_mgr.LoadbalancerBaseManager):

    @log_helpers.log_method_call
    def create(self, context, pool):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      pool.tenant_id)
        if pool.loadbalancer:
            # Verify that this is the same plugin as the loadbalancer
            lb_p = self.core_plugin._get_plugin_from_project(
                context, pool.loadbalancer.tenant_id)
            if lb_p != p:
                msg = (_('Pool must belong to the plugin %s, as the '
                         'loadbalancer') % lb_p.plugin_type())
                raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
        return p.lbv2_driver.pool.create(context, pool)

    @log_helpers.log_method_call
    def update(self, context, old_pool, new_pool):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      new_pool.tenant_id)
        return p.lbv2_driver.pool.update(context, old_pool, new_pool)

    @log_helpers.log_method_call
    def delete(self, context, pool):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      pool.tenant_id)
        return p.lbv2_driver.pool.delete(context, pool)


class EdgeMemberManager(base_mgr.LoadbalancerBaseManager):

    @log_helpers.log_method_call
    def create(self, context, member):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      member.tenant_id)
        if member.pool and member.pool.loadbalancer:
            # Verify that this is the same plugin as the loadbalancer
            lb_p = self.core_plugin._get_plugin_from_project(
                context, member.pool.loadbalancer.tenant_id)
            if lb_p != p:
                msg = (_('Member must belong to the plugin %s, as the '
                         'loadbalancer') % lb_p.plugin_type())
                raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
        return p.lbv2_driver.member.create(context, member)

    @log_helpers.log_method_call
    def update(self, context, old_member, new_member):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      new_member.tenant_id)
        return p.lbv2_driver.member.update(context, old_member, new_member)

    @log_helpers.log_method_call
    def delete(self, context, member):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      member.tenant_id)
        return p.lbv2_driver.member.delete(context, member)


class EdgeHealthMonitorManager(base_mgr.LoadbalancerBaseManager):

    @log_helpers.log_method_call
    def create(self, context, hm):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      hm.tenant_id)
        if hm.pool and hm.pool.loadbalancer:
            # Verify that this is the same plugin as the loadbalancer
            lb_p = self.core_plugin._get_plugin_from_project(
                context, hm.pool.loadbalancer.tenant_id)
            if lb_p != p:
                msg = (_('Health monitor must belong to the plugin %s, as the '
                         'loadbalancer') % lb_p.plugin_type())
                raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
        return p.lbv2_driver.healthmonitor.create(context, hm)

    @log_helpers.log_method_call
    def update(self, context, old_hm, new_hm):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      new_hm.tenant_id)
        return p.lbv2_driver.healthmonitor.update(context, old_hm, new_hm)

    @log_helpers.log_method_call
    def delete(self, context, hm):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      hm.tenant_id)
        return p.lbv2_driver.healthmonitor.delete(context, hm)


class EdgeL7PolicyManager(base_mgr.LoadbalancerBaseManager):

    @log_helpers.log_method_call
    def create(self, context, policy):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      policy.tenant_id)
        if policy.listener and policy.listener.loadbalancer:
            # Verify that this is the same plugin as the loadbalancer
            lb_p = self.core_plugin._get_plugin_from_project(
                context, policy.listener.loadbalancer.tenant_id)
            if lb_p != p:
                msg = (_('L7 Policy must belong to the plugin %s, as the '
                         'loadbalancer') % lb_p.plugin_type())
                raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
        return p.lbv2_driver.l7policy.create(context, policy)

    @log_helpers.log_method_call
    def update(self, context, old_policy, new_policy):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      new_policy.tenant_id)
        return p.lbv2_driver.l7policy.update(context, old_policy, new_policy)

    @log_helpers.log_method_call
    def delete(self, context, policy):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      policy.tenant_id)
        return p.lbv2_driver.l7policy.delete(context, policy)


class EdgeL7RuleManager(base_mgr.LoadbalancerBaseManager):

    @log_helpers.log_method_call
    def create(self, context, rule):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      rule.tenant_id)
        if (rule.policy and rule.policy.listener and
            rule.policy.listener.loadbalancer):
            # Verify that this is the same plugin as the loadbalancer
            lb_p = self.core_plugin._get_plugin_from_project(
                context, rule.policy.listener.loadbalancer.tenant_id)
            if lb_p != p:
                msg = (_('L7 Rule must belong to the plugin %s, as the '
                         'loadbalancer') % lb_p.plugin_type())
                raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
        return p.lbv2_driver.l7rule.create(context, rule)

    @log_helpers.log_method_call
    def update(self, context, old_rule, new_rule):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      new_rule.tenant_id)
        return p.lbv2_driver.l7rule.update(context, old_rule, new_rule)

    @log_helpers.log_method_call
    def delete(self, context, rule):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      rule.tenant_id)
        return p.lbv2_driver.l7rule.delete(context, rule)
