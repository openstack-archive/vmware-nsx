# Copyright 2015 VMware, Inc.
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

from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_helper
from vmware_nsx.services.lbaas import lb_translators
from vmware_nsx.services.lbaas.nsx_v.implementation import healthmon_mgr
from vmware_nsx.services.lbaas.nsx_v.implementation import l7policy_mgr
from vmware_nsx.services.lbaas.nsx_v.implementation import l7rule_mgr
from vmware_nsx.services.lbaas.nsx_v.implementation import listener_mgr
from vmware_nsx.services.lbaas.nsx_v.implementation import loadbalancer_mgr
from vmware_nsx.services.lbaas.nsx_v.implementation import member_mgr
from vmware_nsx.services.lbaas.nsx_v.implementation import pool_mgr


class EdgeLoadbalancerDriverV2(base_mgr.LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeLoadbalancerDriverV2, self).__init__()
        # Init all LBaaS objects
        # Note(asarfaty): self.lbv2_driver is not yet defined at init time
        # so lambda is used to retrieve it later.
        self.loadbalancer = lb_helper.LBaaSNSXObjectManagerWrapper(
            "loadbalancer",
            loadbalancer_mgr.EdgeLoadBalancerManagerFromDict(self),
            lb_translators.lb_loadbalancer_obj_to_dict,
            lambda: self.lbv2_driver.load_balancer)

        self.listener = lb_helper.LBaaSNSXObjectManagerWrapper(
            "listener",
            listener_mgr.EdgeListenerManagerFromDict(self),
            lb_translators.lb_listener_obj_to_dict,
            lambda: self.lbv2_driver.listener)

        self.pool = lb_helper.LBaaSNSXObjectManagerWrapper(
            "pool",
            pool_mgr.EdgePoolManagerFromDict(self),
            lb_translators.lb_pool_obj_to_dict,
            lambda: self.lbv2_driver.pool)

        self.member = lb_helper.LBaaSNSXObjectManagerWrapper(
            "member",
            member_mgr.EdgeMemberManagerFromDict(self),
            lb_translators.lb_member_obj_to_dict,
            lambda: self.lbv2_driver.member)

        self.healthmonitor = lb_helper.LBaaSNSXObjectManagerWrapper(
            "healthmonitor",
            healthmon_mgr.EdgeHealthMonitorManagerFromDict(self),
            lb_translators.lb_hm_obj_to_dict,
            lambda: self.lbv2_driver.health_monitor)

        self.l7policy = lb_helper.LBaaSNSXObjectManagerWrapper(
            "l7policy",
            l7policy_mgr.EdgeL7PolicyManagerFromDict(self),
            lb_translators.lb_l7policy_obj_to_dict,
            lambda: self.lbv2_driver.l7policy)

        self.l7rule = lb_helper.LBaaSNSXObjectManagerWrapper(
            "l7rule",
            l7rule_mgr.EdgeL7RuleManagerFromDict(self),
            lb_translators.lb_l7rule_obj_to_dict,
            lambda: self.lbv2_driver.l7rule)
