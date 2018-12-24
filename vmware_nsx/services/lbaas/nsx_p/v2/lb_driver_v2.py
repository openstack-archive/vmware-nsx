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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_consts
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_helper
from vmware_nsx.services.lbaas import lb_translators
from vmware_nsx.services.lbaas.nsx_p.implementation import healthmonitor_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import l7policy_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import l7rule_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import listener_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import loadbalancer_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import member_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import pool_mgr
from vmware_nsx.services.lbaas.octavia import constants as oct_const

LOG = logging.getLogger(__name__)


class NotImplementedManager(object):
    """Helper class to make any subclass of LoadBalancerBaseDriver explode if
    it is missing any of the required object managers.
    """

    def create(self, context, obj):
        raise NotImplementedError()

    def update(self, context, old_obj, obj):
        raise NotImplementedError()

    def delete(self, context, obj):
        raise NotImplementedError()


class EdgeLoadbalancerDriverV2(base_mgr.LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeLoadbalancerDriverV2, self).__init__()

        # Init all LBaaS objects
        # Note(asarfaty): self.lbv2_driver is not yet defined at init time
        # so lambda is used to retrieve it later.
        self.loadbalancer = lb_helper.LBaaSNSXObjectManagerWrapper(
            "loadbalancer",
            loadbalancer_mgr.EdgeLoadBalancerManagerFromDict(),
            lb_translators.lb_loadbalancer_obj_to_dict,
            lambda: self.lbv2_driver.load_balancer)

        self.listener = lb_helper.LBaaSNSXObjectManagerWrapper(
            "listener",
            listener_mgr.EdgeListenerManagerFromDict(),
            lb_translators.lb_listener_obj_to_dict,
            lambda: self.lbv2_driver.listener)

        self.pool = lb_helper.LBaaSNSXObjectManagerWrapper(
            "pool",
            pool_mgr.EdgePoolManagerFromDict(),
            lb_translators.lb_pool_obj_to_dict,
            lambda: self.lbv2_driver.pool)

        self.member = lb_helper.LBaaSNSXObjectManagerWrapper(
            "member",
            member_mgr.EdgeMemberManagerFromDict(),
            lb_translators.lb_member_obj_to_dict,
            lambda: self.lbv2_driver.member)

        self.healthmonitor = lb_helper.LBaaSNSXObjectManagerWrapper(
            "healthmonitor",
            healthmonitor_mgr.EdgeHealthMonitorManagerFromDict(),
            lb_translators.lb_hm_obj_to_dict,
            lambda: self.lbv2_driver.health_monitor)

        self.l7policy = lb_helper.LBaaSNSXObjectManagerWrapper(
            "l7policy",
            l7policy_mgr.EdgeL7PolicyManagerFromDict(),
            lb_translators.lb_l7policy_obj_to_dict,
            lambda: self.lbv2_driver.l7policy)

        self.l7rule = lb_helper.LBaaSNSXObjectManagerWrapper(
            "l7rule",
            l7rule_mgr.EdgeL7RuleManagerFromDict(),
            lb_translators.lb_l7rule_obj_to_dict,
            lambda: self.lbv2_driver.l7rule)

        self._subscribe_router_delete_callback()

    def _subscribe_router_delete_callback(self):
        # Check if there is any LB attachment for the NSX router.
        # This callback is subscribed here to prevent router/GW/interface
        # deletion if it still has LB service attached to it.

        #Note(asarfaty): Those callbacks are used by Octavia as well even
        # though they are bound only here
        registry.subscribe(self._check_lb_service_on_router,
                           resources.ROUTER, events.BEFORE_DELETE)
        registry.subscribe(self._check_lb_service_on_router,
                           resources.ROUTER_GATEWAY, events.BEFORE_DELETE)
        registry.subscribe(self._check_lb_service_on_router_interface,
                           resources.ROUTER_INTERFACE, events.BEFORE_DELETE)

    def _unsubscribe_router_delete_callback(self):
        registry.unsubscribe(self._check_lb_service_on_router,
                             resources.ROUTER, events.BEFORE_DELETE)
        registry.unsubscribe(self._check_lb_service_on_router,
                             resources.ROUTER_GATEWAY, events.BEFORE_DELETE)
        registry.unsubscribe(self._check_lb_service_on_router_interface,
                             resources.ROUTER_INTERFACE, events.BEFORE_DELETE)

    def _get_lb_ports(self, context, subnet_ids):
        dev_owner_v2 = n_consts.DEVICE_OWNER_LOADBALANCERV2
        dev_owner_oct = oct_const.DEVICE_OWNER_OCTAVIA
        filters = {'device_owner': [dev_owner_v2, dev_owner_oct],
                   'fixed_ips': {'subnet_id': subnet_ids}}
        return self.loadbalancer.core_plugin.get_ports(
            context, filters=filters)

    def _check_lb_service_on_router(self, resource, event, trigger,
                                    payload=None):
        """Prevent removing a router GW or deleting a router used by LB"""
        pass

    def _check_lb_service_on_router_interface(
            self, resource, event, trigger, payload=None):
        # Prevent removing the interface of an LB subnet from a router
        pass
