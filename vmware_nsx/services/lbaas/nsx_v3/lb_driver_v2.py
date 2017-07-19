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

from vmware_nsx.services.lbaas.nsx_v3 import healthmonitor_mgr as hm_mgr
from vmware_nsx.services.lbaas.nsx_v3 import listener_mgr
from vmware_nsx.services.lbaas.nsx_v3 import loadbalancer_mgr as lb_mgr
from vmware_nsx.services.lbaas.nsx_v3 import member_mgr
from vmware_nsx.services.lbaas.nsx_v3 import pool_mgr

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


class EdgeLoadbalancerDriverV2(object):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeLoadbalancerDriverV2, self).__init__()

        self.loadbalancer = lb_mgr.EdgeLoadBalancerManager()
        self.listener = listener_mgr.EdgeListenerManager()
        self.pool = pool_mgr.EdgePoolManager()
        self.member = member_mgr.EdgeMemberManager()
        self.healthmonitor = hm_mgr.EdgeHealthMonitorManager()


class DummyLoadbalancerDriverV2(object):
    @log_helpers.log_method_call
    def __init__(self):
        self.load_balancer = NotImplementedManager()
        self.listener = NotImplementedManager()
        self.pool = NotImplementedManager()
        self.member = NotImplementedManager()
        self.health_monitor = NotImplementedManager()
        self.l7policy = NotImplementedManager()
        self.l7rule = NotImplementedManager()
