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

from vmware_nsx.services.lbaas.nsx_v.v2 import healthmon_mgr as hm_mgr
from vmware_nsx.services.lbaas.nsx_v.v2 import listener_mgr
from vmware_nsx.services.lbaas.nsx_v.v2 import loadbalancer_mgr as lb_mgr
from vmware_nsx.services.lbaas.nsx_v.v2 import member_mgr
from vmware_nsx.services.lbaas.nsx_v.v2 import pool_mgr


class EdgeLoadbalancerDriverV2(object):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeLoadbalancerDriverV2, self).__init__()
        self.loadbalancer = lb_mgr.EdgeLoadBalancerManager(self)
        self.listener = listener_mgr.EdgeListenerManager(self)
        self.pool = pool_mgr.EdgePoolManager(self)
        self.member = member_mgr.EdgeMemberManager(self)
        self.healthmonitor = hm_mgr.EdgeHealthMonitorManager(self)
