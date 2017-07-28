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
from neutron_lib.callbacks import exceptions as nc_exc
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from vmware_nsx._i18n import _
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas.nsx_v3 import healthmonitor_mgr as hm_mgr
from vmware_nsx.services.lbaas.nsx_v3 import l7policy_mgr
from vmware_nsx.services.lbaas.nsx_v3 import l7rule_mgr
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
        self.l7policy = l7policy_mgr.EdgeL7PolicyManager()
        self.l7rule = l7rule_mgr.EdgeL7RuleManager()
        self._subscribe_router_delete_callback()

    def _subscribe_router_delete_callback(self):
        # Check if there is any LB attachment for the NSX router.
        # This callback is subscribed here to prevent router deletion
        # if it still has LB service attached to it.
        registry.subscribe(self._check_lb_service_on_router,
                           resources.ROUTER, events.BEFORE_DELETE)

    def _unsubscribe_router_delete_callback(self):
        registry.unsubscribe(self._check_lb_service_on_router,
                             resources.ROUTER, events.BEFORE_DELETE)

    def _check_lb_service_on_router(self, resource, event, trigger,
                                    **kwargs):
        """Check if there is any lb service on nsx router"""

        nsx_router_id = nsx_db.get_nsx_router_id(kwargs['context'].session,
                                                 kwargs['router_id'])
        nsxlib = self.loadbalancer.core_plugin.nsxlib
        service_client = nsxlib.load_balancer.service
        lb_service = service_client.get_router_lb_service(nsx_router_id)
        if lb_service:
            msg = _('Cannot delete router as it still has lb service '
                    'attachment')
            raise nc_exc.CallbackFailure(msg)


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
