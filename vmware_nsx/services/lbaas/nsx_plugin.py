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

from neutron_lbaas.db.loadbalancer import models
from neutron_lbaas.services.loadbalancer import plugin

from vmware_nsx.services.lbaas import lb_const

LOG = logging.getLogger(__name__)


class LoadBalancerNSXPluginV2(plugin.LoadBalancerPluginv2):
    """NSX Plugin for LBaaS V2.

    This plugin overrides the statuses call to issue the DB update before
    displaying the results.
    """

    def nsx_update_operational_statuses(self, context, loadbalancer_id,
                                        with_members=False):
        """Update LB objects operating status

        Call the driver to get the current statuses, and update those in the DB
        """
        # get the driver
        driver = self._get_driver_for_loadbalancer(
            context, loadbalancer_id)
        driver_obj = driver.load_balancer.lbv2_driver

        # Get the current statuses from the driver
        lb_statuses = driver_obj.loadbalancer.get_operating_status(
            context, loadbalancer_id, with_members=with_members)
        if not lb_statuses:
            return

        # update the new statuses in the LBaaS DB
        if lb_const.LOADBALANCERS in lb_statuses:
            for lb in lb_statuses[lb_const.LOADBALANCERS]:
                self.db.update_status(context, models.LoadBalancer, lb['id'],
                                      operating_status=lb['status'])
        if lb_const.LISTENERS in lb_statuses:
            for listener in lb_statuses[lb_const.LISTENERS]:
                self.db.update_status(context, models.Listener, listener['id'],
                                      operating_status=listener['status'])
        if lb_const.POOLS in lb_statuses:
            for pool in lb_statuses[lb_const.POOLS]:
                self.db.update_status(context, models.PoolV2, pool['id'],
                                      operating_status=pool['status'])
        if lb_const.MEMBERS in lb_statuses:
            for member in lb_statuses[lb_const.MEMBERS]:
                self.db.update_status(context, models.MemberV2, member['id'],
                                      operating_status=member['status'])

    def statuses(self, context, loadbalancer_id):
        # Update the LB statuses before letting the plugin display them
        self.nsx_update_operational_statuses(context, loadbalancer_id,
                                             with_members=True)

        # use super code to get the updated statuses
        return super(LoadBalancerNSXPluginV2, self).statuses(
            context, loadbalancer_id)

    def get_loadbalancer(self, context, loadbalancer_id, fields=None):
        # Update the LB status before letting the plugin display it in the
        # loadbalancer display
        self.nsx_update_operational_statuses(context, loadbalancer_id)

        return super(LoadBalancerNSXPluginV2, self).get_loadbalancer(
            context, loadbalancer_id, fields=fields)

    # TODO(asarfaty) : do the implementation for V objects as well
