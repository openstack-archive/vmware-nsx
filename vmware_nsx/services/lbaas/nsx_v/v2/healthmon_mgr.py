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
from oslo_log import log as logging
from oslo_utils import excutils

from neutron_lib import exceptions as n_exc

from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as nsxv_exc
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common

LOG = logging.getLogger(__name__)


class EdgeHealthMonitorManager(base_mgr.EdgeLoadbalancerBaseManager):

    @log_helpers.log_method_call
    def _convert_lbaas_monitor(self, hm):
        """
        Transform OpenStack health monitor dict to NSXv health monitor dict.
        """
        mon = {
            'type': lb_const.HEALTH_MONITOR_MAP.get(hm.type, 'icmp'),
            'interval': hm.delay,
            'timeout': hm.timeout,
            'maxRetries': hm.max_retries,
            'name': hm.id}

        if hm.http_method:
            mon['method'] = hm.http_method

        if hm.url_path:
            mon['url'] = hm.url_path
        return mon

    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeHealthMonitorManager, self).__init__(vcns_driver)

    @log_helpers.log_method_call
    def create(self, context, hm):
        lb_id = hm.pool.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        edge_id = lb_binding['edge_id']

        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, hm.pool.id)
        if not pool_binding:
            self.lbv2_driver.health_monitor.failed_completion(
                context, hm)
            msg = _('Failed to create health monitor on edge: %s. '
                    'Binding not found') % edge_id
            LOG.error(msg)
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

        edge_pool_id = pool_binding['edge_pool_id']

        hm_binding = nsxv_db.get_nsxv_lbaas_monitor_binding(
            context.session, lb_id, hm.pool.id, hm.id, edge_id)
        edge_mon_id = None

        if hm_binding:
            edge_mon_id = hm_binding['edge_mon_id']
        else:
            edge_monitor = self._convert_lbaas_monitor(hm)
            try:
                with locking.LockManager.get_lock(edge_id):
                    h = self.vcns.create_health_monitor(edge_id,
                                                        edge_monitor)[0]
                    edge_mon_id = lb_common.extract_resource_id(h['location'])

                nsxv_db.add_nsxv_lbaas_monitor_binding(
                    context.session, lb_id, hm.pool.id, hm.id, edge_id,
                    edge_mon_id)

            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lbv2_driver.health_monitor.failed_completion(
                        context, hm)
                    LOG.error('Failed to create health monitor on edge: %s',
                              edge_id)

        try:
            # Associate monitor with Edge pool
            with locking.LockManager.get_lock(edge_id):
                edge_pool = self.vcns.get_pool(edge_id, edge_pool_id)[1]
                if edge_pool.get('monitorId'):
                    edge_pool['monitorId'].append(edge_mon_id)
                else:
                    edge_pool['monitorId'] = [edge_mon_id]

                self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.health_monitor.failed_completion(context, hm)
                LOG.error(
                    'Failed to create health monitor on edge: %s',
                    edge_id)

        self.lbv2_driver.health_monitor.successful_completion(context, hm)

    @log_helpers.log_method_call
    def update(self, context, old_hm, new_hm):
        lb_id = new_hm.pool.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)

        edge_id = lb_binding['edge_id']

        hm_binding = nsxv_db.get_nsxv_lbaas_monitor_binding(
            context.session, lb_id, new_hm.pool.id, new_hm.id, edge_id)

        edge_monitor = self._convert_lbaas_monitor(new_hm)

        try:
            with locking.LockManager.get_lock(edge_id):
                self.vcns.update_health_monitor(edge_id,
                                                hm_binding['edge_mon_id'],
                                                edge_monitor)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.health_monitor.failed_completion(context,
                                                                  new_hm)
                LOG.error('Failed to update monitor on edge: %s', edge_id)

        self.lbv2_driver.health_monitor.successful_completion(context, new_hm)

    @log_helpers.log_method_call
    def delete(self, context, hm):
        pool_id = hm.pool.id
        lb_id = hm.pool.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        edge_id = lb_binding['edge_id']

        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, pool_id)
        if not pool_binding:
            nsxv_db.del_nsxv_lbaas_monitor_binding(
                context.session, lb_id, pool_id, hm.id, edge_id)
            self.lbv2_driver.health_monitor.successful_completion(
                context, hm, delete=True)
            return

        edge_pool_id = pool_binding['edge_pool_id']

        hm_binding = nsxv_db.get_nsxv_lbaas_monitor_binding(
            context.session, lb_id, pool_id, hm.id, edge_id)

        edge_pool = self.vcns.get_pool(edge_id, edge_pool_id)[1]
        if hm_binding['edge_mon_id'] in edge_pool['monitorId']:
            edge_pool['monitorId'].remove(hm_binding['edge_mon_id'])

            try:
                with locking.LockManager.get_lock(edge_id):
                    self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)
            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lbv2_driver.health_monitor.failed_completion(context,
                                                                      hm)
                    LOG.error('Failed to delete monitor mapping on edge: %s',
                              edge_id)

        # If this monitor is not used on this edge anymore, delete it
        if not edge_pool['monitorId']:
            try:
                with locking.LockManager.get_lock(edge_id):
                    self.vcns.delete_health_monitor(hm_binding['edge_id'],
                                                    hm_binding['edge_mon_id'])
            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lbv2_driver.health_monitor.failed_completion(context,
                                                                      hm)
                    LOG.error('Failed to delete monitor on edge: %s', edge_id)

        nsxv_db.del_nsxv_lbaas_monitor_binding(
            context.session, lb_id, pool_id, hm.id, edge_id)
        self.lbv2_driver.health_monitor.successful_completion(
            context, hm, delete=True)
