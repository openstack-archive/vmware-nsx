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

from vmware_nsx._i18n import _LE
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as nsxv_exc
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common
from vmware_nsx.services.lbaas.nsx_v import lbaas_const as lb_const
from vmware_nsx.services.lbaas.nsx_v.v2 import base_mgr
from vmware_nsx.services.lbaas.nsx_v.v2 import listener_mgr

LOG = logging.getLogger(__name__)


class EdgePoolManager(base_mgr.EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgePoolManager, self).__init__(vcns_driver)

    @log_helpers.log_method_call
    def create(self, context, pool):

        edge_pool = {
            'name': 'pool_' + pool.id,
            'description': getattr(pool, 'description', getattr(pool, 'name')),
            'algorithm': lb_const.BALANCE_MAP.get(pool.lb_algorithm,
                                                  'round-robin'),
            'transparent': False
        }

        lb_id = pool.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)

        edge_id = lb_binding['edge_id']

        try:
            with locking.LockManager.get_lock(edge_id):
                h = self.vcns.create_pool(edge_id, edge_pool)[0]
                edge_pool_id = lb_common.extract_resource_id(h['location'])
            nsxv_db.add_nsxv_lbaas_pool_binding(context.session, lb_id,
                                                pool.id,
                                                edge_pool_id)

            if pool.listener:
                listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
                    context.session, lb_id, pool.listener.id)
                # Associate listener with pool
                vse = listener_mgr.listener_to_edge_vse(
                    pool.listener,
                    lb_binding['vip_address'],
                    edge_pool_id,
                    listener_binding['app_profile_id'])
                with locking.LockManager.get_lock(edge_id):
                    self.vcns.update_vip(edge_id, listener_binding['vse_id'],
                                         vse)

            self.lbv2_driver.pool.successful_completion(context, pool)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.pool.failed_completion(context, pool)
                LOG.error(_LE('Failed to create pool %s'), pool['id'])

    @log_helpers.log_method_call
    def update(self, context, old_pool, new_pool):
        edge_pool = {
            'name': 'pool_' + new_pool.id,
            'description': getattr(new_pool, 'description',
                                   getattr(new_pool, 'name')),
            'algorithm': lb_const.BALANCE_MAP.get(
                new_pool.lb_algorithm, 'round-robin'),
            'transparent': False
        }

        if new_pool.listener:
            listener = new_pool.listener
            lb_id = listener.loadbalancer_id
        else:
            lb_id = new_pool.loadbalancer_id

        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, new_pool.id)

        edge_id = lb_binding['edge_id']
        edge_pool_id = pool_binding['edge_pool_id']

        try:
            with locking.LockManager.get_lock(edge_id):
                self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)

            self.lbv2_driver.pool.successful_completion(context, new_pool)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.pool.failed_completion(context, new_pool)
                LOG.error(_LE('Failed to update pool %s'), new_pool['id'])

    @log_helpers.log_method_call
    def delete(self, context, pool):
        lb_id = pool.loadbalancer_id

        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, pool.id)

        edge_id = lb_binding['edge_id']
        edge_pool_id = pool_binding['edge_pool_id']

        try:
            if pool.listeners:
                for listener in pool.listeners:
                    listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
                        context.session, lb_id, listener.id)
                    vse = listener_mgr.listener_to_edge_vse(
                        listener,
                        lb_binding['vip_address'],
                        None,
                        listener_binding['app_profile_id'])
                    with locking.LockManager.get_lock(edge_id):
                        self.vcns.update_vip(
                            edge_id, listener_binding['vse_id'], vse)
            self.vcns.delete_pool(edge_id, edge_pool_id)
            self.lbv2_driver.pool.successful_completion(
                context, pool, delete=True)
            nsxv_db.del_nsxv_lbaas_pool_binding(
                context.session, lb_id, pool.id)
        except nsxv_exc.VcnsApiException:
            self.lbv2_driver.pool.failed_completion(context, pool)
            LOG.error(_LE('Failed to delete pool %s'), pool['id'])
