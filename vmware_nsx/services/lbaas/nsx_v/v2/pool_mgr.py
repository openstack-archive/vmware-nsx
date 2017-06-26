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
        if not lb_binding:
            msg = _(
                'No suitable Edge found for pool %s') % pool.id
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
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
                    context,
                    pool.listener,
                    lb_binding['vip_address'],
                    edge_pool_id,
                    listener_binding['app_profile_id'])
                with locking.LockManager.get_lock(edge_id):
                    self.vcns.update_vip(edge_id, listener_binding['vse_id'],
                                         vse)
                # This action also set this pool as the default pool of the
                # listener, so the application profile may need to be updated
                if pool.session_persistence:
                    listener_mgr.update_app_profile(
                        self.vcns, context, pool.listener, edge_id)

            self.lbv2_driver.pool.successful_completion(context, pool)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.pool.failed_completion(context, pool)
                LOG.error('Failed to create pool %s', pool.id)

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
                # get the configured monitor-id
                org_edge_pool = self.vcns.get_pool(edge_id, edge_pool_id)[1]
                monitor_id = org_edge_pool.get('monitorId')
                if monitor_id:
                    edge_pool['monitorId'] = monitor_id

                # Keep the current members
                if org_edge_pool.get('member'):
                    edge_pool['member'] = org_edge_pool['member']

                self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)

            self.lbv2_driver.pool.successful_completion(context, new_pool)

            # if the the session_persistence was changed,
            # we may need to update the listener application profile
            if new_pool.listener:
                old_sess_persist = old_pool.session_persistence
                new_sess_persist = new_pool.session_persistence

                if new_sess_persist != old_sess_persist:
                    listener_mgr.update_app_profile(
                        self.vcns, context, new_pool.listener, edge_id)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.pool.failed_completion(context, new_pool)
                LOG.error('Failed to update pool %s', new_pool.id)

    @log_helpers.log_method_call
    def delete(self, context, pool):
        lb_id = pool.loadbalancer_id

        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, pool.id)

        edge_id = lb_binding['edge_id']
        if not pool_binding:
            self.lbv2_driver.pool.successful_completion(
                context, pool, delete=True)
            return

        edge_pool_id = pool_binding['edge_pool_id']

        listeners_to_update = []
        try:
            if pool.listeners:
                for listener in pool.listeners:
                    # the pool session persistence may affect the associated
                    # pool application profile
                    if (pool.session_persistence and listener.default_pool and
                            listener.default_pool.id == pool.id):
                        listeners_to_update.append(listener)

                    listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
                        context.session, lb_id, listener.id)
                    vse = listener_mgr.listener_to_edge_vse(
                        context,
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

            for listener in listeners_to_update:
                # need to update the listeners too, now with no default pool
                listener.default_pool = None
                listener_mgr.update_app_profile(
                    self.vcns, context, listener, edge_id)

        except nsxv_exc.VcnsApiException:
            self.lbv2_driver.pool.failed_completion(context, pool)
            LOG.error('Failed to delete pool %s', pool.id)
