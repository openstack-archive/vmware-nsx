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

from neutron_lib import exceptions as n_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3 import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgePoolManager(base_mgr.Nsxv3LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgePoolManager, self).__init__()

    @log_helpers.log_method_call
    def create(self, context, pool):
        listener_id = pool.listener.id
        lb_id = pool.loadbalancer_id
        pool_client = self.core_plugin.nsxlib.load_balancer.pool
        vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server
        pool_name = utils.get_name_and_uuid(pool.name, pool.id)
        tags = lb_utils.get_tags(self.core_plugin, pool.id,
                                 lb_const.LB_POOL_TYPE, pool.tenant_id,
                                 context.project_name)
        try:
            snat_translation = {'type': "LbSnatAutoMap"}
            lb_pool = pool_client.create(display_name=pool_name,
                                         tags=tags,
                                         algorithm=pool.lb_algorithm,
                                         snat_translation=snat_translation)
        except nsxlib_exc.ManagerError:
            self.lbv2_driver.pool.failed_completion(context, pool)
            msg = (_('Failed to create pool on NSX backend: %(pool)s') %
                   {'pool': pool.id})
            raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)

        binding = nsx_db.get_nsx_lbaas_listener_binding(
            context.session, lb_id, listener_id)
        if binding:
            vs_id = binding['lb_vs_id']
            try:
                vs_client.update(vs_id, pool_id=lb_pool['id'])
            except nsxlib_exc.ManagerError:
                with excutils.save_and_reraise_exception():
                    self.lbv2_driver.pool.failed_completion(context, pool)
                    LOG.error('Failed to attach pool %s to virtual server %s',
                              lb_pool['id'], vs_id)
            nsx_db.add_nsx_lbaas_pool_binding(
                context.session, lb_id, pool.id, lb_pool['id'], vs_id)
        else:
            msg = (_("Couldn't find binding on the listener: %s") %
                   listener_id)
            raise nsx_exc.NsxPluginException(err_msg=msg)
        self.lbv2_driver.pool.successful_completion(context, pool)

    @log_helpers.log_method_call
    def update(self, context, old_pool, new_pool):
        try:
            self.lbv2_driver.pool.successful_completion(context, new_pool)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.pool.failed_completion(context, new_pool)

    @log_helpers.log_method_call
    def delete(self, context, pool):
        lb_id = pool.loadbalancer_id
        pool_client = self.core_plugin.nsxlib.load_balancer.pool
        vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server
        service_client = self.core_plugin.nsxlib.load_balancer.service

        binding = nsx_db.get_nsx_lbaas_pool_binding(
            context.session, lb_id, pool.id)
        if binding:
            vs_id = binding['lb_vs_id']
            lb_pool_id = binding['lb_pool_id']
            try:
                vs_client.update(vs_id, pool_id='')
            except nsxlib_exc.ManagerError:
                self.lbv2_driver.pool.failed_completion(context, pool)
                msg = _('Failed to remove lb pool %(pool)s from virtual '
                        'server %(vs)s') % {'pool': lb_pool_id,
                                            'vs': vs_id}
                raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)
            try:
                pool_client.delete(lb_pool_id)
            except nsxlib_exc.ManagerError:
                self.lbv2_driver.pool.failed_completion(context, pool)
                msg = (_('Failed to delete lb pool from nsx: %(pool)s') %
                       {'pool': lb_pool_id})
                raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)
            nsx_db.delete_nsx_lbaas_pool_binding(context.session,
                                                 lb_id, pool.id)
            lb_binding = nsx_db.get_nsx_lbaas_loadbalancer_binding(
                context.session, lb_id)
            if lb_binding:
                lb_service_id = lb_binding['lb_service_id']
                try:
                    lb_service = service_client.get(lb_service_id)
                    vs_list = lb_service.get('virtual_server_ids')
                    if vs_list and vs_id in vs_list:
                        vs_list.remove(vs_id)
                    else:
                        LOG.debug('virtual server id %s is not in the lb '
                                  'service virtual server list %s',
                                  vs_id, vs_list)
                    service_client.update(lb_service_id,
                                          virtual_server_ids=vs_list)
                    if not vs_list:
                        service_client.delete(lb_service_id)
                        nsx_db.delete_nsx_lbaas_loadbalancer_binding(
                            context.session, lb_id)
                except nsxlib_exc.ManagerError:
                    self.lbv2_driver.pool.failed_completion(context, pool)
                    msg = (_('Failed to delete lb pool from nsx: %(pool)s') %
                           {'pool': lb_pool_id})
                    raise n_exc.BadRequest(resource='lbaas-pool', msg=msg)

        self.lbv2_driver.pool.successful_completion(
            context, pool, delete=True)
