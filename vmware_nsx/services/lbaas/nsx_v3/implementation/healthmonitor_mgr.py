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
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeHealthMonitorManagerFromDict(base_mgr.Nsxv3LoadbalancerBaseManager):

    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeHealthMonitorManagerFromDict, self).__init__()

    @log_helpers.log_method_call
    def _build_monitor_args(self, hm):
        if hm['type'] in lb_const.NSXV3_MONITOR_MAP:
            monitor_type = lb_const.NSXV3_MONITOR_MAP.get(hm['type'])
        else:
            msg = (_('Cannot create health monitor %(monitor)s with '
                     'type %(type)s') % {'monitor': hm['id'],
                                         'type': hm['type']})
            raise n_exc.InvalidInput(error_message=msg)
        body = {'resource_type': monitor_type,
                'interval': hm['delay'],
                'fall_count': hm['max_retries'],
                'timeout': hm['timeout']}
        if monitor_type in [lb_const.LB_HEALTH_MONITOR_HTTP,
                            lb_const.LB_HEALTH_MONITOR_HTTPS]:
            if hm['http_method']:
                body['request_method'] = hm['http_method']
            if hm['url_path']:
                body['request_url'] = hm['url_path']
            # TODO(tongl): nsxv3 backend doesn't support granular control
            # of expected_codes. So we ignore it and use default for now.
            # Once backend supports it, we can add it back.
            # if hm['expected_codes']:
            #    body['response_status'] = hm['expected_codes']
        return body

    def create(self, context, hm, completor):
        lb_id = hm['pool']['loadbalancer_id']
        pool_id = hm['pool']['id']
        pool_client = self.core_plugin.nsxlib.load_balancer.pool
        monitor_client = self.core_plugin.nsxlib.load_balancer.monitor
        monitor_name = utils.get_name_and_uuid(hm['name'] or 'monitor',
                                               hm['id'])
        tags = lb_utils.get_tags(self.core_plugin, hm['id'],
                                 lb_const.LB_HM_TYPE,
                                 hm['tenant_id'], context.project_name)
        monitor_body = self._build_monitor_args(hm)

        try:
            lb_monitor = monitor_client.create(
                display_name=monitor_name, tags=tags, **monitor_body)
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                completor(success=False)

        binding = nsx_db.get_nsx_lbaas_pool_binding(
            context.session, lb_id, pool_id)
        if binding:
            lb_pool_id = binding['lb_pool_id']
            try:
                pool_client.add_monitor_to_pool(lb_pool_id,
                                                lb_monitor['id'])
            except nsxlib_exc.ManagerError:
                completor(success=False)
                msg = _('Failed to attach monitor %(monitor)s to pool '
                        '%(pool)s') % {'monitor': lb_monitor['id'],
                                       'pool': lb_pool_id}
                raise n_exc.BadRequest(resource='lbaas-hm', msg=msg)
            nsx_db.add_nsx_lbaas_monitor_binding(
                context.session, lb_id, pool_id, hm['id'], lb_monitor['id'],
                lb_pool_id)
        else:
            completor(success=False)
            msg = _('Failed to attach monitor %(monitor)s to pool '
                    '%(pool)s: NSX pool was not found on the DB') % {
                    'monitor': hm['id'],
                    'pool': pool_id}
            raise n_exc.BadRequest(resource='lbaas-hm', msg=msg)

        completor(success=True)

    def update(self, context, old_hm, new_hm, completor):
        lb_id = new_hm['pool']['loadbalancer_id']
        pool_id = new_hm['pool']['id']
        monitor_client = self.core_plugin.nsxlib.load_balancer.monitor
        binding = nsx_db.get_nsx_lbaas_monitor_binding(
            context.session, lb_id, pool_id, new_hm['id'])
        if binding:
            lb_monitor_id = binding['lb_monitor_id']
            monitor_body = self._build_monitor_args(new_hm)
            monitor_name = utils.get_name_and_uuid(new_hm['name'] or 'monitor',
                                                   new_hm['id'])
            monitor_client.update(lb_monitor_id, display_name=monitor_name,
                                  **monitor_body)
        else:
            completor(success=False)
            msg = _('Failed to update monitor %(monitor)s: NSX monitor was '
                    'not found in DB') % {'monitor': new_hm['id'],
                                          'pool': pool_id}
            raise n_exc.BadRequest(resource='lbaas-hm', msg=msg)

        completor(success=True)

    def delete(self, context, hm, completor):
        lb_id = hm['pool']['loadbalancer_id']
        pool_id = hm['pool']['id']
        pool_client = self.core_plugin.nsxlib.load_balancer.pool
        monitor_client = self.core_plugin.nsxlib.load_balancer.monitor

        binding = nsx_db.get_nsx_lbaas_monitor_binding(
            context.session, lb_id, pool_id, hm['id'])
        if binding:
            lb_monitor_id = binding['lb_monitor_id']
            lb_pool_id = binding['lb_pool_id']
            try:
                pool_client.remove_monitor_from_pool(lb_pool_id,
                                                     lb_monitor_id)
            except nsxlib_exc.ManagerError as exc:
                LOG.error('Failed to remove monitor %(monitor)s from pool '
                          '%(pool)s with exception from nsx %(exc)s)',
                          {'monitor': lb_monitor_id,
                           'pool': lb_pool_id,
                           'exc': exc})
            try:
                monitor_client.delete(lb_monitor_id)
            except nsxlib_exc.ManagerError as exc:
                LOG.error('Failed to delete monitor %(monitor)s from '
                          'backend with exception %(exc)s',
                          {'monitor': lb_monitor_id,
                           'exc': exc})

            nsx_db.delete_nsx_lbaas_monitor_binding(context.session, lb_id,
                                                    pool_id, hm['id'])
        else:
            # Do not fail a delete action
            pass

        completor(success=True)
