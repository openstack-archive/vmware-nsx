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

from neutron_lib import exceptions as n_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeHealthMonitorManagerFromDict(base_mgr.NsxpLoadbalancerBaseManager):

    def _get_monitor_policy_client(self, hm):
        lb_client = self.core_plugin.nsxpolicy.load_balancer
        if hm['type'] == lb_const.LB_HEALTH_MONITOR_TCP:
            return lb_client.lb_monitor_profile_tcp
        elif hm['type'] == lb_const.LB_HEALTH_MONITOR_HTTP:
            return lb_client.lb_monitor_profile_http
        elif hm['type'] == lb_const.LB_HEALTH_MONITOR_HTTPS:
            return lb_client.lb_monitor_profile_https
        elif hm['type'] == lb_const.LB_HEALTH_MONITOR_PING:
            return lb_client.lb_monitor_profile_icmp
        else:
            msg = (_('Cannot create health monitor %(monitor)s with '
                     'type %(type)s') % {'monitor': hm['id'],
                                         'type': hm['type']})
            raise n_exc.InvalidInput(error_message=msg)

    def _build_monitor_args(self, hm):
        body = {
            'interval': hm['delay'],
            'fall_count': hm['max_retries'],
            'timeout': hm['timeout'],
            'name': utils.get_name_and_uuid(hm['name'] or 'monitor', hm['id'])
        }
        if hm['type'] in [lb_const.LB_HEALTH_MONITOR_HTTP,
                          lb_const.LB_HEALTH_MONITOR_HTTPS]:
            if hm['http_method']:
                body['request_method'] = hm['http_method']
            if hm['url_path']:
                body['request_url'] = hm['url_path']
            if hm['expected_codes']:
                codes = hm['expected_codes'].split(",")
                body['response_status_codes'] = [
                    int(code) for code in codes]
        return body

    @log_helpers.log_method_call
    def create(self, context, hm, completor):
        pool_id = hm['pool']['id']
        pool_client = self.core_plugin.nsxpolicy.load_balancer.lb_pool
        monitor_client = self._get_monitor_policy_client(hm)
        tags = lb_utils.get_tags(self.core_plugin, hm['id'],
                                 lb_const.LB_HM_TYPE,
                                 hm['tenant_id'], context.project_name)
        monitor_body = self._build_monitor_args(hm)
        lb_monitor = None
        try:
            lb_monitor = monitor_client.create_or_overwrite(
                lb_monitor_profile_id=hm['id'],
                tags=tags, **monitor_body)
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                completor(success=False)

        if pool_id and lb_monitor:
            try:
                hm_path = monitor_client.get_path(hm['id'])
                pool_client.add_monitor_to_pool(pool_id, [hm_path])
            except nsxlib_exc.ManagerError:
                completor(success=False)
                msg = _('Failed to attach monitor %(monitor)s to pool '
                        '%(pool)s') % {'monitor': hm['id'],
                                       'pool': pool_id}
                raise n_exc.BadRequest(resource='lbaas-hm', msg=msg)
        else:
            completor(success=False)
            msg = _('Failed to attach monitor %(monitor)s to pool '
                    '%(pool)s: NSX pool was not found on the DB') % {
                    'monitor': hm['id'],
                    'pool': pool_id}
            raise n_exc.BadRequest(resource='lbaas-hm', msg=msg)

        completor(success=True)

    @log_helpers.log_method_call
    def update(self, context, old_hm, new_hm, completor):
        monitor_client = self._get_monitor_policy_client(new_hm)
        try:
            monitor_body = self._build_monitor_args(new_hm)
            monitor_name = utils.get_name_and_uuid(new_hm['name'] or 'monitor',
                                                   new_hm['id'])
            monitor_client.update(new_hm['id'], name=monitor_name,
                                  **monitor_body)
        except nsxlib_exc.ManagerError as exc:
            completor(success=False)
            msg = _('Failed to update monitor %(monitor)s with exception'
                    ' %s(exc)s') % {'monitor': new_hm['id'], 'exc': exc}
            raise n_exc.BadRequest(resource='lbaas-hm', msg=msg)

        completor(success=True)

    @log_helpers.log_method_call
    def delete(self, context, hm, completor):
        pool_id = hm['pool']['id']
        pool_client = self.core_plugin.nsxpolicy.load_balancer.lb_pool
        monitor_client = self._get_monitor_policy_client(hm)

        try:
            hm_path = monitor_client.get_path(hm['id'])
            pool_client.remove_monitor_from_pool(pool_id,
                                                 hm_path)
        except nsxlib_exc.ResourceNotFound:
            pass
        except nsxlib_exc.ManagerError as exc:
            completor(success=False)
            msg = _('Failed to remove monitor %(monitor)s from pool %(pool)s '
                    'with exception from nsx %(exc)s') % {
                      'monitor': hm['id'],
                      'pool': pool_id,
                      'exc': exc}
            raise n_exc.BadRequest(resource='lbaas-hm', msg=msg)

        try:
            monitor_client.delete(hm['id'])
        except nsxlib_exc.ResourceNotFound:
            pass
        except nsxlib_exc.ManagerError as exc:
            completor(success=False)
            msg = _('Failed to delete monitor %(monitor)s from backend with '
                    'exception %(exc)s') % {'monitor': hm['id'], 'exc': exc}
            raise n_exc.BadRequest(resource='lbaas-hm', msg=msg)

        completor(success=True)

    @log_helpers.log_method_call
    def delete_cascade(self, context, hm, completor):
        self.delete(context, hm, completor)
