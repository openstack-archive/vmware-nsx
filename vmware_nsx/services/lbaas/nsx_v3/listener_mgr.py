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

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3 import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeListenerManager(base_mgr.Nsxv3LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeListenerManager, self).__init__()

    @log_helpers.log_method_call
    def create(self, context, listener, certificate=None):
        lb_id = listener.loadbalancer_id
        vip_address = listener.loadbalancer.vip_address
        load_balancer = self.core_plugin.nsxlib.load_balancer
        app_client = load_balancer.application_profile
        vs_client = load_balancer.virtual_server
        service_client = load_balancer.service
        vs_name = utils.get_name_and_uuid(listener.name, listener.id)
        tags = lb_utils.get_tags(self.core_plugin, listener.id,
                                 lb_const.LB_LISTENER_TYPE,
                                 listener.tenant_id,
                                 context.project_name)
        tags.append({'scope': 'os-lbaas-lb-name',
                     'tag': listener.loadbalancer.name})
        tags.append({'scope': 'os-lbaas-lb-id',
                     'tag': lb_id})
        if listener.protocol == 'HTTP' or listener.protocol == 'HTTPS':
            profile_type = lb_const.LB_HTTP_PROFILE
        elif listener.protocol == 'TCP':
            profile_type = lb_const.LB_TCP_PROFILE
        else:
            msg = (_('Cannot create listener %(listener)s with '
                     'protocol %(protocol)s') %
                   {'listener': listener.id,
                    'protocol': listener.protocol})
            raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)
        try:
            app_profile = app_client.create(
                display_name=vs_name, resource_type=profile_type, tags=tags)
            app_profile_id = app_profile['id']
            virtual_server = vs_client.create(
                display_name=vs_name,
                tags=tags,
                enabled=listener.admin_state_up,
                ip_address=vip_address,
                port=listener.protocol_port,
                application_profile_id=app_profile_id)
        except nsxlib_exc.ManagerError:
            self.lbv2_driver.listener.failed_completion(context, listener)
            msg = _('Failed to create virtual server at NSX backend')
            raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)

        # If there is already lb:lb_service binding, add the virtual
        # server to the lb service
        binding = nsx_db.get_nsx_lbaas_loadbalancer_binding(
            context.session, lb_id)
        if binding:
            lb_service_id = binding['lb_service_id']
            try:
                service_client.add_virtual_server(lb_service_id,
                                                  virtual_server['id'])
            except nsxlib_exc.ManagerError:
                self.lbv2_driver.listener.failed_completion(context, listener)
                msg = _('Failed to add virtual server to lb service '
                        'at NSX backend')
                raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)

        nsx_db.add_nsx_lbaas_listener_binding(
            context.session, lb_id, listener.id, app_profile_id,
            virtual_server['id'])
        self.lbv2_driver.listener.successful_completion(
            context, listener)

    @log_helpers.log_method_call
    def update(self, context, old_listener, new_listener, certificate=None):
        self.lbv2_driver.listener.successful_completion(context, new_listener)

    @log_helpers.log_method_call
    def delete(self, context, listener):
        lb_id = listener.loadbalancer_id
        load_balancer = self.core_plugin.nsxlib.load_balancer
        service_client = load_balancer.service
        vs_client = load_balancer.virtual_server
        app_client = load_balancer.application_profile

        binding = nsx_db.get_nsx_lbaas_listener_binding(
            context.session, lb_id, listener.id)
        if binding:
            vs_id = binding['lb_vs_id']
            app_profile_id = binding['app_profile_id']
            lb_binding = nsx_db.get_nsx_lbaas_loadbalancer_binding(
                context.session, lb_id)
            if lb_binding:
                try:
                    lbs_id = lb_binding.get('lb_service_id')
                    lb_service = service_client.get(lbs_id)
                    vs_list = lb_service.get('virtual_server_ids')
                    if vs_list and vs_id in vs_list:
                        service_client.remove_virtual_server(lbs_id, vs_id)
                except nsxlib_exc.ManagerError:
                    self.lbv2_driver.listener.failed_completion(context,
                                                                listener)
                    msg = (_('Failed to remove virtual server: %(listener)s '
                             'from lb service %(lbs)s') %
                           {'listener': listener.id, 'lbs': lbs_id})
                    raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)
            try:
                if listener.default_pool_id:
                    vs_client.update(vs_id, pool_id='')
                    # Update pool binding to disassociate virtual server
                    pool_binding = nsx_db.get_nsx_lbaas_pool_binding(
                        context.session, lb_id, listener.default_pool_id)
                    if pool_binding:
                        nsx_db.update_nsx_lbaas_pool_binding(
                            context.session, lb_id, listener.default_pool_id,
                            None)
                vs_client.delete(vs_id)
            except nsx_exc.NsxResourceNotFound:
                msg = (_("virtual server not found on nsx: %(vs)s") %
                       {'vs': vs_id})
                raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)
            except nsxlib_exc.ManagerError:
                self.lbv2_driver.listener.failed_completion(context,
                                                            listener)
                msg = (_('Failed to delete virtual server: %(listener)s') %
                       {'listener': listener.id})
                raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)
            try:
                app_client.delete(app_profile_id)
            except nsx_exc.NsxResourceNotFound:
                msg = (_("application profile not found on nsx: %s") %
                       app_profile_id)
                raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)
            except nsxlib_exc.ManagerError:
                self.lbv2_driver.listener.failed_completion(context,
                                                            listener)
                msg = (_('Failed to delete application profile: %(app)s') %
                       {'app': app_profile_id})
                raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)
            nsx_db.delete_nsx_lbaas_listener_binding(
                context.session, lb_id, listener.id)

        self.lbv2_driver.listener.successful_completion(
            context, listener, delete=True)
