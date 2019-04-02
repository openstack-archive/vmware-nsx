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
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3.policy import core_resources
from vmware_nsxlib.v3.policy import lb_defs
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeListenerManagerFromDict(base_mgr.NsxpLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def _get_listener_tags(self, context, listener):
        tags = lb_utils.get_tags(self.core_plugin, listener['id'],
                                 lb_const.LB_LISTENER_TYPE,
                                 listener['tenant_id'],
                                 context.project_name)
        tags.append({
            'scope': 'os-lbaas-lb-name',
            'tag': listener['loadbalancer']['name'][:utils.MAX_TAG_LEN]})
        tags.append({
            'scope': 'os-lbaas-lb-id',
            'tag': listener['loadbalancer_id']})
        return tags

    @log_helpers.log_method_call
    def _upload_certificate(self, listener_id, cert_href, tags,
                            certificate=None):
        cert_client = self.core_plugin.nsxpolicy.certificate

        passphrase = certificate.get_private_key_passphrase()
        if not passphrase:
            passphrase = core_resources.IGNORE
        cert_client.create_or_overwrite(
            cert_href, certificate_id=listener_id,
            pem_encoded=certificate.get_certificate(),
            private_key=certificate.get_private_key(),
            passphrase=passphrase,
            tags=tags)

        return {
            'client_ssl_profile_binding': {
                'ssl_profile_id': self.core_plugin.client_ssl_profile,
                'default_certificate_id': listener_id
            }
        }

    @log_helpers.log_method_call
    def _get_virtual_server_kwargs(self, context, listener, vs_name, tags,
                                   certificate=None):
        # If loadbalancer vip_port already has floating ip, use floating
        # IP as the virtual server VIP address. Else, use the loadbalancer
        # vip_address directly on virtual server.
        filters = {'port_id': [listener['loadbalancer']['vip_port_id']]}
        floating_ips = self.core_plugin.get_floatingips(context,
                                                        filters=filters)
        if floating_ips:
            lb_vip_address = floating_ips[0]['floating_ip_address']
        else:
            lb_vip_address = listener['loadbalancer']['vip_address']
        kwargs = {'virtual_server_id': listener['id'],
                  'ip_address': lb_vip_address,
                  'ports': [listener['protocol_port']],
                  'application_profile_id': listener['id'],
                  'lb_service_id': listener['loadbalancer_id'],
                  'description': listener.get('description')}
        if vs_name:
            kwargs['name'] = vs_name
        if tags:
            kwargs['tags'] = tags
        if listener['connection_limit'] != -1:
            kwargs['max_concurrent_connections'] = listener['connection_limit']
        if listener['default_pool_id']:
            kwargs['pool_id'] = listener['default_pool_id']
        if certificate:
            ssl_profile_binding = self._upload_certificate(
                listener['id'], listener['default_tls_container_id'], tags,
                certificate=certificate)
            if (listener['protocol'] == lb_const.LB_PROTOCOL_TERMINATED_HTTPS
                and ssl_profile_binding):
                kwargs.update(ssl_profile_binding)

        waf_profile, mode = self.core_plugin.get_waf_profile_path_and_mode()
        if (waf_profile and (
            listener['protocol'] == lb_const.LB_PROTOCOL_HTTP or
            listener['protocol'] == lb_const.LB_PROTOCOL_TERMINATED_HTTPS)):
            kwargs['waf_profile_binding'] = lb_defs.WAFProfileBindingDef(
                waf_profile_path=waf_profile,
                operational_mode=mode)

        return kwargs

    def _get_nsxlib_app_profile(self, nsxlib_lb, listener):
        if (listener['protocol'] == lb_const.LB_PROTOCOL_HTTP or
                listener['protocol'] == lb_const.LB_PROTOCOL_TERMINATED_HTTPS):
            app_client = nsxlib_lb.lb_http_profile
        elif (listener['protocol'] == lb_const.LB_PROTOCOL_TCP or
              listener['protocol'] == lb_const.LB_PROTOCOL_HTTPS):
            app_client = nsxlib_lb.lb_fast_tcp_profile
        else:
            msg = (_('Cannot create listener %(listener)s with '
                     'protocol %(protocol)s') %
                   {'listener': listener['id'],
                    'protocol': listener['protocol']})
            raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)

        return app_client

    @log_helpers.log_method_call
    def create(self, context, listener, completor,
               certificate=None):
        nsxlib_lb = self.core_plugin.nsxpolicy.load_balancer
        vs_client = nsxlib_lb.virtual_server
        vs_name = utils.get_name_and_uuid(listener['name'] or 'listener',
                                          listener['id'])
        tags = self._get_listener_tags(context, listener)
        app_client = self._get_nsxlib_app_profile(nsxlib_lb, listener)
        try:
            app_client.create_or_overwrite(
                lb_app_profile_id=listener['id'], name=vs_name, tags=tags)
            kwargs = self._get_virtual_server_kwargs(
                context, listener, vs_name, tags, certificate)
            vs_client.create_or_overwrite(**kwargs)
        except nsxlib_exc.ManagerError:
            completor(success=False)
            msg = _('Failed to create virtual server at NSX backend')
            raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)

        completor(success=True)

    @log_helpers.log_method_call
    def update(self, context, old_listener, new_listener, completor,
               certificate=None):
        nsxlib_lb = self.core_plugin.nsxpolicy.load_balancer
        vs_client = nsxlib_lb.virtual_server
        app_client = self._get_nsxlib_app_profile(nsxlib_lb, old_listener)

        vs_name = None
        tags = None
        if new_listener['name'] != old_listener['name']:
            vs_name = utils.get_name_and_uuid(
                new_listener['name'] or 'listener',
                new_listener['id'])
            tags = self._get_listener_tags(context, new_listener)

        try:
            vs_id = new_listener['id']
            app_profile_id = new_listener['id']
            updated_kwargs = self._get_virtual_server_kwargs(
                context, new_listener, vs_name, tags, app_profile_id,
                certificate)
            vs_client.update(vs_id, **updated_kwargs)
            if vs_name:
                app_client.update(app_profile_id, display_name=vs_name,
                                  tags=tags)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to update listener %(listener)s with '
                          'error %(error)s',
                          {'listener': old_listener['id'], 'error': e})
        completor(success=True)

    @log_helpers.log_method_call
    def delete(self, context, listener, completor):
        nsxlib_lb = self.core_plugin.nsxpolicy.load_balancer
        vs_client = nsxlib_lb.virtual_server
        app_client = self._get_nsxlib_app_profile(nsxlib_lb, listener)

        vs_id = listener['id']
        app_profile_id = listener['id']

        try:
            vs_client.delete(vs_id)
        except nsx_exc.NsxResourceNotFound:
            LOG.error("virtual server not found on nsx: %(vs)s", {'vs': vs_id})
        except nsxlib_exc.ManagerError:
            completor(success=False)
            msg = (_('Failed to delete virtual server: %(vs)s') %
                   {'vs': vs_id})
            raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)

        try:
            app_client.delete(app_profile_id)
        except nsx_exc.NsxResourceNotFound:
            LOG.error("application profile not found on nsx: %s",
                      app_profile_id)

        except nsxlib_exc.ManagerError:
            completor(success=False)
            msg = (_('Failed to delete application profile: %(app)s') %
                   {'app': app_profile_id})
            raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)

        # Delete imported NSX cert if there is any
        if listener['default_tls_container_id']:
            cert_client = self.core_plugin.nsxpolicy.certificate
            try:
                cert_client.delete(listener['id'])
            except nsx_exc.NsxResourceNotFound:
                LOG.error("Certificate not found on nsx: %s", listener['id'])

            except nsxlib_exc.ManagerError:
                completor(success=False)
                msg = (_('Failed to delete certificate: %(crt)s') %
                       {'crt': listener['id']})
                raise n_exc.BadRequest(resource='lbaas-listener', msg=msg)

        completor(success=True)

    @log_helpers.log_method_call
    def delete_cascade(self, context, listener, completor):
        self.delete(context, listener, completor)


def stats_getter(context, core_plugin, ignore_list=None):
    """Update Octavia statistics for each listener (virtual server)"""
    #TODO(kobis): Implement
