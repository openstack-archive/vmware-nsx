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

from vmware_nsx._i18n import _, _LE
from vmware_nsx.common import exceptions as nsxv_exc
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as vcns_exc
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common
from vmware_nsx.services.lbaas.nsx_v import lbaas_const as lb_const
from vmware_nsx.services.lbaas.nsx_v.v2 import base_mgr

LOG = logging.getLogger(__name__)


def listener_to_edge_app_profile(listener, edge_cert_id):
    edge_app_profile = {
        'insertXForwardedFor': False,
        'name': listener.id,
        'serverSslEnabled': False,
        'sslPassthrough': False,
        'template': lb_const.PROTOCOL_MAP[listener.protocol],
    }

    if (listener.protocol == lb_const.LB_PROTOCOL_HTTPS
        or listener.protocol == lb_const.LB_PROTOCOL_TERMINATED_HTTPS):
        if edge_cert_id:
            edge_app_profile['clientSsl'] = {
                'caCertificate': [],
                'clientAuth': 'ignore',
                'crlCertificate': [],
                'serviceCertificate': [edge_cert_id]}
        else:
            edge_app_profile['sslPassthrough'] = True

    if listener.default_pool:
        if listener.default_pool.sessionpersistence:
            persistence = {
                'method':
                    lb_const.SESSION_PERSISTENCE_METHOD_MAP.get(
                        listener.default_pool.sessionpersistence.type)}

            if (listener.default_pool.sessionpersistence.type in
                    lb_const.SESSION_PERSISTENCE_COOKIE_MAP):
                persistence.update({
                    'cookieName': getattr(
                        listener.default_pool.sessionpersistence,
                        'cookie_name',
                        'default_cookie_name'),
                    'cookieMode': lb_const.SESSION_PERSISTENCE_COOKIE_MAP[
                        listener.default_pool.sessionpersistence.type]})

                edge_app_profile['persistence'] = persistence

    return edge_app_profile


def listener_to_edge_vse(listener, vip_address, default_pool, app_profile_id):
    if listener.connection_limit:
        connection_limit = max(0, listener.connection_limit)
    else:
        connection_limit = 0

    return {
        'name': 'vip_' + listener.id,
        'description': listener.description,
        'ipAddress': vip_address,
        'protocol': lb_const.PROTOCOL_MAP[listener.protocol],
        'port': listener.protocol_port,
        'connectionLimit': connection_limit,
        'defaultPoolId': default_pool,
        'applicationProfileId': app_profile_id}


class EdgeListenerManager(base_mgr.EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeListenerManager, self).__init__(vcns_driver)

    def _upload_certificate(self, context, edge_id, cert_id, certificate):
        cert_binding = nsxv_db.get_nsxv_lbaas_certificate_binding(
            context.session, cert_id, edge_id)
        if cert_binding:
            return cert_binding['edge_cert_id']

        request = {
            'pemEncoding': certificate.get_certificate(),
            'privateKey': certificate.get_private_key()}
        passphrase = certificate.get_private_key_passphrase()
        if passphrase:
            request['passphrase'] = passphrase
        cert_obj = self.vcns.upload_edge_certificate(edge_id, request)[1]
        cert_list = cert_obj.get('certificates', {})
        if cert_list:
            edge_cert_id = cert_list[0]['objectId']
        else:
            error = _("Failed to upload a certificate to edge %s") % edge_id
            raise nsxv_exc.NsxPluginException(err_msg=error)
        nsxv_db.add_nsxv_lbaas_certificate_binding(
            context.session, cert_id, edge_id, edge_cert_id)
        return edge_cert_id

    @log_helpers.log_method_call
    def create(self, context, listener, certificate=None):
        default_pool = None

        lb_id = listener.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        edge_id = lb_binding['edge_id']

        if listener.default_pool and listener.default_pool.id:
            pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
                context.session, lb_id, listener.default_pool.id)
            if pool_binding:
                default_pool = pool_binding['edge_pool_id']

        edge_cert_id = None
        if certificate:
            try:
                edge_cert_id = self._upload_certificate(
                    context, edge_id, listener.default_tls_container_id,
                    certificate)
            except Exception:
                with excutils.save_and_reraise_exception():
                    self.lbv2_driver.listener.failed_completion(context,
                                                                listener)

        app_profile = listener_to_edge_app_profile(listener, edge_cert_id)
        app_profile_id = None

        try:
            with locking.LockManager.get_lock(edge_id):
                h = (self.vcns.create_app_profile(edge_id, app_profile))[0]
                app_profile_id = lb_common.extract_resource_id(h['location'])
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.listener.failed_completion(context, listener)
                LOG.error(_LE('Failed to create app profile on edge: %s'),
                          lb_binding['edge_id'])

        vse = listener_to_edge_vse(listener, lb_binding['vip_address'],
                                   default_pool,
                                   app_profile_id)

        try:
            with locking.LockManager.get_lock(edge_id):
                h = self.vcns.create_vip(edge_id, vse)[0]
                edge_vse_id = lb_common.extract_resource_id(h['location'])

            nsxv_db.add_nsxv_lbaas_listener_binding(context.session,
                                                    lb_id,
                                                    listener.id,
                                                    app_profile_id,
                                                    edge_vse_id)
            self.lbv2_driver.listener.successful_completion(context, listener)

        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.listener.failed_completion(context, listener)
                LOG.error(_LE('Failed to create vip on Edge: %s'), edge_id)
                self.vcns.delete_app_profile(edge_id, app_profile_id)

    @log_helpers.log_method_call
    def update(self, context, old_listener, new_listener, certificate=None):

        default_pool = None
        if new_listener.default_pool and new_listener.default_pool.id:
            pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
                context.session, new_listener.loadbalancer_id,
                new_listener.default_pool.id)
            if pool_binding:
                default_pool = pool_binding['edge_pool_id']
            else:
                LOG.error(_LE("Couldn't find pool binding for pool %s"),
                          new_listener.default_pool.id)

        lb_id = new_listener.loadbalancer_id
        listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
            context.session, lb_id, new_listener.id)
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        edge_id = lb_binding['edge_id']

        edge_cert_id = None
        if certificate:
            if (old_listener.default_tls_container_id !=
                    new_listener.default_tls_container_id):
                try:
                    edge_cert_id = self._upload_certificate(
                        context, edge_id,
                        new_listener.default_tls_container_id,
                        certificate)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        self.lbv2_driver.listener.failed_completion(
                            context, new_listener)
            else:
                cert_binding = nsxv_db.get_nsxv_lbaas_certificate_binding(
                    context.session, new_listener.default_tls_container_id,
                    edge_id)
                edge_cert_id = cert_binding['edge_cert_id']

        app_profile_id = listener_binding['app_profile_id']
        app_profile = listener_to_edge_app_profile(new_listener, edge_cert_id)

        try:
            with locking.LockManager.get_lock(edge_id):
                self.vcns.update_app_profile(
                    edge_id, app_profile_id, app_profile)

            vse = listener_to_edge_vse(new_listener,
                                       lb_binding['vip_address'],
                                       default_pool,
                                       app_profile_id)

            with locking.LockManager.get_lock(edge_id):
                self.vcns.update_vip(edge_id, listener_binding['vse_id'], vse)

            self.lbv2_driver.listener.successful_completion(context,
                                                            new_listener)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.listener.failed_completion(context,
                                                          new_listener)
                LOG.error(_LE('Failed to update app profile on edge: %s'),
                          edge_id)

    @log_helpers.log_method_call
    def delete(self, context, listener):
        lb_id = listener.loadbalancer_id
        listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
            context.session, lb_id, listener.id)
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)

        if lb_binding and listener_binding:
            edge_id = lb_binding['edge_id']
            edge_vse_id = listener_binding['vse_id']
            app_profile_id = listener_binding['app_profile_id']

            try:
                with locking.LockManager.get_lock(edge_id):
                    self.vcns.delete_vip(edge_id, edge_vse_id)

            except vcns_exc.ResourceNotFound:
                LOG.error(_LE('vip not found on edge: %s'), edge_id)
            except vcns_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lbv2_driver.listener.failed_completion(context,
                                                                listener)
                    LOG.error(
                        _LE('Failed to delete vip on edge: %s'), edge_id)

            try:
                with locking.LockManager.get_lock(edge_id):
                    self.vcns.delete_app_profile(edge_id, app_profile_id)
            except vcns_exc.ResourceNotFound:
                LOG.error(_LE('app profile not found on edge: %s'), edge_id)
            except vcns_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lbv2_driver.listener.failed_completion(context,
                                                                listener)
                    LOG.error(
                        _LE('Failed to delete app profile on Edge: %s'),
                        edge_id)

            nsxv_db.del_nsxv_lbaas_listener_binding(context.session, lb_id,
                                                    listener.id)

        self.lbv2_driver.listener.successful_completion(
            context, listener, delete=True)
