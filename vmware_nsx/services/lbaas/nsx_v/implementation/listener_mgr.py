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

import copy

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsxv_exc
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as vcns_exc
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common

LOG = logging.getLogger(__name__)


def listener_to_edge_app_profile(listener, edge_cert_id):
    edge_app_profile = {
        'insertXForwardedFor': False,
        'name': listener['id'],
        'serverSslEnabled': False,
        'sslPassthrough': False,
        'template': lb_const.PROTOCOL_MAP[listener['protocol']],
    }

    if (listener['protocol'] == lb_const.LB_PROTOCOL_HTTPS or
        listener['protocol'] == lb_const.LB_PROTOCOL_TERMINATED_HTTPS):
        if edge_cert_id:
            edge_app_profile['clientSsl'] = {
                'caCertificate': [],
                'clientAuth': 'ignore',
                'crlCertificate': [],
                'serviceCertificate': [edge_cert_id]}
        else:
            edge_app_profile['sslPassthrough'] = True

    if (listener.get('default_pool') and
        listener['default_pool'].get('session_persistence')):
        pool_sess_persist = listener['default_pool']['session_persistence']
        sess_persist_type = pool_sess_persist['type']
        persistence = {
            'method':
                lb_const.SESSION_PERSISTENCE_METHOD_MAP.get(
                    sess_persist_type)}

        if (sess_persist_type in
                lb_const.SESSION_PERSISTENCE_COOKIE_MAP):
            cookie_name = pool_sess_persist.get('cookie_name', None)
            if cookie_name is None:
                cookie_name = lb_const.SESSION_PERSISTENCE_DEFAULT_COOKIE_NAME
            persistence.update({
                'cookieName': cookie_name,
                'cookieMode': lb_const.SESSION_PERSISTENCE_COOKIE_MAP[
                    sess_persist_type]})

        edge_app_profile['persistence'] = persistence

    return edge_app_profile


def listener_to_edge_vse(context, listener, vip_address, default_pool,
                         app_profile_id):
    if listener['connection_limit']:
        connection_limit = max(0, listener['connection_limit'])
    else:
        connection_limit = 0

    vse = {
        'name': 'vip_' + listener['id'],
        'description': listener['description'],
        'ipAddress': vip_address,
        'protocol': lb_const.PROTOCOL_MAP[listener['protocol']],
        'port': listener['protocol_port'],
        'connectionLimit': connection_limit,
        'defaultPoolId': default_pool,
        'accelerationEnabled': (
            listener['protocol'] == lb_const.LB_PROTOCOL_TCP),
        'applicationProfileId': app_profile_id,
        'enabled': listener['admin_state_up']}

    # Add the L7 policies
    if listener['l7_policies']:
        app_rule_ids = []
        for pol in listener['l7_policies']:
            binding = nsxv_db.get_nsxv_lbaas_l7policy_binding(
                context.session, pol['id'])
            if binding:
                app_rule_ids.append(binding['edge_app_rule_id'])
        vse['applicationRuleId'] = app_rule_ids

    return vse


def update_app_profile(vcns, context, listener, edge_id, edge_cert_id=None):
    lb_id = listener['loadbalancer_id']
    listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
        context.session, lb_id, listener['id'])
    app_profile_id = listener_binding['app_profile_id']
    app_profile = listener_to_edge_app_profile(listener, edge_cert_id)
    with locking.LockManager.get_lock(edge_id):
        vcns.update_app_profile(
            edge_id, app_profile_id, app_profile)
    return app_profile_id


class EdgeListenerManagerFromDict(base_mgr.EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeListenerManagerFromDict, self).__init__(vcns_driver)

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

    def create(self, context, listener, completor, certificate=None):
        default_pool = None

        lb_id = listener['loadbalancer_id']
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        edge_id = lb_binding['edge_id']

        if listener.get('default_pool') and listener['default_pool'].get('id'):
            pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
                context.session, lb_id, listener['default_pool']['id'])
            if pool_binding:
                default_pool = pool_binding['edge_pool_id']

        edge_cert_id = None
        if certificate:
            try:
                edge_cert_id = self._upload_certificate(
                    context, edge_id, listener['default_tls_container_id'],
                    certificate)
            except Exception:
                with excutils.save_and_reraise_exception():
                    completor(success=False)

        app_profile = listener_to_edge_app_profile(listener, edge_cert_id)
        app_profile_id = None

        try:
            with locking.LockManager.get_lock(edge_id):
                h = (self.vcns.create_app_profile(edge_id, app_profile))[0]
                app_profile_id = lb_common.extract_resource_id(h['location'])
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to create app profile on edge: %s',
                          lb_binding['edge_id'])

        vse = listener_to_edge_vse(context, listener,
                                   lb_binding['vip_address'],
                                   default_pool,
                                   app_profile_id)

        try:
            with locking.LockManager.get_lock(edge_id):
                h = self.vcns.create_vip(edge_id, vse)[0]
                edge_vse_id = lb_common.extract_resource_id(h['location'])

            nsxv_db.add_nsxv_lbaas_listener_binding(context.session,
                                                    lb_id,
                                                    listener['id'],
                                                    app_profile_id,
                                                    edge_vse_id)
            completor(success=True)

        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to create vip on Edge: %s', edge_id)
                self.vcns.delete_app_profile(edge_id, app_profile_id)

    def update(self, context, old_listener, new_listener, completor,
               certificate=None):
        default_pool = None
        if (new_listener.get('default_pool') and
            new_listener['default_pool'].get('id')):
            pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
                context.session, new_listener['loadbalancer_id'],
                new_listener['default_pool']['id'])
            if pool_binding:
                default_pool = pool_binding['edge_pool_id']
            else:
                LOG.error("Couldn't find pool binding for pool %s",
                          new_listener['default_pool']['id'])

        lb_id = new_listener['loadbalancer_id']
        listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
            context.session, lb_id, new_listener['id'])
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        edge_id = lb_binding['edge_id']

        edge_cert_id = None
        if certificate:
            if (old_listener['default_tls_container_id'] !=
                    new_listener['default_tls_container_id']):
                try:
                    edge_cert_id = self._upload_certificate(
                        context, edge_id,
                        new_listener['default_tls_container_id'],
                        certificate)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        completor(success=False)
            else:
                cert_binding = nsxv_db.get_nsxv_lbaas_certificate_binding(
                    context.session, new_listener['default_tls_container_id'],
                    edge_id)
                edge_cert_id = cert_binding['edge_cert_id']

        try:
            app_profile_id = update_app_profile(
                self.vcns, context, new_listener,
                edge_id, edge_cert_id=edge_cert_id)
            vse = listener_to_edge_vse(context, new_listener,
                                       lb_binding['vip_address'],
                                       default_pool,
                                       app_profile_id)

            with locking.LockManager.get_lock(edge_id):
                self.vcns.update_vip(edge_id, listener_binding['vse_id'], vse)

            completor(success=True)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to update app profile on edge: %s',
                          edge_id)

    def delete(self, context, listener, completor):
        lb_id = listener['loadbalancer_id']
        listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
            context.session, lb_id, listener['id'])
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)

        if lb_binding and listener_binding:
            edge_id = lb_binding['edge_id']
            edge_vse_id = listener_binding['vse_id']
            app_profile_id = listener_binding['app_profile_id']

            try:
                with locking.LockManager.get_lock(edge_id):
                    self.vcns.delete_vip(edge_id, edge_vse_id)

            except (vcns_exc.ResourceNotFound, vcns_exc.RequestBad):
                LOG.error('vip not found on edge: %s', edge_id)
            except vcns_exc.VcnsApiException:
                LOG.error('Failed to delete vip on edge: %s', edge_id)

            try:
                with locking.LockManager.get_lock(edge_id):
                    self.vcns.delete_app_profile(edge_id, app_profile_id)
            except (vcns_exc.ResourceNotFound, vcns_exc.RequestBad):
                    LOG.error('app profile not found on edge: %s', edge_id)
            except vcns_exc.VcnsApiException:
                LOG.error('Failed to delete app profile on Edge: %s', edge_id)

            nsxv_db.del_nsxv_lbaas_listener_binding(context.session, lb_id,
                                                    listener['id'])

        completor(success=True)

    def delete_cascade(self, context, listener, completor):
        self.delete(context, listener, completor)


def stats_getter(context, core_plugin, ignore_list=None):
    """Update Octavia statistics for each listener (virtual server)"""
    stat_list = []
    vcns = core_plugin.nsx_v.vcns
    # go over all LB edges
    bindings = nsxv_db.get_nsxv_lbaas_loadbalancer_bindings(context.session)
    for binding in bindings:
        lb_id = binding['loadbalancer_id']
        if ignore_list and lb_id in ignore_list:
            continue
        edge_id = binding['edge_id']

        try:
            lb_stats = vcns.get_loadbalancer_statistics(edge_id)

            virtual_servers_stats = lb_stats[1].get('virtualServer', [])
            for vs_stats in virtual_servers_stats:
                # Get the stats of the virtual server
                stats = copy.copy(lb_const.LB_EMPTY_STATS)
                stats['bytes_in'] += vs_stats.get('bytesIn', 0)
                stats['bytes_out'] += vs_stats.get('bytesOut', 0)
                stats['active_connections'] += vs_stats.get('curSessions', 0)
                stats['total_connections'] += vs_stats.get('totalSessions', 0)
                stats['request_errors'] = 0  # currently unsupported

                # Find the listener Id
                vs_id = vs_stats.get('virtualServerId')
                list_bind = nsxv_db.get_nsxv_lbaas_listener_binding_by_vse(
                    context.session, lb_id, vs_id)
                if not list_bind:
                    continue
                stats['id'] = list_bind['listener_id']

                stat_list.append(stats)

        except vcns_exc.VcnsApiException as e:
            LOG.warning('Failed to read load balancer statistics for %s: %s',
                        edge_id, e)

    return stat_list
