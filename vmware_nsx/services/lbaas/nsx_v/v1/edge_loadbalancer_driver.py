# Copyright 2015 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron import manager
from neutron.plugins.common import constants
from neutron_lib import exceptions as n_exc
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _, _LE
from vmware_nsx.common import locking
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as nsxv_exc
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common
from vmware_nsx.services.lbaas.nsx_v import lbaas_const as lb_const

LOG = logging.getLogger(__name__)


def convert_lbaas_pool(lbaas_pool):
    """
    Transform OpenStack pool dict to NSXv pool dict.
    """
    edge_pool = {
        'name': 'pool_' + lbaas_pool['id'],
        'description': lbaas_pool.get('description',
                                      lbaas_pool.get('name')),
        'algorithm': lb_const.BALANCE_MAP.get(
            lbaas_pool.get('lb_method'), 'round-robin'),
        'transparent': False
    }
    return edge_pool


def convert_lbaas_app_profile(name, sess_persist, protocol):
    """
    Create app profile dict for lbaas VIP.

    Neutron-lbaas VIP objects breaks into an application profile object, and
    a virtual server object in NSXv.
    """
    vcns_app_profile = {
        'insertXForwardedFor': False,
        'name': name,
        'serverSslEnabled': False,
        'sslPassthrough': False,
        'template': protocol,
    }
    # Since SSL Termination is not supported right now, so just use
    # sslPassthrough method if the protocol is HTTPS.
    if protocol == lb_const.LB_PROTOCOL_HTTPS:
        vcns_app_profile['sslPassthrough'] = True

    if sess_persist:
        persist_type = sess_persist.get('type')
        if persist_type:
            # If protocol is not HTTP, only source_ip is supported
            if (protocol != lb_const.LB_PROTOCOL_HTTP and
                    persist_type != lb_const.LB_SESSION_PERSISTENCE_SOURCE_IP):
                msg = (_('Invalid %(protocol)s persistence method: %(type)s') %
                       {'protocol': protocol,
                        'type': persist_type})
                raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
            persistence = {
                'method':
                    lb_const.SESSION_PERSISTENCE_METHOD_MAP.get(persist_type)}
            if persist_type in lb_const.SESSION_PERSISTENCE_COOKIE_MAP:
                persistence.update({
                    'cookieName': sess_persist.get('cookie_name',
                                                   'default_cookie_name'),
                    'cookieMode':
                        lb_const.SESSION_PERSISTENCE_COOKIE_MAP[persist_type]})

            vcns_app_profile['persistence'] = persistence
    return vcns_app_profile


def convert_lbaas_vip(vip, app_profile_id, pool_mapping):
    """
    Transform OpenStack VIP dict to NSXv virtual server dict.
    """
    pool_id = pool_mapping['edge_pool_id']
    return {
        'name': 'vip_' + vip['id'],
        'description': vip['description'],
        'ipAddress': vip['address'],
        'protocol': vip.get('protocol'),
        'port': vip['protocol_port'],
        'connectionLimit': max(0, vip.get('connection_limit')),
        'defaultPoolId': pool_id,
        'applicationProfileId': app_profile_id}


def convert_lbaas_member(member):
    """
    Transform OpenStack pool member dict to NSXv pool member dict.
    """
    return {
        'ipAddress': member['address'],
        'weight': member['weight'],
        'port': member['protocol_port'],
        'monitorPort': member['protocol_port'],
        'name': lb_common.get_member_id(member['id']),
        'condition': 'enabled' if member['admin_state_up'] else 'disabled'}


def convert_lbaas_monitor(monitor):
    """
    Transform OpenStack health monitor dict to NSXv health monitor dict.
    """
    mon = {
        'type': lb_const.HEALTH_MONITOR_MAP.get(monitor['type'], 'icmp'),
        'interval': monitor['delay'],
        'timeout': monitor['timeout'],
        'maxRetries': monitor['max_retries'],
        'name': monitor['id']}

    if monitor.get('http_method'):
        mon['method'] = monitor['http_method']

    if monitor.get('url_path'):
        mon['url'] = monitor['url_path']
    return mon


class EdgeLbDriver(object):
    def __init__(self):
        super(EdgeLbDriver, self).__init__()
        LOG.debug('Initializing Edge loadbalancer')
        # self.vcns is initialized by subclass
        self.vcns = None
        self._fw_section_id = None
        self._lb_plugin = None
        self._lbv1_driver_prop = None

    def _get_lb_plugin(self):
        if not self._lb_plugin:
            loaded_plugins = manager.NeutronManager.get_service_plugins()
            self._lb_plugin = loaded_plugins.get(constants.LOADBALANCER)
        return self._lb_plugin

    @property
    def lbv1_driver(self):
        if not self._lbv1_driver_prop:
            plugin = self._get_lb_plugin()
            self._lbv1_driver_prop = plugin.drivers['vmwareedge']

        return self._lbv1_driver_prop

    def _get_lbaas_fw_section_id(self):
        if not self._fw_section_id:
            self._fw_section_id = lb_common.get_lbaas_fw_section_id(self.vcns)
        return self._fw_section_id

    def _get_pool_member_ips(self, context, pool_id, operation, address):
        plugin = self._get_lb_plugin()
        members = plugin.get_members(
            context,
            filters={'pool_id': [pool_id]},
            fields=['address'])
        member_ips = {member['address'] for member in members}
        if operation == 'add':
            member_ips.add(address)
        elif operation == 'del' and address in member_ips:
            member_ips.remove(address)

        return list(member_ips)

    def create_pool(self, context, pool):
        LOG.debug('Creating pool %s', pool)
        edge_id = lb_common.get_lbaas_edge_id_for_subnet(
            context, self.callbacks.plugin, pool['subnet_id'],
            pool['tenant_id'])

        if edge_id is None:
            self.lbv1_driver.pool_failed(context, pool)
            msg = _(
                'No suitable Edge found for subnet %s') % pool['subnet_id']
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

        # If Edge appliance is used for the 1st time for LB,
        # enable LB acceleration
        if not self.is_edge_in_use(context,
                                   edge_id):
            lb_common.enable_edge_acceleration(self.vcns, edge_id)

        edge_pool = convert_lbaas_pool(pool)
        try:
            with locking.LockManager.get_lock(edge_id):
                h = self.vcns.create_pool(edge_id, edge_pool)[0]
            edge_pool_id = lb_common.extract_resource_id(h['location'])
            self.lbv1_driver.create_pool_successful(
                context, pool, edge_id, edge_pool_id)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv1_driver.pool_failed(context, pool)
                LOG.error(_LE('Failed to create pool %s'), pool['id'])

    def update_pool(self, context, old_pool, pool, pool_mapping):
        LOG.debug('Updating pool %s to %s', old_pool, pool)
        edge_pool = convert_lbaas_pool(pool)
        try:
            with locking.LockManager.get_lock(pool_mapping['edge_id']):
                curr_pool = self.vcns.get_pool(pool_mapping['edge_id'],
                                               pool_mapping['edge_pool_id'])[1]
                curr_pool.update(edge_pool)
                self.vcns.update_pool(pool_mapping['edge_id'],
                                      pool_mapping['edge_pool_id'],
                                      curr_pool)
                self.lbv1_driver.pool_successful(context, pool)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv1_driver.pool_failed(context, pool)
                LOG.error(_LE('Failed to update pool %s'), pool['id'])

    def delete_pool(self, context, pool, pool_mapping):
        LOG.debug('Deleting pool %s', pool)

        if pool_mapping:
            try:
                with locking.LockManager.get_lock(pool_mapping['edge_id']):
                    self.vcns.delete_pool(pool_mapping['edge_id'],
                                          pool_mapping['edge_pool_id'])
            except nsxv_exc.VcnsApiException:
                LOG.error(_LE('Failed to delete pool %s'), pool['id'])
        else:
            LOG.error(_LE('No mapping found for pool %s'), pool['id'])

        self.lbv1_driver.delete_pool_successful(context, pool)

    def create_vip(self, context, vip, pool_mapping):
        LOG.debug('Create VIP %s', vip)

        app_profile = convert_lbaas_app_profile(
            vip['id'], vip.get('session_persistence', {}),
            vip.get('protocol'))

        if not pool_mapping:
            msg = _('Pool %s in not mapped to any Edge appliance') % (
                vip['pool_id'])
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
        edge_id = pool_mapping['edge_id']

        try:
            with locking.LockManager.get_lock(edge_id):
                h = (self.vcns.create_app_profile(edge_id, app_profile))[0]
            app_profile_id = lb_common.extract_resource_id(h['location'])
        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv1_driver.vip_failed(context, vip)
                LOG.error(_LE('Failed to create app profile on edge: %s'),
                          edge_id)

        edge_vip = convert_lbaas_vip(vip, app_profile_id, pool_mapping)
        try:
            lb_common.add_vip_as_secondary_ip(self.vcns, edge_id,
                                              vip['address'])
            with locking.LockManager.get_lock(edge_id):
                h = self.vcns.create_vip(edge_id, edge_vip)[0]
            edge_vip_id = lb_common.extract_resource_id(h['location'])
            edge_fw_rule_id = lb_common.add_vip_fw_rule(self.vcns,
                                                        edge_id, vip['id'],
                                                        vip['address'])
            self.lbv1_driver.create_vip_successful(
                context, vip, edge_id, app_profile_id, edge_vip_id,
                edge_fw_rule_id)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv1_driver.vip_failed(context, vip)
                LOG.error(_LE('Failed to create vip on Edge: %s'), edge_id)
                with locking.LockManager.get_lock(edge_id):
                    self.vcns.delete_app_profile(edge_id, app_profile_id)

    def update_vip(self, context, old_vip, vip, pool_mapping, vip_mapping):
        LOG.debug('Updating VIP %s to %s', old_vip, vip)

        edge_id = vip_mapping['edge_id']
        edge_vip_id = vip_mapping['edge_vse_id']
        app_profile_id = vip_mapping['edge_app_profile_id']
        app_profile = convert_lbaas_app_profile(
            vip['name'], vip.get('session_persistence', {}),
            vip.get('protocol'))
        try:
            with locking.LockManager.get_lock(edge_id):
                self.vcns.update_app_profile(edge_id, app_profile_id,
                                             app_profile)
        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv1_driver.vip_failed(context, vip)
                LOG.error(_LE('Failed to update app profile on edge: %s'),
                          edge_id)

        edge_vip = convert_lbaas_vip(vip, app_profile_id, pool_mapping)
        try:
            with locking.LockManager.get_lock(edge_id):
                self.vcns.update_vip(edge_id, edge_vip_id, edge_vip)
            self.lbv1_driver.vip_successful(context, vip)
        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv1_driver.vip_failed(context, vip)
                LOG.error(_LE('Failed to update vip on edge: %s'), edge_id)

    def delete_vip(self, context, vip, vip_mapping):
        LOG.debug('Deleting VIP %s', vip)

        if not vip_mapping:
            LOG.error(_LE('No mapping found for vip %s'), vip['id'])
        else:
            edge_id = vip_mapping['edge_id']
            edge_vse_id = vip_mapping['edge_vse_id']
            app_profile_id = vip_mapping['edge_app_profile_id']

            try:
                with locking.LockManager.get_lock(edge_id):
                    self.vcns.delete_vip(edge_id, edge_vse_id)
            except Exception as e:
                LOG.error(_LE('Failed to delete VIP from edge %(edge)s. '
                              'Exception is %(exc)s'),
                          {'edge': edge_id, 'exc': e})
            try:
                lb_common.del_vip_as_secondary_ip(self.vcns, edge_id,
                                                  vip['address'])
            except Exception as e:
                LOG.error(_LE('Failed to delete secondary IP from edge '
                              '%(edge)s. Exception is %(exc)s'),
                          {'edge': edge_id, 'exc': e})
            try:
                lb_common.del_vip_fw_rule(self.vcns, edge_id,
                                          vip_mapping['edge_fw_rule_id'])
            except Exception as e:
                LOG.error(_LE('Failed to delete VIP FW rule from edge '
                              '%(edge)s. Exception is %(exc)s'),
                          {'edge': edge_id, 'exc': e})
            try:
                with locking.LockManager.get_lock(edge_id):
                    self.vcns.delete_app_profile(edge_id, app_profile_id)
            except Exception as e:
                LOG.error(_LE('Failed to delete app profile from edge '
                              '%(edge)s. Exception is %(exc)s'),
                          {'edge': edge_id, 'exc': e})

        self.lbv1_driver.delete_vip_successful(context, vip)

    def create_member(self, context, member, pool_mapping):
        LOG.debug('Creating member %s', member)

        with locking.LockManager.get_lock(pool_mapping['edge_id']):
            edge_pool = self.vcns.get_pool(pool_mapping['edge_id'],
                                           pool_mapping['edge_pool_id'])[1]
            edge_member = convert_lbaas_member(member)

            if edge_pool['member']:
                edge_pool['member'].append(edge_member)
            else:
                edge_pool['member'] = [edge_member]

            try:
                self.vcns.update_pool(
                    pool_mapping['edge_id'],
                    pool_mapping['edge_pool_id'],
                    edge_pool)

                member_ips = self._get_pool_member_ips(
                    context, member['pool_id'], 'add', member['address'])
                lb_common.update_pool_fw_rule(
                    self.vcns, member['pool_id'], pool_mapping['edge_id'],
                    self._get_lbaas_fw_section_id(), member_ips)

                self.lbv1_driver.member_successful(context, member)

            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lbv1_driver.member_failed(context, member)
                    LOG.error(_LE('Failed to create member on edge: %s'),
                              pool_mapping['edge_id'])

    def update_member(self, context, old_member, member, pool_mapping):
        LOG.debug('Updating member %s to %s', old_member, member)

        with locking.LockManager.get_lock(pool_mapping['edge_id']):
            edge_pool = self.vcns.get_pool(pool_mapping['edge_id'],
                                           pool_mapping['edge_pool_id'])[1]

            edge_member = convert_lbaas_member(member)
            for i, m in enumerate(edge_pool['member']):
                if m['name'] == lb_common.get_member_id(member['id']):
                    edge_pool['member'][i] = edge_member
                    break

            try:
                self.vcns.update_pool(pool_mapping['edge_id'],
                                      pool_mapping['edge_pool_id'],
                                      edge_pool)
                self.lbv1_driver.member_successful(context, member)
            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lbv1_driver.member_failed(context, member)
                    LOG.error(_LE('Failed to update member on edge: %s'),
                              pool_mapping['edge_id'])

    def delete_member(self, context, member, pool_mapping):
        LOG.debug('Deleting member %s', member)

        if pool_mapping:
            with locking.LockManager.get_lock(pool_mapping['edge_id']):
                edge_pool = self.vcns.get_pool(
                    pool_mapping['edge_id'],
                    pool_mapping['edge_pool_id'])[1]

                for i, m in enumerate(edge_pool['member']):
                    if m['name'] == lb_common.get_member_id(member['id']):
                        edge_pool['member'].pop(i)
                        break

                try:
                    self.vcns.update_pool(pool_mapping['edge_id'],
                                          pool_mapping['edge_pool_id'],
                                          edge_pool)
                    member_ips = self._get_pool_member_ips(
                        context, member['pool_id'], 'del', member['address'])
                    lb_common.update_pool_fw_rule(
                        self.vcns, member['pool_id'], pool_mapping['edge_id'],
                        self._get_lbaas_fw_section_id(), member_ips)

                except nsxv_exc.VcnsApiException:
                    with excutils.save_and_reraise_exception():
                        self.lbv1_driver.member_failed(context, member)
                        LOG.error(_LE('Failed to update member on edge: %s'),
                                  pool_mapping['edge_id'])

        lb_plugin = self._get_lb_plugin()
        lb_plugin._delete_db_member(context, member['id'])

    def create_pool_health_monitor(self, context, health_monitor, pool_id,
                                   pool_mapping, mon_mappings):
        LOG.debug('Create HM %s', health_monitor)

        edge_mon_id = None
        with locking.LockManager.get_lock(pool_mapping['edge_id']):
            # 1st, we find if we already have a pool with the same monitor, on
            # the same Edge appliance.
            # If there is no pool on this Edge which is already associated with
            # this monitor, create this monitor on Edge
            if mon_mappings:
                edge_mon_id = mon_mappings['edge_monitor_id']
            else:
                edge_monitor = convert_lbaas_monitor(health_monitor)
                try:
                    h = self.vcns.create_health_monitor(
                        pool_mapping['edge_id'], edge_monitor)[0]
                    edge_mon_id = lb_common.extract_resource_id(h['location'])

                except nsxv_exc.VcnsApiException:
                    self.lbv1_driver.pool_health_monitor_failed(context,
                                                               health_monitor,
                                                               pool_id)
                    with excutils.save_and_reraise_exception():
                        LOG.error(
                            _LE('Failed to associate monitor on edge: %s'),
                            pool_mapping['edge_id'])

            try:
                # Associate monitor with Edge pool
                edge_pool = self.vcns.get_pool(pool_mapping['edge_id'],
                                               pool_mapping['edge_pool_id'])[1]
                if edge_pool['monitorId']:
                    edge_pool['monitorId'].append(edge_mon_id)
                else:
                    edge_pool['monitorId'] = [edge_mon_id]

                self.vcns.update_pool(pool_mapping['edge_id'],
                                      pool_mapping['edge_pool_id'],
                                      edge_pool)

            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lbv1_driver.pool_health_monitor_failed(context,
                                                               health_monitor,
                                                               pool_id)
                    LOG.error(
                        _LE('Failed to associate monitor on edge: %s'),
                        pool_mapping['edge_id'])

        self.lbv1_driver.create_pool_health_monitor_successful(
            context, health_monitor, pool_id, pool_mapping['edge_id'],
            edge_mon_id)

    def update_pool_health_monitor(self, context, old_health_monitor,
                                   health_monitor, pool_id, mon_mapping):
        LOG.debug('Update HM %s to %s', old_health_monitor, health_monitor)

        edge_monitor = convert_lbaas_monitor(health_monitor)

        try:
            with locking.LockManager.get_lock(mon_mapping['edge_id']):
                self.vcns.update_health_monitor(
                    mon_mapping['edge_id'],
                    mon_mapping['edge_monitor_id'],
                    edge_monitor)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv1_driver.pool_health_monitor_failed(context,
                                                           health_monitor,
                                                           pool_id)
                LOG.error(
                    _LE('Failed to update monitor on edge: %s'),
                    mon_mapping['edge_id'])

        self.lbv1_driver.pool_health_monitor_successful(context,
                                                       health_monitor,
                                                       pool_id)

    def delete_pool_health_monitor(self, context, health_monitor, pool_id,
                                   pool_mapping, mon_mapping):
        LOG.debug('Deleting HM %s', health_monitor)

        edge_id = pool_mapping['edge_id']
        if not mon_mapping:
            return

        with locking.LockManager.get_lock(pool_mapping['edge_id']):
            edge_pool = self.vcns.get_pool(edge_id,
                                           pool_mapping['edge_pool_id'])[1]
            edge_pool['monitorId'].remove(mon_mapping['edge_monitor_id'])

            try:
                self.vcns.update_pool(edge_id,
                                      pool_mapping['edge_pool_id'],
                                      edge_pool)
            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lbv1_driver.pool_health_monitor_failed(context,
                                                               health_monitor,
                                                               pool_id)
                    LOG.error(
                        _LE('Failed to delete monitor mapping on edge: %s'),
                        mon_mapping['edge_id'])

            # If this monitor is not used on this edge anymore, delete it
            if not edge_pool['monitorId']:
                try:
                    self.vcns.delete_health_monitor(
                        mon_mapping['edge_id'],
                        mon_mapping['edge_monitor_id'])
                except nsxv_exc.VcnsApiException:
                    with excutils.save_and_reraise_exception():
                        self.lbv1_driver.pool_health_monitor_failed(
                            context, health_monitor, pool_id)
                        LOG.error(
                            _LE('Failed to delete monitor on edge: %s'),
                            mon_mapping['edge_id'])

        self.lbv1_driver.delete_pool_health_monitor_successful(
            context, health_monitor, pool_id, mon_mapping)

    def stats(self, context, pool_id, pool_mapping):
        LOG.debug('Retrieving stats for pool %s', pool_id)

        try:
            lb_stats = self.vcns.get_loadbalancer_statistics(
                pool_mapping['edge_id'])

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.error(
                    _LE('Failed to read load balancer statistics, edge: %s'),
                    pool_mapping['edge_id'])

        pools_stats = lb_stats[1].get('pool', [])
        plugin = self._get_lb_plugin()
        members = plugin.get_members(
            context,
            filters={'pool_id': [pool_id]},
            fields=['id', 'status'])
        member_map = {m['id']: m['status'] for m in members}

        for pool_stats in pools_stats:
            if pool_stats['poolId'] == pool_mapping['edge_pool_id']:
                stats = {'bytes_in': pool_stats.get('bytesIn', 0),
                         'bytes_out': pool_stats.get('bytesOut', 0),
                         'active_connections':
                             pool_stats.get('curSessions', 0),
                         'total_connections':
                             pool_stats.get('totalSessions', 0)}

                member_stats = {}
                for member in pool_stats.get('member', []):
                    member_id = member['name'][len(lb_common.MEMBER_ID_PFX):]
                    if member_map[member_id] != 'ERROR':
                        member_stats[member_id] = {
                            'status': ('INACTIVE'
                                       if member['status'] == 'DOWN'
                                       else 'ACTIVE')}

                stats['members'] = member_stats
                return stats

        return {'bytes_in': 0,
                'bytes_out': 0,
                'active_connections': 0,
                'total_connections': 0}

    def is_edge_in_use(self, context, edge_id):
        return self.lbv1_driver.is_edge_in_use(context, edge_id)

    def is_subnet_in_use(self, context, subnet_id):
        plugin = self._get_lb_plugin()
        if plugin:
            pools = plugin.get_pools(context,
                                     filters={'subnet_id': [subnet_id]})
            if pools:
                return True
