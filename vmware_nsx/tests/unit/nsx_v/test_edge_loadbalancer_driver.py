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

import mock

from neutron import context
from neutron.tests import base

from vmware_nsx.plugins.nsx_v.vshield import vcns_driver
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common

EDGE_PROVIDER = ('LOADBALANCER:vmwareedge:neutron.services.'
                 'loadbalancer.drivers.vmware.edge_driver.'
                 'EdgeLoadbalancerDriver:default')

HEALTHMON_ID = 'cb297614-66c9-4048-8838-7e87231569ae'
POOL_ID = 'b3dfb476-6fdf-4ddd-b6bd-e86ae78dc30b'
TENANT_ID = 'f9135d3a908842bd8d785816c2c90d36'
SUBNET_ID = 'c8924d77-ff57-406f-a13c-a8c5def01fc9'
VIP_ID = 'f6393b95-34b0-4299-9001-cbc21e32bf03'
VIP_PORT_ID = '49c547e3-6775-42ea-a607-91e8f1a07432'
MEMBER_ID = '90dacafd-9c11-4af7-9d89-234e2d1fedb1'

EDGE_ID = 'edge-x'
EDGE_POOL_ID = '111'
EDGE_VSE_ID = '222'
APP_PROFILE_ID = '333'
EDGE_MON_ID = '444'
EDGE_FW_RULE_ID = '555'


def lbaas_pool_maker(**kwargs):
    lbaas_dict = {
        'status': 'PENDING_CREATE',
        'lb_method': 'ROUND_ROBIN',
        'protocol': 'HTTP',
        'description': '',
        'health_monitors': [],
        'members': [],
        'status_description': None,
        'id': POOL_ID,
        'vip_id': None,
        'name': 'testpool',
        'admin_state_up': True,
        'subnet_id': SUBNET_ID,
        'tenant_id': TENANT_ID,
        'health_monitors_status': [],
        'provider': 'vmwareedge'}

    lbaas_dict.update(kwargs)
    return lbaas_dict


def lbaas_vip_maker(**kwargs):
    lbaas_vip = {
        'status': 'PENDING_CREATE',
        'protocol': 'HTTP',
        'description': '',
        'address': '10.0.0.8',
        'protocol_port': 555,
        'port_id': VIP_PORT_ID,
        'id': VIP_ID,
        'status_description': None,
        'name': 'testvip1',
        'admin_state_up': True,
        'subnet_id': SUBNET_ID,
        'tenant_id': TENANT_ID,
        'connection_limit': -1,
        'pool_id': POOL_ID,
        'session_persistence': {'type': 'SOURCE_IP'}}

    lbaas_vip.update(kwargs)
    return lbaas_vip


def lbaas_member_maker(**kwargs):
    lbaas_member = {
        'admin_state_up': True,
        'status': 'PENDING_CREATE',
        'status_description': None,
        'weight': 5,
        'address': '10.0.0.4',
        'tenant_id': TENANT_ID,
        'protocol_port': 555,
        'id': MEMBER_ID,
        'pool_id': POOL_ID}

    lbaas_member.update(kwargs)
    return lbaas_member


def lbaas_hmon_maker(**kwargs):
    hmon = {
        'admin_state_up': True,
        'tenant_id': TENANT_ID,
        'delay': 5,
        'max_retries': 5,
        'timeout': 5,
        'pools': [{'status': 'PENDING_CREATE', 'status_description': None,
                   'pool_id': POOL_ID}],
        'type': 'PING',
        'id': HEALTHMON_ID}
    hmon.update(kwargs)
    return hmon


class TestEdgeLbDriver(base.BaseTestCase):
    def setUp(self):
        super(TestEdgeLbDriver, self).setUp()
        self.context = context.get_admin_context()
        callbacks = mock.Mock()
        callbacks.plugin = mock.Mock()
        self.edge_driver = vcns_driver.VcnsDriver(callbacks)
        self.edge_driver._lbv1_driver_prop = mock.Mock()
        self._temp_get_lbaas_edge_id_for_subnet = (
            lb_common.get_lbaas_edge_id_for_subnet)
        self._temp_update_pool_fw_rule = lb_common.update_pool_fw_rule
        self._temp_add_vip_as_secondary_ip = lb_common.add_vip_as_secondary_ip
        self._temp_add_vip_fw_rule = lb_common.add_vip_fw_rule
        self._temp_del_vip_as_secondary_ip = lb_common.del_vip_as_secondary_ip
        self._temp_del_vip_fw_rule = lb_common.del_vip_fw_rule
        lb_common.get_lbaas_edge_id_for_subnet = mock.Mock()
        lb_common.update_pool_fw_rule = mock.Mock()
        lb_common.add_vip_as_secondary_ip = mock.Mock()
        lb_common.add_vip_fw_rule = mock.Mock()
        lb_common.del_vip_as_secondary_ip = mock.Mock()
        lb_common.del_vip_fw_rule = mock.Mock()

    def tearDown(self):
        super(TestEdgeLbDriver, self).tearDown()
        lb_common.get_lbaas_edge_id_for_subnet = (
            self._temp_get_lbaas_edge_id_for_subnet)
        lb_common.update_pool_fw_rule = self._temp_update_pool_fw_rule
        lb_common.add_vip_as_secondary_ip = self._temp_add_vip_as_secondary_ip
        lb_common.add_vip_fw_rule = self._temp_add_vip_fw_rule
        lb_common.del_vip_as_secondary_ip = self._temp_del_vip_as_secondary_ip
        lb_common.del_vip_fw_rule = self._temp_del_vip_fw_rule

    def _mock_edge_driver(self, attr):
        return mock.patch.object(self.edge_driver, attr)

    def _mock_edge_driver_vcns(self, attr):
        return mock.patch.object(self.edge_driver.vcns, attr)

    def _mock_edge_lbv1_driver(self, attr):
        return mock.patch.object(self.edge_driver.lbv1_driver, attr)

    def test_create_pool(self):
        lbaas_pool = lbaas_pool_maker()

        edge_pool = {
            'transparent': False, 'name': 'pool_' + POOL_ID,
            'algorithm': 'round-robin', 'description': ''}

        with self._mock_edge_lbv1_driver(
                'create_pool_successful') as create_pool_successful, \
                self._mock_edge_driver_vcns('create_pool') as create_pool:

            lb_common.get_lbaas_edge_id_for_subnet.return_value = EDGE_ID
            create_pool.return_value = ({'location': 'x/' + EDGE_POOL_ID},
                                        None)

            self.edge_driver.create_pool(self.context, lbaas_pool)
            create_pool.assert_called_with(EDGE_ID, edge_pool)
            create_pool_successful.assert_called_with(
                self.context, lbaas_pool, EDGE_ID, EDGE_POOL_ID)

    def test_update_pool(self):
        from_pool = lbaas_pool_maker(status='ACTIVE')
        to_pool = lbaas_pool_maker(status='PENDING_UPDATE',
                                   lb_method='LEAST_CONNECTIONS')

        edge_pool = {
            'transparent': False, 'name': 'pool_' + POOL_ID,
            'algorithm': 'leastconn', 'description': ''}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}
        with self._mock_edge_lbv1_driver('pool_successful') as pool_successful,\
                self._mock_edge_driver_vcns('get_pool') as get_pool, \
                self._mock_edge_driver_vcns('update_pool') as update_pool:

            get_pool.return_value = (None, {})
            self.edge_driver.update_pool(
                self.context, from_pool, to_pool, pool_mapping)
            update_pool.assert_called_with(EDGE_ID, EDGE_POOL_ID, edge_pool)
            pool_successful.assert_called_with(self.context, to_pool)

    def test_delete_pool(self):
        lbaas_pool = lbaas_pool_maker()

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}

        with self._mock_edge_driver_vcns('delete_pool'),\
                self._mock_edge_lbv1_driver(
                    'delete_pool_successful') as mock_delete_successful:

            self.edge_driver.delete_pool(
                self.context, lbaas_pool, pool_mapping)
            mock_delete_successful.assert_called_with(self.context, lbaas_pool)

    def test_create_vip(self):
        lbaas_vip = lbaas_vip_maker()
        edge_app_prof = {
            'name': VIP_ID, 'insertXForwardedFor': False,
            'serverSslEnabled': False, 'template': 'HTTP',
            'sslPassthrough': False, 'persistence': {'method': 'sourceip'}}
        edge_vip = {
            'protocol': 'HTTP', 'name': 'vip_' + VIP_ID, 'connectionLimit': 0,
            'defaultPoolId': EDGE_POOL_ID, 'ipAddress': '10.0.0.8',
            'port': 555, 'applicationProfileId': APP_PROFILE_ID,
            'description': ''}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}

        with self._mock_edge_driver_vcns(
                    'create_app_profile') as mock_create_app_profile,\
                self._mock_edge_driver_vcns('create_vip') as mock_create_vip,\
                self._mock_edge_lbv1_driver(
                    'create_vip_successful') as mock_vip_successful:

            mock_create_app_profile.return_value = (
                {'location': 'x/' + APP_PROFILE_ID}, None)
            mock_create_vip.return_value = (
                {'location': 'x/' + EDGE_VSE_ID}, None)
            lb_common.add_vip_fw_rule.return_value = EDGE_FW_RULE_ID

            self.edge_driver.create_vip(self.context, lbaas_vip, pool_mapping)
            mock_create_app_profile.assert_called_with(EDGE_ID, edge_app_prof)
            lb_common.add_vip_fw_rule.assert_called_with(
                self.edge_driver.vcns, EDGE_ID, VIP_ID, '10.0.0.8')
            mock_create_vip.assert_called_with(EDGE_ID, edge_vip)
            mock_vip_successful.assert_called_with(
                self.context, lbaas_vip, EDGE_ID, APP_PROFILE_ID, EDGE_VSE_ID,
                EDGE_FW_RULE_ID)

    def test_update_vip(self):
        vip_from = lbaas_vip_maker(status='ACTIVE')
        vip_to = lbaas_vip_maker(status='PENDING_UPDATE',
                                 session_persistence={'type': 'HTTP_COOKIE'})
        edge_app_prof = {
            'name': 'testvip1', 'insertXForwardedFor': False,
            'serverSslEnabled': False, 'template': 'HTTP',
            'sslPassthrough': False,
            'persistence': {'cookieName': 'default_cookie_name',
                            'method': 'cookie', 'cookieMode': 'insert'}}
        edge_vip = {
            'protocol': 'HTTP', 'name': 'vip_' + VIP_ID, 'connectionLimit': 0,
            'defaultPoolId': EDGE_POOL_ID, 'ipAddress': '10.0.0.8',
            'port': 555, 'applicationProfileId': '333', 'description': ''}

        pool_mapping = {'edge_pool_id': '111'}
        vip_mapping = {'edge_id': EDGE_ID, 'edge_vse_id': EDGE_VSE_ID,
                       'edge_app_profile_id': APP_PROFILE_ID}

        with self._mock_edge_driver_vcns('update_vip') as mock_upd_vip,\
                self._mock_edge_driver_vcns(
                    'update_app_profile') as mock_upd_app_prof,\
                self._mock_edge_lbv1_driver(
                    'vip_successful') as mock_vip_successful:

            self.edge_driver.update_vip(self.context, vip_from, vip_to,
                                        pool_mapping, vip_mapping)

            mock_upd_app_prof.assert_called_with(EDGE_ID, APP_PROFILE_ID,
                                                 edge_app_prof)
            mock_upd_vip.assert_called_with(EDGE_ID, EDGE_VSE_ID, edge_vip)
            mock_vip_successful.assert_called_with(self.context, vip_to)

    def test_delete_vip(self):
        lbaas_vip = lbaas_vip_maker(status='PENDING_DELETE')
        vip_mapping = {'edge_id': EDGE_ID, 'edge_vse_id': EDGE_VSE_ID,
                       'edge_app_profile_id': APP_PROFILE_ID,
                       'edge_fw_rule_id': EDGE_FW_RULE_ID}

        with self._mock_edge_driver_vcns(
                    'delete_app_profile') as mock_del_app_profile,\
                self._mock_edge_driver_vcns('delete_vip') as mock_del_vip,\
                self._mock_edge_lbv1_driver(
                    'delete_vip_successful') as mock_del_successful:

            self.edge_driver.delete_vip(self.context, lbaas_vip, vip_mapping)
            mock_del_app_profile.assert_called_with(EDGE_ID, APP_PROFILE_ID)
            mock_del_vip.assert_called_with(EDGE_ID, EDGE_VSE_ID)
            lb_common.del_vip_fw_rule.assert_called_with(
                self.edge_driver.vcns, EDGE_ID, EDGE_FW_RULE_ID)
            mock_del_successful.assert_called_with(self.context, lbaas_vip)

    def test_create_member(self):
        lbaas_member = lbaas_member_maker()
        edge_pool = {
            'monitorId': [], 'name': POOL_ID, 'applicationRuleId': [],
            'member': [], 'poolId': 'pool-1', 'algorithm': 'round-robin',
            'transparent': False}
        edge_member = {
            'condition': 'enabled', 'ipAddress': '10.0.0.4', 'port': 555,
            'weight': 5, 'name': 'member-' + MEMBER_ID}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}

        with self._mock_edge_driver_vcns('update_pool'),\
                self._mock_edge_driver_vcns('get_pool') as mock_get_pool,\
                self._mock_edge_driver(
                    '_get_pool_member_ips') as mock_get_ips, \
                self._mock_edge_driver(
                    '_get_lbaas_fw_section_id') as mock_fw_sect, \
                self._mock_edge_lbv1_driver(
                    'member_successful') as mock_member_successful:

            mock_get_pool.return_value = (None, edge_pool)
            mock_get_ips.return_value = ['10.0.0.4']
            mock_fw_sect.return_value = 10010
            self.edge_driver.create_member(self.context, lbaas_member,
                                           pool_mapping)
            edge_pool['member'].append(edge_member)
            mock_member_successful.assert_called_with(self.context,
                                                      lbaas_member)

    def test_update_member(self):
        member_from = lbaas_member_maker(status='ACTIVE')
        member_to = lbaas_member_maker(status='PENDING_UPDATE', weight=10)
        edge_pool = {
            'monitorId': [], 'name': POOL_ID, 'applicationRuleId': [],
            'member': [
                {'condition': 'enabled', 'ipAddress': '10.0.0.4', 'port': 555,
                 'weight': 5, 'name': 'member-' + MEMBER_ID}],
            'poolId': 'pool-1', 'algorithm': 'round-robin',
            'transparent': False}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}

        with self._mock_edge_driver_vcns('get_pool') as mock_get_pool,\
                self._mock_edge_driver_vcns(
                    'update_pool') as mock_update_pool,\
                self._mock_edge_lbv1_driver(
                    'member_successful') as mock_member_successful:

            mock_get_pool.return_value = (None, edge_pool)
            self.edge_driver.update_member(self.context, member_from,
                                           member_to, pool_mapping)
            edge_pool['member'][0]['weight'] = 6
            mock_update_pool.assert_called_with(EDGE_ID, EDGE_POOL_ID,
                                                edge_pool)
            mock_member_successful.assert_called_with(self.context, member_to)

    def test_delete_member(self):
        def _del_member(context, member_id):
            self.assertEqual(context, self.context)
            self.assertEqual(member_id, MEMBER_ID)

        lbaas_member = lbaas_member_maker(status='PENDING_DELETE')
        edge_pool = {
            'monitorId': [], 'name': POOL_ID, 'applicationRuleId': [],
            'member': [
                {'condition': 'enabled', 'ipAddress': '10.0.0.4', 'port': 555,
                 'weight': 5, 'name': 'member-' + MEMBER_ID}],
            'poolId': 'pool-1', 'algorithm': 'round-robin',
            'transparent': False}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}
        mock_lb_plugin = mock.Mock()
        mock_lb_plugin._delete_db_member = _del_member

        with self._mock_edge_driver('_get_lb_plugin') as mock_get_lb_plugin,\
                self._mock_edge_driver_vcns('get_pool') as mock_get_pool,\
                self._mock_edge_driver(
                    '_get_lbaas_fw_section_id') as mock_fw_sect, \
                self._mock_edge_driver_vcns(
                    'update_pool') as mock_update_pool:

            mock_get_pool.return_value = (None, edge_pool)
            self.edge_driver.delete_member(self.context, lbaas_member,
                                           pool_mapping)
            mock_fw_sect.return_value = 10010
            mock_get_lb_plugin.return_value = mock_lb_plugin
            edge_pool['member'] = []
            mock_update_pool.assert_called_with(EDGE_ID, EDGE_POOL_ID,
                                                edge_pool)

    def test_create_pool_health_monitor(self):
        hmon = lbaas_hmon_maker()
        edge_hm = {'maxRetries': 5, 'interval': 5, 'type': 'icmp',
                   'name': HEALTHMON_ID, 'timeout': 5}
        edge_pool = {'monitorId': [], 'name': POOL_ID,
                     'applicationRuleId': [], 'member': [],
                     'poolId': 'pool-1', 'algorithm': 'round-robin',
                     'transparent': False}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}

        with self._mock_edge_driver_vcns('update_pool') as mock_update_pool,\
                self._mock_edge_driver_vcns('get_pool') as mock_get_pool,\
                self._mock_edge_driver_vcns(
                    'create_health_monitor') as mock_create_mon,\
                self._mock_edge_lbv1_driver(
                    'create_pool_health_monitor_successful') as (
                        mock_create_successful):

            mock_create_mon.return_value = ({'location': 'x/' + HEALTHMON_ID},
                                            None)
            mock_get_pool.return_value = (None, edge_pool)
            self.edge_driver.create_pool_health_monitor(
                self.context, hmon, POOL_ID, pool_mapping, None)
            mock_create_mon.assert_called_with(EDGE_ID, edge_hm)
            edge_pool['monitorId'].append(HEALTHMON_ID)
            mock_update_pool.assert_called_with(EDGE_ID, EDGE_POOL_ID,
                                                edge_pool)
            mock_create_successful.assert_called_with(
                self.context, hmon, POOL_ID, EDGE_ID, HEALTHMON_ID)

    def test_update_pool_health_monitor(self):
        from_hmon = lbaas_hmon_maker(status='ACTIVE')
        to_hmon = lbaas_hmon_maker(status='PENDING_UPDATE',
                                   max_retries=10)
        edge_hmon = {'maxRetries': 10, 'interval': 5, 'type': 'icmp',
                     'name': HEALTHMON_ID, 'timeout': 5}

        mon_mapping = {'edge_id': EDGE_ID, 'edge_monitor_id': EDGE_MON_ID}

        with self._mock_edge_driver_vcns(
            'update_health_monitor') as mock_update_mon,\
                self._mock_edge_lbv1_driver(
                    'pool_health_monitor_successful') as mock_hmon_successful:

            self.edge_driver.update_pool_health_monitor(
                self.context, from_hmon, to_hmon, POOL_ID, mon_mapping)

            mock_update_mon.assert_called_with(EDGE_ID, EDGE_MON_ID, edge_hmon)
            mock_hmon_successful.assert_called_with(self.context, to_hmon,
                                                    POOL_ID,)

    def test_delete_pool_health_monitor(self):
        hmon = lbaas_hmon_maker(status='PENDING_DELETE')
        edge_pool = {'monitorId': [EDGE_MON_ID], 'name': POOL_ID,
                     'applicationRuleId': [], 'member': [],
                     'poolId': 'pool-1', 'algorithm': 'round-robin',
                     'transparent': False}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}
        mon_mapping = {'edge_id': EDGE_ID, 'edge_monitor_id': EDGE_MON_ID}

        with self._mock_edge_driver_vcns('update_pool') as mock_update_pool,\
                self._mock_edge_driver_vcns('get_pool') as mock_get_pool,\
                self._mock_edge_driver_vcns(
                    'delete_health_monitor') as mock_del_mon,\
                self._mock_edge_lbv1_driver(
                    'delete_pool_health_monitor_successful') as (
                        mock_del_successful):

            mock_get_pool.return_value = (None, edge_pool)
            self.edge_driver.delete_pool_health_monitor(
                self.context, hmon, POOL_ID, pool_mapping, mon_mapping)

            edge_pool['monitorId'] = []
            mock_update_pool.assert_called_with(EDGE_ID, EDGE_POOL_ID,
                                                edge_pool)
            mock_del_mon.assert_called_with(EDGE_ID, EDGE_MON_ID)
            mock_del_successful.assert_called_with(self.context, hmon, POOL_ID,
                                                   mon_mapping)

    def test_stats(self):
        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}
        pool_stats = (
            {
                'status': '200',
                'content-location': '',
                'transfer-encoding': 'chunked',
                'expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
                'server': '',
                'cache-control': 'private, no-cache',
                'date': 'Thu, 30 Jul 2015 08:59:27 GMT',
                'content-type': 'application/json'},
            {
                'timeStamp': 1427358733,
                'virtualServer': [
                    {'name': 'MdSrv',
                     'virtualServerId': 'virtualServer-1',
                     'bytesIn': 0,
                     'bytesOut': 0,
                     'totalSessions': 0,
                     'ipAddress': '169.254.128.2',
                     'curSessions': 0}],
                'pool': [
                    {'status': 'UP',
                     'totalSessions': 10000,
                     'rateMax': 0,
                     'name': 'MDSrvPool',
                     'bytesOut': 100000,
                     'rateLimit': 0,
                     'member': [
                         {'status': 'UP',
                          'name': 'member-xxx-xxx-xxx-xxx',
                          'bytesOut': 0,
                          'memberId': 'member-1',
                          'totalSessions': 20000,
                          'ipAddress': '192.168.55.101',
                          'httpReqRateMax': 0,
                          'curSessions': 0,
                          'bytesIn': 0},
                         {'status': 'UP',
                          'name': 'member-yyy-yyy-yyy-yyy',
                          'bytesOut': 0,
                          'memberId': 'member-2',
                          'totalSessions': 20000,
                          'ipAddress': '192.168.55.102',
                          'httpReqRateMax': 0,
                          'curSessions': 0,
                          'bytesIn': 0}],
                     'poolId': EDGE_POOL_ID,
                     'maxSessions': 10000,
                     'httpReqRateMax': 0,
                     'curSessions': 5000,
                     'bytesIn': 1000000}]})
        expected_stats = {'active_connections': 5000,
                          'bytes_in': 1000000,
                          'bytes_out': 100000,
                          'total_connections': 10000,
                          'members': {'xxx-xxx-xxx-xxx': {'status': 'ACTIVE'}}}

        members = [{'id': 'xxx-xxx-xxx-xxx', 'status': 'ACTIVE'},
                   {'id': 'yyy-yyy-yyy-yyy', 'status': 'ERROR'}]
        mock_lb_plugin = mock.Mock()
        with mock.patch.object(self.edge_driver.vcns,
                               'get_loadbalancer_statistics',
                               return_value=pool_stats), \
            mock.patch.object(self.edge_driver,
                              '_get_lb_plugin',
                              return_value=mock_lb_plugin), \
            mock.patch.object(mock_lb_plugin, 'get_members',
                              return_value=members):
            stats = self.edge_driver.stats(self.context, POOL_ID, pool_mapping)
            self.assertEqual(stats, expected_stats)
