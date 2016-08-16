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

from neutron import context

import mock
from neutron.tests import base
from neutron_lbaas.services.loadbalancer import data_models as lb_models

from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield import vcns_driver
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common
from vmware_nsx.services.lbaas.nsx_v.v2 import base_mgr


LB_VIP = '10.0.0.10'
LB_EDGE_ID = 'edge-x'
LB_ID = 'xxx-xxx'
LB_TENANT_ID = 'yyy-yyy'
LB_VIP_FWR_ID = 'fwr-1'
LB_BINDING = {'loadbalancer_id': LB_ID,
              'edge_id': LB_EDGE_ID,
              'edge_fw_rule_id': LB_VIP_FWR_ID,
              'vip_address': LB_VIP}
LISTENER_ID = 'xxx-111'
EDGE_APP_PROFILE_ID = 'appp-x'
EDGE_APP_PROF_DEF = {'sslPassthrough': False, 'insertXForwardedFor': False,
                     'serverSslEnabled': False, 'name': LISTENER_ID,
                     'template': 'http'}
EDGE_VIP_ID = 'vip-aaa'
EDGE_VIP_DEF = {'protocol': 'http', 'name': 'vip_' + LISTENER_ID,
                'connectionLimit': 0, 'defaultPoolId': None,
                'ipAddress': LB_VIP, 'port': 80,
                'applicationProfileId': EDGE_APP_PROFILE_ID, 'description': ''}
LISTENER_BINDING = {'loadbalancer_id': LB_ID,
                    'listener_id': LISTENER_ID,
                    'app_profile_id': EDGE_APP_PROFILE_ID,
                    'vse_id': EDGE_VIP_ID}
POOL_ID = 'ppp-qqq'
EDGE_POOL_ID = 'pool-xx'
EDGE_POOL_DEF = {'transparent': False, 'name': 'pool_' + POOL_ID,
                 'algorithm': 'round-robin', 'description': ''}
POOL_BINDING = {'loadbalancer_id': LB_ID,
                'pool_id': POOL_ID,
                'edge_pool_id': EDGE_POOL_ID}
MEMBER_ID = 'mmm-mmm'
MEMBER_ADDRESS = '10.0.0.200'
EDGE_MEMBER_DEF = {'monitorPort': 80, 'name': 'member-' + MEMBER_ID,
                   'weight': 1, 'ipAddress': MEMBER_ADDRESS, 'port': 80,
                   'condition': 'disabled'}
POOL_FW_SECT = '10001'
HM_ID = 'hhh-mmm'
EDGE_HM_ID = 'hm-xx'
EDGE_HM_DEF = {'maxRetries': 1, 'interval': 3, 'type': 'icmp', 'name': HM_ID,
               'timeout': 3}

HM_BINDING = {'loadbalancer_id': LB_ID,
              'pool_id': POOL_ID,
              'hm_id': HM_ID,
              'edge_id': LB_EDGE_ID,
              'edge_mon_id': EDGE_HM_ID}


class BaseTestEdgeLbaasV2(base.BaseTestCase):
    def _tested_entity(self):
        return None

    def setUp(self):
        super(BaseTestEdgeLbaasV2, self).setUp()

        self.context = context.get_admin_context()
        callbacks = mock.Mock()
        callbacks.plugin = mock.Mock()
        self.edge_driver = vcns_driver.VcnsDriver(callbacks)

        self.lbv2_driver = mock.Mock()
        self.core_plugin = mock.Mock()
        base_mgr.EdgeLoadbalancerBaseManager._lbv2_driver = self.lbv2_driver
        base_mgr.EdgeLoadbalancerBaseManager._core_plugin = self.core_plugin
        self._patch_lb_plugin(self.lbv2_driver, self._tested_entity)

        self.lb = lb_models.LoadBalancer(LB_ID, LB_TENANT_ID, 'lb-name', '',
                                         'some-subnet', 'port-id', LB_VIP)
        self.listener = lb_models.Listener(LISTENER_ID, LB_TENANT_ID,
                                           'l-name', '', None, LB_ID,
                                           'HTTP', protocol_port=80,
                                           loadbalancer=self.lb)
        self.pool = lb_models.Pool(POOL_ID, LB_TENANT_ID, 'pool-name', '',
                                   None, 'HTTP', 'ROUND_ROBIN',
                                   loadbalancer_id=LB_ID,
                                   listener=self.listener,
                                   listeners=[self.listener])
        self.member = lb_models.Member(MEMBER_ID, LB_TENANT_ID, POOL_ID,
                                       MEMBER_ADDRESS, 80, 1, pool=self.pool)
        self.hm = lb_models.HealthMonitor(HM_ID, LB_TENANT_ID, 'PING', 3, 3,
                                          1, pool=self.pool)

    def tearDown(self):
        self._unpatch_lb_plugin(self.lbv2_driver, self._tested_entity)
        super(BaseTestEdgeLbaasV2, self).tearDown()

    def _patch_lb_plugin(self, lb_plugin, manager):
        self.real_manager = getattr(lb_plugin, manager)
        lb_manager = mock.patch.object(lb_plugin, manager).start()
        mock.patch.object(lb_manager, 'create').start()
        mock.patch.object(lb_manager, 'update').start()
        mock.patch.object(lb_manager, 'delete').start()
        mock.patch.object(lb_manager, 'successful_completion').start()

    def _unpatch_lb_plugin(self, lb_plugin, manager):
        setattr(lb_plugin, manager, self.real_manager)


class TestEdgeLbaasV2Loadbalancer(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2Loadbalancer, self).setUp()

    @property
    def _tested_entity(self):
        return 'load_balancer'

    def test_create(self):
        with mock.patch.object(lb_common, 'get_lbaas_edge_id_for_subnet'
                               ) as mock_get_edge, \
            mock.patch.object(lb_common, 'add_vip_as_secondary_ip'
                              ) as mock_vip_sec_ip, \
            mock.patch.object(lb_common, 'add_vip_fw_rule'
                              ) as mock_add_vip_fwr, \
            mock.patch.object(lb_common, 'enable_edge_acceleration'
                              ) as mock_enable_edge_acceleration, \
            mock.patch.object(nsxv_db,
                              'get_nsxv_lbaas_loadbalancer_binding_by_edge'
                              ) as mock_get_lb_binding_by_edge, \
            mock.patch.object(nsxv_db, 'add_nsxv_lbaas_loadbalancer_binding'
                              ) as mock_db_binding:
            mock_get_edge.return_value = LB_EDGE_ID
            mock_add_vip_fwr.return_value = LB_VIP_FWR_ID
            mock_get_lb_binding_by_edge.return_value = []

            self.edge_driver.loadbalancer.create(self.context, self.lb)

            mock_vip_sec_ip.assert_called_with(self.edge_driver.vcns,
                                               LB_EDGE_ID,
                                               LB_VIP)
            mock_add_vip_fwr.assert_called_with(self.edge_driver.vcns,
                                                LB_EDGE_ID,
                                                LB_ID,
                                                LB_VIP)
            mock_db_binding.assert_called_with(self.context.session,
                                               LB_ID,
                                               LB_EDGE_ID,
                                               LB_VIP_FWR_ID,
                                               LB_VIP)
            mock_successful_completion = (
                self.lbv2_driver.load_balancer.successful_completion)
            mock_successful_completion.assert_called_with(self.context,
                                                          self.lb)
            mock_enable_edge_acceleration.assert_called_with(
                self.edge_driver.vcns, LB_EDGE_ID)

    def test_update(self):
        new_lb = lb_models.LoadBalancer(LB_ID, 'yyy-yyy', 'lb-name', 'heh-huh',
                                    'some-subnet', 'port-id', LB_VIP)

        self.edge_driver.loadbalancer.update(self.context, self.lb, new_lb)

        mock_successful_completion = (
            self.lbv2_driver.load_balancer.successful_completion)
        mock_successful_completion.assert_called_with(self.context, new_lb)

    def test_delete(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_binding, \
            mock.patch.object(lb_common, 'del_vip_fw_rule') as mock_del_fwr, \
            mock.patch.object(lb_common, 'del_vip_as_secondary_ip'
                              ) as mock_vip_sec_ip, \
            mock.patch.object(nsxv_db, 'del_nsxv_lbaas_loadbalancer_binding',
                              ) as mock_del_binding:
            mock_get_binding.return_value = LB_BINDING

            self.edge_driver.loadbalancer.delete(self.context, self.lb)

            mock_del_fwr.assert_called_with(self.edge_driver.vcns,
                                            LB_EDGE_ID,
                                            LB_VIP_FWR_ID)
            mock_vip_sec_ip.assert_called_with(self.edge_driver.vcns,
                                               LB_EDGE_ID,
                                               LB_VIP)
            mock_del_binding.assert_called_with(self.context.session,
                                                LB_ID)
            mock_successful_completion = (
                self.lbv2_driver.load_balancer.successful_completion)
            mock_successful_completion.assert_called_with(self.context,
                                                          self.lb,
                                                          delete=True)

    def test_stats(self):
        pass

    def test_refresh(self):
        pass


class TestEdgeLbaasV2Listener(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2Listener, self).setUp()

    @property
    def _tested_entity(self):
        return 'listener'

    def test_create(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(self.edge_driver.vcns, 'create_app_profile'
                              ) as mock_create_app_prof, \
            mock.patch.object(self.edge_driver.vcns, 'create_vip'
                              ) as mock_create_vip, \
            mock.patch.object(nsxv_db, 'add_nsxv_lbaas_listener_binding'
                              ) as mock_add_binding:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_create_app_prof.return_value = (
                {'location': 'x/' + EDGE_APP_PROFILE_ID}, None)
            mock_create_vip.return_value = (
                {'location': 'x/' + EDGE_VIP_ID}, None)

            self.edge_driver.listener.create(self.context, self.listener)

            mock_create_app_prof.assert_called_with(LB_EDGE_ID,
                                                    EDGE_APP_PROF_DEF)
            mock_create_vip.assert_called_with(LB_EDGE_ID,
                                               EDGE_VIP_DEF)
            mock_add_binding.assert_called_with(
                self.context.session, LB_ID, LISTENER_ID, EDGE_APP_PROFILE_ID,
                EDGE_VIP_ID)
            mock_successful_completion = (
                self.lbv2_driver.listener.successful_completion)
            mock_successful_completion.assert_called_with(self.context,
                                                          self.listener)

    def test_update(self):
        new_listener = lb_models.Listener(LISTENER_ID, LB_TENANT_ID,
                                          'l-name', '', None, LB_ID,
                                          'HTTP', protocol_port=8000,
                                          loadbalancer=self.lb)

        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_listener_binding'
                               ) as mock_get_listener_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                              ) as mock_get_lb_binding, \
            mock.patch.object(self.edge_driver.vcns, 'update_app_profile'
                              ) as mock_upd_app_prof, \
            mock.patch.object(self.edge_driver.vcns, 'update_vip'
                              ) as mock_upd_vip:
            mock_get_listener_binding.return_value = LISTENER_BINDING
            mock_get_lb_binding.return_value = LB_BINDING

            self.edge_driver.listener.update(
                self.context, self.listener, new_listener)

            mock_upd_app_prof.assert_called_with(LB_EDGE_ID,
                                                 EDGE_APP_PROFILE_ID,
                                                 EDGE_APP_PROF_DEF)

            edge_vip_def = EDGE_VIP_DEF.copy()
            edge_vip_def['port'] = 8000
            mock_upd_vip.assert_called_with(LB_EDGE_ID, EDGE_VIP_ID,
                                            edge_vip_def)
            mock_successful_completion = (
                self.lbv2_driver.listener.successful_completion)
            mock_successful_completion.assert_called_with(self.context,
                                                          new_listener)

    def test_delete(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_listener_binding'
                               ) as mock_get_listener_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                              ) as mock_get_lb_binding, \
            mock.patch.object(self.edge_driver.vcns, 'delete_vip'
                              ) as mock_del_vip, \
            mock.patch.object(self.edge_driver.vcns, 'delete_app_profile'
                              ) as mock_del_app_prof, \
            mock.patch.object(nsxv_db, 'del_nsxv_lbaas_listener_binding'
                              ) as mock_del_binding:
            mock_get_listener_binding.return_value = LISTENER_BINDING
            mock_get_lb_binding.return_value = LB_BINDING

            self.edge_driver.listener.delete(self.context, self.listener)

            mock_del_vip.assert_called_with(LB_EDGE_ID, EDGE_VIP_ID)
            mock_del_app_prof.assert_called_with(LB_EDGE_ID,
                                                 EDGE_APP_PROFILE_ID)
            mock_del_binding.assert_called_with(self.context.session,
                                                LB_ID, LISTENER_ID)
            mock_successful_completion = (
                self.lbv2_driver.listener.successful_completion)
            mock_successful_completion.assert_called_with(self.context,
                                                          self.listener,
                                                          delete=True)


class TestEdgeLbaasV2Pool(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2Pool, self).setUp()

    @property
    def _tested_entity(self):
        return 'pool'

    def test_create(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_listener_binding'
                               ) as mock_get_listener_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                              ) as mock_get_lb_binding, \
            mock.patch.object(self.edge_driver.vcns, 'create_pool'
                              ) as mock_create_pool, \
            mock.patch.object(nsxv_db, 'add_nsxv_lbaas_pool_binding'
                              ) as mock_add_binding, \
            mock.patch.object(self.edge_driver.vcns, 'update_vip'
                              ) as mock_upd_vip:
            mock_get_listener_binding.return_value = LISTENER_BINDING
            mock_get_lb_binding.return_value = LB_BINDING
            mock_create_pool.return_value = (
                {'location': 'x/' + EDGE_POOL_ID}, None)

            self.edge_driver.pool.create(self.context, self.pool)

            mock_create_pool.assert_called_with(LB_EDGE_ID,
                                                EDGE_POOL_DEF.copy())
            mock_add_binding.assert_called_with(self.context.session,
                                                LB_ID, POOL_ID, EDGE_POOL_ID)
            edge_vip_def = EDGE_VIP_DEF.copy()
            edge_vip_def['defaultPoolId'] = EDGE_POOL_ID
            mock_upd_vip.assert_called_with(LB_EDGE_ID, EDGE_VIP_ID,
                                            edge_vip_def)
            mock_successful_completion = (
                self.lbv2_driver.pool.successful_completion)
            mock_successful_completion.assert_called_with(self.context,
                                                          self.pool)

    def test_update(self):
        new_pool = lb_models.Pool(POOL_ID, LB_TENANT_ID, 'pool-name', '',
                                  None, 'HTTP', 'LEAST_CONNECTIONS',
                                  listener=self.listener)
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding,\
            mock.patch.object(self.edge_driver.vcns, 'update_pool'
                              ) as mock_upd_pool:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING

            self.edge_driver.pool.update(self.context, self.pool, new_pool)

            edge_pool_def = EDGE_POOL_DEF.copy()
            edge_pool_def['algorithm'] = 'leastconn'
            mock_upd_pool.assert_called_with(
                LB_EDGE_ID, EDGE_POOL_ID, edge_pool_def)
            mock_successful_completion = (
                self.lbv2_driver.pool.successful_completion)
            mock_successful_completion.assert_called_with(self.context,
                                                          new_pool)

    def test_delete(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding,\
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_listener_binding'
                              ) as mock_get_listener_binding, \
            mock.patch.object(self.edge_driver.vcns, 'update_vip'
                              ) as mock_upd_vip, \
            mock.patch.object(self.edge_driver.vcns, 'delete_pool'
                              ) as mock_del_pool, \
            mock.patch.object(nsxv_db, 'del_nsxv_lbaas_pool_binding'
                              ) as mock_del_binding:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            mock_get_listener_binding.return_value = LISTENER_BINDING

            self.edge_driver.pool.delete(self.context, self.pool)

            mock_upd_vip.assert_called_with(LB_EDGE_ID, EDGE_VIP_ID,
                                            EDGE_VIP_DEF)
            mock_del_pool.assert_called_with(LB_EDGE_ID, EDGE_POOL_ID)
            mock_del_binding.assert_called_with(
                self.context.session, LB_ID, POOL_ID)
            mock_successful_completion = (
                self.lbv2_driver.pool.successful_completion)
            mock_successful_completion.assert_called_with(self.context,
                                                          self.pool,
                                                          delete=True)


class TestEdgeLbaasV2Member(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2Member, self).setUp()

    @property
    def _tested_entity(self):
        return 'member'

    def test_create(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding, \
            mock.patch.object(self.edge_driver.vcns, 'get_pool'
                              ) as mock_get_pool, \
            mock.patch.object(self.edge_driver.vcns, 'update_pool'
                              ) as mock_update_pool, \
            mock.patch.object(self.edge_driver.member,
                              '_get_lbaas_fw_section_id'
                              ) as mock_get_sect, \
            mock.patch.object(lb_common, 'update_pool_fw_rule'
                              ) as mock_upd_fw:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            mock_get_pool.return_value = (None, EDGE_POOL_DEF.copy())
            mock_get_sect.return_value = POOL_FW_SECT

            self.edge_driver.member.create(self.context, self.member)

            edge_pool_def = EDGE_POOL_DEF.copy()
            edge_pool_def['member'] = [EDGE_MEMBER_DEF]
            mock_update_pool.assert_called_with(
                LB_EDGE_ID, EDGE_POOL_ID, edge_pool_def)
            mock_upd_fw.assert_called_with(self.edge_driver.vcns, POOL_ID,
                                           LB_EDGE_ID, POOL_FW_SECT,
                                           [MEMBER_ADDRESS])
            mock_successful_completion = (
                self.lbv2_driver.member.successful_completion)
            mock_successful_completion.assert_called_with(self.context,
                                                          self.member)

    def test_update(self):
        new_member = lb_models.Member(MEMBER_ID, LB_TENANT_ID, POOL_ID,
                                      MEMBER_ADDRESS, 8000, 1, True,
                                      pool=self.pool)
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding, \
            mock.patch.object(self.edge_driver.vcns, 'get_pool'
                              ) as mock_get_pool, \
            mock.patch.object(self.edge_driver.vcns, 'update_pool'
                              ) as mock_update_pool:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            edge_pool_def = EDGE_POOL_DEF.copy()
            edge_pool_def['member'] = [EDGE_MEMBER_DEF]
            mock_get_pool.return_value = (None, edge_pool_def)

            self.edge_driver.member.update(self.context, self.member,
                                           new_member)

            edge_member_def = EDGE_MEMBER_DEF.copy()
            edge_member_def['port'] = 8000
            edge_member_def['monitorPort'] = 8000
            edge_member_def['condition'] = 'enabled'
            edge_pool_def['member'] = [edge_member_def]
            mock_update_pool.assert_called_with(
                LB_EDGE_ID, EDGE_POOL_ID, edge_pool_def)
            mock_successful_completion = (
                self.lbv2_driver.member.successful_completion)
            mock_successful_completion.assert_called_with(self.context,
                                                          new_member)

    def test_delete(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding, \
            mock.patch.object(self.edge_driver.vcns, 'get_pool'
                              ) as mock_get_pool, \
            mock.patch.object(self.edge_driver.vcns, 'update_pool'
                              ) as mock_update_pool:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            edge_pool_def = EDGE_POOL_DEF.copy()
            edge_pool_def['member'] = [EDGE_MEMBER_DEF]
            mock_get_pool.return_value = (None, edge_pool_def)

            self.edge_driver.member.delete(self.context, self.member)

            edge_pool_def['member'] = []
            mock_update_pool.assert_called_with(
                LB_EDGE_ID, EDGE_POOL_ID, edge_pool_def)
            mock_successful_completion = (
                self.lbv2_driver.member.successful_completion)
            mock_successful_completion.assert_called_with(self.context,
                                                          self.member,
                                                          delete=True)


class TestEdgeLbaasV2HealthMonitor(BaseTestEdgeLbaasV2):
    def setUp(self):
        super(TestEdgeLbaasV2HealthMonitor, self).setUp()

    @property
    def _tested_entity(self):
        return 'health_monitor'

    def test_create(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_monitor_binding'
                              ) as mock_get_mon_binding, \
            mock.patch.object(self.edge_driver.vcns, 'create_health_monitor'
                              ) as mock_create_hm, \
            mock.patch.object(nsxv_db, 'add_nsxv_lbaas_monitor_binding'
                              ) as mock_add_hm_binding, \
            mock.patch.object(self.edge_driver.vcns, 'get_pool'
                              ) as mock_get_pool, \
            mock.patch.object(self.edge_driver.vcns, 'update_pool'
                              ) as mock_update_pool:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            mock_get_mon_binding.return_value = None
            mock_create_hm.return_value = (
                {'location': 'x/' + EDGE_HM_ID}, None)
            mock_get_pool.return_value = (None, EDGE_POOL_DEF.copy())

            self.edge_driver.healthmonitor.create(self.context, self.hm)

            mock_create_hm.assert_called_with(LB_EDGE_ID, EDGE_HM_DEF)
            mock_add_hm_binding.assert_called_with(
                self.context.session, LB_ID, POOL_ID, HM_ID, LB_EDGE_ID,
                EDGE_HM_ID)
            edge_pool_def = EDGE_POOL_DEF.copy()
            edge_pool_def['monitorId'] = [EDGE_HM_ID]
            mock_update_pool.assert_called_with(
                LB_EDGE_ID, EDGE_POOL_ID, edge_pool_def)
            mock_successful_completion = (
                self.lbv2_driver.health_monitor.successful_completion)
            mock_successful_completion.assert_called_with(self.context,
                                                          self.hm)

    def test_update(self):
        new_hm = lb_models.HealthMonitor(HM_ID, LB_TENANT_ID, 'PING', 3, 3,
                                         3, pool=self.pool)

        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_monitor_binding'
                              ) as mock_get_mon_binding, \
            mock.patch.object(self.edge_driver.vcns, 'update_health_monitor'
                              ) as mock_upd_hm:
            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            mock_get_mon_binding.return_value = HM_BINDING

            self.edge_driver.healthmonitor.update(
                self.context, self.hm, new_hm)

            edge_hm_def = EDGE_HM_DEF.copy()
            edge_hm_def['maxRetries'] = 3
            mock_upd_hm.assert_called_with(LB_EDGE_ID, EDGE_HM_ID, edge_hm_def)
            mock_successful_completion = (
                self.lbv2_driver.health_monitor.successful_completion)
            mock_successful_completion.assert_called_with(self.context,
                                                          new_hm)

    def test_delete(self):
        with mock.patch.object(nsxv_db, 'get_nsxv_lbaas_loadbalancer_binding'
                               ) as mock_get_lb_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_pool_binding'
                              ) as mock_get_pool_binding, \
            mock.patch.object(nsxv_db, 'get_nsxv_lbaas_monitor_binding'
                              ) as mock_get_mon_binding, \
            mock.patch.object(self.edge_driver.vcns, 'delete_health_monitor'
                              ) as mock_del_hm, \
            mock.patch.object(self.edge_driver.vcns, 'get_pool'
                              ) as mock_get_pool, \
            mock.patch.object(self.edge_driver.vcns, 'update_pool'
                              ) as mock_update_pool, \
            mock.patch.object(nsxv_db, 'del_nsxv_lbaas_monitor_binding'
                              ) as mock_del_binding:

            mock_get_lb_binding.return_value = LB_BINDING
            mock_get_pool_binding.return_value = POOL_BINDING
            mock_get_mon_binding.return_value = HM_BINDING
            edge_pool_def = EDGE_POOL_DEF.copy()
            edge_pool_def['monitorId'] = [EDGE_HM_ID]
            mock_get_pool.return_value = (None, edge_pool_def)

            self.edge_driver.healthmonitor.delete(
                self.context, self.hm)

            mock_del_hm.assert_called_with(LB_EDGE_ID, EDGE_HM_ID)
            edge_pool_def['monitorId'] = []
            mock_update_pool.assert_called_with(
                LB_EDGE_ID, EDGE_POOL_ID, edge_pool_def)
            mock_del_binding.assert_called_with(self.context.session, LB_ID,
                                                POOL_ID, HM_ID, LB_EDGE_ID)
            mock_successful_completion = (
                self.lbv2_driver.health_monitor.successful_completion)
            mock_successful_completion.assert_called_with(self.context,
                                                          self.hm,
                                                          delete=True)
