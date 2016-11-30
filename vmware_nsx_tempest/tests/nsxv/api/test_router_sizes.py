# Copyright 2016 VMware Inc
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

import re
import time

from oslo_log import log as logging

from tempest.api.network import base_routers as base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.services import network as net_clients
from tempest import test
from vmware_nsx_tempest.services import nsxv_client

CONF = config.CONF
LOG = logging.getLogger(__name__)
ROUTER_SIZE = ('compact', 'large', 'xlarge', 'quadlarge')


class RouterSizeBaseTest(base.BaseRouterTest):
    """Base class to test creating routers with different router sizes:

    NSX-v allows exclusive router to be created with one of ROUTER_SIZE.
    Starts with VIO-3.0 it can update its router_size after created.

    tempest internally uses urllib3 and by default it will retry very 60
    seconds. However this retry mechanism causes bug#1716696.

    A better solution is to change request's retry-time so it will not
    cause neutront keep creating routers while router was not created
    in time.

    Methods should be used to change retry-time are:

       create_exclusive_router & change_router_size

       The retry-time is http_timeout in request.__init__() and is
       defined by CONF.nsxv.create_router_http_timeout.
    """

    @classmethod
    def skip_checks(cls):
        super(RouterSizeBaseTest, cls).skip_checks()
        if not test.is_extension_enabled('nsxv-router-type', 'network'):
            msg = "router-type extension is not enabled"
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(RouterSizeBaseTest, cls).setup_clients()

    @classmethod
    def resource_setup(cls):
        super(RouterSizeBaseTest, cls).resource_setup()
        cls.tenant_cidr = (CONF.network.project_network_cidr
                           if cls._ip_version == 4 else
                           CONF.network.project_network_v6_cidr)
        manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                               CONF.nsxv.manager_uri).group(0)
        cls.vsm = nsxv_client.VSMClient(
            manager_ip, CONF.nsxv.user, CONF.nsxv.password)

    def setUp(self):
        super(RouterSizeBaseTest, self).setUp()
        params = {'build_interval': self.routers_client.build_interval,
                  'build_timeout': self.routers_client.build_timeout}
        http_timeout = CONF.nsxv.create_router_http_timeout
        self.router_sizes_client = net_clients.RoutersClient(
            self.routers_client.auth_provider,
            self.routers_client.service,
            self.routers_client.region,
            self.routers_client.endpoint_type,
            http_timeout=http_timeout,
            **params)

    def create_exclusive_router(self, router_size):
        name = data_utils.rand_name('rtr1-%s' % router_size)
        LOG.debug("create router with size=%s", router_size)
        ext_gw_info = dict(
            network_id=CONF.network.public_network_id)
        rtr_cfg = dict(
            name=name, admin_state_up=False,
            external_gateway_info=ext_gw_info,
            router_type='exclusive',
            router_size=router_size)
        router = self.router_sizes_client.create_router(**rtr_cfg)
        router = router.get('router', router)
        self.routers.append(router)
        self.assertEqual(router['name'], name)
        self.check_router_nsx_name(router, router_size)
        return router

    def change_router_size(self, router, new_router_size):
        LOG.debug("update router to size=%s", new_router_size)
        update_router = self.router_sizes_client.update_router(
            router['id'], router_size=new_router_size)['router']
        self.assertEqual(update_router['router_size'], new_router_size)
        self.check_router_nsx_name(update_router, new_router_size)
        return router

    def check_router_nsx_name(self, router, router_size=None):
        router_nsxv_name = self.get_router_nsx_name(router)
        exc_edge = self.vsm.get_edge(router_nsxv_name)
        self.assertTrue(exc_edge is not None)
        self.assertEqual(exc_edge['edgeType'], 'gatewayServices')
        if router_size:
            edge_type = exc_edge['appliancesSummary']['applianceSize']
            LOG.debug("check router size at backend is %s", router_size)
            self.assertEqual(edge_type, router_size)
        return router_nsxv_name

    def get_router_nsx_name(self, router):
        router_nsxv_name = '%s-%s' % (router['name'], router['id'])
        return router_nsxv_name

    def do_create_update_delete_router_with_size(self,
                                                 router_size,
                                                 del_waitfor=10.0,
                                                 del_interval=1.5):
        router = self.create_exclusive_router(router_size)
        updated_name = 'updated-' + router['name']
        update_router = self.router_sizes_client.update_router(
            router['id'], name=updated_name)['router']
        self.assertEqual(update_router['name'], updated_name)
        # change router name, the backend also change
        router = self.router_sizes_client.show_router(
            router['id'])['router']
        nsxv_edge_name = self.check_router_nsx_name(router, router_size)
        # Delete the exclusive router and verify it has been deleted
        # from nsxv backend
        self.router_sizes_client.delete_router(router['id'])
        list_body = self.router_sizes_client.list_routers()
        routers_list = [r['id'] for r in list_body['routers']]
        self.assertNotIn(router['id'], routers_list)
        wait_till = time.time() + del_waitfor
        while (time.time() < wait_till):
            try:
                self.assertIsNone(self.vsm.get_edge(nsxv_edge_name))
                return
            except Exception:
                time.sleep(del_interval)
        # last try. Fail if nesx_edge still exists
        fail_msg = ("%s router nsxv_edge[%s] still exists after %s seconds." %
                    (router_size, nsxv_edge_name, del_waitfor))
        self.assertEqual(self.vsm.get_edge(nsxv_edge_name), None, fail_msg)

    def do_router_size_change_test(self, router_size, new_router_size_list):
        router = self.create_exclusive_router(router_size)
        for new_router_size in new_router_size_list:
            self.change_router_size(router, new_router_size)


class CompactRouterTest(RouterSizeBaseTest):
    @test.attr(type='nsxv')
    @test.idempotent_id('d75fbcd5-c8cb-49ea-a868-ada12fd8c87f')
    def test_create_update_delete_compact_router(self):
        self.do_create_update_delete_router_with_size('compact')


class LargeRouterTest(RouterSizeBaseTest):
    @test.attr(type='nsxv')
    @test.idempotent_id('da00c74f-81e6-4ef9-8aca-8e0345b376e9')
    def test_create_update_delete_large_router(self):
        self.do_create_update_delete_router_with_size('large', 20.0)


class XlargeRouterTest(RouterSizeBaseTest):
    @test.attr(type='nsxv')
    @test.idempotent_id('091dad07-6044-4ca3-b16c-54a3ef92254b')
    def test_create_update_delete_xlarge_router(self):
        self.do_create_update_delete_router_with_size('xlarge', 20.0)


class QuadlargeRouterTest(RouterSizeBaseTest):
    @test.attr(type='nsxv')
    @test.idempotent_id('0f69bf8a-4b06-47ac-a3f7-eedba95fd395')
    def test_create_update_delete_quadlarge_router(self):
        self.do_create_update_delete_router_with_size('quadlarge', 30.0)


class RouterSizeChangeTest(RouterSizeBaseTest):
    @test.idempotent_id('3201b0a9-702c-46cf-8512-f166a6ea5109')
    def test_router_size_1sizeup_change(self):
        self.do_router_size_change_test(
            'compact',
            ('large', 'xlarge', 'quadlarge'))

    @test.idempotent_id('c7ee9f78-4938-4bdd-b39c-1d736d41a84b')
    def test_router_size_outofseq_change(self):
        self.do_router_size_change_test(
            "large",
            ('quadlarge', 'compact', 'xlarge', 'large'))
