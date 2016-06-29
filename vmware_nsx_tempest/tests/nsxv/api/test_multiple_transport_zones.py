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
import six

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

import base_provider as base
from tempest import config
from tempest import test
from vmware_nsx_tempest.services import nsxv_client

CONF = config.CONF


class MultipleTransportZonesTest(base.BaseAdminNetworkTest):
    """Validate that NSX-v plugin can support multiple transport zones.

    The test environment must at least have 1 additional TZ created.
    The default number of TZs used to test, include the default TZ is 3.
    However, all MTZ tests can run with 2 TZs in the testbed.
    """
    @classmethod
    def skip_checks(cls):
        super(MultipleTransportZonesTest, cls).skip_checks()
        if not test.is_extension_enabled('provider', 'network'):
            msg = "provider extension is not enabled"
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(MultipleTransportZonesTest, cls).setup_clients()

    @classmethod
    def resource_setup(cls):
        super(MultipleTransportZonesTest, cls).resource_setup()
        manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                               CONF.nsxv.manager_uri).group(0)
        cls.vsm = nsxv_client.VSMClient(
            manager_ip, CONF.nsxv.user, CONF.nsxv.password)
        cls.nsxv_scope_ids = cls.get_all_scope_id_list(with_default_scope=True)
        if len(cls.nsxv_scope_ids) < 2:
            msg = "Only one transport zone deployed. Need at least 2."
            raise cls.skipException(msg)
        cls.provider_network_type = getattr(CONF.nsxv,
                                            "provider_network_type",
                                            'vxlan')
        cls.MAX_MTZ = CONF.nsxv.max_mtz

    @classmethod
    def create_project_network_subnet(cls, name_prefix='mtz-project'):
        network_name = data_utils.rand_name(name_prefix)
        resp = cls.create_network(client=cls.networks_client,
                                  name=network_name)
        network = resp.get('network', resp)
        cls.tenant_net = [None, network]
        resp = cls.create_subnet(network,
                                 name=network_name,
                                 client=cls.subnets_client)
        subnet = resp.get('subnet', resp)
        return (network['id'], (None, network, subnet))

    @classmethod
    def get_all_scope_id_list(cls, with_default_scope=False):
        """return all scope IDs w/wo the default scope defined in NSX."""
        scopes = cls.vsm.get_all_vdn_scopes()
        scope_id_list = [x['objectId'] for x in scopes]
        if with_default_scope:
            return scope_id_list
        try:
            scope_id_list.remove(CONF.nsxv.vdn_scope_id)
        except Exception:
            pass
        return scope_id_list

    def create_network_subnet(self, scope_id, cidr=None, cidr_offset=0):
        network_name = data_utils.rand_name('mtz-network-')
        create_kwargs = {'provider:network_type': self.provider_network_type,
                         'provider:physical_network': scope_id}
        resp = self.create_network(network_name, **create_kwargs)
        network = resp.get('network', resp)
        net_id = network['id']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_network, net_id)
        self.assertEqual(scope_id,
                         network['provider:physical_network'])
        resp = self.create_subnet(network,
                                  name=network_name,
                                  cidr=cidr,
                                  cidr_offset=cidr_offset)
        subnet = resp.get('subnet', resp)
        resp = self.show_network(net_id)
        s_network = resp.get('network', resp)
        net_subnets = s_network['subnets']
        self.assertIn(subnet['id'], net_subnets)
        lswitch_list = self.vsm.get_all_logical_switches(scope_id)
        lswitch_list = [x for x in lswitch_list if x['name'] == net_id]
        msg = ("network=%s is not configured by specified vdn_scope_id=%s"
               % (net_id, scope_id))
        self.assertTrue(len(lswitch_list) == 1, msg=msg)
        return (net_id, s_network, subnet)

    def delete_networks(self, nets):
        for net_id in six.iterkeys(nets):
            self.delete_network(net_id)

    def check_update_network(self, network):
        new_name = network['name'] + "-2nd"
        self.update_network(network['id'], name=new_name)
        resp = self.show_network(network['id'])
        s_network = resp.get('network', resp)
        self.assertEqual(new_name, s_network['name'])

    def check_update_subnet(self, subnet):
        new_name = subnet['name'] + "-2nd"
        self.update_subnet(subnet['id'], name=new_name)
        resp = self.show_subnet(subnet['id'])['subnet']
        s_subnet = resp.get('subnet', resp)
        self.assertEqual(new_name, s_subnet['name'])

    def create_show_update_delete_mtz_network_subnet(self, s_id):
        net_id, network, subnet = self.create_network_subnet(s_id)
        self.check_update_network(network)
        self.check_update_subnet(subnet)
        self.delete_network(net_id)

    def create_router_by_type(self, router_type, name=None, **kwargs):
        routers_client = self.admin_manager.routers_client
        router_name = name or data_utils.rand_name('mtz-')
        create_kwargs = dict(name=router_name, external_gateway_info={
            "network_id": CONF.network.public_network_id})
        if router_type in ('shared', 'exclusive'):
            create_kwargs['router_type'] = router_type
        elif router_type in ('distributed'):
            create_kwargs['distributed'] = True
        kwargs.update(create_kwargs)
        router = routers_client.create_router(**kwargs)
        router = router['router'] if 'router' in router else router
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        routers_client.delete_router, router['id'])
        self.assertEqual(router['name'], router_name)
        return (routers_client, router)

    def create_router_and_add_interfaces(self, router_type, nets):
        (routers_client, router) = self.create_router_by_type(router_type)
        if router_type == 'exclusive':
            router_nsxv_name = '%s-%s' % (router['name'], router['id'])
            exc_edge = self.vsm.get_edge(router_nsxv_name)
            self.assertTrue(exc_edge is not None)
            self.assertEqual(exc_edge['edgeType'], 'gatewayServices')
        for net_id, (s_id, network, subnet) in six.iteritems(nets):
            # register to cleanup before adding interfaces so interfaces
            # and router can be deleted if test is aborted.
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                routers_client.remove_router_interface,
                router['id'], subnet_id=subnet['id'])
            routers_client.add_router_interface(
                router['id'], subnet_id=subnet['id'])
        return router

    def clear_router_gateway_and_interfaces(self, router, nets):
        routers_client = self.admin_manager.routers_client
        routers_client.update_router(router['id'],
                                    external_gateway_info=dict())
        for net_id, (s_id, network, subnet) in six.iteritems(nets):
            try:
                routers_client.remove_router_interface(
                    router['id'], subnet_id=subnet['id'])
            except Exception:
                pass

    def _test_router_with_multiple_mtz_networks(self, router_type):
        """test router attached with multiple TZs."""
        scope_id_list = self.get_all_scope_id_list(with_default_scope=True)
        nets = {}
        for cidr_step in range(0, self.MAX_MTZ):
            s_id = scope_id_list[cidr_step % len(scope_id_list)]
            net_id, network, subnet = self.create_network_subnet(
                s_id, cidr_offset=(cidr_step + 2))
            nets[net_id] = (s_id, network, subnet)
        router = self.create_router_and_add_interfaces(router_type, nets)
        self.clear_router_gateway_and_interfaces(router, nets)

    def _test_router_with_network_and_mtz_networks(self, router_type):
        """test router attached with multiple TZs and one tenant network."""
        scope_id_list = self.get_all_scope_id_list(with_default_scope=True)
        nets = {}
        net_id, net_info = self.create_project_network_subnet('mtz-tenant')
        nets[net_id] = net_info
        for cidr_step in range(0, self.MAX_MTZ):
            s_id = scope_id_list[cidr_step % len(scope_id_list)]
            net_id, network, subnet = self.create_network_subnet(
                s_id, cidr_offset=(cidr_step + 2))
            nets[net_id] = (s_id, network, subnet)
        router = self.create_router_and_add_interfaces(router_type, nets)
        self.clear_router_gateway_and_interfaces(router, nets)

    @test.idempotent_id('39bc7909-912c-4e16-8246-773ae6a40ba4')
    def test_mtz_network_crud_operations(self):
        scope_id_list = self.get_all_scope_id_list(with_default_scope=False)
        s_id = scope_id_list[0]
        self.create_show_update_delete_mtz_network_subnet(s_id)

    @test.idempotent_id('4e1717d6-df39-4539-99da-df23814cfe14')
    def test_mtz_overlay_network(self):
        """overlay subnets with the same TZ"""
        scope_id_list = self.get_all_scope_id_list(with_default_scope=True)
        s_id = scope_id_list[0]
        nets = {}
        for cidr_step in range(1, self.MAX_MTZ):
            net_id, network, subnet = self.create_network_subnet(s_id)
            nets[net_id] = (s_id, network, subnet)
        self.delete_networks(nets)

    @test.idempotent_id('6ecf67fc-4396-41d9-9d84-9d8c936dcb8f')
    def test_multiple_mtz_overlay_network(self):
        """overlay subnets from multiple TZs."""
        scope_id_list = self.get_all_scope_id_list(with_default_scope=True)
        nets = {}
        cidr_step = 0
        for s_id in scope_id_list:
            net_id, network, subnet = self.create_network_subnet(s_id)
            nets[net_id] = (s_id, network, subnet)
            net_id, network, subnet = self.create_network_subnet(s_id)
            nets[net_id] = (s_id, network, subnet)
            cidr_step += 1
            if cidr_step < self.MAX_MTZ:
                break
        self.delete_networks(nets)

    @test.idempotent_id('e7e0fc6c-41fd-44bc-b9b1-4501ce618738')
    def test_mtz_non_overlay_network(self):
        """non-overlay subnets from one TZ."""
        scope_id_list = self.get_all_scope_id_list(with_default_scope=False)
        s_id = scope_id_list[0]
        nets = {}
        for cidr_step in range(0, self.MAX_MTZ):
            net_id, network, subnet = self.create_network_subnet(
                s_id, cidr_offset=(cidr_step + 1))
            nets[net_id] = (s_id, network, subnet)
        self.delete_networks(nets)

    @test.idempotent_id('b1cb5815-6380-421f-beef-ae3cb148cef4')
    def test_multiple_mtz_non_overlay_network(self):
        """non-overlay subnets from multiple TZs."""
        scope_id_list = self.get_all_scope_id_list(with_default_scope=True)
        nets = {}
        for cidr_step in range(0, self.MAX_MTZ):
            s_id = scope_id_list[cidr_step % len(scope_id_list)]
            net_id, network, subnet = self.create_network_subnet(
                s_id, cidr_offset=cidr_step)
            nets[net_id] = (s_id, network, subnet)
        self.delete_networks(nets)

    @test.idempotent_id('006a1a4b-4b63-4663-8baa-affe5df62b11')
    def test_shared_router_with_multiple_mtz_networks(self):
        """shared router attached with multiple TZs."""
        self._test_router_with_multiple_mtz_networks(
            router_type='shared')

    @test.idempotent_id('b160d1dc-0332-4d1a-b2a0-c11f57fe4dd9')
    def test_exclusive_router_with_multiple_mtz_networks(self):
        """exclusive router attached with multiple TZs."""
        self._test_router_with_multiple_mtz_networks(
            router_type='exclusive')

    @decorators.skip_because(bug="1592174")
    @test.idempotent_id('2c46290c-8a08-4037-aada-f96fd34b3260')
    def test_distributed_router_with_multiple_mtz_networks(self):
        """exclusive router attached with multiple TZs."""
        self._test_router_with_multiple_mtz_networks(
            router_type='distributed')

    @test.idempotent_id('be8f7320-2246-43f3-a826-768f763c9bd0')
    def test_shared_router_with_network_and_mtz_networks(self):
        """router attached with multiple TZs and one tenant network."""
        self._test_router_with_network_and_mtz_networks(
            router_type='shared')

    @test.idempotent_id('3cb27410-67e2-4e82-95c7-3dbbe9a8c64b')
    def test_exclusive_router_with_network_and_mtz_networks(self):
        """router attached with multiple TZs and one tenant network."""
        self._test_router_with_network_and_mtz_networks(
            router_type='exclusive')

    @decorators.skip_because(bug="1592174")
    @test.idempotent_id('e7c066d5-c2f1-41e7-bc86-9b6295461903')
    def test_distributed_router_with_network_and_mtz_networks(self):
        """router attached with multiple TZs and one tenant network."""
        self._test_router_with_network_and_mtz_networks(
            router_type='distributed')
