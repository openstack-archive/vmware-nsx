# Copyright 2017 VMware, Inc.
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
import contextlib

import mock
from neutron.api import extensions
from neutron_dynamic_routing.db import bgp_db  # noqa
from neutron_dynamic_routing import extensions as dr_extensions
from neutron_dynamic_routing.extensions import bgp as ext_bgp
from neutron_dynamic_routing.tests.unit.db import test_bgp_db
from neutron_lib.api.definitions import address_scope
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory

from vmware_nsx.common import exceptions as exc
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.drivers import (
    shared_router_driver as router_driver)
from vmware_nsx.services.dynamic_routing import bgp_plugin
from vmware_nsx.services.dynamic_routing.nsx_v import driver as bgp_driver
from vmware_nsx.tests.unit.nsx_v import test_plugin

BGP_PLUGIN = 'vmware_nsx.services.dynamic_routing.bgp_plugin.NSXvBgpPlugin'


class TestNSXvBgpPlugin(test_plugin.NsxVPluginV2TestCase,
                        test_bgp_db.BgpTests):
    def setUp(self):
        extensions.append_api_extensions_path(dr_extensions.__path__)
        service_plugins = {ext_bgp.BGP_EXT_ALIAS: BGP_PLUGIN}
        super(TestNSXvBgpPlugin, self).setUp(service_plugins=service_plugins)
        self.bgp_plugin = bgp_plugin.NSXvBgpPlugin()
        self.nsxv_driver = self.bgp_plugin.drivers['nsx-v']
        self.nsxv_driver._validate_gateway_network = mock.Mock()
        self.nsxv_driver._validate_bgp_configuration_on_peer_esg = (
            mock.Mock())
        self.plugin = directory.get_plugin()
        self.l3plugin = self.plugin
        self.plugin.init_is_complete = True
        self.context = context.get_admin_context()
        self.project_id = 'dummy_project'

    @contextlib.contextmanager
    def gw_network(self, external=True, **kwargs):
        with super(TestNSXvBgpPlugin, self).gw_network(external=external,
                                                       **kwargs) as gw_net:
            if external:
                gw_net['network']['router:external'] = True
                gw_net['network'][address_scope.IPV4_ADDRESS_SCOPE] = True
            yield gw_net

    @contextlib.contextmanager
    def subnet(self, network=None, **kwargs):
        if network and network['network'].get('router:external'):
            kwargs['gateway_ip'] = None
            kwargs['enable_dhcp'] = False

        with super(TestNSXvBgpPlugin, self).subnet(network=network,
                                                   **kwargs) as sub:
            yield sub

    @contextlib.contextmanager
    def router(self, **kwargs):
        if 'external_gateway_info' in kwargs:
            kwargs['external_gateway_info']['enable_snat'] = False
        with super(TestNSXvBgpPlugin, self).router(**kwargs) as r:
            yield r

    @contextlib.contextmanager
    def esg_bgp_peer(self, esg_id):
        data = {'name': '',
                'peer_ip': '192.168.1.10',
                'remote_as': '65000',
                'esg_id': esg_id,
                'auth_type': 'none',
                'password': '',
                'tenant_id': self.project_id}
        bgp_peer = self.bgp_plugin.create_bgp_peer(self.context,
                                                   {'bgp_peer': data})
        yield bgp_peer
        self.bgp_plugin.delete_bgp_peer(self.context, bgp_peer['id'])

    @contextlib.contextmanager
    def bgp_speaker(self, ip_version, local_as, name='my-speaker',
                    advertise_fip_host_routes=True,
                    advertise_tenant_networks=True,
                    networks=None, peers=None):
        data = {'ip_version': ip_version,
                test_bgp_db.ADVERTISE_FIPS_KEY: advertise_fip_host_routes,
                'advertise_tenant_networks': advertise_tenant_networks,
                'local_as': local_as, 'name': name,
                'tenant_id': self.project_id}
        bgp_speaker = self.bgp_plugin.create_bgp_speaker(self.context,
                                                        {'bgp_speaker': data})
        bgp_speaker_id = bgp_speaker['id']

        if networks:
            for network_id in networks:
                self.bgp_plugin.add_gateway_network(
                                                   self.context,
                                                   bgp_speaker_id,
                                                   {'network_id': network_id})
        if peers:
            for peer_id in peers:
                self.bgp_plugin.add_bgp_peer(self.context, bgp_speaker_id,
                                             {'bgp_peer_id': peer_id})

        yield self.bgp_plugin.get_bgp_speaker(self.context, bgp_speaker_id)

    def test_get_external_networks_for_port_same_address_scope_v6(self):
        self.skipTest("IPv6 not supported by this plugin.")

    def test_get_external_networks_for_port_different_address_scope_v6(self):
        self.skipTest("IPv6 not supported by this plugin.")

    def test__get_dvr_fixed_ip_routes_by_bgp_speaker_same_scope(self):
        self.skipTest("DVR specific.")

    def test_get_external_networks_for_port_different_address_scope_v4(self):
        self.skipTest("DVR specific.")

    def test__get_dvr_fixed_ip_routes_by_bgp_speaker_different_scope(self):
        self.skipTest("DVR specific.")

    def test__get_dvr_fixed_ip_routes_by_bgp_speaker_no_scope(self):
        self.skipTest("DVR specific.")

    def test_create_v6_bgp_speaker(self):
        fake_bgp_speaker = {
            "bgp_speaker": {
                "ip_version": 6,
                "local_as": "1000",
                "name": "bgp-speaker",
                "tenant_id": self.project_id
            }
        }
        self.assertRaises(n_exc.InvalidInput,
                          self.bgp_plugin.create_bgp_speaker,
                          self.context, fake_bgp_speaker)

    def test_create_v6_bgp_peer(self):
        fake_bgp_peer = {
            "bgp_peer": {
                "auth_type": "none",
                "remote_as": "1000",
                "name": "bgp-peer",
                "peer_ip": "fc00::/7",
                "tenant_id": self.project_id
            }
        }
        self.assertRaises(n_exc.InvalidInput,
                          self.bgp_plugin.create_bgp_peer,
                          self.context, fake_bgp_peer)

    def test_bgp_peer_esg_id(self):
        edge_id = 'edge-123'
        with self.esg_bgp_peer(esg_id='edge-123') as esg_peer:
            self.assertEqual(edge_id, esg_peer['esg_id'])

            peer_id = esg_peer['id']
            bgp_peer = self.bgp_plugin.get_bgp_peer(self.context, peer_id)
            self.assertEqual(edge_id, bgp_peer['esg_id'])

    def test_create_bgp_peer_md5_auth_no_password(self):
        bgp_peer = {'bgp_peer':
                    {'auth_type': 'md5', 'password': None,
                     'peer_ip': '10.0.0.3',
                     'tenant_id': self.project_id}}
        self.assertRaises(ext_bgp.InvalidBgpPeerMd5Authentication,
                          self.bgp_plugin.create_bgp_peer,
                          self.context, bgp_peer)

    def test_add_non_external_gateway_network(self):
        self.nsxv_driver._validate_gateway_network = (
            bgp_driver.NSXvBgpDriver(
                self.bgp_plugin)._validate_gateway_network)
        with self.gw_network(external=False) as net,\
            self.subnetpool_with_address_scope(4,
                                               prefixes=['8.0.0.0/8']) as sp:
            network_id = net['network']['id']
            with self.bgp_speaker(sp['ip_version'], 1234) as speaker:
                self.assertRaises(exc.NsxBgpNetworkNotExternal,
                                  self.bgp_plugin.add_gateway_network,
                                  self.context, speaker['id'],
                                  {'network_id': network_id})

    @mock.patch.object(nsxv_db, 'get_nsxv_bgp_speaker_binding',
                       return_value={'bgp_identifier': '10.0.0.11'})
    def test_shared_router_on_gateway_clear(self, m1):
        with self.gw_network(external=True) as net,\
            self.subnetpool_with_address_scope(4,
                                               prefixes=['10.0.0.0/24']) as sp:
            with self.subnet(network=net,
                             subnetpool_id=sp['id']) as s1,\
                self.bgp_speaker(sp['ip_version'], 1234,
                                 networks=[net['network']['id']]):
                subnet_id = s1['subnet']['id']
                gw_info1 = {'network_id': net['network']['id'],
                            'external_fixed_ips': [{'ip_address': '10.0.0.11',
                                                    'subnet_id': subnet_id}]}
                gw_info2 = {'network_id': net['network']['id'],
                            'external_fixed_ips': [{'ip_address': '10.0.0.12',
                                                    'subnet_id': subnet_id}]}
                router_obj = router_driver.RouterSharedDriver(self.plugin)
                with mock.patch.object(self.plugin, '_find_router_driver',
                                       return_value=router_obj):
                    with self.router(external_gateway_info=gw_info1) as rtr1,\
                        self.router(external_gateway_info=gw_info2) as rtr2,\
                        mock.patch.object(
                            self.nsxv_driver, '_get_router_edge_info',
                            return_value=('edge-1', False)),\
                        mock.patch.object(
                            self.plugin.edge_manager,
                            'get_routers_on_same_edge',
                            return_value=[rtr1['id'], rtr2['id']]),\
                        mock.patch.object(
                            self.nsxv_driver,
                            '_update_edge_bgp_identifier') as up_bgp:
                        gw_clear = {u'router': {u'external_gateway_info': {}}}
                        self.plugin.update_router(self.context,
                                                  rtr1['id'],
                                                  gw_clear)
                        up_bgp.assert_called_once_with(mock.ANY,
                                                       mock.ANY,
                                                       mock.ANY,
                                                       '10.0.0.12')

    def test__bgp_speakers_for_gateway_network_by_ip_version(self):
        # REVISIT(roeyc): Base class test use ipv6 which is not supported.
        pass

    def test__bgp_speakers_for_gateway_network_by_ip_version_no_binding(self):
        # REVISIT(roeyc): Base class test use ipv6 which is not supported.
        pass

    def test__tenant_prefixes_by_router_no_gateway_port(self):
        # REVISIT(roeyc): Base class test use ipv6 which is not supported.
        pass

    def test_all_routes_by_bgp_speaker_different_tenant_address_scope(self):
        # REVISIT(roeyc): Base class test use ipv6 which is not supported.
        pass

    def test__get_address_scope_ids_for_bgp_speaker(self):
        pass

    def test__get_dvr_fip_host_routes_by_binding(self):
        pass

    def test__get_dvr_fip_host_routes_by_router(self):
        pass

    def test__get_fip_next_hop_dvr(self):
        pass

    def test__get_fip_next_hop_legacy(self):
        pass

    def test_get_routes_by_bgp_speaker_id_with_fip_dvr(self):
        pass

    def test_ha_router_fips_has_no_next_hop_to_fip_agent_gateway(self):
        pass

    def test_legacy_router_fips_has_no_next_hop_to_fip_agent_gateway(self):
        pass

    def test_floatingip_update_callback(self):
        pass

    def test_get_ipv6_tenant_subnet_routes_by_bgp_speaker_ipv6(self):
        pass

    def test_get_routes_by_bgp_speaker_id_with_fip(self):
        # base class tests uses no-snat router with floating ips
        self.skipTest('No SNAT with floating ips not supported')

    def test_get_routes_by_bgp_speaker_binding_with_fip(self):
        # base class tests uses no-snat router with floating ips
        self.skipTest('No SNAT with floating ips not supported')

    def test__get_routes_by_router_with_fip(self):
        # base class tests uses no-snat router with floating ips
        self.skipTest('No SNAT with floating ips not supported')

    def test_add_bgp_peer_with_bad_id(self):
            with self.subnetpool_with_address_scope(
                4, prefixes=['8.0.0.0/8']) as sp:
                with self.bgp_speaker(sp['ip_version'], 1234) as speaker:
                    self.assertRaises(ext_bgp.BgpPeerNotFound,
                                      self.bgp_plugin.add_bgp_peer,
                                      self.context,
                                      speaker['id'],
                                      {'bgp_peer_id': 'aaa'})
