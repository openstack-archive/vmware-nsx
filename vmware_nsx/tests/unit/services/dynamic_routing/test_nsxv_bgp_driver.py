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
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory

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
        self.plugin = directory.get_plugin()
        self.l3plugin = self.plugin
        self.plugin.init_is_complete = True
        self.context = context.get_admin_context()

    @contextlib.contextmanager
    def esg_bgp_peer(self, esg_id):
        data = {'name': '',
                'peer_ip': '192.168.1.10',
                'remote_as': '65000',
                'esg_id': esg_id,
                'auth_type': 'none',
                'password': '',
                'tenant_id': ''}
        bgp_peer = self.bgp_plugin.create_bgp_peer(self.context,
                                                   {'bgp_peer': data})
        yield bgp_peer
        self.bgp_plugin.delete_bgp_peer(self.context, bgp_peer['id'])

    def test_create_v6_bgp_speaker(self):
        fake_bgp_speaker = {
            "bgp_speaker": {
                "ip_version": 6,
                "local_as": "1000",
                "name": "bgp-speaker"
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
                "peer_ip": "fc00::/7"
            }
        }
        self.assertRaises(n_exc.InvalidInput,
                          self.bgp_plugin.create_bgp_peer,
                          self.context, fake_bgp_peer)

    def test_bgp_peer_esg_id(self):
        edge_id = 'edge-123'
        with mock.patch.object(bgp_driver.NSXvBgpDriver,
                               '_validate_bgp_configuration_on_peer_esg',
                               side_effect=None):
            with self.esg_bgp_peer(esg_id='edge-123') as esg_peer:
                self.assertEqual(edge_id, esg_peer['esg_id'])

                peer_id = esg_peer['id']
                bgp_peer = self.bgp_plugin.get_bgp_peer(self.context, peer_id)
                self.assertEqual(edge_id, bgp_peer['esg_id'])

    def test_create_bgp_peer_md5_auth_no_password(self):
        # TODO(roeyc): Test requires a minor fix in base class.
        pass

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
        # REVISIT(roeyc): Base class creates subnets with gateway-ip on
        # external network, NSXv plugin requires that gateway-ip is not
        # specified for subnets in BGP backed networks.
        pass

    def test_get_ipv4_tenant_subnet_routes_by_bgp_speaker_dvr_router(self):
        # REVISIT(roeyc): Base class creates subnets with gateway-ip on
        # external network, NSXv plugin requires that gateway-ip is not
        # specified for subnets in BGP backed networks.
        pass

    def test_get_ipv4_tenant_subnet_routes_by_bgp_speaker_ipv4(self):
        # REVISIT(roeyc): Base class creates subnets with gateway-ip on
        # external network, NSXv plugin requires that gateway-ip is not
        # specified for subnets in BGP backed networks.
        pass

    def test_get_routes_by_bgp_speaker_binding(self):
        # REVISIT(roeyc): Base class creates subnets with gateway-ip on
        # external network, NSXv plugin requires that gateway-ip is not
        # specified for subnets in BGP backed networks.
        pass

    def test_get_routes_by_binding_network(self):
        # REVISIT(roeyc): Base class creates subnets with gateway-ip on
        # external network, NSXv plugin requires that gateway-ip is not
        # specified for subnets in BGP backed networks.
        pass

    def test__get_dvr_fip_host_routes_by_binding(self):
        pass

    def test__get_dvr_fip_host_routes_by_router(self):
        pass

    def test__get_fip_next_hop_dvr(self):
        pass

    def test__get_fip_next_hop_legacy(self):
        pass

    def test__get_routes_by_router_with_fip(self):
        pass

    def test_get_routes_by_bgp_speaker_binding_with_fip(self):
        pass

    def test_get_routes_by_bgp_speaker_id_with_fip(self):
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
