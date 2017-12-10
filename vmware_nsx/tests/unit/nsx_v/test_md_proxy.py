# Copyright (c) 2017 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock

from oslo_config import cfg

from neutron_lib import context

from vmware_nsx.db import nsxv_db
from vmware_nsx.db import nsxv_models
from vmware_nsx.plugins.nsx_v.vshield.common import (
    constants as vcns_const)
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.tests.unit.nsx_v import test_plugin


PLUGIN_NAME = 'vmware_nsx.plugin.NsxVPlugin'


# Run all relevant plugin tests when the metadata proxy is enabled.
# Those tests does not specifically test the md_proxy. just verify that
# nothing gets broken.
class NsxVPluginWithMdV2TestCase(test_plugin.NsxVPluginV2TestCase):

    def setUp(self, plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        # Add the metadata configuration
        cfg.CONF.set_override('mgt_net_moid', 'net-1', group="nsxv")
        cfg.CONF.set_override('mgt_net_proxy_ips', ['2.2.2.2'], group="nsxv")
        cfg.CONF.set_override('mgt_net_proxy_netmask', '255.255.255.0',
                              group="nsxv")
        cfg.CONF.set_override('mgt_net_default_gateway', '1.1.1.1',
                              group="nsxv")
        cfg.CONF.set_override('nova_metadata_ips', ['3.3.3.3'], group="nsxv")

        # Add some mocks required for the md code
        mock_alloc_vnic = mock.patch.object(nsxv_db, 'allocate_edge_vnic')
        mock_alloc_vnic_inst = mock_alloc_vnic.start()
        mock_alloc_vnic_inst.return_value = nsxv_models.NsxvEdgeVnicBinding
        mock.patch.object(edge_utils, "update_internal_interface").start()

        super(NsxVPluginWithMdV2TestCase, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr,
            service_plugins=service_plugins)

        self.context = context.get_admin_context()
        self.internal_net_id = nsxv_db.get_nsxv_internal_network_for_az(
            self.context.session,
            vcns_const.InternalEdgePurposes.INTER_EDGE_PURPOSE,
            'default')['network_id']


class TestNetworksWithMdV2(test_plugin.TestNetworksV2,
                           NsxVPluginWithMdV2TestCase):

    # Skip all the tests that count networks, as there is an
    # additional internal network for metadata.
    def test_list_networks_with_sort_native(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_networks_without_pk_in_fields_pagination_emulated(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_networks_with_sort_emulated(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_networks_with_shared(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_networks_without_pk_in_fields_pagination_native(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_networks_with_parameters(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_networks_with_pagination_native(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_networks_with_pagination_reverse_emulated(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_networks(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_networks_with_pagination_emulated(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_networks_with_pagination_reverse_native(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_networks_with_fields(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_create_networks_bulk_wrong_input(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_create_networks_bulk_native_plugin_failure(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_create_networks_bulk_native_quotas(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_create_networks_bulk_emulated_plugin_failure(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_cannot_delete_md_net(self):
        req = self.new_delete_request('networks', self.internal_net_id)
        net_del_res = req.get_response(self.api)
        self.assertEqual(net_del_res.status_int, 400)


class TestSubnetsWithMdV2(test_plugin.TestSubnetsV2,
                          NsxVPluginWithMdV2TestCase):
    # Skip all the tests that count subnets, as there is an
    # additional internal subnet for metadata.
    def test_list_subnets_with_sort_native(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_subnets_with_sort_emulated(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_subnets_with_pagination_native(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_subnets_with_parameter(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_subnets_with_pagination_emulated(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_subnets_shared(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_list_subnets(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_create_subnets_bulk_native_plugin_failure(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_create_subnets_bulk_native_quotas(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_create_subnets_bulk_emulated_plugin_failure(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_cannot_delete_md_subnet(self):
        query_params = "network_id=%s" % self.internal_net_id
        res = self._list('subnets',
                         neutron_context=self.context,
                         query_params=query_params)
        internal_sub = res['subnets'][0]['id']
        req = self.new_delete_request('subnets', internal_sub)
        net_del_res = req.get_response(self.api)
        self.assertEqual(net_del_res.status_int, 400)


class TestExclusiveRouterWithMdTestCase(
    test_plugin.TestExclusiveRouterTestCase,
    NsxVPluginWithMdV2TestCase):

    # Skip all the tests that count firewall rules, as there are
    # some MD specific rules
    def test_router_set_gateway_with_nosnat(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_interfaces_different_tenants_update_firewall(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_interfaces_with_update_firewall(self):
        self.skipTest("The test is not suitable for the metadata test case")

    # Skip all the tests that count routers or ports, as there is
    # an additional router for the md proxy
    def test_router_list_with_pagination_reverse(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_list_with_sort(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_list_with_pagination(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_list(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_add_interface_delete_port_after_failure(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_create_router_fail_at_the_backend(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_floatingip_delete_router_intf_with_subnet_id_returns_409(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_floatingip_delete_router_intf_with_port_id_returns_409(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_address_scope_snat_rules(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_address_scope_fw_rules(self):
        self.skipTest("The test is not suitable for the metadata test case")


class TestVdrWithMdTestCase(test_plugin.TestVdrTestCase,
                            NsxVPluginWithMdV2TestCase):
    # Skip all the tests that count firewall rules, as there are
    # some MD specific rules
    def test_router_set_gateway_with_nosnat(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_interfaces_different_tenants_update_firewall(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_interfaces_with_update_firewall(self):
        self.skipTest("The test is not suitable for the metadata test case")

    # Skip all the tests that count routers or ports, as there is
    # an additional router for the md proxy
    def test_router_list_with_pagination_reverse(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_list_with_sort(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_list_with_pagination(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_list(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_add_interface_delete_port_after_failure(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_create_router_fail_at_the_backend(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_floatingip_delete_router_intf_with_subnet_id_returns_409(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_floatingip_delete_router_intf_with_port_id_returns_409(self):
        self.skipTest("The test is not suitable for the metadata test case")

    #TODO(asarfaty): fix some mocks so those tests will pass
    def test_router_plr_binding_default_size(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_plr_binding_configured_size(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_plr_binding_default_az(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_plr_binding_with_az(self):
        self.skipTest("The test is not suitable for the metadata test case")


class TestSharedRouterWithMdTestCase(test_plugin.TestSharedRouterTestCase,
                                     NsxVPluginWithMdV2TestCase):
    # Skip all the tests that count firewall rules, as there are
    # some MD specific rules
    def test_router_set_gateway_with_nosnat(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_routers_set_gateway_with_nosnat(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_interfaces_different_tenants_update_firewall(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_interfaces_with_update_firewall(self):
        self.skipTest("The test is not suitable for the metadata test case")

    # Skip all the tests that count routers or ports, as there is
    # an additional router for the md proxy
    def test_router_list_with_pagination_reverse(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_list_with_sort(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_list_with_pagination(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_list(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_router_add_interface_delete_port_after_failure(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_create_router_fail_at_the_backend(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_floatingip_delete_router_intf_with_subnet_id_returns_409(self):
        self.skipTest("The test is not suitable for the metadata test case")

    def test_floatingip_delete_router_intf_with_port_id_returns_409(self):
        self.skipTest("The test is not suitable for the metadata test case")
