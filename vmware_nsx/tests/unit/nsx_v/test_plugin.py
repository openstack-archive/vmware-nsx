# Copyright (c) 2012 OpenStack Foundation.
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

import contextlib
from eventlet import greenthread
import mock
import netaddr
from neutron.api.v2 import attributes
from neutron import context
from neutron.extensions import dvr as dist_router
from neutron.extensions import external_net
from neutron.extensions import l3
from neutron.extensions import l3_ext_gw_mode
from neutron.extensions import portbindings
from neutron.extensions import portsecurity as psec
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as secgrp
from neutron import manager
from neutron.plugins.common import constants as plugin_const
from neutron.tests.unit import _test_extension_portbindings as test_bindings
import neutron.tests.unit.db.test_allowedaddresspairs_db as test_addr_pair
import neutron.tests.unit.db.test_db_base_plugin_v2 as test_plugin
import neutron.tests.unit.extensions.test_l3 as test_l3_plugin
import neutron.tests.unit.extensions.test_l3_ext_gw_mode as test_ext_gw_mode
import neutron.tests.unit.extensions.test_portsecurity as test_psec
import neutron.tests.unit.extensions.test_securitygroup as ext_sg
from neutron.tests.unit import testlib_api
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_utils import uuidutils
import six
import webob.exc

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsxv_exc
from vmware_nsx.common import nsx_constants
from vmware_nsx.db import nsxv_db
from vmware_nsx.extensions import routersize as router_size
from vmware_nsx.extensions import routertype as router_type
from vmware_nsx.extensions import vnicindex as ext_vnic_idx
from vmware_nsx.plugins.nsx_v.drivers import (
    shared_router_driver as router_driver)
from vmware_nsx.plugins.nsx_v import md_proxy
from vmware_nsx.plugins.nsx_v.vshield.common import constants as vcns_const
from vmware_nsx.plugins.nsx_v.vshield import edge_firewall_driver
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.plugins.nsx_v.vshield.tasks import (
    constants as task_constants)
from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.extensions import test_vnic_index
from vmware_nsx.tests.unit.nsx_v.vshield import fake_vcns
from vmware_nsx.tests.unit import test_utils

PLUGIN_NAME = 'vmware_nsx.plugin.NsxVPlugin'

_uuid = uuidutils.generate_uuid


class NsxVPluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

    def _create_network(self, fmt, name, admin_state_up,
                        arg_list=None, providernet_args=None,
                        set_context=False, tenant_id=None,
                        **kwargs):
        tenant_id = tenant_id or self._tenant_id
        data = {'network': {'name': name,
                            'admin_state_up': admin_state_up,
                            'tenant_id': tenant_id}}
        # Fix to allow the router:external attribute and any other
        # attributes containing a colon to be passed with
        # a double underscore instead
        kwargs = dict((k.replace('__', ':'), v) for k, v in kwargs.items())
        if external_net.EXTERNAL in kwargs:
            arg_list = (external_net.EXTERNAL, ) + (arg_list or ())

        attrs = kwargs
        if providernet_args:
            attrs.update(providernet_args)
        for arg in (('admin_state_up', 'tenant_id', 'shared') +
                    (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs:
                data['network'][arg] = kwargs[arg]
        network_req = self.new_create_request('networks', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            network_req.environ['neutron.context'] = context.Context(
                '', tenant_id)
        return network_req.get_response(self.api)

    @mock.patch.object(edge_utils.EdgeManager, '_deploy_edge')
    def setUp(self, mock_deploy_edge,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        test_utils.override_nsx_ini_test()
        mock_vcns = mock.patch(vmware.VCNS_NAME, autospec=True)
        mock_vcns_instance = mock_vcns.start()
        self.fc2 = fake_vcns.FakeVcns()
        mock_vcns_instance.return_value = self.fc2
        edge_utils.query_dhcp_service_config = mock.Mock(return_value=[])
        self.mock_create_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'create_dhcp_edge_service'))
        self.mock_create_dhcp_service.start()
        mock_update_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'update_dhcp_edge_service'))
        mock_update_dhcp_service.start()
        mock_delete_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'delete_dhcp_edge_service'))
        mock_delete_dhcp_service.start()
        super(NsxVPluginV2TestCase, self).setUp(plugin=plugin,
                                                ext_mgr=ext_mgr)
        self.addCleanup(self.fc2.reset_all)
        plugin_instance = manager.NeutronManager.get_plugin()
        plugin_instance._get_edge_id_by_rtr_id = mock.Mock()
        plugin_instance._get_edge_id_by_rtr_id.return_value = False

    def test_get_vlan_network_name(self):
        p = manager.NeutronManager.get_plugin()
        id = uuidutils.generate_uuid()
        net = {'name': '',
               'id': id}
        expected = id
        self.assertEqual(expected,
                         p._get_vlan_network_name(net))
        net = {'name': 'pele',
               'id': id}
        expected = '%s-%s' % ('pele', id)
        self.assertEqual(expected,
                         p._get_vlan_network_name(net))
        name = 'X' * 500
        net = {'name': name,
               'id': id}
        expected = '%s-%s' % (name[:43], id)
        self.assertEqual(expected,
                         p._get_vlan_network_name(net))

    def test_create_port_anticipating_allocation(self):
        with self.network(shared=True) as network:
            with self.subnet(network=network, cidr='10.0.0.0/24') as subnet:
                fixed_ips = [{'subnet_id': subnet['subnet']['id']},
                             {'subnet_id': subnet['subnet']['id'],
                              'ip_address': '10.0.0.3'}]
                self._create_port(self.fmt, network['network']['id'],
                                  webob.exc.HTTPCreated.code,
                                  fixed_ips=fixed_ips)


class TestNetworksV2(test_plugin.TestNetworksV2, NsxVPluginV2TestCase):

    def test_create_network_vlan_transparent(self):
        self.skipTest("Currently no support in plugin for this")

    def _test_create_bridge_network(self, vlan_id=0):
        net_type = vlan_id and 'vlan' or 'flat'
        name = 'bridge_net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (pnet.NETWORK_TYPE, net_type),
                    (pnet.PHYSICAL_NETWORK, 'tzuuid'),
                    (pnet.SEGMENTATION_ID, vlan_id)]
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: 'tzuuid'}
        if vlan_id:
            providernet_args[pnet.SEGMENTATION_ID] = vlan_id
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK,
                                    pnet.SEGMENTATION_ID)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_bridge_network(self):
        self._test_create_bridge_network()

    def test_create_bridge_vlan_network(self):
        self._test_create_bridge_network(vlan_id=123)

    def test_create_bridge_vlan_network_outofrange_returns_400(self):
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_bridge_network(vlan_id=5000)
        self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_external_portgroup_network(self):
        name = 'ext_net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (external_net.EXTERNAL, True),
                    (pnet.NETWORK_TYPE, 'portgroup'),
                    (pnet.PHYSICAL_NETWORK, 'tzuuid')]
        providernet_args = {pnet.NETWORK_TYPE: 'portgroup',
                            pnet.PHYSICAL_NETWORK: 'tzuuid',
                            external_net.EXTERNAL: True}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK,
                                    external_net.EXTERNAL)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_delete_network_after_removing_subnet(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        fmt = 'json'
        # Create new network
        res = self._create_network(fmt=fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(fmt, res)
        subnet = self._make_subnet(fmt, network, gateway_ip,
                                   cidr, ip_version=4)
        req = self.new_delete_request('subnets', subnet['subnet']['id'])
        sub_del_res = req.get_response(self.api)
        self.assertEqual(sub_del_res.status_int, 204)
        req = self.new_delete_request('networks', network['network']['id'])
        net_del_res = req.get_response(self.api)
        self.assertEqual(net_del_res.status_int, 204)

    def test_list_networks_with_shared(self):
        with self.network(name='net1'):
            with self.network(name='net2', shared=True):
                req = self.new_list_request('networks')
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(len(res['networks']), 2)
                req_2 = self.new_list_request('networks')
                req_2.environ['neutron.context'] = context.Context('',
                                                                   'somebody')
                res = self.deserialize('json', req_2.get_response(self.api))
                # tenant must see a single network
                self.assertEqual(len(res['networks']), 1)

    def test_create_network_name_exceeds_40_chars(self):
        name = 'this_is_a_network_whose_name_is_longer_than_40_chars'
        with self.network(name=name) as net:
            # Assert neutron name is not truncated
            self.assertEqual(net['network']['name'], name)

    def test_update_network_with_admin_false(self):
        data = {'network': {'admin_state_up': False}}
        with self.network() as net:
            plugin = manager.NeutronManager.get_plugin()
            self.assertRaises(NotImplementedError,
                              plugin.update_network,
                              context.get_admin_context(),
                              net['network']['id'], data)

    def test_create_extend_dvs_provider_network(self):
        name = 'provider_net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (pnet.NETWORK_TYPE, 'flat'),
                    (pnet.PHYSICAL_NETWORK, 'dvs-uuid')]
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_same_vlan_network_with_different_dvs(self):
        name = 'dvs-provider-net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (pnet.NETWORK_TYPE, 'vlan'),
                    (pnet.SEGMENTATION_ID, 43),
                    (pnet.PHYSICAL_NETWORK, 'dvs-uuid-1')]
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 43,
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid-1'}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.SEGMENTATION_ID,
                                    pnet.PHYSICAL_NETWORK)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

            expected_same_vlan = [(pnet.NETWORK_TYPE, 'vlan'),
                                  (pnet.SEGMENTATION_ID, 43),
                                  (pnet.PHYSICAL_NETWORK, 'dvs-uuid-2')]
            providernet_args_1 = {pnet.NETWORK_TYPE: 'vlan',
                                  pnet.SEGMENTATION_ID: 43,
                                  pnet.PHYSICAL_NETWORK: 'dvs-uuid-2'}
            with self.network(name=name,
                              providernet_args=providernet_args_1,
                              arg_list=(pnet.NETWORK_TYPE,
                                        pnet.SEGMENTATION_ID,
                                        pnet.PHYSICAL_NETWORK)) as net1:
                for k, v in expected_same_vlan:
                    self.assertEqual(net1['network'][k], v)

    def test_create_vxlan_with_tz_provider_network(self):
        name = 'provider_net_vxlan'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (pnet.NETWORK_TYPE, 'vxlan'),
                    (pnet.PHYSICAL_NETWORK, 'vdnscope-2')]
        providernet_args = {pnet.NETWORK_TYPE: 'vxlan',
                            pnet.PHYSICAL_NETWORK: 'vdnscope-2'}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_vxlan_with_tz_provider_network_not_found_fail(self):
        name = 'provider_net_vxlan'
        data = {'network': {
                   'name': name,
                   'tenant_id': self._tenant_id,
                   pnet.SEGMENTATION_ID: attributes.ATTR_NOT_SPECIFIED,
                   pnet.NETWORK_TYPE: 'vxlan',
                   pnet.PHYSICAL_NETWORK: 'vdnscope-2'}}
        p = manager.NeutronManager.get_plugin()
        with mock.patch.object(p.nsx_v.vcns, 'validate_vdn_scope',
                               side_effect=[False]):
            self.assertRaises(nsxv_exc.NsxResourceNotFound,
                              p.create_network,
                              context.get_admin_context(),
                              data)


class TestVnicIndex(NsxVPluginV2TestCase,
                    test_vnic_index.VnicIndexDbTestCase):
    def test_update_port_twice_with_the_same_index(self):
        """Tests that updates which does not modify the port vnic
        index association do not produce any errors
        """
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                res = self._port_index_update(port['port']['id'], 2)
                self.assertEqual(2, res['port'][ext_vnic_idx.VNIC_INDEX])
                res = self._port_index_update(port['port']['id'], 2)
                self.assertEqual(2, res['port'][ext_vnic_idx.VNIC_INDEX])


class TestPortsV2(NsxVPluginV2TestCase,
                  test_plugin.TestPortsV2,
                  test_bindings.PortBindingsTestCase,
                  test_bindings.PortBindingsHostTestCaseMixin,
                  test_bindings.PortBindingsVnicTestCaseMixin):

    VIF_TYPE = nsx_constants.VIF_TYPE_DVS
    HAS_PORT_FILTER = True

    def test_get_ports_count(self):
        with self.port(), self.port(), self.port(), self.port() as p:
            tenid = p['port']['tenant_id']
            ctx = context.Context(user_id=None, tenant_id=tenid,
                                  is_admin=False)
            pl = manager.NeutronManager.get_plugin()
            count = pl.get_ports_count(ctx, filters={'tenant_id': [tenid]})
            # Each port above has subnet => we have an additional port
            # for DHCP
            self.assertEqual(8, count)

    def test_update_port_mac_v6_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_port_invalid_fixed_ip_address_v6_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_port_excluding_ipv6_slaac_subnet_from_fixed_ips(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_requested_subnet_id_v6_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_ip_allocation_for_ipv6_subnet_slaac_address_mode(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_requested_fixed_ip_address_v6_slaac_router_iface(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_port_with_ipv6_slaac_subnet_in_fixed_ips(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_requested_invalid_fixed_ip_address_v6_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_delete_port_with_ipv6_slaac_address(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_ip_allocation_for_ipv6_2_subnet_slaac_mode(self):
        self.skipTest('No DHCP v6 Support yet')

    def _test_create_port_with_ipv6_subnet_in_fixed_ips(self, addr_mode,
                                                        ipv6_pd=False):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_port_json(self):
        keys = [('admin_state_up', True), ('status', self.port_create_status)]
        with self.port(name='myname') as port:
            for k, v in keys:
                self.assertEqual(port['port'][k], v)
            self.assertIn('mac_address', port['port'])
            ips = port['port']['fixed_ips']
            self.assertEqual(len(ips), 1)
            self.assertEqual(ips[0]['ip_address'], '10.0.0.3')
            self.assertEqual('myname', port['port']['name'])

    def test_list_ports(self):
        # for this test we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet) as port1,\
                self.port(subnet) as port2,\
                self.port(subnet) as port3:
            self._test_list_resources('port', [port1, port2, port3])

    def test_list_ports_public_network(self):
        with self.network(shared=True) as network:
            with self.subnet(network, enable_dhcp=False) as subnet,\
                    self.port(subnet, tenant_id='tenant_1') as port1,\
                    self.port(subnet, tenant_id='tenant_2') as port2:

                # Admin request - must return both ports
                self._test_list_resources('port', [port1, port2])
                # Tenant_1 request - must return single port
                q_context = context.Context('', 'tenant_1')
                self._test_list_resources('port', [port1],
                                          neutron_context=q_context)
                # Tenant_2 request - must return single port
                q_context = context.Context('', 'tenant_2')
                self._test_list_resources('port', [port2],
                                          neutron_context=q_context)

    def test_list_ports_with_pagination_emulated(self):
        helper_patcher = mock.patch(
            'neutron.api.v2.base.Controller._get_pagination_helper',
            new=test_plugin._fake_get_pagination_helper)
        helper_patcher.start()
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, mac_address='00:00:00:00:00:01') as port1,\
                self.port(subnet, mac_address='00:00:00:00:00:02') as port2,\
                self.port(subnet, mac_address='00:00:00:00:00:03') as port3:
            self._test_list_with_pagination('port',
                                            (port1, port2, port3),
                                            ('mac_address', 'asc'), 2, 2)

    def test_list_ports_with_pagination_native(self):
        if self._skip_native_pagination:
            self.skipTest("Skip test for not implemented pagination feature")
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, mac_address='00:00:00:00:00:01') as port1,\
                self.port(subnet, mac_address='00:00:00:00:00:02') as port2,\
                self.port(subnet, mac_address='00:00:00:00:00:03') as port3:
            self._test_list_with_pagination('port',
                                            (port1, port2, port3),
                                            ('mac_address', 'asc'), 2, 2)

    def test_list_ports_with_sort_emulated(self):
        helper_patcher = mock.patch(
            'neutron.api.v2.base.Controller._get_sorting_helper',
            new=test_plugin._fake_get_sorting_helper)
        helper_patcher.start()
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, admin_state_up='True',
                          mac_address='00:00:00:00:00:01') as port1,\
                self.port(subnet, admin_state_up='False',
                          mac_address='00:00:00:00:00:02') as port2,\
                self.port(subnet, admin_state_up='False',
                          mac_address='00:00:00:00:00:03') as port3:

            self._test_list_with_sort('port', (port3, port2, port1),
                                      [('admin_state_up', 'asc'),
                                      ('mac_address', 'desc')])

    def test_list_ports_with_sort_native(self):
        if self._skip_native_sorting:
            self.skipTest("Skip test for not implemented sorting feature")
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, admin_state_up='True',
                          mac_address='00:00:00:00:00:01') as port1,\
                self.port(subnet, admin_state_up='False',
                          mac_address='00:00:00:00:00:02') as port2,\
                self.port(subnet, admin_state_up='False',
                          mac_address='00:00:00:00:00:03') as port3:

            self._test_list_with_sort('port', (port3, port2, port1),
                                      [('admin_state_up', 'asc'),
                                      ('mac_address', 'desc')])

    def test_update_port_delete_ip(self):
        # This test case overrides the default because the nsx plugin
        # implements port_security/security groups and it is not allowed
        # to remove an ip address from a port unless the security group
        # is first removed.
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                data = {'port': {'admin_state_up': False,
                                 'fixed_ips': [],
                                 secgrp.SECURITYGROUPS: []}}
                req = self.new_update_request('ports',
                                              data, port['port']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(res['port']['admin_state_up'],
                                 data['port']['admin_state_up'])
                self.assertEqual(res['port']['fixed_ips'],
                                 data['port']['fixed_ips'])

    def _update_port_index(self, port_id, device_id, index):
        data = {'port': {'device_id': device_id, 'vnic_index': index}}
        req = self.new_update_request('ports',
                                      data, port_id)
        res = self.deserialize('json', req.get_response(self.api))
        return res

    @mock.patch.object(edge_utils.EdgeManager, 'delete_dhcp_binding')
    def test_update_port_index(self, delete_dhcp_binding):
        q_context = context.Context('', 'tenant_1')
        device_id = _uuid()
        with self.subnet() as subnet:
            with self.port(subnet=subnet,
                           device_id=device_id,
                           device_owner='compute:None') as port:
                self.assertIsNone(port['port']['vnic_index'])

                vnic_index = 3
                res = self._update_port_index(
                    port['port']['id'], device_id, vnic_index)
                self.assertEqual(vnic_index, res['port']['vnic_index'])

                # Updating the vnic_index to None implies the vnic does
                # no longer obtain the addresses associated with this port,
                # we need to inactivate previous addresses configurations for
                # this vnic in the context of this network spoofguard policy.
                self.fc2.inactivate_vnic_assigned_addresses = (
                    mock.Mock().inactivate_vnic_assigned_addresses)

                policy_id = nsxv_db.get_spoofguard_policy_id(
                    q_context.session, port['port']['network_id'])

                res = self._update_port_index(port['port']['id'], '', None)

                vnic_id = '%s.%03d' % (device_id, vnic_index)
                (self.fc2.inactivate_vnic_assigned_addresses.
                 assert_called_once_with(policy_id, vnic_id))
                self.assertTrue(delete_dhcp_binding.called)

    def test_update_port_with_compute_device_owner(self):
        """
        Test that DHCP binding is created when ports 'device_owner'
        is updated to compute, for example when attaching an interface to a
        instance with existing port.
        """
        with self.port() as port:
            with mock.patch(PLUGIN_NAME + '._create_dhcp_static_binding'):
                update = {'port': {'device_owner'}}
                self.new_update_request('ports',
                                        update, port['port']['id'])

    def test_create_port_public_network_with_ip(self):
        with self.network(shared=True) as network:
            with self.subnet(enable_dhcp=False,
                             network=network, cidr='10.0.0.0/24') as subnet:
                keys = [('admin_state_up', True),
                        ('status', self.port_create_status),
                        ('fixed_ips', [{'subnet_id': subnet['subnet']['id'],
                                        'ip_address': '10.0.0.2'}])]
                port_res = self._create_port(self.fmt,
                                             network['network']['id'],
                                             webob.exc.HTTPCreated.code,
                                             tenant_id='another_tenant',
                                             set_context=True)
                port = self.deserialize(self.fmt, port_res)
                for k, v in keys:
                    self.assertEqual(port['port'][k], v)
                self.assertIn('mac_address', port['port'])
                self._delete('ports', port['port']['id'])

    def test_no_more_port_exception(self):
        with self.subnet(enable_dhcp=False, cidr='10.0.0.0/31',
                         gateway_ip=None) as subnet:
            id = subnet['subnet']['network_id']
            res = self._create_port(self.fmt, id)
            data = self.deserialize(self.fmt, res)
            msg = str(n_exc.IpAddressGenerationFailure(net_id=id))
            self.assertEqual(data['NeutronError']['message'], msg)
            self.assertEqual(res.status_int, webob.exc.HTTPConflict.code)

    def test_ports_vif_host(self):
        cfg.CONF.set_default('allow_overlapping_ips', True)
        host_arg = {portbindings.HOST_ID: self.hostname}
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, name='name1',
                          arg_list=(portbindings.HOST_ID,), **host_arg),\
                self.port(subnet, name='name2'):
            ctx = context.get_admin_context()
            ports = self._list('ports', neutron_context=ctx)['ports']
            self.assertEqual(2, len(ports))
            for port in ports:
                if port['name'] == 'name1':
                    self._check_response_portbindings_host(port)
                else:
                    self.assertFalse(port[portbindings.HOST_ID])
            # By default user is admin - now test non admin user
            ctx = context.Context(user_id=None,
                                  tenant_id=self._tenant_id,
                                  is_admin=False,
                                  read_deleted="no")
            ports = self._list('ports', neutron_context=ctx)['ports']
            self.assertEqual(2, len(ports))
            for non_admin_port in ports:
                self._check_response_no_portbindings_host(non_admin_port)

    def test_ports_vif_host_update(self):
        cfg.CONF.set_default('allow_overlapping_ips', True)
        host_arg = {portbindings.HOST_ID: self.hostname}
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, name='name1',
                          arg_list=(portbindings.HOST_ID,),
                          **host_arg) as port1,\
                self.port(subnet, name='name2') as port2:
            data = {'port': {portbindings.HOST_ID: 'testhosttemp'}}
            req = self.new_update_request(
                'ports', data, port1['port']['id'])
            req.get_response(self.api)
            req = self.new_update_request(
                'ports', data, port2['port']['id'])
            ctx = context.get_admin_context()
            req.get_response(self.api)
            ports = self._list('ports', neutron_context=ctx)['ports']
        self.assertEqual(2, len(ports))
        for port in ports:
            self.assertEqual('testhosttemp', port[portbindings.HOST_ID])

    def test_ports_vif_details(self):
        plugin = manager.NeutronManager.get_plugin()
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet), self.port(subnet):
            ctx = context.get_admin_context()
            ports = plugin.get_ports(ctx)
            self.assertEqual(len(ports), 2)
            for port in ports:
                self._check_response_portbindings(port)
            # By default user is admin - now test non admin user
            ctx = self._get_non_admin_context()
            ports = self._list('ports', neutron_context=ctx)['ports']
            self.assertEqual(len(ports), 2)
            for non_admin_port in ports:
                self._check_response_no_portbindings(non_admin_port)

    def test_ports_vnic_type(self):
        cfg.CONF.set_default('allow_overlapping_ips', True)
        vnic_arg = {portbindings.VNIC_TYPE: self.vnic_type}
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, name='name1',
                          arg_list=(portbindings.VNIC_TYPE,), **vnic_arg),\
                self.port(subnet, name='name2'):
            ctx = context.get_admin_context()
            ports = self._list('ports', neutron_context=ctx)['ports']
            self.assertEqual(2, len(ports))
            for port in ports:
                if port['name'] == 'name1':
                    self._check_response_portbindings_vnic_type(port)
                else:
                    self.assertEqual(portbindings.VNIC_NORMAL,
                                     port[portbindings.VNIC_TYPE])
            # By default user is admin - now test non admin user
            ctx = context.Context(user_id=None,
                                  tenant_id=self._tenant_id,
                                  is_admin=False,
                                  read_deleted="no")
            ports = self._list('ports', neutron_context=ctx)['ports']
            self.assertEqual(2, len(ports))
            for non_admin_port in ports:
                self._check_response_portbindings_vnic_type(non_admin_port)

    def test_ports_vnic_type_list(self):
        cfg.CONF.set_default('allow_overlapping_ips', True)
        vnic_arg = {portbindings.VNIC_TYPE: self.vnic_type}
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, name='name1',
                          arg_list=(portbindings.VNIC_TYPE,),
                          **vnic_arg) as port1,\
                self.port(subnet, name='name2') as port2,\
                self.port(subnet, name='name3',
                          arg_list=(portbindings.VNIC_TYPE,),
                          **vnic_arg) as port3:

            self._test_list_resources('port', (port1, port2, port3),
                                      query_params='%s=%s' % (
                                          portbindings.VNIC_TYPE,
                                          self.vnic_type))

    def test_range_allocation(self):
        with self.subnet(enable_dhcp=False, gateway_ip='10.0.0.3',
                         cidr='10.0.0.0/29') as subnet:
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']}]}
                net_id = subnet['subnet']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port = self.deserialize(self.fmt, res)
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 5)
                alloc = ['10.0.0.1', '10.0.0.2', '10.0.0.4', '10.0.0.5',
                         '10.0.0.6']
                for ip in ips:
                    self.assertIn(ip['ip_address'], alloc)
                    self.assertEqual(ip['subnet_id'],
                                     subnet['subnet']['id'])
                    alloc.remove(ip['ip_address'])
                self.assertEqual(len(alloc), 0)
                self._delete('ports', port['port']['id'])

        with self.subnet(enable_dhcp=False, gateway_ip='11.0.0.6',
                         cidr='11.0.0.0/29') as subnet:
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet['subnet']['id']}]}
                net_id = subnet['subnet']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port = self.deserialize(self.fmt, res)
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 5)
                alloc = ['11.0.0.1', '11.0.0.2', '11.0.0.3', '11.0.0.4',
                         '11.0.0.5']
                for ip in ips:
                    self.assertIn(ip['ip_address'], alloc)
                    self.assertEqual(ip['subnet_id'],
                                     subnet['subnet']['id'])
                    alloc.remove(ip['ip_address'])
                self.assertEqual(len(alloc), 0)
                self._delete('ports', port['port']['id'])

    def test_requested_duplicate_ip(self):
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Check configuring of duplicate IP
                kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id'],
                                         'ip_address': ips[0]['ip_address']}]}
                net_id = port['port']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                self.assertEqual(res.status_int, webob.exc.HTTPConflict.code)

    def test_requested_invalid_fixed_ips(self):
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Test invalid subnet_id
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id']},
                           {'subnet_id':
                            '00000000-ffff-ffff-ffff-000000000000'}]}
                net_id = port['port']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

                # Test invalid IP address on specified subnet_id
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id'],
                            'ip_address': '1.1.1.1'}]}
                net_id = port['port']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int,
                                 webob.exc.HTTPClientError.code)

                # Test invalid addresses - IP's not on subnet or network
                # address or broadcast address
                bad_ips = ['1.1.1.1', '10.0.0.0', '10.0.0.255']
                net_id = port['port']['network_id']
                for ip in bad_ips:
                    kwargs = {"fixed_ips": [{'ip_address': ip}]}
                    res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                    port2 = self.deserialize(self.fmt, res)
                    self.assertEqual(res.status_int,
                                     webob.exc.HTTPClientError.code)

                # Enable allocation of gateway address
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id'],
                            'ip_address': '10.0.0.1'}]}
                net_id = port['port']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(self.fmt, res)
                ips = port2['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.1')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                self._delete('ports', port2['port']['id'])

    def test_requested_split(self):
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet) as port:
                ports_to_delete = []
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Allocate specific IP
                kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id'],
                                         'ip_address': '10.0.0.5'}]}
                net_id = port['port']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(self.fmt, res)
                ports_to_delete.append(port2)
                ips = port2['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.5')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Allocate specific IP's
                allocated = ['10.0.0.3', '10.0.0.4', '10.0.0.6']

                for a in allocated:
                    res = self._create_port(self.fmt, net_id=net_id)
                    port2 = self.deserialize(self.fmt, res)
                    ports_to_delete.append(port2)
                    ips = port2['port']['fixed_ips']
                    self.assertEqual(len(ips), 1)
                    self.assertEqual(ips[0]['ip_address'], a)
                    self.assertEqual(ips[0]['subnet_id'],
                                     subnet['subnet']['id'])

                for p in ports_to_delete:
                    self._delete('ports', p['port']['id'])

    def test_requested_ips_only(self):
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                ips_only = ['10.0.0.18', '10.0.0.20', '10.0.0.22', '10.0.0.21',
                            '10.0.0.3', '10.0.0.17', '10.0.0.19']
                ports_to_delete = []
                for i in ips_only:
                    kwargs = {"fixed_ips": [{'ip_address': i}]}
                    net_id = port['port']['network_id']
                    res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                    port = self.deserialize(self.fmt, res)
                    ports_to_delete.append(port)
                    ips = port['port']['fixed_ips']
                    self.assertEqual(len(ips), 1)
                    self.assertEqual(ips[0]['ip_address'], i)
                    self.assertEqual(ips[0]['subnet_id'],
                                     subnet['subnet']['id'])
                for p in ports_to_delete:
                    self._delete('ports', p['port']['id'])

    def test_requested_subnet_id(self):
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                # Request an IP from specific subnet
                kwargs = {"fixed_ips": [{'subnet_id': subnet['subnet']['id']}]}
                net_id = port['port']['network_id']
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port2 = self.deserialize(self.fmt, res)
                ips = port2['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.3')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                self._delete('ports', port2['port']['id'])

    def test_requested_subnet_id_v4_and_v6(self):
        with self.subnet(enable_dhcp=False) as subnet:
                # Get an IPv4 and IPv6 address
                tenant_id = subnet['subnet']['tenant_id']
                net_id = subnet['subnet']['network_id']
                res = self._create_subnet(
                    self.fmt,
                    tenant_id=tenant_id,
                    net_id=net_id,
                    cidr='2607:f0d0:1002:51::/124',
                    ip_version=6,
                    gateway_ip=attributes.ATTR_NOT_SPECIFIED,
                    enable_dhcp=False)
                subnet2 = self.deserialize(self.fmt, res)
                kwargs = {"fixed_ips":
                          [{'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet2['subnet']['id']}]}
                res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                port3 = self.deserialize(self.fmt, res)
                ips = port3['port']['fixed_ips']
                self.assertEqual(len(ips), 2)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                self.assertEqual(ips[1]['ip_address'], '2607:f0d0:1002:51::2')
                self.assertEqual(ips[1]['subnet_id'], subnet2['subnet']['id'])
                res = self._create_port(self.fmt, net_id=net_id)
                port4 = self.deserialize(self.fmt, res)
                # Check that a v4 and a v6 address are allocated
                ips = port4['port']['fixed_ips']
                self.assertEqual(len(ips), 2)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.3')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                self.assertEqual(ips[1]['ip_address'], '2607:f0d0:1002:51::3')
                self.assertEqual(ips[1]['subnet_id'], subnet2['subnet']['id'])
                self._delete('ports', port3['port']['id'])
                self._delete('ports', port4['port']['id'])

    def test_update_port_add_additional_ip(self):
        """Test update of port with additional IP."""
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet) as port:
                data = {'port': {'admin_state_up': False,
                                 'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id']},
                                               {'subnet_id':
                                                subnet['subnet']['id']}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertEqual(res['port']['admin_state_up'],
                                 data['port']['admin_state_up'])
                ips = res['port']['fixed_ips']
                self.assertEqual(len(ips), 2)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.3')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                self.assertEqual(ips[1]['ip_address'], '10.0.0.4')
                self.assertEqual(ips[1]['subnet_id'], subnet['subnet']['id'])

    def test_update_port_update_ip(self):
        """Test update of port IP.

        Check that a configured IP 10.0.0.2 is replaced by 10.0.0.10.
        """
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': "10.0.0.10"}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                ips = res['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.10')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])

    def test_update_port_update_ip_dhcp(self):
        #Test updating a port IP when the device owner is DHCP
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet,
                           device_owner=constants.DEVICE_OWNER_DHCP) as port:
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': "10.0.0.10"}]}}
                plugin = manager.NeutronManager.get_plugin()
                ctx = context.get_admin_context()
                with mock.patch.object(
                    plugin.edge_manager,
                    'update_dhcp_edge_service') as update_dhcp:
                    plugin.update_port(ctx, port['port']['id'], data)
                    self.assertTrue(update_dhcp.called)

    def test_update_port_update_ip_compute(self):
        #Test that updating a port IP succeed if the device owner starts
        #with compute.
        owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'xxx'
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet, device_id=_uuid(),
                           device_owner=owner) as port:
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': "10.0.0.10"}]}}
                plugin = manager.NeutronManager.get_plugin()
                with mock.patch.object(
                    plugin.edge_manager,
                    'delete_dhcp_binding') as delete_dhcp:
                    with mock.patch.object(
                        plugin.edge_manager,
                        'create_static_binding') as create_static:
                        with mock.patch.object(
                            plugin.edge_manager,
                            'create_dhcp_bindings') as create_dhcp:
                            plugin.update_port(context.get_admin_context(),
                                               port['port']['id'], data)
                            self.assertTrue(delete_dhcp.called)
                            self.assertTrue(create_static.called)
                            self.assertTrue(create_dhcp.called)

    def test_update_port_update_ip_and_owner_fail(self):
        #Test that updating a port IP and device owner at the same
        #transaction fails
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet,
                           device_owner='aaa') as port:
                data = {'port': {'device_owner': 'bbb',
                                 'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': "10.0.0.10"}]}}
                plugin = manager.NeutronManager.get_plugin()
                self.assertRaises(n_exc.BadRequest,
                                  plugin.update_port,
                                  context.get_admin_context(),
                                  port['port']['id'], data)

    def test_update_port_update_ip_router(self):
        #Test that updating a port IP succeed if the device owner is a router
        owner = constants.DEVICE_OWNER_ROUTER_GW
        router_id = _uuid()
        old_ip = '10.0.0.3'
        new_ip = '10.0.0.10'
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet, device_id=router_id,
                           device_owner=owner,
                           fixed_ips=[{'ip_address': old_ip}]) as port:
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': new_ip}]}}
                plugin = manager.NeutronManager.get_plugin()
                ctx = context.get_admin_context()
                router_obj = router_driver.RouterSharedDriver(plugin)
                with mock.patch.object(plugin, '_find_router_driver',
                                       return_value=router_obj):
                    with mock.patch.object(
                        router_obj,
                        'update_router_interface_ip') as update_router:
                        port_id = port['port']['id']
                        plugin.update_port(ctx, port_id, data)
                        net_id = port['port']['network_id']
                        update_router.assert_called_once_with(
                            ctx,
                            router_id,
                            port_id,
                            net_id,
                            old_ip,
                            new_ip, "255.255.255.0")

    def test_update_port_update_ip_unatached_router(self):
        #Test that updating a port IP succeed if the device owner is a router
        #and the shared router is not attached to any edge yet
        owner = constants.DEVICE_OWNER_ROUTER_GW
        router_id = _uuid()
        old_ip = '10.0.0.3'
        new_ip = '10.0.0.10'
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet, device_id=router_id,
                           device_owner=owner,
                           fixed_ips=[{'ip_address': old_ip}]) as port:
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': new_ip}]}}
                plugin = manager.NeutronManager.get_plugin()
                ctx = context.get_admin_context()
                router_obj = router_driver.RouterSharedDriver(plugin)
                with mock.patch.object(plugin, '_find_router_driver',
                                       return_value=router_obj):
                    # make sure the router will not be attached to an edge
                    with mock.patch.object(
                        edge_utils, 'get_router_edge_id',
                        return_value=None):
                        port_id = port['port']['id']
                        # The actual test here is that this call does not
                        # raise an exception
                        new_port = plugin.update_port(ctx, port_id, data)
                        ips = new_port['fixed_ips']
                        self.assertEqual(len(ips), 1)
                        self.assertEqual(ips[0]['ip_address'], new_ip)
                        self.assertEqual(ips[0]['subnet_id'],
                                         subnet['subnet']['id'])

    def test_update_port_delete_ip_router(self):
        #Test that deleting a port IP succeed if the device owner is a router
        owner = constants.DEVICE_OWNER_ROUTER_GW
        router_id = _uuid()
        old_ip = '10.0.0.3'
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet, device_id=router_id,
                           device_owner=owner,
                           fixed_ips=[{'ip_address': old_ip}]) as port:
                data = {'port': {'fixed_ips': []}}
                plugin = manager.NeutronManager.get_plugin()
                ctx = context.get_admin_context()
                router_obj = router_driver.RouterSharedDriver(plugin)
                with mock.patch.object(plugin, '_find_router_driver',
                                       return_value=router_obj):
                    with mock.patch.object(
                        router_obj,
                        'update_router_interface_ip') as update_router:
                        port_id = port['port']['id']
                        plugin.update_port(ctx, port_id, data)
                        net_id = port['port']['network_id']
                        update_router.assert_called_once_with(
                            ctx,
                            router_id,
                            port_id,
                            net_id,
                            old_ip,
                            None, None)

    def test_update_port_update_ip_address_only(self):
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(len(ips), 1)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': "10.0.0.10"},
                                               {'ip_address': "10.0.0.2"}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                ips = res['port']['fixed_ips']
                self.assertEqual(len(ips), 2)
                self.assertEqual(ips[0]['ip_address'], '10.0.0.2')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                self.assertEqual(ips[1]['ip_address'], '10.0.0.10')
                self.assertEqual(ips[1]['subnet_id'], subnet['subnet']['id'])

    def test_update_dhcp_port_with_exceeding_fixed_ips(self):
        self.skipTest('Updating dhcp port IP is not supported')

    def test_requested_subnet_id_v4_and_v6_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_router_port_ipv4_and_ipv6_slaac_no_fixed_ips(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_port_with_multiple_ipv4_and_ipv6_subnets(self):
        # This test should fail as the NSX-v plugin should cause Neutron to
        # return a 400 status code
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            super(TestPortsV2, self).\
                test_create_port_with_multiple_ipv4_and_ipv6_subnets()
            self.assertEqual(ctx_manager.exception.code, 400)

    def test_list_ports_for_network_owner(self):
        with self.network(tenant_id='tenant_1') as network:
            with self.subnet(network, enable_dhcp=False) as subnet:
                with self.port(subnet, tenant_id='tenant_1') as port1,\
                        self.port(subnet, tenant_id='tenant_2') as port2:
                    # network owner request, should return all ports
                    port_res = self._list_ports(
                        'json', set_context=True, tenant_id='tenant_1')
                    port_list = self.deserialize('json', port_res)['ports']
                    port_ids = [p['id'] for p in port_list]
                    self.assertEqual(2, len(port_list))
                    self.assertIn(port1['port']['id'], port_ids)
                    self.assertIn(port2['port']['id'], port_ids)

                    # another tenant request, only return ports belong to it
                    port_res = self._list_ports(
                        'json', set_context=True, tenant_id='tenant_2')
                    port_list = self.deserialize('json', port_res)['ports']
                    port_ids = [p['id'] for p in port_list]
                    self.assertEqual(1, len(port_list))
                    self.assertNotIn(port1['port']['id'], port_ids)
                    self.assertIn(port2['port']['id'], port_ids)


class TestSubnetsV2(NsxVPluginV2TestCase,
                    test_plugin.TestSubnetsV2):
    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(TestSubnetsV2, self).setUp()
        self.context = context.get_admin_context()

    def test__subnet_ipv6_not_supported(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'gateway': 'fe80::1',
                               'cidr': '2607:f0d0:1002:51::/64',
                               'ip_version': '6',
                               'tenant_id': network['network']['tenant_id']}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, webob.exc.HTTPClientError.code)

    def test_create_subnet_ipv6_gw_is_nw_end_addr_returns_201(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_out_of_cidr_global(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_pd_gw_values(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_slaac_with_port_on_network(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_slaac_with_snat_intf_on_network(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_dhcpv6_stateless_with_port_on_network(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_slaac_with_dhcp_port_on_network(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_delete_subnet_ipv6_slaac_port_exists(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_slaac_with_router_intf_on_network(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_out_of_cidr_lla(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_subnet_inconsistent_ipv6_hostroute_dst_v4(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_only_ip_version_v6(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_subnet_ipv6_address_mode_fails(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_with_v6_allocation_pool(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_with_v6_pd_allocation_pool(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_subnet_ipv6_ra_mode_fails(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_delete_subnet_ipv6_slaac_router_port_exists(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_subnet_inconsistent_ipv6_hostroute_np_v4(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_subnet_inconsistent_ipv6_gatewayv4(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_subnet_ipv6_attributes_fails(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_subnet_ipv6_cannot_disable_dhcp(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_V6_pd_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_V6_pd_stateless(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_V6_pd_statefull(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_V6_pd_no_mode(self):
        self.skipTest('No DHCP v6 Support yet')

    def _create_subnet_bulk(self, fmt, number, net_id, name,
                            ip_version=4, **kwargs):
        base_data = {'subnet': {'network_id': net_id,
                                'ip_version': ip_version,
                                'enable_dhcp': False,
                                'tenant_id': self._tenant_id}}
        # auto-generate cidrs as they should not overlap
        overrides = dict((k, v)
                         for (k, v) in zip(range(number),
                                           [{'cidr': "10.0.%s.0/24" % num}
                                            for num in range(number)]))
        kwargs.update({'override': overrides})
        return self._create_bulk(fmt, number, 'subnet', base_data, **kwargs)

    def test_create_subnet_with_two_host_routes(self):
        self.skipTest("Skip test for not implemented host_routes feature")

    def test_delete_subnet_with_route(self):
        self.skipTest("Skip test for not implemented host_routes feature")

    def test_update_subnet_adding_additional_host_routes_and_dns(self):
        self.skipTest("Skip test for not implemented host_routes feature")

    def test_delete_subnet_with_dns_and_route(self):
        self.skipTest("Skip test for not implemented host_routes feature")

    def test_update_subnet_route(self):
        self.skipTest("Skip test for not implemented host_routes feature")

    def test_update_subnet_route_to_None(self):
        self.skipTest("Skip test for not implemented host_routes feature")

    def test_create_subnet_with_one_host_route(self):
        self.skipTest("Skip test for not implemented host_routes feature")

    def test_create_subnet_nonzero_cidr(self):
            awkward_cidrs = [{'nonezero': '10.129.122.5/8',
                              'corrected': '10.0.0.0/8'},
                             {'nonezero': '11.129.122.5/15',
                              'corrected': '11.128.0.0/15'},
                             {'nonezero': '12.129.122.5/16',
                              'corrected': '12.129.0.0/16'},
                             {'nonezero': '13.129.122.5/18',
                              'corrected': '13.129.64.0/18'},
                             {'nonezero': '14.129.122.5/22',
                              'corrected': '14.129.120.0/22'},
                             {'nonezero': '15.129.122.5/24',
                              'corrected': '15.129.122.0/24'},
                             {'nonezero': '16.129.122.5/28',
                              'corrected': '16.129.122.0/28'}, ]

            for cidr in awkward_cidrs:
                with self.subnet(enable_dhcp=False,
                                 cidr=cidr['nonezero']) as subnet:
                    # the API should accept and correct these cidrs for users
                    self.assertEqual(cidr['corrected'],
                                     subnet['subnet']['cidr'])

            with self.subnet(enable_dhcp=False, cidr='17.129.122.5/32',
                             gateway_ip=None) as subnet:
                self.assertEqual('17.129.122.5/32', subnet['subnet']['cidr'])

    def test_create_subnet_ipv6_attributes(self):
        # Expected to fail for now as we don't support IPv6 for NSXv
        cidr = "fe80::/80"
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(cidr=cidr)
            self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_subnet_with_different_dhcp_server(self):
        self.mock_create_dhcp_service.stop()
        name = 'dvs-provider-net'
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 43,
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
        with self.network(name=name, do_delete=False,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.SEGMENTATION_ID,
                                    pnet.PHYSICAL_NETWORK)) as net:
            self._test_create_subnet(network=net, cidr='10.0.0.0/24')
            dhcp_router_id = (vcns_const.DHCP_EDGE_PREFIX +
                              net['network']['id'])[:36]
            dhcp_server_id = nsxv_db.get_nsxv_router_binding(
                self.context.session, dhcp_router_id)['edge_id']
            providernet_args_1 = {pnet.NETWORK_TYPE: 'vlan',
                                  pnet.SEGMENTATION_ID: 43,
                                  pnet.PHYSICAL_NETWORK: 'dvs-uuid-1'}
            with self.network(name=name, do_delete=False,
                              providernet_args=providernet_args_1,
                              arg_list=(pnet.NETWORK_TYPE,
                                        pnet.SEGMENTATION_ID,
                                        pnet.PHYSICAL_NETWORK)) as net1:
                self._test_create_subnet(network=net1, cidr='10.0.1.0/24')
                router_id = (vcns_const.DHCP_EDGE_PREFIX +
                             net1['network']['id'])[:36]
                dhcp_server_id_1 = nsxv_db.get_nsxv_router_binding(
                    self.context.session, router_id)['edge_id']
                self.assertNotEqual(dhcp_server_id, dhcp_server_id_1)

    def test_create_subnet_with_different_dhcp_by_flat_net(self):
        self.mock_create_dhcp_service.stop()
        name = 'flat-net'
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
        with self.network(name=name, do_delete=False,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK)) as net:
            self._test_create_subnet(network=net, cidr='10.0.0.0/24')
            dhcp_router_id = (vcns_const.DHCP_EDGE_PREFIX +
                              net['network']['id'])[:36]
            dhcp_server_id = nsxv_db.get_nsxv_router_binding(
                self.context.session, dhcp_router_id)['edge_id']
            providernet_args_1 = {pnet.NETWORK_TYPE: 'flat',
                                  pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
            with self.network(name=name, do_delete=False,
                              providernet_args=providernet_args_1,
                              arg_list=(pnet.NETWORK_TYPE,
                                        pnet.PHYSICAL_NETWORK)) as net1:
                self._test_create_subnet(network=net1, cidr='10.0.1.0/24')
                router_id = (vcns_const.DHCP_EDGE_PREFIX +
                             net1['network']['id'])[:36]
                dhcp_server_id_1 = nsxv_db.get_nsxv_router_binding(
                    self.context.session, router_id)['edge_id']
                self.assertNotEqual(dhcp_server_id, dhcp_server_id_1)

    def test_create_subnet_ipv6_slaac_with_db_reference_error(self):
        self.skipTest('Currently not support')

    def test_create_subnet_ipv6_gw_values(self):
        # This test should fail with response code 400 as IPv6 subnets with
        # DHCP are not supported by this plugin
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            super(TestSubnetsV2, self).test_create_subnet_ipv6_gw_values()
            self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_subnet_only_ip_version_v6_old(self):
        self.skipTest('Currently not supported')

    def test_create_subnet_reserved_network(self):
        self.mock_create_dhcp_service.stop()
        name = 'overlap-reserved-net'
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            with self.network(name=name, do_delete=False,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.SEGMENTATION_ID,
                                    pnet.PHYSICAL_NETWORK)) as net:
                self._test_create_subnet(network=net,
                                         cidr='169.254.128.128/25')
                self.assertEqual(ctx_manager.exception.code, 400)


class TestSubnetPoolsV2(NsxVPluginV2TestCase, test_plugin.TestSubnetsV2):
    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(TestSubnetPoolsV2, self).setUp()
        self.context = context.get_admin_context()

    def test_create_subnet_ipv6_gw_is_nw_end_addr_returns_201(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_out_of_cidr_global(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_V6_pd_stateless(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_V6_pd_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_dhcpv6_stateless_with_port_on_network(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_gw_values(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_out_of_cidr_lla(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_pd_gw_values(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_slaac_with_db_reference_error(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_slaac_with_dhcp_port_on_network(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_slaac_with_port_on_network(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_slaac_with_router_intf_on_network(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_slaac_with_snat_intf_on_network(self):
        self.skipTest('Not supported')

    def test_create_subnet_only_ip_version_v6(self):
        self.skipTest('Not supported')

    def test_create_subnet_with_one_host_route(self):
        self.skipTest("Skip test for not implemented host_routes feature")

    def test_create_subnet_with_two_host_routes(self):
        self.skipTest("Skip test for not implemented host_routes feature")

    def test_create_subnet_with_v6_allocation_pool(self):
        self.skipTest('Not supported')

    def test_create_subnet_with_v6_pd_allocation_pool(self):
        self.skipTest('Not supported')

    def test_delete_subnet_ipv6_slaac_port_exists(self):
        self.skipTest('Not supported')

    def test_delete_subnet_ipv6_slaac_router_port_exists(self):
        self.skipTest('Not supported')

    def test_delete_subnet_with_dns_and_route(self):
        self.skipTest("Skip test for not implemented host_routes feature")

    def test_delete_subnet_with_route(self):
        self.skipTest("Skip test for not implemented host_routes feature")

    def test_update_subnet_adding_additional_host_routes_and_dns(self):
        self.skipTest("Skip test for not implemented host_routes feature")

    def test_update_subnet_inconsistent_ipv6_gatewayv4(self):
        self.skipTest('Not supported')

    def test_update_subnet_inconsistent_ipv6_hostroute_dst_v4(self):
        self.skipTest('Not supported')

    def test_update_subnet_inconsistent_ipv6_hostroute_np_v4(self):
        self.skipTest('Not supported')

    def test_update_subnet_ipv6_address_mode_fails(self):
        self.skipTest('Not supported')

    def test_update_subnet_ipv6_attributes_fails(self):
        self.skipTest('Not supported')

    def test_update_subnet_ipv6_cannot_disable_dhcp(self):
        self.skipTest('Not supported')

    def test_update_subnet_ipv6_ra_mode_fails(self):
        self.skipTest('Not supported')

    def test_update_subnet_route(self):
        self.skipTest("Skip test for not implemented host_routes feature")

    def test_update_subnet_route_to_None(self):
        self.skipTest("Skip test for not implemented host_routes feature")

    def test_create_subnet_only_ip_version_v6_old(self):
        self.skipTest('Currently not supported')


class TestBasicGet(test_plugin.TestBasicGet, NsxVPluginV2TestCase):
    pass


class TestV2HTTPResponse(test_plugin.TestV2HTTPResponse, NsxVPluginV2TestCase):
    pass


class TestL3ExtensionManager(object):

    def get_resources(self):
        # Simulate extension of L3 attribute map
        # First apply attribute extensions
        for key in l3.RESOURCE_ATTRIBUTE_MAP.keys():
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                l3_ext_gw_mode.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                dist_router.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                router_type.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                router_size.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
        # Finally add l3 resources to the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            l3.RESOURCE_ATTRIBUTE_MAP)
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


def backup_l3_attribute_map():
    """Return a backup of the original l3 attribute map."""
    return dict((res, attrs.copy()) for
                (res, attrs) in six.iteritems(l3.RESOURCE_ATTRIBUTE_MAP))


def restore_l3_attribute_map(map_to_restore):
    """Ensure changes made by fake ext mgrs are reverted."""
    l3.RESOURCE_ATTRIBUTE_MAP = map_to_restore


class L3NatTest(test_l3_plugin.L3BaseForIntTests, NsxVPluginV2TestCase):

    def _restore_l3_attribute_map(self):
        l3.RESOURCE_ATTRIBUTE_MAP = self._l3_attribute_map_bk

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None, service_plugins=None):
        self._l3_attribute_map_bk = {}
        for item in l3.RESOURCE_ATTRIBUTE_MAP:
            self._l3_attribute_map_bk[item] = (
                l3.RESOURCE_ATTRIBUTE_MAP[item].copy())
        cfg.CONF.set_override('task_status_check_interval', 200, group="nsxv")

        cfg.CONF.set_override('api_extensions_path', vmware.NSXEXT_PATH)
        l3_attribute_map_bk = backup_l3_attribute_map()
        self.addCleanup(restore_l3_attribute_map, l3_attribute_map_bk)
        ext_mgr = ext_mgr or TestL3ExtensionManager()
        super(L3NatTest, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        self.plugin_instance = manager.NeutronManager.get_plugin()
        self._plugin_name = "%s.%s" % (
            self.plugin_instance.__module__,
            self.plugin_instance.__class__.__name__)
        self._plugin_class = self.plugin_instance.__class__

    def tearDown(self):
        plugin = manager.NeutronManager.get_plugin()
        _manager = plugin.nsx_v.task_manager
        # wait max ~10 seconds for all tasks to be finished
        for i in range(100):
            if not _manager.has_pending_task():
                break
            greenthread.sleep(0.1)
        if _manager.has_pending_task():
            _manager.show_pending_tasks()
            raise Exception(_("Tasks not completed"))
        _manager.stop()
        # Ensure the manager thread has been stopped
        self.assertIsNone(_manager._thread)
        super(L3NatTest, self).tearDown()

    def _create_l3_ext_network(self, vlan_id=None):
        name = 'l3_ext_net'
        return self.network(name=name,
                            router__external=True)

    def _create_router(self, fmt, tenant_id, name=None,
                       admin_state_up=None, set_context=False,
                       arg_list=None, **kwargs):
        tenant_id = tenant_id or _uuid()
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up:
            data['router']['admin_state_up'] = admin_state_up
        for arg in (('admin_state_up', 'tenant_id') + (arg_list or ())):
            # Arg must be present and not empty
            if kwargs.get(arg):
                data['router'][arg] = kwargs[arg]
        router_req = self.new_create_request('routers', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            router_req.environ['neutron.context'] = context.Context(
                '', tenant_id)

        return router_req.get_response(self.ext_api)

    def _make_router(self, fmt, tenant_id, name=None, admin_state_up=None,
                     external_gateway_info=None, set_context=False,
                     arg_list=None, **kwargs):
        if external_gateway_info:
            arg_list = ('external_gateway_info', ) + (arg_list or ())
        res = self._create_router(fmt, tenant_id, name,
                                  admin_state_up, set_context,
                                  arg_list=arg_list,
                                  external_gateway_info=external_gateway_info,
                                  **kwargs)
        return self.deserialize(fmt, res)

    @contextlib.contextmanager
    def router(self, name=None, admin_state_up=True,
               fmt=None, tenant_id=None,
               external_gateway_info=None, set_context=False,
               **kwargs):
        # avoid name duplication of edge
        if not name:
            name = _uuid()
        router = self._make_router(fmt or self.fmt, tenant_id, name,
                                   admin_state_up, external_gateway_info,
                                   set_context, **kwargs)
        yield router

    def _recursive_sort_list(self, lst):
        sorted_list = []
        for ele in lst:
            if isinstance(ele, list):
                sorted_list.append(self._recursive_sort_list(ele))
            elif isinstance(ele, dict):
                sorted_list.append(self._recursive_sort_dict(ele))
            else:
                sorted_list.append(ele)
        return sorted(sorted_list)

    def _recursive_sort_dict(self, dct):
        sorted_dict = {}
        for k, v in dct.items():
            if isinstance(v, list):
                sorted_dict[k] = self._recursive_sort_list(v)
            elif isinstance(v, dict):
                sorted_dict[k] = self._recursive_sort_dict(v)
            else:
                sorted_dict[k] = v
        return sorted_dict

    def _update_router_enable_snat(self, router_id, network_id, enable_snat):
        return self._update('routers', router_id,
                            {'router': {'external_gateway_info':
                                        {'network_id': network_id,
                                         'enable_snat': enable_snat}}})

    def test_floatingip_association_on_unowned_router(self):
        self.skipTest("Currently no support in plugin for this")


class L3NatTestCaseBase(test_l3_plugin.L3NatTestCaseMixin):

    def test_floatingip_multi_external_one_internal(self):
        with self.subnet(cidr="10.0.0.0/24",
                         enable_dhcp=False) as ext1,\
                self.subnet(cidr="11.0.0.0/24",
                            enable_dhcp=False) as ext2,\
                self.subnet(cidr="12.0.0.0/24",
                            enable_dhcp=False) as inter1:

            network_ex_id1 = ext1['subnet']['network_id']
            network_ex_id2 = ext2['subnet']['network_id']
            self._set_net_external(network_ex_id1)
            self._set_net_external(network_ex_id2)
            r2i_fixed_ips = [{'ip_address': '12.0.0.2'}]

            with self.router(no_delete=True) as r1,\
                    self.router(no_delete=True) as r2,\
                    self.port(subnet=inter1, fixed_ips=r2i_fixed_ips) as r2i:

                self._add_external_gateway_to_router(
                    r1['router']['id'],
                    network_ex_id1)
                self._router_interface_action('add', r1['router']['id'],
                                              inter1['subnet']['id'],
                                              None)
                self._add_external_gateway_to_router(
                    r2['router']['id'],
                    network_ex_id2)
                self._router_interface_action('add', r2['router']['id'],
                                              None,
                                              r2i['port']['id'])

                with self.port(subnet=inter1,
                               fixed_ips=[{'ip_address': '12.0.0.3'}]
                               ) as private_port:

                    fp1 = self._make_floatingip(self.fmt, network_ex_id1,
                                            private_port['port']['id'],
                                            floating_ip='10.0.0.3')
                    fp2 = self._make_floatingip(self.fmt, network_ex_id2,
                                            private_port['port']['id'],
                                            floating_ip='11.0.0.3')
                    self.assertEqual(fp1['floatingip']['router_id'],
                                     r1['router']['id'])
                    self.assertEqual(fp2['floatingip']['router_id'],
                                     r2['router']['id'])

    def test_create_floatingip_with_multisubnet_id(self):
        with self.network() as network:
            self._set_net_external(network['network']['id'])
            with self.subnet(network,
                             enable_dhcp=False,
                             cidr='10.0.12.0/24') as subnet1:
                with self.subnet(network,
                                 enable_dhcp=False,
                                 cidr='10.0.13.0/24') as subnet2:
                    with self.router():
                        res = self._create_floatingip(
                            self.fmt,
                            subnet1['subnet']['network_id'],
                            subnet_id=subnet1['subnet']['id'])
                        fip1 = self.deserialize(self.fmt, res)
                        res = self._create_floatingip(
                            self.fmt,
                            subnet1['subnet']['network_id'],
                            subnet_id=subnet2['subnet']['id'])
                        fip2 = self.deserialize(self.fmt, res)
        self.assertTrue(
            fip1['floatingip']['floating_ip_address'].startswith('10.0.12'))
        self.assertTrue(
            fip2['floatingip']['floating_ip_address'].startswith('10.0.13'))

    def test_create_floatingip_with_wrong_subnet_id(self):
        with self.network() as network1:
            self._set_net_external(network1['network']['id'])
            with self.subnet(network1,
                             enable_dhcp=False,
                             cidr='10.0.12.0/24') as subnet1:
                with self.network() as network2:
                    self._set_net_external(network2['network']['id'])
                    with self.subnet(network2,
                                     enable_dhcp=False,
                                     cidr='10.0.13.0/24') as subnet2:
                        with self.router():
                            res = self._create_floatingip(
                                self.fmt,
                                subnet1['subnet']['network_id'],
                                subnet_id=subnet2['subnet']['id'])
        self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

    @mock.patch.object(edge_utils, "update_firewall")
    def test_router_set_gateway_with_nosnat(self, mock):
        expected_fw = [{'action': 'allow',
                        'enabled': True,
                        'source_ip_address': [],
                        'destination_ip_address': []}]
        nosnat_fw = [{'action': 'allow',
                      'enabled': True,
                      'source_vnic_groups': ["external"],
                      'destination_ip_address': []}]

        with self.router() as r1,\
                self.subnet() as ext_subnet,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(cidr='12.0.0.0/24') as s2:
            self._set_net_external(ext_subnet['subnet']['network_id'])

            self._router_interface_action(
                'add', r1['router']['id'],
                s1['subnet']['id'], None)
            expected_fw[0]['source_ip_address'] = ['11.0.0.0/24']
            expected_fw[0]['destination_ip_address'] = ['11.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(self._recursive_sort_list(expected_fw),
                             self._recursive_sort_list(fw_rules))
            self._add_external_gateway_to_router(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'])
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(self._recursive_sort_list(expected_fw),
                             self._recursive_sort_list(fw_rules))
            self._update_router_enable_snat(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'],
                False)
            nosnat_fw[0]['destination_ip_address'] = ['11.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw + nosnat_fw),
                self._recursive_sort_list(fw_rules))
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            expected_fw[0]['source_ip_address'] = ['12.0.0.0/24',
                                                   '11.0.0.0/24']
            expected_fw[0]['destination_ip_address'] = ['12.0.0.0/24',
                                                        '11.0.0.0/24']
            nosnat_fw[0]['destination_ip_address'] = ['11.0.0.0/24',
                                                      '12.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw + nosnat_fw),
                self._recursive_sort_list(fw_rules))
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            expected_fw[0]['source_ip_address'] = ['12.0.0.0/24']
            expected_fw[0]['destination_ip_address'] = ['12.0.0.0/24']
            nosnat_fw[0]['destination_ip_address'] = ['12.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw + nosnat_fw),
                self._recursive_sort_list(fw_rules))
            self._update_router_enable_snat(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'],
                True)
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw),
                self._recursive_sort_list(fw_rules))
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._remove_external_gateway_from_router(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'])

    def test_router_add_interface_port_bad_tenant_returns_404(self):
        self.skipTest('TBD')

    def test_router_add_interface_subnet_with_bad_tenant_returns_404(self):
        self.skipTest('TBD')

    def test_create_floatingip_ipv6_only_network_returns_400(self):
        with self.subnet(cidr="2001:db8::/48", ip_version=6,
                         enable_dhcp=False) as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            res = self._create_floatingip(
                self.fmt,
                public_sub['subnet']['network_id'])
            self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

    def test_create_floatingip_ipv6_and_ipv4_network_creates_ipv4(self):
        with self.network() as n,\
                self.subnet(cidr="2001:db8::/48", ip_version=6, network=n,
                            enable_dhcp=False),\
                self.subnet(cidr="192.168.1.0/24", ip_version=4, network=n,
                            enable_dhcp=False):
            self._set_net_external(n['network']['id'])
            fip = self._make_floatingip(self.fmt, n['network']['id'])
            self.assertEqual(fip['floatingip']['floating_ip_address'],
                             '192.168.1.2')

    def test_create_floatingip_with_assoc_to_ipv6_subnet(self):
        with self.subnet() as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.subnet(cidr="2001:db8::/48",
                             ip_version=6, enable_dhcp=False) as private_sub:
                with self.port(subnet=private_sub) as private_port:
                    res = self._create_floatingip(
                        self.fmt,
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'])
                    self.assertEqual(res.status_int,
                                     webob.exc.HTTPBadRequest.code)

    def test_create_floatingip_with_assoc_to_ipv4_and_ipv6_port(self):
        with self.network() as n,\
                self.subnet(cidr='10.0.0.0/24', network=n) as s4,\
                self.subnet(cidr='2001:db8::/64', ip_version=6, network=n,
                            enable_dhcp=False),\
                self.port(subnet=s4) as p:
            self.assertEqual(len(p['port']['fixed_ips']), 2)
            ipv4_address = next(i['ip_address'] for i in
                    p['port']['fixed_ips'] if
                    netaddr.IPAddress(i['ip_address']).version == 4)
            with self.floatingip_with_assoc(port_id=p['port']['id']) as fip:
                self.assertEqual(fip['floatingip']['fixed_ip_address'],
                                 ipv4_address)
                floating_ip = netaddr.IPAddress(
                        fip['floatingip']['floating_ip_address'])
                self.assertEqual(floating_ip.version, 4)

    def test_router_add_interface_multiple_ipv6_subnets_same_net(self):
        """Test router-interface-add for multiple ipv6 subnets on a network.

        Verify that adding multiple ipv6 subnets from the same network
        to a router places them all on the same router interface.
        """
        with self.router() as r, self.network() as n:
            with (self.subnet(network=n, cidr='fd00::1/64',
                              enable_dhcp=False, ip_version=6)
                  ) as s1, self.subnet(network=n, cidr='fd01::1/64',
                                       ip_version=6, enable_dhcp=False) as s2:
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s1['subnet']['id'],
                                                         None)
                    pid1 = body['port_id']
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s2['subnet']['id'],
                                                         None)
                    pid2 = body['port_id']
                    self.assertEqual(pid1, pid2)
                    port = self._show('ports', pid1)
                    self.assertEqual(2, len(port['port']['fixed_ips']))
                    port_subnet_ids = [fip['subnet_id'] for fip in
                                       port['port']['fixed_ips']]
                    self.assertIn(s1['subnet']['id'], port_subnet_ids)
                    self.assertIn(s2['subnet']['id'], port_subnet_ids)
                    self._router_interface_action('remove', r['router']['id'],
                                                  s1['subnet']['id'], None)
                    self._router_interface_action('remove', r['router']['id'],
                                                  s2['subnet']['id'], None)

    def test_router_add_interface_multiple_ipv6_subnets_different_net(self):
        """Test router-interface-add for ipv6 subnets on different networks.

        Verify that adding multiple ipv6 subnets from different networks
        to a router places them on different router interfaces.
        """
        with self.router() as r, self.network() as n1, self.network() as n2:
            with (self.subnet(network=n1, cidr='fd00::1/64',
                              enable_dhcp=False, ip_version=6)
                  ) as s1, self.subnet(network=n2, cidr='fd01::1/64',
                                       ip_version=6, enable_dhcp=False) as s2:
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s1['subnet']['id'],
                                                         None)
                    pid1 = body['port_id']
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s2['subnet']['id'],
                                                         None)
                    pid2 = body['port_id']
                    self.assertNotEqual(pid1, pid2)
                    self._router_interface_action('remove', r['router']['id'],
                                                  s1['subnet']['id'], None)
                    self._router_interface_action('remove', r['router']['id'],
                                                  s2['subnet']['id'], None)

    def test_router_add_interface_ipv6_port_existing_network_returns_400(self):
        """Ensure unique IPv6 router ports per network id.

        Adding a router port containing one or more IPv6 subnets with the same
        network id as an existing router port should fail. This is so
        there is no ambiguity regarding on which port to add an IPv6 subnet
        when executing router-interface-add with a subnet and no port.
        """
        with self.network() as n, self.router() as r:
            with self.subnet(network=n, cidr='fd00::/64',
                             ip_version=6, enable_dhcp=False) as s1, (
                 self.subnet(network=n, cidr='fd01::/64',
                             ip_version=6, enable_dhcp=False)) as s2:
                with self.port(subnet=s1) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)
                    exp_code = webob.exc.HTTPBadRequest.code
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'],
                                                  expected_code=exp_code)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)

    def test_router_add_interface_multiple_ipv6_subnet_port(self):
        """A port with multiple IPv6 subnets can be added to a router

        Create a port with multiple associated IPv6 subnets and attach
        it to a router. The action should succeed.
        """
        with self.network() as n, self.router() as r:
            with self.subnet(network=n, cidr='fd00::/64',
                             ip_version=6, enable_dhcp=False) as s1, (
                 self.subnet(network=n, cidr='fd01::/64',
                             ip_version=6, enable_dhcp=False)) as s2:
                fixed_ips = [{'subnet_id': s1['subnet']['id']},
                             {'subnet_id': s2['subnet']['id']}]
                with self.port(subnet=s1, fixed_ips=fixed_ips) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_router_add_interface_ipv6_subnet_without_gateway_ip(self):
        with self.router() as r:
            with self.subnet(ip_version=6, cidr='fe80::/64',
                             gateway_ip=None, enable_dhcp=False) as s:
                error_code = webob.exc.HTTPBadRequest.code
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None,
                                              expected_code=error_code)

    def test_router_delete_ipv6_slaac_subnet_inuse_returns_409(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_router_delete_dhcpv6_stateless_subnet_inuse_returns_409(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_router_add_iface_ipv6_ext_ra_subnet_returns_400(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_router_remove_ipv6_subnet_from_interface(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_router_update_gateway_add_multiple_prefixes_ipv6(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_router_update_gateway_upon_subnet_create_ipv6(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_router_update_gateway_upon_subnet_create_max_ips_ipv6(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_floatingip_via_router_interface_returns_201(self):
        self.skipTest('not supported')

    def test_floatingip_via_router_interface_returns_404(self):
        self.skipTest('not supported')


class IPv6ExpectedFailuresTestMixin(object):

    def test_router_add_interface_ipv6_subnet(self):
        # Expect a 400 statuc code as IPv6 subnets w/DHCP are not supported
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            super(IPv6ExpectedFailuresTestMixin, self).\
                test_router_add_interface_ipv6_subnet()
            self.assertEqual(ctx_manager.exception.code, 400)

    def test_router_add_iface_ipv6_ext_ra_subnet_returns_400(self):
        # This returns a 400 too, but as an exception is raised the response
        # code need to be asserted differently
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            super(IPv6ExpectedFailuresTestMixin, self).\
                test_router_add_iface_ipv6_ext_ra_subnet_returns_400()
            self.assertEqual(ctx_manager.exception.code, 400)

    def test_router_add_gateway_multiple_subnets_ipv6(self):
        # Expect a 400 statuc code as IPv6 subnets w/DHCP are not supported
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            super(IPv6ExpectedFailuresTestMixin, self).\
                test_router_add_gateway_multiple_subnets_ipv6()
            self.assertEqual(ctx_manager.exception.code, 400)


class TestExclusiveRouterTestCase(L3NatTest, L3NatTestCaseBase,
                                  test_l3_plugin.L3NatDBIntTestCase,
                                  IPv6ExpectedFailuresTestMixin,
                                  NsxVPluginV2TestCase):

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None, service_plugins=None):
        super(TestExclusiveRouterTestCase, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        self.plugin_instance.nsx_v.is_subnet_in_use = mock.Mock()
        self.plugin_instance.nsx_v.is_subnet_in_use.return_value = False

    def _create_router(self, fmt, tenant_id, name=None,
                       admin_state_up=None, set_context=False,
                       arg_list=None, **kwargs):
        tenant_id = tenant_id or _uuid()
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up:
            data['router']['admin_state_up'] = admin_state_up
        for arg in (('admin_state_up', 'tenant_id') + (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs and kwargs[arg]:
                data['router'][arg] = kwargs[arg]

        data['router']['router_type'] = kwargs.get('router_type', 'exclusive')

        router_req = self.new_create_request('routers', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            router_req.environ['neutron.context'] = context.Context(
                '', tenant_id)

        return router_req.get_response(self.ext_api)

    def _test_create_l3_ext_network(self, vlan_id=0):
        name = 'l3_ext_net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (external_net.EXTERNAL, True)]
        with self._create_l3_ext_network(vlan_id) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_router_fail_at_the_backend(self):
        p = manager.NeutronManager.get_plugin()
        edge_manager = p.edge_manager
        with mock.patch.object(edge_manager, 'create_lrouter',
                               side_effect=[n_exc.NeutronException]):
            router = {'router': {'admin_state_up': True,
                      'name': 'e161be1d-0d0d-4046-9823-5a593d94f72c',
                      'tenant_id': context.get_admin_context().tenant_id,
                      'router_type': 'exclusive'}}
            self.assertRaises(n_exc.NeutronException,
                              p.create_router,
                              context.get_admin_context(),
                              router)
            self._test_list_resources('router', ())

    def test_create_l3_ext_network_with_dhcp(self):
        with self._create_l3_ext_network() as net:
            with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
                with self.subnet(network=net):
                    self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_l3_ext_network_without_vlan(self):
        self._test_create_l3_ext_network()

    def _test_router_create_with_gwinfo_and_l3_ext_net(self, vlan_id=None,
                                                       validate_ext_gw=False):
        with self._create_l3_ext_network(vlan_id) as net:
            with self.subnet(network=net, enable_dhcp=False) as s:
                data = {'router': {'tenant_id': 'whatever'}}
                data['router']['name'] = 'router1'
                data['router']['external_gateway_info'] = {
                    'network_id': s['subnet']['network_id']}
                router_req = self.new_create_request('routers', data,
                                                     self.fmt)
                res = router_req.get_response(self.ext_api)
                router = self.deserialize(self.fmt, res)
                self.assertEqual(
                    s['subnet']['network_id'],
                    (router['router']['external_gateway_info']
                     ['network_id']))
                if validate_ext_gw:
                    pass

    def test_router_create_with_gwinfo_and_l3_ext_net(self):
        self._test_router_create_with_gwinfo_and_l3_ext_net()

    def test_router_create_with_gwinfo_and_l3_ext_net_with_vlan(self):
        self._test_router_create_with_gwinfo_and_l3_ext_net(444)

    def test_router_create_with_different_sizes(self):
        data = {'router': {
                    'tenant_id': 'whatever',
                    'name': 'test_router',
                    'router_type': 'exclusive'}}
        for size in ['compact', 'large', 'xlarge', 'quadlarge']:
            data['router']['router_size'] = size
            router_req = self.new_create_request('routers', data, self.fmt)
            res = router_req.get_response(self.ext_api)
            router = self.deserialize(self.fmt, res)
            self.assertEqual(size, router['router']['router_size'])

    def test_router_create_overriding_default_edge_size(self):
        data = {'router': {
                    'tenant_id': 'whatever',
                    'name': 'test_router',
                    'router_type': 'exclusive'}}
        cfg.CONF.set_override('exclusive_router_appliance_size',
                              'xlarge', group='nsxv')
        router_req = self.new_create_request('routers', data, self.fmt)
        res = router_req.get_response(self.ext_api)
        router = self.deserialize(self.fmt, res)
        self.assertEqual('xlarge', router['router']['router_size'])

    def test_router_add_gateway_invalid_network_returns_404(self):
        # NOTE(salv-orlando): This unit test has been overridden
        # as the nsx plugin support the ext_gw_mode extension
        # which mandates an uuid for the external network identifier
        with self.router() as r:
            self._add_external_gateway_to_router(
                r['router']['id'],
                uuidutils.generate_uuid(),
                expected_code=webob.exc.HTTPNotFound.code)

    def _test_router_update_gateway_on_l3_ext_net(self, vlan_id=None,
                                                  validate_ext_gw=False,
                                                  distributed=False):
        with self.router(
            arg_list=('distributed',), distributed=distributed) as r:
            with self.subnet() as s1:
                with self._create_l3_ext_network(vlan_id) as net:
                    with self.subnet(network=net, enable_dhcp=False) as s2:
                        self._set_net_external(s1['subnet']['network_id'])
                        try:
                            self._add_external_gateway_to_router(
                                r['router']['id'],
                                s1['subnet']['network_id'])
                            body = self._show('routers', r['router']['id'])
                            net_id = (body['router']
                                      ['external_gateway_info']['network_id'])
                            self.assertEqual(net_id,
                                             s1['subnet']['network_id'])
                            # Plug network with external mapping
                            self._set_net_external(s2['subnet']['network_id'])
                            self._add_external_gateway_to_router(
                                r['router']['id'],
                                s2['subnet']['network_id'])
                            body = self._show('routers', r['router']['id'])
                            net_id = (body['router']
                                      ['external_gateway_info']['network_id'])
                            self.assertEqual(net_id,
                                             s2['subnet']['network_id'])
                            if validate_ext_gw:
                                pass
                        finally:
                            # Cleanup
                            self._remove_external_gateway_from_router(
                                r['router']['id'],
                                s2['subnet']['network_id'])

    def test_router_update_gateway_on_l3_ext_net(self):
        self._test_router_update_gateway_on_l3_ext_net()

    def test_router_update_gateway_on_l3_ext_net_with_vlan(self):
        self._test_router_update_gateway_on_l3_ext_net(444)

    def test_router_update_gateway_with_existing_floatingip(self):
        with self._create_l3_ext_network() as net:
            with self.subnet(network=net, enable_dhcp=False) as subnet:
                with self.floatingip_with_assoc() as fip:
                    self._add_external_gateway_to_router(
                        fip['floatingip']['router_id'],
                        subnet['subnet']['network_id'],
                        expected_code=webob.exc.HTTPConflict.code)

    def test_router_list_by_tenant_id(self):
        with self.router(), self.router():
            with self.router(tenant_id='custom') as router:
                self._test_list_resources('router', [router],
                                          query_params="tenant_id=custom")

    def test_create_l3_ext_network_with_vlan(self):
        self._test_create_l3_ext_network(666)

    def test_floatingip_with_assoc_fails(self):
        self._test_floatingip_with_assoc_fails(
            self._plugin_name + '._check_and_get_fip_assoc')

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)

    def test_floatingip_update(self):
        super(TestExclusiveRouterTestCase, self).test_floatingip_update(
            constants.FLOATINGIP_STATUS_DOWN)

    def test_floatingip_disassociate(self):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.floatingip_no_assoc(private_sub) as fip:
                self.assertEqual(fip['floatingip']['status'],
                                 constants.FLOATINGIP_STATUS_DOWN)
                port_id = p['port']['id']
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': port_id}})
                self.assertEqual(body['floatingip']['port_id'], port_id)
                self.assertEqual(body['floatingip']['status'],
                                 constants.FLOATINGIP_STATUS_ACTIVE)
                # Disassociate
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': None}})
                body = self._show('floatingips', fip['floatingip']['id'])
                self.assertIsNone(body['floatingip']['port_id'])
                self.assertIsNone(body['floatingip']['fixed_ip_address'])
                self.assertEqual(body['floatingip']['status'],
                                 constants.FLOATINGIP_STATUS_DOWN)

    def test_update_floatingip_with_edge_router_update_failure(self):
        p = manager.NeutronManager.get_plugin()
        with self.subnet() as subnet,\
                self.port(subnet=subnet) as p1,\
                self.port(subnet=subnet) as p2:
            p1_id = p1['port']['id']
            p2_id = p2['port']['id']
            with self.floatingip_with_assoc(port_id=p1_id) as fip:
                with self._mock_edge_router_update_with_exception():
                    self.assertRaises(object,
                                      p.update_floatingip,
                                      context.get_admin_context(),
                                      fip['floatingip']['id'],
                                      floatingip={'floatingip':
                                                  {'port_id': p2_id}})
                res = self._list(
                    'floatingips', query_params="port_id=%s" % p1_id)
                self.assertEqual(len(res['floatingips']), 1)
                res = self._list(
                    'floatingips', query_params="port_id=%s" % p2_id)
                self.assertEqual(len(res['floatingips']), 0)

    def test_create_floatingip_with_edge_router_update_failure(self):
        p = manager.NeutronManager.get_plugin()
        with self.subnet(cidr='200.0.0.0/24') as public_sub:
            public_network_id = public_sub['subnet']['network_id']
            self._set_net_external(public_network_id)
            with self.port() as private_port:
                port_id = private_port['port']['id']
                tenant_id = private_port['port']['tenant_id']
                subnet_id = private_port['port']['fixed_ips'][0]['subnet_id']
                with self.router() as r:
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  subnet_id,
                                                  None)
                    floatingip = {'floatingip': {
                                  'tenant_id': tenant_id,
                                  'floating_network_id': public_network_id,
                                  'port_id': port_id}}

                    with self._mock_edge_router_update_with_exception():
                        self.assertRaises(object,
                                          p.create_floatingip,
                                          context.get_admin_context(),
                                          floatingip=floatingip)
                        res = self._list(
                            'floatingips', query_params="port_id=%s" % port_id)
                        self.assertEqual(len(res['floatingips']), 0)
                    # Cleanup
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  subnet_id,
                                                  None)
                    self._remove_external_gateway_from_router(
                        r['router']['id'], public_network_id)

    @contextlib.contextmanager
    def _mock_edge_router_update_with_exception(self):
        nsx_router_update = PLUGIN_NAME + '._update_edge_router'
        with mock.patch(nsx_router_update) as update_edge:
            update_edge.side_effect = object()
            yield update_edge

    @mock.patch.object(edge_utils, "update_firewall")
    def test_router_interfaces_with_update_firewall(self, mock):
        s1_cidr = '10.0.0.0/24'
        s2_cidr = '11.0.0.0/24'
        with self.router() as r,\
                self.subnet(cidr=s1_cidr) as s1,\
                self.subnet(cidr=s2_cidr) as s2:

            self._router_interface_action('add',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            expected_cidrs = [s1_cidr, s2_cidr]
            expected_fw = [{'action': 'allow',
                            'enabled': True,
                            'source_ip_address': expected_cidrs,
                            'destination_ip_address': expected_cidrs}]
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(self._recursive_sort_list(expected_fw),
                             self._recursive_sort_list(fw_rules))
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s2['subnet']['id'],
                                          None)

    @mock.patch.object(edge_utils, "update_firewall")
    def test_router_interfaces_with_update_firewall_metadata(self, mock):
        self.plugin_instance.metadata_proxy_handler = mock.Mock()
        s1_cidr = '10.0.0.0/24'
        s2_cidr = '11.0.0.0/24'
        with self.router() as r,\
                self.subnet(cidr=s1_cidr) as s1,\
                self.subnet(cidr=s2_cidr) as s2:
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            # build the list of expected fw rules
            expected_cidrs = [s1_cidr, s2_cidr]
            fw_rule = {'action': 'allow',
                       'enabled': True,
                       'source_ip_address': expected_cidrs,
                       'destination_ip_address': expected_cidrs}
            vse_rule = {'action': 'allow',
                        'enabled': True,
                        'name': 'VSERule',
                        'source_vnic_groups': ['vse']}
            dest_intern = [md_proxy.INTERNAL_SUBNET]
            md_inter = {'action': 'deny',
                        'destination_ip_address': dest_intern,
                        'enabled': True,
                        'name': 'MDInterEdgeNet'}
            dest_srvip = [md_proxy.METADATA_IP_ADDR]
            md_srvip = {'action': 'allow',
                        'destination_ip_address': dest_srvip,
                        'destination_port': '80,443,8775',
                        'enabled': True,
                        'name': 'MDServiceIP',
                        'protocol': 'tcp'}
            expected_fw = [fw_rule,
                           vse_rule,
                           md_inter,
                           md_srvip]
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(self._recursive_sort_list(expected_fw),
                             self._recursive_sort_list(fw_rules))

            # Also test the md_srvip conversion:
            drv = edge_firewall_driver.EdgeFirewallDriver()
            rule = drv._convert_firewall_rule(
                context.get_admin_context(), md_srvip)
            exp_service = {'service': [{'port': [80, 443, 8775],
                                        'protocol': 'tcp'}]}
            exp_rule = {'action': 'accept',
                        'application': exp_service,
                        'destination': {'ipAddress': dest_srvip},
                        'enabled': True,
                        'name': 'MDServiceIP'}
            self.assertEqual(exp_rule, rule)

            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s2['subnet']['id'],
                                          None)

    @mock.patch.object(edge_utils, "update_firewall")
    def test_router_interfaces_with_update_firewall_metadata_conf(self, mock):
        """Test the metadata proxy firewall rule with additional configured ports
        """
        cfg.CONF.set_override('metadata_service_allowed_ports',
            ['55', ' 66 ', '55', 'xx'], group='nsxv')
        self.plugin_instance.metadata_proxy_handler = mock.Mock()
        s1_cidr = '10.0.0.0/24'
        with self.router() as r,\
                self.subnet(cidr=s1_cidr) as s1:
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            # build the expected fw rule
            # at this stage the string of ports is not sorted/unique/validated
            dest_srvip = [md_proxy.METADATA_IP_ADDR]
            rule_name = 'MDServiceIP'
            md_srvip = {'action': 'allow',
                        'destination_ip_address': dest_srvip,
                        'destination_port': '80,443,8775,55, 66 ,55,xx',
                        'enabled': True,
                        'name': rule_name,
                        'protocol': 'tcp'}
            # compare it to the rule with the same name
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            rule_found = False
            for fw_rule in fw_rules:
                if (attributes.is_attr_set(fw_rule.get("name")) and
                    fw_rule['name'] == rule_name):
                    self.assertEqual(md_srvip, fw_rule)
                    rule_found = True
                    break
            self.assertTrue(rule_found)

            # Also test the rule conversion
            # Ports should be sorted & unique, and ignore non numeric values
            drv = edge_firewall_driver.EdgeFirewallDriver()
            rule = drv._convert_firewall_rule(
                context.get_admin_context(), md_srvip)
            exp_service = {'service': [{'port': [55, 66, 80, 443, 8775],
                                        'protocol': 'tcp'}]}
            exp_rule = {'action': 'accept',
                        'application': exp_service,
                        'destination': {'ipAddress': dest_srvip},
                        'enabled': True,
                        'name': 'MDServiceIP'}
            self.assertEqual(exp_rule, rule)

    @mock.patch.object(edge_utils, "update_firewall")
    def test_router_interfaces_different_tenants_update_firewall(self, mock):
        tenant_id = _uuid()
        other_tenant_id = _uuid()
        s1_cidr = '10.0.0.0/24'
        s2_cidr = '11.0.0.0/24'
        with self.router(tenant_id=tenant_id) as r,\
                self.network(tenant_id=tenant_id) as n1,\
                self.network(tenant_id=other_tenant_id) as n2,\
                self.subnet(network=n1, cidr=s1_cidr) as s1,\
                self.subnet(network=n2, cidr=s2_cidr) as s2:

            self._router_interface_action('add',
                                          r['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None,
                                          tenant_id=tenant_id)
            expected_cidrs = [s1_cidr, s2_cidr]
            expected_fw = [{'action': 'allow',
                            'enabled': True,
                            'source_ip_address': expected_cidrs,
                            'destination_ip_address': expected_cidrs}]
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(self._recursive_sort_list(expected_fw),
                             self._recursive_sort_list(fw_rules))
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None,
                                          tenant_id=tenant_id)
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            expected_fw = []
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(expected_fw, fw_rules)

    def test_delete_ext_net_with_disassociated_floating_ips(self):
        with self.network() as net:
            net_id = net['network']['id']
            self._set_net_external(net_id)
            with self.subnet(network=net, enable_dhcp=False):
                self._make_floatingip(self.fmt, net_id)

    def test_create_router_gateway_fails(self):
        self.skipTest('not supported')

    def test_migrate_exclusive_router_to_shared(self):
        with self._create_l3_ext_network() as net:
            with self.subnet(network=net, enable_dhcp=False) as s:
                data = {'router': {'tenant_id': 'whatever'}}
                data['router']['name'] = 'router1'
                data['router']['external_gateway_info'] = {
                    'network_id': s['subnet']['network_id']}
                data['router']['router_type'] = 'exclusive'

                router_req = self.new_create_request('routers', data,
                                                     self.fmt)
                res = router_req.get_response(self.ext_api)
                router = self.deserialize(self.fmt, res)
                # update the router type:
                router_id = router['router']['id']
                self._update('routers', router_id,
                             {'router': {'router_type': 'shared'}})

                # get the updated router and check it's type
                body = self._show('routers', router_id)
                self.assertEqual('shared', body['router']['router_type'])

    @mock.patch.object(edge_utils.EdgeManager,
                       'update_interface_addr')
    def test_router_update_gateway_with_different_external_subnet(self, mock):
        # This test calls the backend, so we need a mock for the edge_utils
        super(
            TestExclusiveRouterTestCase,
            self).test_router_update_gateway_with_different_external_subnet()

    @mock.patch.object(edge_utils.EdgeManager,
                       'update_interface_addr')
    def test_router_add_interface_multiple_ipv6_subnets_same_net(self, mock):
        # This test calls the backend, so we need a mock for the edge_utils
        super(
            TestExclusiveRouterTestCase,
            self).test_router_add_interface_multiple_ipv6_subnets_same_net()

    def test_create_router_with_update_error(self):
        p = manager.NeutronManager.get_plugin()

        # make sure there is an available edge so we will use backend update
        available_edge = {'edge_id': 'edge-11', 'router_id': 'fake_id'}
        nsxv_db.add_nsxv_router_binding(
            context.get_admin_context().session, available_edge['router_id'],
            available_edge['edge_id'], None, plugin_const.ACTIVE)
        with mock.patch.object(p.edge_manager,
                               '_get_available_router_binding',
                               return_value=available_edge):
            # Mock for update_edge task failure
            with mock.patch.object(
                p.nsx_v, '_update_edge',
                return_value=task_constants.TaskStatus.ERROR):
                router = {'router': {'admin_state_up': True,
                          'name': 'e161be1d-0d0d-4046-9823-5a593d94f72c',
                          'tenant_id': context.get_admin_context().tenant_id,
                          'router_type': 'exclusive'}}
                # router creation should succeed
                returned_router = p.create_router(context.get_admin_context(),
                                                  router)
                # router status should be 'error'
                self.assertEqual(plugin_const.ERROR, returned_router['status'])

                # check the same after get_router
                new_router = p.get_router(context.get_admin_context(),
                                          returned_router['id'])
                self.assertEqual(plugin_const.ERROR, new_router['status'])


class ExtGwModeTestCase(NsxVPluginV2TestCase,
                        test_ext_gw_mode.ExtGwModeIntTestCase):
    pass


class NsxVSecurityGroupsTestCase(ext_sg.SecurityGroupDBTestCase):
    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        test_utils.override_nsx_ini_test()
        mock_vcns = mock.patch(vmware.VCNS_NAME, autospec=True)
        mock_vcns_instance = mock_vcns.start()
        self.fc2 = fake_vcns.FakeVcns()
        mock_vcns_instance.return_value = self.fc2
        edge_utils.query_dhcp_service_config = mock.Mock(return_value=[])
        mock_create_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'create_dhcp_edge_service'))
        mock_create_dhcp_service.start()
        mock_update_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'update_dhcp_edge_service'))
        mock_update_dhcp_service.start()
        mock_delete_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'delete_dhcp_edge_service'))
        mock_delete_dhcp_service.start()
        super(NsxVSecurityGroupsTestCase, self).setUp(plugin=plugin,
                                                      ext_mgr=ext_mgr)
        self.plugin = manager.NeutronManager.get_plugin()
        self.addCleanup(self.fc2.reset_all)


class NsxVTestSecurityGroup(ext_sg.TestSecurityGroups,
                            NsxVSecurityGroupsTestCase):

    @mock.patch.object(edge_utils.EdgeManager, '_deploy_edge')
    def setUp(self, mock_deploy,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):

        super(NsxVTestSecurityGroup, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        plugin_instance = manager.NeutronManager.get_plugin()
        plugin_instance._get_edge_id_by_rtr_id = mock.Mock()
        plugin_instance._get_edge_id_by_rtr_id.return_value = False

    def test_list_ports_security_group(self):
        with self.network() as n:
            with self.subnet(n, enable_dhcp=False):
                self._create_port(self.fmt, n['network']['id'])
                req = self.new_list_request('ports')
                res = req.get_response(self.api)
                ports = self.deserialize(self.fmt, res)
                port = ports['ports'][0]
                self.assertEqual(len(port[secgrp.SECURITYGROUPS]), 1)
                self._delete('ports', port['id'])

    def test_vnic_security_group_membership(self):
        p = manager.NeutronManager.get_plugin()
        self.fc2.add_member_to_security_group = (
            mock.Mock().add_member_to_security_group)
        self.fc2.remove_member_from_security_group = (
            mock.Mock().remove_member_from_security_group)
        nsx_sg_id = str(self.fc2._securitygroups['ids'])
        device_id = _uuid()
        port_index = 0
        # The expected vnic-id format by NsxV
        vnic_id = '%s.%03d' % (device_id, port_index)
        with self.port(device_id=device_id,
                       device_owner='compute:None') as port:
            (self.fc2.add_member_to_security_group
             .assert_called_once_with(p.sg_container_id, nsx_sg_id))
            self.fc2.add_member_to_security_group.reset_mock()
            data = {'port': {'vnic_index': port_index}}
            self.new_update_request('ports', data,
                                    port['port']['id']).get_response(self.api)
            # The vnic should be added as a member to the nsx-security-groups
            # which match the port security-groups
            (self.fc2.add_member_to_security_group
             .assert_called_once_with(nsx_sg_id, vnic_id))

        # The vnic should be removed from the nsx-security-groups which match
        # the deleted port security-groups
        #TODO(kobis): Port is not removed automatically
        # (self.fc2.remove_member_from_security_group
        #  .assert_called_once_with(nsx_sg_id, vnic_id))

    def test_skip_duplicate_default_sg_error(self):
        num_called = [0]
        original_func = self.plugin.create_security_group

        def side_effect(context, security_group, default_sg):
            # can't always raise, or create_security_group will hang
            self.assertTrue(default_sg)
            self.assertTrue(num_called[0] < 2)
            num_called[0] += 1
            ret = original_func(context, security_group, default_sg)
            if num_called[0] == 1:
                return ret
            # make another call to cause an exception.
            # NOTE(yamamoto): raising the exception by ourselves
            # doesn't update the session state appropriately.
            self.assertRaises(db_exc.DBDuplicateEntry(),
                              original_func, context, security_group,
                              default_sg)

        with mock.patch.object(self.plugin,
                               'create_security_group',
                               side_effect=side_effect):
            self.plugin.create_network(
                context.get_admin_context(),
                {'network': {'name': 'foo',
                             'admin_state_up': True,
                             'shared': False,
                             'tenant_id': 'bar',
                             'port_security_enabled': True}})

    def test_create_secgroup_deleted_upon_fw_section_create_fail(self):
        _context = context.Context('', 'tenant_id')
        sg = {'security_group': {'name': 'default',
                                 'tenant_id': 'tenant_id',
                                 'description': ''}}
        expected_id = str(self.fc2._securitygroups['ids'])
        with mock.patch.object(self.fc2,
                               'create_section') as create_section:
            with mock.patch.object(self.fc2,
                                   'delete_security_group') as delete_sg:

                create_section.side_effect = webob.exc.HTTPInternalServerError
                self.assertRaises(webob.exc.HTTPInternalServerError,
                                  self.plugin.create_security_group,
                                  _context.elevated(), sg, default_sg=True)
                delete_sg.assert_called_once_with(expected_id)

    def test_create_security_group_rule_duplicate_rules(self):
        name = 'webservers'
        description = 'my webservers'
        with mock.patch.object(self.plugin.nsx_v.vcns,
                               'remove_rule_from_section') as rm_rule_mock:
            with self.security_group(name, description) as sg:
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    constants.PROTO_NAME_TCP, '22', '22')
                self._create_security_group_rule(self.fmt, rule)
                res = self._create_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)
        rm_rule_mock.assert_called_once_with(mock.ANY, mock.ANY)

    def test_create_security_group_rule_with_specific_id(self):
        # This test is aimed to test the security-group db mixin
        pass


class TestVdrTestCase(L3NatTest, L3NatTestCaseBase,
                      test_l3_plugin.L3NatDBIntTestCase,
                      IPv6ExpectedFailuresTestMixin,
                      NsxVPluginV2TestCase):

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None, service_plugins=None):
        super(TestVdrTestCase, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        self.plugin_instance.nsx_v.is_subnet_in_use = mock.Mock()
        self.plugin_instance.nsx_v.is_subnet_in_use.return_value = False
        self._default_tenant_id = self._tenant_id
        self._router_tenant_id = 'test-router-tenant'

    @mock.patch.object(edge_utils.EdgeManager,
                       'update_interface_addr')
    def test_router_update_gateway_with_different_external_subnet(self, mock):
        # This test calls the backend, so we need a mock for the edge_utils
        super(
            TestVdrTestCase,
            self).test_router_update_gateway_with_different_external_subnet()

    def test_floatingip_multi_external_one_internal(self):
        self.skipTest('skipped')

    def test_router_add_interface_dup_subnet2_returns_400(self):
        self.skipTest('skipped')

    def test_floatingip_same_external_and_internal(self):
        self.skipTest('skipped')

    def test_create_router_fail_at_the_backend(self):
        p = manager.NeutronManager.get_plugin()
        edge_manager = p.edge_manager
        with mock.patch.object(edge_manager, 'create_lrouter',
                               side_effect=[n_exc.NeutronException]):
            router = {'router': {'admin_state_up': True,
                      'name': 'e161be1d-0d0d-4046-9823-5a593d94f72c',
                      'tenant_id': context.get_admin_context().tenant_id,
                      'distributed': True}}
            self.assertRaises(n_exc.NeutronException,
                              p.create_router,
                              context.get_admin_context(),
                              router)
            self._test_list_resources('router', ())

    def test_update_port_device_id_to_different_tenants_router(self):
        self.skipTest('TBD')

    def test_router_add_and_remove_gateway_tenant_ctx(self):
        self.skipTest('TBD')

    def _create_router(self, fmt, tenant_id, name=None,
                       admin_state_up=None, set_context=False,
                       arg_list=None, **kwargs):
        tenant_id = tenant_id or _uuid()
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up:
            data['router']['admin_state_up'] = admin_state_up
        for arg in (('admin_state_up', 'tenant_id') + (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs and kwargs[arg]:
                data['router'][arg] = kwargs[arg]

        if 'distributed' in kwargs:
                data['router']['distributed'] = kwargs['distributed']
        else:
                data['router']['distributed'] = True

        if kwargs.get('router_type'):
            data['router']['router_type'] = kwargs.get('router_type')

        router_req = self.new_create_request('routers', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            router_req.environ['neutron.context'] = context.Context(
                '', tenant_id)

        return router_req.get_response(self.ext_api)

    def _test_router_create_with_distributed(self, dist_input, dist_expected,
                                             return_code=201, **kwargs):
        data = {'tenant_id': 'whatever'}
        data['name'] = 'router1'
        data['distributed'] = dist_input
        for k, v in six.iteritems(kwargs):
            data[k] = v
        router_req = self.new_create_request(
            'routers', {'router': data}, self.fmt)
        res = router_req.get_response(self.ext_api)
        self.assertEqual(return_code, res.status_int)
        if res.status_int == 201:
            router = self.deserialize(self.fmt, res)
            self.assertIn('distributed', router['router'])
            if dist_input:
                self.assertNotIn('router_type', router['router'])
            self.assertEqual(dist_expected,
                             router['router']['distributed'])

    def test_create_router_fails_with_router_type(self):
        self._test_router_create_with_distributed(True, True,
                                                  return_code=400,
                                                  router_type="shared")

    def test_router_create_distributed(self):
        self._test_router_create_with_distributed(True, True)

    def test_router_create_not_distributed(self):
        self._test_router_create_with_distributed(False, False)

    def test_router_create_distributed_unspecified(self):
        self._test_router_create_with_distributed(None, False)

    def test_floatingip_with_assoc_fails(self):
        self._test_floatingip_with_assoc_fails(
            self._plugin_name + '._check_and_get_fip_assoc')

    def test_floatingip_update(self):
        super(TestVdrTestCase, self).test_floatingip_update(
            constants.FLOATINGIP_STATUS_DOWN)

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)

    def test_router_add_gateway_invalid_network_returns_404(self):
        with self.router() as r:
            self._add_external_gateway_to_router(
                r['router']['id'],
                uuidutils.generate_uuid(),
                expected_code=webob.exc.HTTPNotFound.code)

    def test_router_add_interfaces_with_multiple_subnets_on_same_network(self):
        with self.router() as r,\
                self.network() as n,\
                self.subnet(network=n) as s1,\
                self.subnet(network=n, cidr='11.0.0.0/24') as s2:
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            err_code = webob.exc.HTTPBadRequest.code
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s2['subnet']['id'],
                                          None,
                                          err_code)
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None)

    def test_router_add_interface_with_external_net_fail(self):
        with self.router() as r,\
                self.network() as n,\
                self.subnet(network=n) as s:
            # Set the network as an external net
            net_id = n['network']['id']
            self._set_net_external(net_id)
            err_code = webob.exc.HTTPBadRequest.code
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s['subnet']['id'],
                                          None,
                                          err_code)

    def test_different_type_routers_add_interfaces_on_same_network_pass(self):
        with self.router() as dist, \
            self.router(distributed=False, router_type='shared') as shared, \
            self.router(distributed=False, router_type='exclusive') as excl:
            with self.network() as n:
                with self.subnet(network=n) as s1, \
                    self.subnet(network=n, cidr='11.0.0.0/24') as s2, \
                    self.subnet(network=n, cidr='12.0.0.0/24') as s3:
                    self._router_interface_action('add',
                                                  shared['router']['id'],
                                                  s1['subnet']['id'],
                                                  None)
                    self._router_interface_action('add',
                                                  excl['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)
                    self._router_interface_action('add',
                                                  dist['router']['id'],
                                                  s3['subnet']['id'],
                                                  None)
                    self._router_interface_action('remove',
                                                  dist['router']['id'],
                                                  s3['subnet']['id'],
                                                  None)
                    self._router_interface_action('remove',
                                                  excl['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)
                    self._router_interface_action('remove',
                                                  shared['router']['id'],
                                                  s1['subnet']['id'],
                                                  None)

    def test_delete_ext_net_with_disassociated_floating_ips(self):
        with self.network() as net:
            net_id = net['network']['id']
            self._set_net_external(net_id)
            with self.subnet(network=net, enable_dhcp=False):
                self._make_floatingip(self.fmt, net_id)

    def test_router_add_interface_multiple_ipv4_subnets(self):
        self.skipTest('TBD')

    def test_router_remove_ipv6_subnet_from_interface(self):
        self.skipTest('TBD')

    def test_router_add_interface_multiple_ipv6_subnets_same_net(self):
        self.skipTest('TBD')

    def test_router_add_interface_multiple_ipv6_subnets_different_net(self):
        self.skipTest('TBD')

    def test_create_router_gateway_fails(self):
        self.skipTest('not supported')


class TestNSXvAllowedAddressPairs(NsxVPluginV2TestCase,
                                  test_addr_pair.TestAllowedAddressPairs):

    def setUp(self, plugin=PLUGIN_NAME):
        super(TestNSXvAllowedAddressPairs, self).setUp(plugin=plugin)

    # NOTE: the tests below are skipped due to the fact that they update the
    # mac address. The NSX|V does not support address pairs when a MAC address
    # is configured.
    def test_create_port_allowed_address_pairs(self):
        pass

    def test_update_add_address_pairs(self):
        pass

    def test_equal_to_max_allowed_address_pair(self):
        pass

    def test_update_port_security_off_address_pairs(self):
        pass

    def test_create_port_security_true_allowed_address_pairs(self):
        pass

    def test_create_port_security_false_allowed_address_pairs(self):
        pass

    def _test_create_port_remove_allowed_address_pairs(self, update_value):
        pass

    def test_create_overlap_with_fixed_ip(self):
        pass

    def test_get_vlan_network_name(self):
        pass


class TestNSXPortSecurity(test_psec.TestPortSecurity,
                          NsxVPluginV2TestCase):
    def setUp(self, plugin=PLUGIN_NAME):
        super(TestNSXPortSecurity, self).setUp(plugin=plugin)

    def test_create_port_fails_with_secgroup_and_port_security_false(self):
        # Security Groups can be used even when port-security is disabled
        pass

    def test_update_port_security_off_with_security_group(self):
        # Security Groups can be used even when port-security is disabled
        pass

    def test_create_port_security_overrides_network_value(self):
        pass

    def test_create_port_with_security_group_and_net_sec_false(self):
        pass

    def test_create_port_security_doese_not_overrides_network_value(self):
        """NSXv plugin port port-security-enabled is decided by the networks
        port-security state
        """
        res = self._create_network('json', 'net1', True,
                                   arg_list=('port_security_enabled',),
                                   port_security_enabled=False)
        net = self.deserialize('json', res)
        res = self._create_port('json', net['network']['id'],
                                arg_list=('port_security_enabled',),
                                port_security_enabled=True)
        port = self.deserialize('json', res)
        self.assertEqual(port['port'][psec.PORTSECURITY], False)
        self._delete('ports', port['port']['id'])

    def test_update_port_remove_port_security_security_group(self):
        pass

    def test_update_port_remove_port_security_security_group_read(self):
        pass

    def test_update_port_port_security_raise_not_implemented(self):
        with self.network() as net:
            with self.subnet(network=net) as sub:
                with self.port(subnet=sub) as port:
                    update_port = {'port': {psec.PORTSECURITY: False}}
                    plugin = manager.NeutronManager.get_plugin()
                    self.assertRaises(NotImplementedError,
                                      plugin.update_port,
                                      context.get_admin_context(),
                                      port['port']['id'], update_port)


class TestSharedRouterTestCase(L3NatTest, L3NatTestCaseBase,
                               test_l3_plugin.L3NatTestCaseMixin,
                               NsxVPluginV2TestCase):

    def _create_router(self, fmt, tenant_id, name=None,
                       admin_state_up=None, set_context=False,
                       arg_list=None, **kwargs):
        tenant_id = tenant_id or _uuid()
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up:
            data['router']['admin_state_up'] = admin_state_up
        for arg in (('admin_state_up', 'tenant_id') + (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs and kwargs[arg]:
                data['router'][arg] = kwargs[arg]

        data['router']['router_type'] = kwargs.get('router_type', 'shared')

        router_req = self.new_create_request('routers', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            router_req.environ['neutron.context'] = context.Context(
                '', tenant_id)

        return router_req.get_response(self.ext_api)

    @mock.patch.object(edge_utils.EdgeManager,
                       'update_interface_addr')
    def test_router_add_interface_multiple_ipv6_subnets_same_net(self, mock):
        super(TestSharedRouterTestCase,
              self).test_router_add_interface_multiple_ipv6_subnets_same_net()

    def test_router_create_with_no_edge(self):
        name = 'router1'
        tenant_id = _uuid()
        expected_value = [('name', name), ('tenant_id', tenant_id),
                          ('admin_state_up', True), ('status', 'ACTIVE'),
                          ('external_gateway_info', None)]
        with self.router(name='router1', admin_state_up=True,
                         tenant_id=tenant_id) as router:
            for k, v in expected_value:
                self.assertEqual(router['router'][k], v)
            self.assertEqual(
                [],
                self.plugin_instance.edge_manager.get_routers_on_same_edge(
                    context.get_admin_context(), router['router']['id']))

    def test_router_create_with_size_fail_at_backend(self):
        data = {'router': {
                    'tenant_id': 'whatever',
                    'router_type': 'shared',
                    'router_size': 'large'}}
        router_req = self.new_create_request('routers', data, self.fmt)
        res = router_req.get_response(self.ext_api)
        router = self.deserialize(self.fmt, res)
        msg = ('Bad router request: '
               'Cannot specify router-size for shared router.')
        self.assertEqual("BadRequest", router['NeutronError']['type'])
        self.assertEqual(msg, router['NeutronError']['message'])

    def test_router_create_with_gwinfo_with_no_edge(self):
        with self._create_l3_ext_network() as net:
            with self.subnet(network=net, enable_dhcp=False) as s:
                data = {'router': {'tenant_id': 'whatever'}}
                data['router']['name'] = 'router1'
                data['router']['external_gateway_info'] = {
                    'network_id': s['subnet']['network_id']}
                router_req = self.new_create_request('routers', data,
                                                     self.fmt)
                res = router_req.get_response(self.ext_api)
                router = self.deserialize(self.fmt, res)
                self.assertEqual(
                    s['subnet']['network_id'],
                    (router['router']['external_gateway_info']
                     ['network_id']))
                self.assertEqual(
                    [],
                    self.plugin_instance.edge_manager.
                    get_routers_on_same_edge(
                        context.get_admin_context(),
                        router['router']['id']))

    def test_router_update_with_routes_fail(self):
        """Shared router currently does not support static routes
        """
        with self.router() as r:
            router_id = r['router']['id']
            body = self._show('routers', router_id)
            body['router']['routes'] = [{'destination': '5.5.5.5/32',
                                         'nexthop': '6.6.6.6'}]
            self._update('routers', router_id, body,
                         expected_code=400,
                         neutron_context=context.get_admin_context())

    def test_router_update_gateway_with_no_edge(self):
        with self.router() as r:
            with self.subnet() as s1:
                with self._create_l3_ext_network() as net:
                    with self.subnet(network=net, enable_dhcp=False) as s2:
                        self._set_net_external(s1['subnet']['network_id'])
                        try:
                            self._add_external_gateway_to_router(
                                r['router']['id'],
                                s1['subnet']['network_id'])
                            body = self._show('routers', r['router']['id'])
                            net_id = (body['router']
                                      ['external_gateway_info']['network_id'])
                            self.assertEqual(net_id,
                                             s1['subnet']['network_id'])
                            self.assertEqual(
                                [],
                                self.plugin_instance.edge_manager.
                                get_routers_on_same_edge(
                                    context.get_admin_context(),
                                    r['router']['id']))
                            # Plug network with external mapping
                            self._set_net_external(s2['subnet']['network_id'])
                            self._add_external_gateway_to_router(
                                r['router']['id'],
                                s2['subnet']['network_id'])
                            body = self._show('routers', r['router']['id'])
                            net_id = (body['router']
                                      ['external_gateway_info']['network_id'])
                            self.assertEqual(net_id,
                                             s2['subnet']['network_id'])
                            self.assertEqual(
                                [],
                                self.plugin_instance.edge_manager.
                                get_routers_on_same_edge(
                                    context.get_admin_context(),
                                    r['router']['id']))
                        finally:
                            # Cleanup
                            self._remove_external_gateway_from_router(
                                r['router']['id'],
                                s2['subnet']['network_id'])

    def test_router_update_gateway_with_existing_floatingip_with_edge(self):
        with self._create_l3_ext_network() as net:
            with self.subnet(network=net, enable_dhcp=False) as subnet:
                with self.floatingip_with_assoc() as fip:
                    self._add_external_gateway_to_router(
                        fip['floatingip']['router_id'],
                        subnet['subnet']['network_id'],
                        expected_code=webob.exc.HTTPConflict.code)
                    self.assertNotEqual(
                        [],
                        self.plugin_instance.edge_manager.
                        get_routers_on_same_edge(
                            context.get_admin_context(),
                            fip['floatingip']['router_id']))

    def test_router_set_gateway_with_interfaces_with_edge(self):
        with self.router() as r, self.subnet() as s1:
            self._set_net_external(s1['subnet']['network_id'])
            try:
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s1['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                net_id = (body['router']
                          ['external_gateway_info']['network_id'])
                self.assertEqual(net_id,
                                 s1['subnet']['network_id'])
                self.assertEqual(
                    [],
                    self.plugin_instance.edge_manager.
                    get_routers_on_same_edge(
                        context.get_admin_context(),
                        r['router']['id']))

                with self.subnet(cidr='11.0.0.0/24') as s11:
                    with self.subnet(cidr='12.0.0.0/24') as s12:

                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      s11['subnet']['id'],
                                                      None)
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      s12['subnet']['id'],
                                                      None)
                        self.assertIsNotNone(
                            self.plugin_instance.edge_manager.
                            get_routers_on_same_edge(
                                context.get_admin_context(),
                                r['router']['id']))
                        self._router_interface_action('remove',
                                                      r['router']['id'],
                                                      s11['subnet']['id'],
                                                      None)
                        self.assertIsNotNone(
                            self.plugin_instance.edge_manager.
                            get_routers_on_same_edge(
                                context.get_admin_context(),
                                r['router']['id']))
                        self._router_interface_action('remove',
                                                      r['router']['id'],
                                                      s12['subnet']['id'],
                                                      None)
                        self.assertEqual(
                            [],
                            self.plugin_instance.edge_manager.
                            get_routers_on_same_edge(
                                context.get_admin_context(),
                                r['router']['id']))
            finally:
                # Cleanup
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s1['subnet']['network_id'])

    @mock.patch.object(edge_utils, "update_firewall")
    def test_routers_set_gateway_with_nosnat(self, mock):
        expected_fw1 = [{'action': 'allow',
                         'enabled': True,
                         'source_ip_address': [],
                         'destination_ip_address': []}]
        expected_fw2 = [{'action': 'allow',
                         'enabled': True,
                         'source_ip_address': [],
                         'destination_ip_address': []}]
        nosnat_fw1 = [{'action': 'allow',
                       'enabled': True,
                       'source_vnic_groups': ["external"],
                       'destination_ip_address': []}]
        nosnat_fw2 = [{'action': 'allow',
                       'enabled': True,
                       'source_vnic_groups': ["external"],
                       'destination_ip_address': []}]
        with self.router() as r1, self.router() as r2,\
                self.subnet() as ext_subnet,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(cidr='12.0.0.0/24') as s2:

            self._set_net_external(ext_subnet['subnet']['network_id'])
            self._router_interface_action(
                'add', r1['router']['id'],
                s1['subnet']['id'], None)
            expected_fw1[0]['source_ip_address'] = ['11.0.0.0/24']
            expected_fw1[0]['destination_ip_address'] = ['11.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(self._recursive_sort_list(expected_fw1),
                             self._recursive_sort_list(fw_rules))
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._add_external_gateway_to_router(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'])
            self._add_external_gateway_to_router(
                r2['router']['id'],
                ext_subnet['subnet']['network_id'])
            expected_fw2[0]['source_ip_address'] = ['12.0.0.0/24']
            expected_fw2[0]['destination_ip_address'] = ['12.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw1 + expected_fw2),
                self._recursive_sort_list(fw_rules))
            self._update_router_enable_snat(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'],
                False)
            nosnat_fw1[0]['destination_ip_address'] = ['11.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw1 + expected_fw2 +
                                          nosnat_fw1),
                self._recursive_sort_list(fw_rules))
            self._update_router_enable_snat(
                r2['router']['id'],
                ext_subnet['subnet']['network_id'],
                False)
            nosnat_fw2[0]['destination_ip_address'] = ['12.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw1 + expected_fw2 +
                                          nosnat_fw1 + nosnat_fw2),
                self._recursive_sort_list(fw_rules))
            self._update_router_enable_snat(
                r2['router']['id'],
                ext_subnet['subnet']['network_id'],
                True)
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw1 + expected_fw2 +
                                          nosnat_fw1),
                self._recursive_sort_list(fw_rules))
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw1 + nosnat_fw1),
                self._recursive_sort_list(fw_rules))
            self._remove_external_gateway_from_router(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'])
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw1),
                self._recursive_sort_list(fw_rules))
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._remove_external_gateway_from_router(
                r2['router']['id'],
                ext_subnet['subnet']['network_id'])

    def test_routers_with_interface_on_same_edge(self):
            with self.router() as r1, self.router() as r2,\
                    self.subnet(cidr='11.0.0.0/24') as s11,\
                    self.subnet(cidr='12.0.0.0/24') as s12:
                self._router_interface_action('add',
                                              r1['router']['id'],
                                              s11['subnet']['id'],
                                              None)
                self._router_interface_action('add',
                                              r2['router']['id'],
                                              s12['subnet']['id'],
                                              None)
                routers_expected = [r1['router']['id'], r2['router']['id']]
                routers_1 = (self.plugin_instance.edge_manager.
                             get_routers_on_same_edge(
                                 context.get_admin_context(),
                                 r1['router']['id']))
                self.assertEqual(set(routers_expected), set(routers_1))
                routers_2 = (self.plugin_instance.edge_manager.
                             get_routers_on_same_edge(
                                 context.get_admin_context(),
                                 r2['router']['id']))
                self.assertEqual(set(routers_expected), set(routers_2))
                self._router_interface_action('remove',
                                              r1['router']['id'],
                                              s11['subnet']['id'],
                                              None)
                self._router_interface_action('remove',
                                              r2['router']['id'],
                                              s12['subnet']['id'],
                                              None)

    def test_routers_with_overlap_interfaces(self):
        with self.router() as r1, self.router() as r2,\
                self.subnet(cidr='11.0.0.0/24') as s11,\
                self.subnet(cidr='11.0.0.0/24') as s12:
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s11['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s12['subnet']['id'],
                                          None)
            r1_expected = [r1['router']['id']]
            routers_1 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r1['router']['id']))
            self.assertEqual(r1_expected, routers_1)
            r2_expected = [r2['router']['id']]
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(r2_expected, routers_2)
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s11['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s12['subnet']['id'],
                                          None)

    def test_routers_with_overlap_interfaces_with_migration(self):
        with self.router() as r1, self.router() as r2,\
                self.subnet(cidr='11.0.0.0/24') as s11,\
                self.subnet(cidr='12.0.0.0/24') as s12,\
                self.subnet(cidr='11.0.0.0/24') as s13:
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s11['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s12['subnet']['id'],
                                          None)
            r1_expected = [r1['router']['id'], r2['router']['id']]
            routers_1 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r1['router']['id']))
            self.assertEqual(set(r1_expected), set(routers_1))
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s13['subnet']['id'],
                                          None)
            r1_expected = [r1['router']['id']]
            routers_1 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r1['router']['id']))
            self.assertEqual(r1_expected, routers_1)
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s11['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s12['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s13['subnet']['id'],
                                          None)

    def test_routers_with_different_subnet_on_same_network(self):
        with self.router() as r1, self.router() as r2,\
                self.network() as net,\
                self.subnet(network=net, cidr='12.0.0.0/24') as s1,\
                self.subnet(network=net, cidr='13.0.0.0/24') as s2:
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(1, len(routers_2))
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)

    def test_routers_with_different_subnet_on_same_network_migration(self):
        with self.router() as r1, self.router() as r2, self.network() as net,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(network=net, cidr='12.0.0.0/24') as s2,\
                self.subnet(network=net, cidr='13.0.0.0/24') as s3:
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(2, len(routers_2))
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s3['subnet']['id'],
                                          None)
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(2, len(routers_2))
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s3['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s3['subnet']['id'],
                                          None)
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(1, len(routers_2))
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s3['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)

    def test_routers_set_same_gateway_on_same_edge(self):
        with self.router() as r1, self.router() as r2,\
                self.network() as ext_net,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(cidr='12.0.0.0/24') as s2,\
                self.subnet(network=ext_net, cidr='13.0.0.0/24'):
            self._set_net_external(ext_net['network']['id'])
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._add_external_gateway_to_router(
                r1['router']['id'],
                ext_net['network']['id'])
            self._add_external_gateway_to_router(
                r2['router']['id'],
                ext_net['network']['id'])
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(2, len(routers_2))

            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._remove_external_gateway_from_router(
                r1['router']['id'],
                ext_net['network']['id'])
            self._remove_external_gateway_from_router(
                r2['router']['id'],
                ext_net['network']['id'])

    def test_routers_set_different_gateway_on_different_edge(self):
        with self.router() as r1, self.router() as r2,\
                self.network() as ext1, self.network() as ext2,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(cidr='12.0.0.0/24') as s2,\
                self.subnet(network=ext1, cidr='13.0.0.0/24'),\
                self.subnet(network=ext2, cidr='14.0.0.0/24'):
            self._set_net_external(ext1['network']['id'])
            self._set_net_external(ext2['network']['id'])
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._add_external_gateway_to_router(
                r1['router']['id'],
                ext1['network']['id'])
            self._add_external_gateway_to_router(
                r2['router']['id'],
                ext1['network']['id'])
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(2, len(routers_2))
            self._add_external_gateway_to_router(
                r2['router']['id'],
                ext2['network']['id'])
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(1, len(routers_2))

            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._remove_external_gateway_from_router(
                r1['router']['id'],
                ext1['network']['id'])
            self._remove_external_gateway_from_router(
                r2['router']['id'],
                ext2['network']['id'])

    def test_get_available_and_conflicting_ids_with_no_conflict(self):
        with self.router() as r1, self.router() as r2,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(cidr='12.0.0.0/24') as s2:
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            router_driver = (self.plugin_instance._router_managers.
                             get_tenant_router_driver(context, 'shared'))
            available_router_ids, conflict_router_ids = (
                router_driver._get_available_and_conflicting_ids(
                    context.get_admin_context(), r1['router']['id']))
            self.assertIn(r2['router']['id'], available_router_ids)
            self.assertEqual(0, len(conflict_router_ids))

    def test_get_available_and_conflicting_ids_with_conflict(self):
        with self.router() as r1, self.router() as r2,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(cidr='11.0.0.0/24') as s2:
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            router_driver = (self.plugin_instance._router_managers.
                             get_tenant_router_driver(context, 'shared'))
            available_router_ids, conflict_router_ids = (
                router_driver._get_available_and_conflicting_ids(
                    context.get_admin_context(), r1['router']['id']))
            self.assertIn(r2['router']['id'], conflict_router_ids)
            self.assertEqual(0, len(available_router_ids))

    def test_get_available_and_conflicting_ids_with_diff_gw(self):
        with self.router() as r1, self.router() as r2,\
                self.network() as ext1, self.network() as ext2,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(cidr='12.0.0.0/24') as s2,\
                self.subnet(network=ext1, cidr='13.0.0.0/24'),\
                self.subnet(network=ext2, cidr='14.0.0.0/24'):
            self._set_net_external(ext1['network']['id'])
            self._set_net_external(ext2['network']['id'])
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._add_external_gateway_to_router(
                r1['router']['id'],
                ext1['network']['id'])
            self._add_external_gateway_to_router(
                r2['router']['id'],
                ext2['network']['id'])
            router_driver = (self.plugin_instance._router_managers.
                             get_tenant_router_driver(context, 'shared'))
            available_router_ids, conflict_router_ids = (
                router_driver._get_available_and_conflicting_ids(
                    context.get_admin_context(), r1['router']['id']))
            self.assertIn(r2['router']['id'], conflict_router_ids)
            self.assertEqual(0, len(available_router_ids))

    def test_migrate_shared_router_to_exclusive(self):
        with self.router(name='r7') as r1, \
                self.subnet(cidr='11.0.0.0/24') as s1:
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)

            # update the router type:
            router_id = r1['router']['id']
            self._update('routers', router_id,
                         {'router': {'router_type': 'exclusive'}})

            # get the updated router and check it's type
            body = self._show('routers', router_id)
            self.assertEqual('exclusive', body['router']['router_type'])
