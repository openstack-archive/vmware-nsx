# Copyright (c) 2015 OpenStack Foundation.
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
import six

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron import context
from neutron.extensions import external_net
from neutron.extensions import extraroute
from neutron.extensions import l3
from neutron.extensions import l3_ext_gw_mode
from neutron.extensions import portbindings
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as secgrp
from neutron import manager
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_extra_dhcp_opt as test_dhcpopts
from neutron.tests.unit.extensions import test_extraroute as test_ext_route
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from neutron.tests.unit.extensions \
    import test_l3_ext_gw_mode as test_ext_gw_mode
from neutron import version

from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from vmware_nsx.common import utils
from vmware_nsx.nsxlib.v3 import client as nsx_client
from vmware_nsx.nsxlib.v3 import cluster as nsx_cluster
from vmware_nsx.plugins.nsx_v3 import plugin as nsx_plugin
from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.extensions import test_metadata
from vmware_nsx.tests.unit.nsx_v3 import mocks as nsx_v3_mocks
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase


PLUGIN_NAME = 'vmware_nsx.plugin.NsxV3Plugin'


class NsxV3PluginTestCaseMixin(test_plugin.NeutronDbPluginV2TestCase,
                               nsxlib_testcase.NsxClientTestCase):

    def setUp(self, plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):

        self._patchers = []

        self.mock_api = nsx_v3_mocks.MockRequestSessionApi()
        nsxlib_testcase.NsxClientTestCase.setup_conf_overrides()
        self.cluster = nsx_cluster.NSXClusteredAPI(
            http_provider=nsxlib_testcase.MemoryMockAPIProvider(self.mock_api))

        self.cluster.revalidate_endpoints()

        def _patch_object(*args, **kwargs):
            patcher = mock.patch.object(*args, **kwargs)
            patcher.start()
            self._patchers.append(patcher)

        def _new_cluster(*args, **kwargs):
            return self.cluster

        self.mocked_rest_fns(
            nsx_plugin.security.firewall, 'nsxclient',
            mock_cluster=self.cluster)
        self.mocked_rest_fns(
            nsx_plugin.router.nsxlib, 'client', mock_cluster=self.cluster)

        mock_client_module = mock.Mock()
        mock_cluster_module = mock.Mock()
        mocked_client = self.new_mocked_client(
            nsx_client.NSX3Client, mock_cluster=self.cluster)
        mock_cluster_module.NSXClusteredAPI.return_value = self.cluster
        mock_client_module.NSX3Client.return_value = mocked_client
        _patch_object(nsx_plugin, 'nsx_client', new=mock_client_module)
        _patch_object(nsx_plugin, 'nsx_cluster', new=mock_cluster_module)

        super(NsxV3PluginTestCaseMixin, self).setUp(plugin=plugin,
                                                    ext_mgr=ext_mgr)

        self.maxDiff = None

        # populate pre-existing mock resources
        cluster_id = uuidutils.generate_uuid()
        self.mock_api.post(
            'api/v1/logical-routers',
            data=jsonutils.dumps({
                'display_name': nsx_v3_mocks.DEFAULT_TIER0_ROUTER_UUID,
                'router_type': "TIER0",
                'id': nsx_v3_mocks.DEFAULT_TIER0_ROUTER_UUID,
                'edge_cluster_id': cluster_id}),
            headers=nsx_client.JSONRESTClient._DEFAULT_HEADERS)

        self.mock_api.post(
            'api/v1/edge-clusters',
            data=jsonutils.dumps({
                'id': cluster_id,
                'members': [
                    {'member_index': 0},
                    {'member_index': 1}
                ]}),
            headers=nsx_client.JSONRESTClient._DEFAULT_HEADERS)

    def tearDown(self):
        for patcher in self._patchers:
            patcher.stop()
        super(NsxV3PluginTestCaseMixin, self).tearDown()

    def _create_network(self, fmt, name, admin_state_up,
                        arg_list=None, providernet_args=None, **kwargs):
        data = {'network': {'name': name,
                            'admin_state_up': admin_state_up,
                            'tenant_id': self._tenant_id}}
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
            # Arg must be present
            if arg in kwargs:
                data['network'][arg] = kwargs[arg]
        network_req = self.new_create_request('networks', data, fmt)
        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            network_req.environ['neutron.context'] = context.Context(
                '', kwargs['tenant_id'])
        return network_req.get_response(self.api)


class TestNetworksV2(test_plugin.TestNetworksV2, NsxV3PluginTestCaseMixin):
    pass


class TestPortsV2(test_plugin.TestPortsV2, NsxV3PluginTestCaseMixin,
                  test_bindings.PortBindingsTestCase,
                  test_bindings.PortBindingsHostTestCaseMixin,
                  test_bindings.PortBindingsVnicTestCaseMixin):

    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = True

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


class DHCPOptsTestCase(test_dhcpopts.TestExtraDhcpOpt,
                       NsxV3PluginTestCaseMixin):

    def setUp(self, plugin=None):
        super(test_dhcpopts.ExtraDhcpOptDBTestCase, self).setUp(
            plugin=PLUGIN_NAME)


class TestL3ExtensionManager(object):

    def get_resources(self):
        # Simulate extension of L3 attribute map
        # First apply attribute extensions
        for key in l3.RESOURCE_ATTRIBUTE_MAP.keys():
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                l3_ext_gw_mode.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                extraroute.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
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


class L3NatTest(test_l3_plugin.L3BaseForIntTests, NsxV3PluginTestCaseMixin):

    def _restore_l3_attribute_map(self):
        l3.RESOURCE_ATTRIBUTE_MAP = self._l3_attribute_map_bk

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None,
              service_plugins=None):
        self._l3_attribute_map_bk = backup_l3_attribute_map()
        cfg.CONF.set_override('api_extensions_path', vmware.NSXEXT_PATH)
        cfg.CONF.set_default('max_routes', 3)
        self.addCleanup(restore_l3_attribute_map, self._l3_attribute_map_bk)
        ext_mgr = ext_mgr or TestL3ExtensionManager()
        super(L3NatTest, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        self.plugin_instance = manager.NeutronManager.get_plugin()
        self._plugin_name = "%s.%s" % (
            self.plugin_instance.__module__,
            self.plugin_instance.__class__.__name__)
        self._plugin_class = self.plugin_instance.__class__

    def _create_l3_ext_network(
        self, physical_network=nsx_v3_mocks.DEFAULT_TIER0_ROUTER_UUID):
        name = 'l3_ext_net'
        net_type = utils.NetworkTypes.L3_EXT
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: physical_network}
        return self.network(name=name,
                            router__external=True,
                            providernet_args=providernet_args,
                            arg_list=(pnet.NETWORK_TYPE,
                                      pnet.PHYSICAL_NETWORK))


class TestL3NatTestCase(L3NatTest,
                        test_l3_plugin.L3NatDBIntTestCase,
                        test_ext_route.ExtraRouteDBTestCaseBase,
                        test_metadata.MetaDataTestCase):

    def setUp(self, plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(TestL3NatTestCase, self).setUp(plugin=plugin, ext_mgr=ext_mgr)
        cfg.CONF.set_override('metadata_mode', None, 'NSX')

    def _test_create_l3_ext_network(
            self, physical_network=nsx_v3_mocks.DEFAULT_TIER0_ROUTER_UUID):
        name = 'l3_ext_net'
        net_type = utils.NetworkTypes.L3_EXT
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (external_net.EXTERNAL, True),
                    (pnet.NETWORK_TYPE, net_type),
                    (pnet.PHYSICAL_NETWORK, physical_network)]
        with self._create_l3_ext_network(physical_network) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_l3_ext_network_with_default_tier0(self):
        self._test_create_l3_ext_network()

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)

    def test_routes_update_for_multiple_routers(self):
        self.skipTest('not supported')

    def test_floatingip_multi_external_one_internal(self):
        self.skipTest('not supported')

    def test_multiple_subnets_on_different_routers(self):
        with self.network() as network:
            with self.subnet(network=network) as s1,\
                    self.subnet(network=network,
                                cidr='11.0.0.0/24') as s2,\
                    self.router() as r1,\
                    self.router() as r2:
                self._router_interface_action('add', r1['router']['id'],
                                              s1['subnet']['id'], None)
                self.assertRaises(n_exc.InvalidInput,
                                  self.plugin_instance.add_router_interface,
                                  context.get_admin_context(),
                                  r2['router']['id'],
                                  {'subnet_id': s2['subnet']['id']})
                self._router_interface_action('remove', r1['router']['id'],
                                              s1['subnet']['id'], None)
                self._router_interface_action('add', r2['router']['id'],
                                              s2['subnet']['id'], None)
                self._router_interface_action('remove', r2['router']['id'],
                                              s2['subnet']['id'], None)

    def test_multiple_subnets_on_same_router(self):
        with self.network() as network:
            with self.subnet(network=network) as s1,\
                    self.subnet(network=network,
                                cidr='11.0.0.0/24') as s2,\
                    self.router() as r1:
                self._router_interface_action('add', r1['router']['id'],
                                              s1['subnet']['id'], None)
                self.assertRaises(n_exc.InvalidInput,
                                  self.plugin_instance.add_router_interface,
                                  context.get_admin_context(),
                                  r1['router']['id'],
                                  {'subnet_id': s2['subnet']['id']})
                self._router_interface_action('remove', r1['router']['id'],
                                              s1['subnet']['id'], None)

    def test_router_update_on_external_port(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                self._set_net_external(s['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                net_id = body['router']['external_gateway_info']['network_id']
                self.assertEqual(net_id, s['subnet']['network_id'])
                port_res = self._list_ports(
                    'json',
                    200,
                    s['subnet']['network_id'],
                    tenant_id=r['router']['tenant_id'],
                    device_owner=constants.DEVICE_OWNER_ROUTER_GW)
                port_list = self.deserialize('json', port_res)
                self.assertEqual(len(port_list['ports']), 1)

                routes = [{'destination': '135.207.0.0/16',
                           'nexthop': '10.0.1.3'}]

                self.assertRaises(n_exc.InvalidInput,
                                  self.plugin_instance.update_router,
                                  context.get_admin_context(),
                                  r['router']['id'],
                                  {'router': {'routes':
                                              routes}})
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                gw_info = body['router']['external_gateway_info']
                self.assertIsNone(gw_info)

    def test_create_router_gateway_fails(self):
        self.skipTest('not supported')

    def test_router_remove_ipv6_subnet_from_interface(self):
        self.skipTest('not supported')

    def test_router_add_interface_multiple_ipv6_subnets_same_net(self):
        self.skipTest('not supported')

    def test_router_add_interface_multiple_ipv4_subnets(self):
        self.skipTest('not supported')


class ExtGwModeTestCase(L3NatTest,
                        test_ext_gw_mode.ExtGwModeIntTestCase):
    pass


class TestNsxV3Utils(NsxV3PluginTestCaseMixin):

    def test_build_v3_tags_payload(self):
        result = utils.build_v3_tags_payload(
            {'id': 'fake_id',
             'tenant_id': 'fake_tenant_id'},
            resource_type='os-neutron-net-id',
            project_name='fake_tenant_name')
        expected = [{'scope': 'os-neutron-net-id', 'tag': 'fake_id'},
                    {'scope': 'os-project-id', 'tag': 'fake_tenant_id'},
                    {'scope': 'os-project-name', 'tag': 'fake_tenant_name'},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()}]
        self.assertEqual(expected, result)

    def test_build_v3_tags_payload_internal(self):
        result = utils.build_v3_tags_payload(
            {'id': 'fake_id',
             'tenant_id': 'fake_tenant_id'},
            resource_type='os-neutron-net-id',
            project_name=None)
        expected = [{'scope': 'os-neutron-net-id', 'tag': 'fake_id'},
                    {'scope': 'os-project-id', 'tag': 'fake_tenant_id'},
                    {'scope': 'os-project-name', 'tag': 'NSX neutron plug-in'},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()}]
        self.assertEqual(expected, result)

    def test_build_v3_tags_payloadi_invalid_length(self):
        self.assertRaises(n_exc.InvalidInput,
                          utils.build_v3_tags_payload,
                          {'id': 'fake_id',
                           'tenant_id': 'fake_tenant_id'},
                          resource_type='os-neutron-maldini-rocks-id',
                          project_name='fake')

    def test_build_v3_api_version_tag(self):
        result = utils.build_v3_api_version_tag()
        expected = [{'scope': 'os-neutron-id',
                     'tag': 'NSX neutron plug-in'},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()}]
        self.assertEqual(expected, result)
