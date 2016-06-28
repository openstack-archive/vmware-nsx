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
import netaddr
import six
from webob import exc

from neutron.api.v2 import attributes
from neutron import context
from neutron.db import models_v2
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
from neutron.tests.unit.scheduler \
    import test_dhcp_agent_scheduler as test_dhcpagent
from neutron import version

from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.dhcp_meta import rpc as nsx_rpc
from vmware_nsx.extensions import advancedserviceproviders as as_providers
from vmware_nsx.nsxlib.v3 import client as nsx_client
from vmware_nsx.nsxlib.v3 import cluster as nsx_cluster
from vmware_nsx.nsxlib.v3 import resources as nsx_resources
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

        # Mock the nsx v3 version
        mock_nsxlib_get_version = mock.patch(
            "vmware_nsx.nsxlib.v3.get_version",
            return_value='1.1.0')
        mock_nsxlib_get_version.start()

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

        self.mock_api.post(
                'api/v1/switching-profiles',
                data=jsonutils.dumps({
                    'id': uuidutils.generate_uuid(),
                    'display_name': nsx_plugin.NSX_V3_NO_PSEC_PROFILE_NAME
                }), headers=nsx_client.JSONRESTClient._DEFAULT_HEADERS)

        self.mock_api.post(
                'api/v1/transport-zones',
                data=jsonutils.dumps({
                    'id': uuidutils.generate_uuid(),
                    'display_name': nsxlib_testcase.NSX_TZ_NAME
                }), headers=nsx_client.JSONRESTClient._DEFAULT_HEADERS)

        self.mock_api.post(
                'api/v1/bridge-clusters',
                data=jsonutils.dumps({
                    'id': uuidutils.generate_uuid(),
                    'display_name': nsx_v3_mocks.NSX_BRIDGE_CLUSTER_NAME
                }), headers=nsx_client.JSONRESTClient._DEFAULT_HEADERS)

        super(NsxV3PluginTestCaseMixin, self).setUp(plugin=plugin,
                                                    ext_mgr=ext_mgr)

        self.maxDiff = None

    def tearDown(self):
        for patcher in self._patchers:
            patcher.stop()
        super(NsxV3PluginTestCaseMixin, self).tearDown()

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

        if providernet_args:
            kwargs.update(providernet_args)
        for arg in (('admin_state_up', 'tenant_id', 'shared',
                     'availability_zone_hints') + (arg_list or ())):
            # Arg must be present
            if arg in kwargs:
                data['network'][arg] = kwargs[arg]
        network_req = self.new_create_request('networks', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            network_req.environ['neutron.context'] = context.Context(
                '', tenant_id)
        return network_req.get_response(self.api)

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

    def _save_networks(self, networks):
        ctx = context.get_admin_context()
        for network_id in networks:
            with ctx.session.begin(subtransactions=True):
                ctx.session.add(models_v2.Network(id=network_id))


class TestNetworksV2(test_plugin.TestNetworksV2, NsxV3PluginTestCaseMixin):

    @mock.patch.object(nsx_plugin.NsxV3Plugin, 'validate_availability_zones')
    def test_create_network_with_availability_zone(self, mock_validate_az):
        name = 'net-with-zone'
        zone = ['zone1']

        mock_validate_az.return_value = None
        with self.network(name=name, availability_zone_hints=zone) as net:
            az_hints = net['network']['availability_zone_hints']
            self.assertListEqual(az_hints, zone)


class TestPortsV2(test_plugin.TestPortsV2, NsxV3PluginTestCaseMixin,
                  test_bindings.PortBindingsTestCase,
                  test_bindings.PortBindingsHostTestCaseMixin,
                  test_bindings.PortBindingsVnicTestCaseMixin):

    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = True

    def setUp(self):
        super(TestPortsV2, self).setUp()
        self.plugin = manager.NeutronManager.get_plugin()
        self.ctx = context.get_admin_context()

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

    def test_fail_create_port_with_ext_net(self):
        expected_error = 'InvalidInput'
        with self._create_l3_ext_network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24'):
                device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'X'
                res = self._create_port(self.fmt,
                                        network['network']['id'],
                                        exc.HTTPBadRequest.code,
                                        device_owner=device_owner)
                data = self.deserialize(self.fmt, res)
                self.assertEqual(expected_error, data['NeutronError']['type'])

    def test_fail_update_port_with_ext_net(self):
        with self._create_l3_ext_network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24') as subnet:
                with self.port(subnet=subnet) as port:
                    device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'X'
                    data = {'port': {'device_owner': device_owner}}
                    req = self.new_update_request('ports',
                                                  data, port['port']['id'])
                    res = req.get_response(self.api)
                    self.assertEqual(exc.HTTPBadRequest.code,
                                     res.status_int)

    def test_create_port_with_qos(self):
        with self.network() as network:
            policy_id = uuidutils.generate_uuid()
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'qos_policy_id': policy_id,
                        'name': 'qos_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'mac_address': '00:00:00:00:00:01'}
                    }
            with mock.patch.object(self.plugin, '_get_qos_profile_id'):
                port = self.plugin.create_port(self.ctx, data)
                self.assertEqual(policy_id, port['qos_policy_id'])
                # Get port should also return the qos policy id
                with mock.patch('vmware_nsx.services.qos.common.utils.'
                                'get_port_policy_id',
                                return_value=policy_id):
                    port = self.plugin.get_port(self.ctx, port['id'])
                    self.assertEqual(policy_id, port['qos_policy_id'])

    def test_update_port_with_qos(self):
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'qos_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'mac_address': '00:00:00:00:00:01'}
                    }
            port = self.plugin.create_port(self.ctx, data)
            policy_id = uuidutils.generate_uuid()
            data['port']['qos_policy_id'] = policy_id
            with mock.patch.object(self.plugin, '_get_qos_profile_id'):
                res = self.plugin.update_port(self.ctx, port['id'], data)
                self.assertEqual(policy_id, res['qos_policy_id'])
                # Get port should also return the qos policy id
                with mock.patch('vmware_nsx.services.qos.common.utils.'
                                'get_port_policy_id',
                                return_value=policy_id):
                    res = self.plugin.get_port(self.ctx, port['id'])
                    self.assertEqual(policy_id, res['qos_policy_id'])

    def test_create_ext_port_with_qos_fail(self):
        with self._create_l3_ext_network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24'):
                policy_id = uuidutils.generate_uuid()
                data = {'port': {'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'qos_policy_id': policy_id}}
                # Cannot add qos policy to a port on ext network
                self.assertRaises(n_exc.InvalidInput,
                          self.plugin.create_port, self.ctx, data)

    def test_create_port_with_qos_on_net(self):
        with self.network() as network:
            policy_id = uuidutils.generate_uuid()
            device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'X'
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'qos_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': device_owner,
                        'fixed_ips': [],
                        'mac_address': '00:00:00:00:00:01'}
                    }
            with mock.patch.object(self.plugin,
                '_get_qos_profile_id') as get_profile:
                with mock.patch('vmware_nsx.services.qos.common.utils.'
                    'get_network_policy_id', return_value=policy_id):
                    self.plugin.create_port(self.ctx, data)
                    get_profile.assert_called_once_with(self.ctx, policy_id)

    def test_update_port_with_qos_on_net(self):
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'qos_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'mac_address': '00:00:00:00:00:01'}
                    }
            port = self.plugin.create_port(self.ctx, data)
            policy_id = uuidutils.generate_uuid()
            device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'X'
            data['port']['device_owner'] = device_owner
            with mock.patch.object(self.plugin,
                '_get_qos_profile_id') as get_profile:
                with mock.patch('vmware_nsx.services.qos.common.utils.'
                    'get_network_policy_id', return_value=policy_id):
                    self.plugin.update_port(self.ctx, port['id'], data)
                    get_profile.assert_called_once_with(self.ctx, policy_id)

    def _get_ports_with_fields(self, tenid, fields, expected_count):
        pl = manager.NeutronManager.get_plugin()
        ctx = context.Context(user_id=None, tenant_id=tenid,
                              is_admin=False)
        ports = pl.get_ports(ctx, filters={'tenant_id': [tenid]},
                             fields=fields)
        self.assertEqual(expected_count, len(ports))

    def test_get_ports_with_fields(self):
        with self.port(), self.port(), self.port(), self.port() as p:
            tenid = p['port']['tenant_id']
            # get all fields:
            self._get_ports_with_fields(tenid, None, 4)

            # get specific fields:
            self._get_ports_with_fields(tenid, 'mac_address', 4)
            self._get_ports_with_fields(tenid, 'network_id', 4)


class DHCPOptsTestCase(test_dhcpopts.TestExtraDhcpOpt,
                       NsxV3PluginTestCaseMixin):

    def setUp(self, plugin=None):
        super(test_dhcpopts.ExtraDhcpOptDBTestCase, self).setUp(
            plugin=PLUGIN_NAME)


class NSXv3DHCPAgentAZAwareWeightSchedulerTestCase(
        test_dhcpagent.DHCPAgentAZAwareWeightSchedulerTestCase,
        NsxV3PluginTestCaseMixin):

    def setUp(self):
        super(NSXv3DHCPAgentAZAwareWeightSchedulerTestCase, self).setUp()
        self.plugin = manager.NeutronManager.get_plugin()
        self.ctx = context.get_admin_context()

    def setup_coreplugin(self, core_plugin=None):
        super(NSXv3DHCPAgentAZAwareWeightSchedulerTestCase,
              self).setup_coreplugin(core_plugin=PLUGIN_NAME)


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


class TestL3NatTestCase(L3NatTest,
                        test_l3_plugin.L3NatDBIntTestCase,
                        test_ext_route.ExtraRouteDBTestCaseBase,
                        test_metadata.MetaDataTestCase):

    def setUp(self, plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(TestL3NatTestCase, self).setUp(plugin=plugin, ext_mgr=ext_mgr)
        cfg.CONF.set_override('metadata_mode', None, 'nsx_v3')
        cfg.CONF.set_override('metadata_on_demand', False, 'nsx_v3')

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

    def test_floatingip_update(self):
        super(TestL3NatTestCase, self).test_floatingip_update(
            expected_status=constants.FLOATINGIP_STATUS_DOWN)

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)

    def test_routes_update_for_multiple_routers(self):
        self.skipTest('not supported')

    def test_floatingip_multi_external_one_internal(self):
        self.skipTest('not supported')

    def test_floatingip_same_external_and_internal(self):
        self.skipTest('not supported')

    def test_route_update_with_external_route(self):
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

    def test_router_remove_interface_inuse_return_409(self):
        with self.router() as r1,\
                self.subnet() as ext_subnet,\
                self.subnet(cidr='11.0.0.0/24') as s1:
            self._set_net_external(ext_subnet['subnet']['network_id'])
            self._router_interface_action(
                'add', r1['router']['id'],
                s1['subnet']['id'], None)
            self._add_external_gateway_to_router(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'])
            with self.port(subnet=s1,) as p:
                fip_res = self._create_floatingip(
                    self.fmt,
                    ext_subnet['subnet']['network_id'],
                    subnet_id=ext_subnet['subnet']['id'],
                    port_id=p['port']['id'])
                fip = self.deserialize(self.fmt, fip_res)
                self._router_interface_action(
                    'remove',
                    r1['router']['id'],
                    s1['subnet']['id'],
                    None,
                    expected_code=exc.HTTPConflict.code)
                self._delete('floatingips', fip['floatingip']['id'])
            self._remove_external_gateway_from_router(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'])
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)

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
                    {'scope': 'os-project-name', 'tag': 'NSX Neutron plugin'},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()}]
        self.assertEqual(expected, result)

    def test_build_v3_tags_payload_invalid_length(self):
        self.assertRaises(n_exc.InvalidInput,
                          utils.build_v3_tags_payload,
                          {'id': 'fake_id',
                           'tenant_id': 'fake_tenant_id'},
                          resource_type='os-neutron-maldini-rocks-id',
                          project_name='fake')

    def test_build_v3_api_version_tag(self):
        result = utils.build_v3_api_version_tag()
        expected = [{'scope': 'os-neutron-id',
                     'tag': 'NSX Neutron plugin'},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()}]
        self.assertEqual(expected, result)

    def test_is_internal_resource(self):
        project_tag = utils.build_v3_tags_payload(
            {'id': 'fake_id',
             'tenant_id': 'fake_tenant_id'},
            resource_type='os-neutron-net-id',
            project_name=None)
        internal_tag = utils.build_v3_api_version_tag()

        expect_false = utils.is_internal_resource({'tags': project_tag})
        self.assertFalse(expect_false)

        expect_true = utils.is_internal_resource({'tags': internal_tag})
        self.assertTrue(expect_true)

    def test_get_name_and_uuid(self):
        uuid = 'afc40f8a-4967-477e-a17a-9d560d1786c7'
        suffix = '_afc40...786c7'
        expected = 'maldini%s' % suffix
        short_name = utils.get_name_and_uuid('maldini', uuid)
        self.assertEqual(expected, short_name)

        name = 'X' * 255
        expected = '%s%s' % ('X' * (80 - len(suffix)), suffix)
        short_name = utils.get_name_and_uuid(name, uuid)
        self.assertEqual(expected, short_name)

    def test_build_v3_tags_max_length_payload(self):
        result = utils.build_v3_tags_payload(
            {'id': 'X' * 255,
             'tenant_id': 'X' * 255},
            resource_type='os-neutron-net-id',
            project_name='X' * 255)
        expected = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-name', 'tag': 'X' * 40},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()}]
        self.assertEqual(expected, result)

    def test_add_v3_tag(self):
        result = utils.add_v3_tag([], 'fake-scope', 'fake-tag')
        expected = [{'scope': 'fake-scope', 'tag': 'fake-tag'}]
        self.assertEqual(expected, result)

    def test_add_v3_tag_max_length_payload(self):
        result = utils.add_v3_tag([], 'fake-scope', 'X' * 255)
        expected = [{'scope': 'fake-scope', 'tag': 'X' * 40}]
        self.assertEqual(expected, result)

    def test_add_v3_tag_invalid_scope_length(self):
        self.assertRaises(n_exc.InvalidInput,
                          utils.add_v3_tag,
                          [],
                          'fake-scope-name-is-far-too-long',
                          'fake-tag')

    def test_update_v3_tags_addition(self):
        tags = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                {'scope': 'os-project-id', 'tag': 'Y' * 40},
                {'scope': 'os-project-name', 'tag': 'Z' * 40},
                {'scope': 'os-api-version',
                 'tag': version.version_info.release_string()}]
        resources = [{'resource_type': 'os-instance-uuid',
                      'tag': 'A' * 40}]
        tags = utils.update_v3_tags(tags, resources)
        expected = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-id', 'tag': 'Y' * 40},
                    {'scope': 'os-project-name', 'tag': 'Z' * 40},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()},
                    {'scope': 'os-instance-uuid',
                     'tag': 'A' * 40}]
        self.assertEqual(sorted(expected), sorted(tags))

    def test_update_v3_tags_removal(self):
        tags = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                {'scope': 'os-project-id', 'tag': 'Y' * 40},
                {'scope': 'os-project-name', 'tag': 'Z' * 40},
                {'scope': 'os-api-version',
                 'tag': version.version_info.release_string()}]
        resources = [{'resource_type': 'os-neutron-net-id',
                      'tag': ''}]
        tags = utils.update_v3_tags(tags, resources)
        expected = [{'scope': 'os-project-id', 'tag': 'Y' * 40},
                    {'scope': 'os-project-name', 'tag': 'Z' * 40},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()}]
        self.assertEqual(sorted(expected), sorted(tags))

    def test_update_v3_tags_update(self):
        tags = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                {'scope': 'os-project-id', 'tag': 'Y' * 40},
                {'scope': 'os-project-name', 'tag': 'Z' * 40},
                {'scope': 'os-api-version',
                 'tag': version.version_info.release_string()}]
        resources = [{'resource_type': 'os-project-id',
                      'tag': 'A' * 40}]
        tags = utils.update_v3_tags(tags, resources)
        expected = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-id', 'tag': 'A' * 40},
                    {'scope': 'os-project-name', 'tag': 'Z' * 40},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()}]
        self.assertEqual(sorted(expected), sorted(tags))


class NsxNativeDhcpTestCase(NsxV3PluginTestCaseMixin):

    def setUp(self):
        super(NsxNativeDhcpTestCase, self).setUp()
        self._orig_dhcp_agent_notification = cfg.CONF.dhcp_agent_notification
        self._orig_native_dhcp_metadata = cfg.CONF.nsx_v3.native_dhcp_metadata
        cfg.CONF.set_override('dhcp_agent_notification', False)
        cfg.CONF.set_override('native_dhcp_metadata', True, 'nsx_v3')
        self._patcher = mock.patch.object(nsx_resources.DhcpProfile, 'get')
        self._patcher.start()
        # Need to run _init_dhcp_metadata() manually because plugin was started
        # before setUp() overrides CONF.nsx_v3.native_dhcp_metadata.
        self.plugin._init_dhcp_metadata()

    def tearDown(self):
        self._patcher.stop()
        cfg.CONF.set_override('dhcp_agent_notification',
                              self._orig_dhcp_agent_notification)
        cfg.CONF.set_override('native_dhcp_metadata',
                              self._orig_native_dhcp_metadata, 'nsx_v3')
        super(NsxNativeDhcpTestCase, self).tearDown()

    def _verify_dhcp_service(self, network_id, tenant_id, enabled):
        # Verify if DHCP service is enabled on a network.
        port_res = self._list_ports('json', 200, network_id,
                                    tenant_id=tenant_id,
                                    device_owner=constants.DEVICE_OWNER_DHCP)
        port_list = self.deserialize('json', port_res)
        self.assertEqual(len(port_list['ports']) == 1, enabled)

    def _verify_dhcp_binding(self, subnet, port_data, update_data,
                             assert_data):
        # Verify if DHCP binding is updated.
        with mock.patch.object(nsx_resources.LogicalDhcpServer,
                               'update_binding') as update_dhcp_binding:
            device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
            device_id = uuidutils.generate_uuid()
            with self.port(subnet=subnet, device_owner=device_owner,
                           device_id=device_id, **port_data) as port:
                # Retrieve the DHCP binding info created in the DB for the
                # new port.
                dhcp_binding = nsx_db.get_nsx_dhcp_bindings(
                    context.get_admin_context().session, port['port']['id'])[0]
                # Update the port with provided data.
                self.plugin.update_port(
                    context.get_admin_context(), port['port']['id'],
                    update_data)
                binding_data = {'mac_address': port['port']['mac_address'],
                                'ip_address': port['port']['fixed_ips'][0][
                                    'ip_address']}
                # Extend basic binding data with to-be-asserted data.
                binding_data.update(assert_data)
                # Verify the update call.
                update_dhcp_binding.assert_called_once_with(
                    dhcp_binding['nsx_service_id'],
                    dhcp_binding['nsx_binding_id'], **binding_data)

    def test_dhcp_profile_configuration(self):
        # Test if dhcp_agent_notification and dhcp_profile_uuid are
        # configured correctly.
        orig_dhcp_agent_notification = cfg.CONF.dhcp_agent_notification
        cfg.CONF.set_override('dhcp_agent_notification', True)
        self.assertRaises(nsx_exc.NsxPluginException,
                          self.plugin._init_dhcp_metadata)
        cfg.CONF.set_override('dhcp_agent_notification',
                              orig_dhcp_agent_notification)
        orig_dhcp_profile_uuid = cfg.CONF.nsx_v3.dhcp_profile_uuid
        cfg.CONF.set_override('dhcp_profile_uuid', '', 'nsx_v3')
        self.assertRaises(cfg.RequiredOptError,
                          self.plugin._init_dhcp_metadata)
        cfg.CONF.set_override('dhcp_profile_uuid', orig_dhcp_profile_uuid,
                              'nsx_v3')

    def test_dhcp_service_with_create_network(self):
        # Test if DHCP service is disabled on a network when it is created.
        with self.network() as network:
            self._verify_dhcp_service(network['network']['id'],
                                      network['network']['tenant_id'], False)

    def test_dhcp_service_with_create_non_dhcp_subnet(self):
        # Test if DHCP service is disabled on a network when a DHCP-disabled
        # subnet is created.
        with self.network() as network:
            with self.subnet(network=network, enable_dhcp=False):
                self._verify_dhcp_service(network['network']['id'],
                                          network['network']['tenant_id'],
                                          False)

    def test_dhcp_service_with_create_multiple_non_dhcp_subnets(self):
        # Test if DHCP service is disabled on a network when multiple
        # DHCP-disabled subnets are created.
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24',
                             enable_dhcp=False):
                with self.subnet(network=network, cidr='20.0.0.0/24',
                                 enable_dhcp=False):
                    self._verify_dhcp_service(network['network']['id'],
                                              network['network']['tenant_id'],
                                              False)

    def test_dhcp_service_with_create_dhcp_subnet(self):
        # Test if DHCP service is enabled on a network when a DHCP-enabled
        # subnet is created.
        with self.network() as network:
            with self.subnet(network=network, enable_dhcp=True):
                self._verify_dhcp_service(network['network']['id'],
                                          network['network']['tenant_id'],
                                          True)

    def test_dhcp_service_with_create_multiple_dhcp_subnets(self):
        # Test if multiple DHCP-enabled subnets cannot be created in a network.
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24',
                             enable_dhcp=True):
                subnet = {'subnet': {'network_id': network['network']['id'],
                                     'cidr': '20.0.0.0/24',
                                     'enable_dhcp': True}}
                self.assertRaises(
                    n_exc.InvalidInput, self.plugin.create_subnet,
                    context.get_admin_context(), subnet)

    def test_dhcp_service_with_delete_dhcp_subnet(self):
        # Test if DHCP service is disabled on a network when a DHCP-disabled
        # subnet is deleted.
        with self.network() as network:
            with self.subnet(network=network, enable_dhcp=True) as subnet:
                self._verify_dhcp_service(network['network']['id'],
                                          network['network']['tenant_id'],
                                          True)
                self.plugin.delete_subnet(context.get_admin_context(),
                                          subnet['subnet']['id'])
                self._verify_dhcp_service(network['network']['id'],
                                          network['network']['tenant_id'],
                                          False)

    def test_dhcp_service_with_update_dhcp_subnet(self):
        # Test if DHCP service is enabled on a network when a DHCP-disabled
        # subnet is updated to DHCP-enabled.
        with self.network() as network:
            with self.subnet(network=network, enable_dhcp=False) as subnet:
                self._verify_dhcp_service(network['network']['id'],
                                       network['network']['tenant_id'], False)
                data = {'subnet': {'enable_dhcp': True}}
                self.plugin.update_subnet(context.get_admin_context(),
                                          subnet['subnet']['id'], data)
                self._verify_dhcp_service(network['network']['id'],
                                          network['network']['tenant_id'],
                                          True)

    def test_dhcp_service_with_update_multiple_dhcp_subnets(self):
        # Test if a DHCP-disabled subnet cannot be updated to DHCP-enabled
        # if a DHCP-enabled subnet already exists in the same network.
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24',
                             enable_dhcp=True):
                with self.subnet(network=network, cidr='20.0.0.0/24',
                                 enable_dhcp=False) as subnet:
                    self._verify_dhcp_service(network['network']['id'],
                                              network['network']['tenant_id'],
                                              True)
                    data = {'subnet': {'enable_dhcp': True}}
                    self.assertRaises(
                        n_exc.InvalidInput, self.plugin.update_subnet,
                        context.get_admin_context(), subnet['subnet']['id'],
                        data)

    def test_dhcp_service_with_update_dhcp_port(self):
        # Test if DHCP server IP is updated when the corresponding DHCP port
        # IP is changed.
        with mock.patch.object(nsx_resources.LogicalDhcpServer,
                               'update') as update_logical_dhcp_server:
            with self.subnet(cidr='10.0.0.0/24', enable_dhcp=True) as subnet:
                dhcp_service = nsx_db.get_nsx_service_binding(
                    context.get_admin_context().session,
                    subnet['subnet']['network_id'], nsx_constants.SERVICE_DHCP)
                port = self.plugin.get_port(context.get_admin_context(),
                                            dhcp_service['port_id'])
                old_ip = port['fixed_ips'][0]['ip_address']
                new_ip = str(netaddr.IPAddress(old_ip) + 1)
                data = {'port': {'fixed_ips': [
                    {'subnet_id': subnet['subnet']['id'],
                     'ip_address': new_ip}]}}
                self.plugin.update_port(context.get_admin_context(),
                                        dhcp_service['port_id'], data)
                update_logical_dhcp_server.assert_called_once_with(
                    dhcp_service['nsx_service_id'], server_ip=new_ip)

    def test_dhcp_binding_with_create_port(self):
        # Test if DHCP binding is added when a compute port is created.
        with mock.patch.object(nsx_resources.LogicalDhcpServer,
                               'create_binding',
                               return_value={"id": uuidutils.generate_uuid()}
                               ) as create_dhcp_binding:
            with self.subnet(enable_dhcp=True) as subnet:
                device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
                device_id = uuidutils.generate_uuid()
                with self.port(subnet=subnet, device_owner=device_owner,
                               device_id=device_id) as port:
                    dhcp_service = nsx_db.get_nsx_service_binding(
                        context.get_admin_context().session,
                        subnet['subnet']['network_id'],
                        nsx_constants.SERVICE_DHCP)
                    ip = port['port']['fixed_ips'][0]['ip_address']
                    hostname = 'host-%s' % ip.replace('.', '-')
                    options = {'option121': {'static_routes': [
                        {'network': '%s' % nsx_rpc.METADATA_DHCP_ROUTE,
                         'next_hop': ip}]}}
                    create_dhcp_binding.assert_called_once_with(
                        dhcp_service['nsx_service_id'],
                        port['port']['mac_address'], ip, hostname,
                        cfg.CONF.nsx_v3.dhcp_lease_time, options)

    def test_dhcp_binding_with_delete_port(self):
        # Test if DHCP binding is removed when the associated compute port
        # is deleted.
        with mock.patch.object(nsx_resources.LogicalDhcpServer,
                               'delete_binding') as delete_dhcp_binding:
            with self.subnet(enable_dhcp=True) as subnet:
                device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
                device_id = uuidutils.generate_uuid()
                with self.port(subnet=subnet, device_owner=device_owner,
                               device_id=device_id) as port:
                    dhcp_binding = nsx_db.get_nsx_dhcp_bindings(
                        context.get_admin_context().session,
                        port['port']['id'])[0]
                    self.plugin.delete_port(
                        context.get_admin_context(), port['port']['id'])
                    delete_dhcp_binding.assert_called_once_with(
                        dhcp_binding['nsx_service_id'],
                        dhcp_binding['nsx_binding_id'])

    def test_dhcp_binding_with_update_port_delete_ip(self):
        # Test if DHCP binding is deleted when the IP of the associated
        # compute port is deleted.
        with mock.patch.object(nsx_resources.LogicalDhcpServer,
                               'delete_binding') as delete_dhcp_binding:
            with self.subnet(enable_dhcp=True) as subnet:
                device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
                device_id = uuidutils.generate_uuid()
                with self.port(subnet=subnet, device_owner=device_owner,
                               device_id=device_id) as port:
                    dhcp_binding = nsx_db.get_nsx_dhcp_bindings(
                        context.get_admin_context().session,
                        port['port']['id'])[0]
                    data = {'port': {'fixed_ips': [],
                                     'admin_state_up': False,
                                     secgrp.SECURITYGROUPS: []}}
                    self.plugin.update_port(
                        context.get_admin_context(), port['port']['id'], data)
                    delete_dhcp_binding.assert_called_once_with(
                        dhcp_binding['nsx_service_id'],
                        dhcp_binding['nsx_binding_id'])

    def test_dhcp_binding_with_update_port_ip(self):
        # Test if DHCP binding is updated when the IP of the associated
        # compute port is changed.
        with self.subnet(cidr='10.0.0.0/24', enable_dhcp=True) as subnet:
            port_data = {'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                                        'ip_address': '10.0.0.3'}]}
            new_ip = '10.0.0.4'
            update_data = {'port': {'fixed_ips': [
                {'subnet_id': subnet['subnet']['id'], 'ip_address': new_ip}]}}
            assert_data = {'host_name': 'host-%s' % new_ip.replace('.', '-'),
                           'ip_address': new_ip,
                           'options': {'option121': {'static_routes': [
                               {'network': '%s' % nsx_rpc.METADATA_DHCP_ROUTE,
                                'next_hop': new_ip}]}}}
            self._verify_dhcp_binding(subnet, port_data, update_data,
                                      assert_data)

    def test_dhcp_binding_with_update_port_mac(self):
        # Test if DHCP binding is updated when the Mac of the associated
        # compute port is changed.
        with self.subnet(enable_dhcp=True) as subnet:
            port_data = {'mac_address': '11:22:33:44:55:66'}
            new_mac = '22:33:44:55:66:77'
            update_data = {'port': {'mac_address': new_mac}}
            assert_data = {'mac_address': new_mac}
            self._verify_dhcp_binding(subnet, port_data, update_data,
                                      assert_data)

    def test_dhcp_binding_with_update_port_mac_ip(self):
        # Test if DHCP binding is updated when the IP and Mac of the associated
        # compute port are changed at the same time.
        with self.subnet(cidr='10.0.0.0/24', enable_dhcp=True) as subnet:
            port_data = {'mac_address': '11:22:33:44:55:66',
                         'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                                        'ip_address': '10.0.0.3'}]}
            new_mac = '22:33:44:55:66:77'
            new_ip = '10.0.0.4'
            update_data = {'port': {'mac_address': new_mac, 'fixed_ips': [
                {'subnet_id': subnet['subnet']['id'], 'ip_address': new_ip}]}}
            assert_data = {'host_name': 'host-%s' % new_ip.replace('.', '-'),
                           'mac_address': new_mac,
                           'ip_address': new_ip,
                           'options': {'option121': {'static_routes': [
                               {'network': '%s' % nsx_rpc.METADATA_DHCP_ROUTE,
                                'next_hop': new_ip}]}}}
            self._verify_dhcp_binding(subnet, port_data, update_data,
                                      assert_data)

    def test_dhcp_binding_with_update_port_name(self):
        # Test if DHCP binding is not updated when the name of the associated
        # compute port is changed.
        with mock.patch.object(nsx_resources.LogicalDhcpServer,
                               'update_binding') as update_dhcp_binding:
            with self.subnet(cidr='10.0.0.0/24', enable_dhcp=True) as subnet:
                device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
                device_id = uuidutils.generate_uuid()
                with self.port(subnet=subnet, device_owner=device_owner,
                               device_id=device_id, name='abc') as port:
                    data = {'port': {'name': 'xyz'}}
                    self.plugin.update_port(
                        context.get_admin_context(), port['port']['id'], data)
                    update_dhcp_binding.assert_not_called()

    def test_dhcp_binding_with_multiple_ips(self):
        # Test create/update/delete DHCP binding with multiple IPs on a
        # compute port.
        with mock.patch.object(nsx_resources.LogicalDhcpServer,
                               'create_binding',
                               side_effect=[{"id": uuidutils.generate_uuid()},
                                            {"id": uuidutils.generate_uuid()}]
                               ) as create_dhcp_binding:
            with mock.patch.object(nsx_resources.LogicalDhcpServer,
                                   'update_binding'
                                   ) as update_dhcp_binding:
                with mock.patch.object(nsx_resources.LogicalDhcpServer,
                                       'delete_binding'
                                       ) as delete_dhcp_binding:
                    with self.subnet(cidr='10.0.0.0/24', enable_dhcp=True
                                     ) as subnet:
                        device_owner = (constants.DEVICE_OWNER_COMPUTE_PREFIX +
                                        'None')
                        device_id = uuidutils.generate_uuid()
                        fixed_ips = [{'subnet_id': subnet['subnet']['id'],
                                      'ip_address': '10.0.0.3'},
                                     {'subnet_id': subnet['subnet']['id'],
                                      'ip_address': '10.0.0.4'}]
                        with self.port(subnet=subnet,
                                       device_owner=device_owner,
                                       device_id=device_id,
                                       fixed_ips=fixed_ips) as port:
                            self.assertEqual(create_dhcp_binding.call_count, 2)
                            new_fixed_ips = [
                                {'subnet_id': subnet['subnet']['id'],
                                 'ip_address': '10.0.0.5'},
                                {'subnet_id': subnet['subnet']['id'],
                                 'ip_address': '10.0.0.6'}]
                            self.plugin.update_port(
                                context.get_admin_context(),
                                port['port']['id'],
                                {'port': {'fixed_ips': new_fixed_ips}})
                            self.assertEqual(update_dhcp_binding.call_count, 2)
                            self.plugin.delete_port(
                                context.get_admin_context(),
                                port['port']['id'])
                            self.assertEqual(delete_dhcp_binding.call_count, 2)


class NsxNativeMetadataTestCase(NsxV3PluginTestCaseMixin):

    def setUp(self):
        super(NsxNativeMetadataTestCase, self).setUp()
        self._orig_dhcp_agent_notification = cfg.CONF.dhcp_agent_notification
        self._orig_native_dhcp_metadata = cfg.CONF.nsx_v3.native_dhcp_metadata
        cfg.CONF.set_override('dhcp_agent_notification', False)
        cfg.CONF.set_override('native_dhcp_metadata', True, 'nsx_v3')
        self._patcher = mock.patch.object(nsx_resources.MetaDataProxy, 'get')
        self._patcher.start()
        # Need to run _init_dhcp_metadata() manually because plugin was
        # started before setUp() overrides CONF.nsx_v3.native_dhcp_metadata.
        self.plugin._init_dhcp_metadata()

    def tearDown(self):
        self._patcher.stop()
        cfg.CONF.set_override('dhcp_agent_notification',
                              self._orig_dhcp_agent_notification)
        cfg.CONF.set_override('native_dhcp_metadata',
                              self._orig_native_dhcp_metadata, 'nsx_v3')
        super(NsxNativeMetadataTestCase, self).tearDown()

    def test_metadata_proxy_configuration(self):
        # Test if dhcp_agent_notification and metadata_proxy_uuid are
        # configured correctly.
        orig_dhcp_agent_notification = cfg.CONF.dhcp_agent_notification
        cfg.CONF.set_override('dhcp_agent_notification', True)
        self.assertRaises(nsx_exc.NsxPluginException,
                          self.plugin._init_dhcp_metadata)
        cfg.CONF.set_override('dhcp_agent_notification',
                              orig_dhcp_agent_notification)
        orig_metadata_proxy_uuid = cfg.CONF.nsx_v3.metadata_proxy_uuid
        cfg.CONF.set_override('metadata_proxy_uuid', '', 'nsx_v3')
        self.assertRaises(cfg.RequiredOptError,
                          self.plugin._init_dhcp_metadata)
        cfg.CONF.set_override('metadata_proxy_uuid', orig_metadata_proxy_uuid,
                              'nsx_v3')

    def test_metadata_proxy_with_create_network(self):
        # Test if native metadata proxy is enabled on a network when it is
        # created.
        with mock.patch.object(nsx_resources.LogicalPort,
                               'create') as create_logical_port:
            with self.network() as network:
                nsx_net_id = self.plugin._get_network_nsx_id(
                    context.get_admin_context(), network['network']['id'])
                tags = utils.build_v3_tags_payload(
                    network['network'], resource_type='os-neutron-net-id',
                    project_name=None)
                create_logical_port.assert_called_once_with(
                    nsx_net_id, cfg.CONF.nsx_v3.metadata_proxy_uuid, tags=tags,
                    attachment_type=nsx_constants.ATTACHMENT_MDPROXY)

    def test_metadata_proxy_with_get_subnets(self):
        # Test if get_subnets() handles advanced-service-provider extension,
        # which is used when processing metadata requests.
        with self.network() as n1, self.network() as n2:
            with self.subnet(network=n1) as s1, self.subnet(network=n2) as s2:
                # Get all the subnets.
                subnets = self._list('subnets')['subnets']
                self.assertEqual(len(subnets), 2)
                self.assertEqual(set([s['id'] for s in subnets]),
                                 set([s1['subnet']['id'], s2['subnet']['id']]))
                lswitch_id = nsx_db.get_nsx_switch_ids(
                    context.get_admin_context().session,
                    n1['network']['id'])[0]
                # Get only the subnets associated with a particular advanced
                # service provider (i.e. logical switch).
                subnets = self._list('subnets', query_params='%s=%s' %
                                     (as_providers.ADV_SERVICE_PROVIDERS,
                                      lswitch_id))['subnets']
                self.assertEqual(len(subnets), 1)
                self.assertEqual(subnets[0]['id'], s1['subnet']['id'])
