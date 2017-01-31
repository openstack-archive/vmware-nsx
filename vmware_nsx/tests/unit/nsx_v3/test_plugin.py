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

import os

import mock
import six
from webob import exc

from neutron.api.v2 import attributes
from neutron import context
from neutron.db import models_v2
from neutron.extensions import external_net
from neutron.extensions import extraroute
from neutron.extensions import l3
from neutron.extensions import l3_ext_gw_mode
from neutron.extensions import securitygroup as secgrp
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_extra_dhcp_opt as test_dhcpopts
from neutron.tests.unit.extensions import test_extraroute as test_ext_route
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from neutron.tests.unit.extensions \
    import test_l3_ext_gw_mode as test_ext_gw_mode
from neutron.tests.unit.scheduler \
    import test_dhcp_agent_scheduler as test_dhcpagent
from neutron.tests.unit import testlib_api

from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import uuidutils

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import utils
from vmware_nsx.plugins.nsx_v3 import cert_utils
from vmware_nsx.plugins.nsx_v3 import plugin as nsx_plugin
from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.extensions import test_metadata
from vmware_nsxlib.tests.unit.v3 import mocks as nsx_v3_mocks
from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase


PLUGIN_NAME = 'vmware_nsx.plugin.NsxV3Plugin'
NSX_TZ_NAME = 'default transport zone'
NSX_DHCP_PROFILE_ID = 'default dhcp profile'
NSX_METADATA_PROXY_ID = 'default metadata proxy'


def _mock_create_firewall_rules(*args):
    # NOTE(arosen): the code in the neutron plugin expects the
    # neutron rule id as the display_name.
    rules = args[5]
    return {
        'rules': [
            {'display_name': rule['id'], 'id': uuidutils.generate_uuid()}
            for rule in rules
        ]}


def _mock_nsx_backend_calls():
    mock.patch("vmware_nsxlib.v3.client.NSX3Client").start()

    fake_profile = {'key': 'FakeKey',
                    'resource_type': 'FakeResource',
                    'id': uuidutils.generate_uuid()}

    def _return_id_key(*args, **kwargs):
        return {'id': uuidutils.generate_uuid()}

    def _return_id(*args, **kwargs):
        return uuidutils.generate_uuid()

    mock.patch(
        "vmware_nsxlib.v3.resources.SwitchingProfile.find_by_display_name",
        return_value=[fake_profile]
    ).start()

    mock.patch(
        "vmware_nsxlib.v3.router.RouterLib.validate_tier0").start()

    mock.patch(
        "vmware_nsxlib.v3.resources.SwitchingProfile."
        "create_port_mirror_profile",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.NsxLibBridgeCluster.get_id_by_name_or_id",
        return_value=uuidutils.generate_uuid()).start()

    mock.patch(
        "vmware_nsxlib.v3.NsxLibTransportZone.get_id_by_name_or_id",
        return_value=uuidutils.generate_uuid()).start()

    mock.patch(
        "vmware_nsxlib.v3.NsxLibBridgeEndpoint.create",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.security.NsxLibNsGroup.find_by_display_name",
    ).start()

    mock.patch(
        "vmware_nsxlib.v3.NsxLibLogicalSwitch.create",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.NsxLibDhcpProfile.get_id_by_name_or_id",
        return_value=NSX_DHCP_PROFILE_ID).start()

    mock.patch(
        "vmware_nsxlib.v3.NsxLibMetadataProxy.get_id_by_name_or_id",
        return_value=NSX_METADATA_PROXY_ID).start()

    mock.patch(
        "vmware_nsxlib.v3.resources.LogicalPort.create",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.resources.LogicalRouter.create",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.resources.LogicalDhcpServer.create",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.resources.LogicalDhcpServer.create_binding",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.NsxLib.get_version",
        return_value="0.6.0").start()


class NsxV3PluginTestCaseMixin(test_plugin.NeutronDbPluginV2TestCase,
                               nsxlib_testcase.NsxClientTestCase):

    def setup_conf_overrides(self):
        cfg.CONF.set_override('default_overlay_tz', NSX_TZ_NAME, 'nsx_v3')
        cfg.CONF.set_override('native_dhcp_metadata', False, 'nsx_v3')
        cfg.CONF.set_override('dhcp_profile',
                              NSX_DHCP_PROFILE_ID, 'nsx_v3')
        cfg.CONF.set_override('metadata_proxy',
                              NSX_METADATA_PROXY_ID, 'nsx_v3')
        cfg.CONF.set_override(
            'network_scheduler_driver',
            'neutron.scheduler.dhcp_agent_scheduler.AZAwareWeightScheduler')

    def setUp(self, plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):

        self._patchers = []

        _mock_nsx_backend_calls()
        self.setup_conf_overrides()

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


class TestSubnetsV2(test_plugin.TestSubnetsV2, NsxV3PluginTestCaseMixin):

    def test_create_subnet_with_shared_address_space(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '100.64.0.0/16'}}
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.create_subnet,
                              context.get_admin_context(), data)


class TestPortsV2(test_plugin.TestPortsV2, NsxV3PluginTestCaseMixin,
                  test_bindings.PortBindingsTestCase,
                  test_bindings.PortBindingsHostTestCaseMixin,
                  test_bindings.PortBindingsVnicTestCaseMixin):

    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = True

    def setUp(self):
        super(TestPortsV2, self).setUp()
        self.plugin = directory.get_plugin()
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
                # Cannot add qos policy to a router port
                self.assertRaises(n_exc.InvalidInput,
                          self.plugin.create_port, self.ctx, data)

    def test_create_router_port_with_qos_fail(self):
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24'):
                policy_id = uuidutils.generate_uuid()
                data = {'port': {'network_id': network['network']['id'],
                                 'tenant_id': self._tenant_id,
                                 'device_owner': 'network:router_interface',
                                 'qos_policy_id': policy_id}}
                # Cannot add qos policy to a router interface port
                self.assertRaises(n_exc.InvalidInput,
                          self.plugin.create_port, self.ctx, data)

    def test_update_router_port_with_qos_fail(self):
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24'):
                policy_id = uuidutils.generate_uuid()
                data = {'port': {'network_id': network['network']['id'],
                                 'tenant_id': self._tenant_id,
                                 'name': 'qos_port',
                                 'admin_state_up': True,
                                 'fixed_ips': [],
                                 'mac_address': '00:00:00:00:00:01',
                                 'device_id': 'dummy',
                                 'device_owner': ''}}
                port = self.plugin.create_port(self.ctx, data)
                policy_id = uuidutils.generate_uuid()
                data['port'] = {'qos_policy_id': policy_id,
                                'device_owner': 'network:router_interface'}
                # Cannot add qos policy to a router interface port
                self.assertRaises(n_exc.InvalidInput,
                          self.plugin.update_port, self.ctx, port['id'], data)

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
        pl = directory.get_plugin()
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
        self.plugin = directory.get_plugin()
        self.ctx = context.get_admin_context()

    def setup_coreplugin(self, core_plugin=None, load_plugins=True):
        super(NSXv3DHCPAgentAZAwareWeightSchedulerTestCase,
              self).setup_coreplugin(core_plugin=PLUGIN_NAME,
                                     load_plugins=load_plugins)


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
        self.plugin_instance = directory.get_plugin()
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

    def test_router_add_interface_dup_subnet2_returns_400(self):
        self.skipTest('not supported')

    def test_router_add_interface_ipv6_port_existing_network_returns_400(self):
        self.skipTest('not supported')

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
                self.assertRaises(n_exc.Conflict,
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

    def test_floatingip_update_to_same_port_id_twice(self):
        self.skipTest('Plugin changes floating port status')


class ExtGwModeTestCase(test_ext_gw_mode.ExtGwModeIntTestCase,
                        L3NatTest):
    def test_router_gateway_set_fail_after_port_create(self):
        self.skipTest("TBD")


class NsxV3PluginClientCertTestCase(testlib_api.WebTestCase):

    CERT = "-----BEGIN CERTIFICATE-----\n" \
        "MIIDJTCCAg0CBFh36j0wDQYJKoZIhvcNAQELBQAwVzELMAkGA1UEBhMCVVMxEzAR\n" \
        "BgNVBAgMCkNhbGlmb3JuaWExDjAMBgNVBAoMBU15T3JnMQ8wDQYDVQQLDAZNeVVu\n" \
        "aXQxEjAQBgNVBAMMCW15b3JnLmNvbTAeFw0xNzAxMTIyMDQyMzdaFw0yNzAxMTAy\n" \
        "MDQyMzdaMFcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMQ4wDAYD\n" \
        "VQQKDAVNeU9yZzEPMA0GA1UECwwGTXlVbml0MRIwEAYDVQQDDAlteW9yZy5jb20w\n" \
        "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/wsYintlWVaSeXwaSrdPa\n" \
        "+AHtL1ooH7q0uf6tt+6Rwiy10YRjAVJhapj9995gqgJ2402J+3gzNXLCbXjjDR/D\n" \
        "9xjAzKHu61r0AVNd9/0+8yXQrEDuzlwHSCKz+zjq5ZEZ7RkLIUdreaZJFPTCwry3\n" \
        "wuTnBfqcE7xWl6WfWR8evooV+ZzIfjQdoSliIyn3YGxNN5pc1P40qt0pxOsNBGXG\n" \
        "2FIZXpML8TpKw0ga/wE70CJd6tRvSsAADxQXehfKvGtHvlJYS+3cTahC7reQXJnc\n" \
        "qsjgYkiWyhhR4jdcTD/tDlVcJroM1jFVxpsCg/AU3srWWWeAGyVe42ZhqWVf0Urz\n" \
        "AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAA/lLfmXe8wPyBhN/VMb5bu5Ey56qz+j\n" \
        "jCn7tz7FjRvsB9P0fLUDOBKNwyon3yopDNYJ4hnm4yKoHCHURQLZKWHzm0XKzE+4\n" \
        "cA/M13M8OEg5otnVVHhz1FPQWnJq7bLHh/KXYcc5Rkc7UeHEPj0sDjfUjCPGdepc\n" \
        "Ghu1ZcgHsL4JCuvcadG+RFGeDTug3yO92Fj2uFy5DlzzWOZSi4otpZRd9JZkAtZ1\n" \
        "umZRBJ2A504nJx4MplmNqvLNkmxMLKQdvZYNNiYr6icOavDOJA5RhzgoppJZkV2w\n" \
        "v2oC+8BFarXnZSk37HAWjwcaqzBLbIyPYpClW5IYMr8LiixSBACc+4w=\n" \
        "-----END CERTIFICATE-----\n"

    PKEY = "-----BEGIN PRIVATE KEY-----\n" \
        "MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQC/wsYintlWVaSe\n" \
        "XwaSrdPa+AHtL1ooH7q0uf6tt+6Rwiy10YRjAVJhapj9995gqgJ2402J+3gzNXLC\n" \
        "bXjjDR/D9xjAzKHu61r0AVNd9/0+8yXQrEDuzlwHSCKz+zjq5ZEZ7RkLIUdreaZJ\n" \
        "FPTCwry3wuTnBfqcE7xWl6WfWR8evooV+ZzIfjQdoSliIyn3YGxNN5pc1P40qt0p\n" \
        "xOsNBGXG2FIZXpML8TpKw0ga/wE70CJd6tRvSsAADxQXehfKvGtHvlJYS+3cTahC\n" \
        "7reQXJncqsjgYkiWyhhR4jdcTD/tDlVcJroM1jFVxpsCg/AU3srWWWeAGyVe42Zh\n" \
        "qWVf0UrzAgMBAAECggEBAJrGuie9cQy3KZzOdD614RaPMPbhTnKuUYOH0GEk4YFy\n" \
        "aaYDS0iiC30njf8HLs10y3JsOuyRNU6X6F24AGe68xW3/pm3UUjHXG0wGLry68wA\n" \
        "c1g/gFV/6FXUSnZc4m7uBjUX4yvRm5TK5oV8TaZZifsEar9xWvrZDx4RXpQEWhL0\n" \
        "L/TyrOZSfRtBgdWX6Ag4XQVsCfZxJoCi2ZyvaMBsWTH06x9AGo1Io5t1AmA9Hsfb\n" \
        "6BsSz186nqb0fq4UMfrWrSCz7M/1s03+hBOVICH2TdaRDZLtDVa1b2x4sFpfdp9t\n" \
        "VVxuSHxcmvzOPMIv3NXwj0VitTYYJDBFKoEfx1mzhNkCgYEA59gYyBfpsuCOevP2\n" \
        "tn7IeysbtaoKDzHE+ksjs3sAn6Vr2Y0Lbed26NpdIVL6u3HAteJxqrIh0zpkpAtp\n" \
        "akdqlj86oRaBUqLXxK3QNpUx19f7KN7UsVAbzUJSOm2n1piPg261ktfhtms2rxnQ\n" \
        "+9yluINu+z1wS4FG9SwrRmwwfsUCgYEA072Ma1sj2MER5tmQw1zLANkzP1PAkUdy\n" \
        "+oDuJmU9A3/+YSIkm8dGprFglPkLUaf1B15oN6wCJVMpB1lza3PM/YT70rpqc7cq\n" \
        "PHJXQlZFMBhyVfIkCv3wICTLD5phhgAWlzlwm094f2uAnbG6WUkrVfZajuh0pW53\n" \
        "1i0OTfxAvlcCgYEAkDB2oSM2JhjApDlMbA2HtAqIbkA1h2OlpSDMMFjEd4WTALdW\n" \
        "r2CwNHtyRkJsS92gQ750gPvOS6daZifuxLlr0cu7M+piPbmnRdvvzbKWUC40NyP2\n" \
        "1dwDnnGr4EjIhI9XWh+lb5EyAJjHZrlAnxOIQawEft6kE2FwdxSkSWUJ+B0CgYEA\n" \
        "n2xYDXzRwKGdmPK2zGFRd5IRw9yLYNcq+vGYXdBb4Aa+wOO0LJYd2+Qxk/jvTMvo\n" \
        "8WNjlIcuFmxGuAHhpUXLUhaOhFtXS0jdxCVTDd9muI+vhoaKHLyVz53kRhs20m2+\n" \
        "lJ3q6wUq9MU8UX8/j3pH5rFV/cOIEAbcs6W4337OQIECgYEAoLtQyqXjH45FlCQx\n" \
        "xK8dY+GuxIP+TIwiq23yhu3e+3LIgXJw8DwBFN5yJyH2HMnhGkD4PurEx2sGHeLO\n" \
        "EG6L8PNDOxpvSzcgxwmZsUK6j3nAbKycF3PDDXA4kt8WDXBr86OMQsFtpjeO+fGh\n" \
        "YWJa+OKc2ExdeMewe9gKIDQ5stw=\n" \
        "-----END PRIVATE KEY-----\n"

    CERTFILE = '/tmp/client_cert.pem'

    def _init_config(self, password=None):
        cfg.CONF.set_override('default_overlay_tz', NSX_TZ_NAME, 'nsx_v3')
        cfg.CONF.set_override('native_dhcp_metadata', False, 'nsx_v3')
        cfg.CONF.set_override('dhcp_profile',
                              NSX_DHCP_PROFILE_ID, 'nsx_v3')
        cfg.CONF.set_override('metadata_proxy',
                              NSX_METADATA_PROXY_ID, 'nsx_v3')

        cfg.CONF.set_override('nsx_use_client_auth', True, 'nsx_v3')
        cfg.CONF.set_override('nsx_client_cert_file', self.CERTFILE, 'nsx_v3')
        cfg.CONF.set_override('nsx_client_cert_storage', 'nsx-db', 'nsx_v3')

        if password:
            cfg.CONF.set_override('nsx_client_cert_pk_password',
                                  password, 'nsx_v3')

    def _init_plugin(self, password=None):
        _mock_nsx_backend_calls()

        self._tenant_id = test_plugin.TEST_TENANT_ID
        self._init_config(password)
        self.setup_coreplugin(PLUGIN_NAME, load_plugins=True)

    def test_init_without_cert(self):
        """Verify init fails if no cert is provided in client cert mode"""
        # certificate not generated - exception should be raised
        self.assertRaises(nsx_exc.ClientCertificateException,
                          self._init_plugin)

    def test_init_with_cert(self):
        """Verify successful certificate load from storage"""

        mock.patch(
            "vmware_nsx.db.db.get_certificate",
            return_value=(self.CERT, self.PKEY)).start()

        self._init_plugin()

        # verify cert data was exported to CERTFILE
        expected = self.CERT + self.PKEY
        with open(self.CERTFILE, 'r') as f:
            actual = f.read()

        self.assertEqual(expected, actual)

        # delete CERTFILE
        os.remove(self.CERTFILE)

    def test_init_with_cert_encrypted(self):
        """Verify successful encrypted PK load from storage"""

        password = 'topsecret'
        secret = cert_utils.generate_secret_from_password(password)
        encrypted_pkey = cert_utils.symmetric_encrypt(secret, self.PKEY)
        # db always returns string
        mock.patch(
            "vmware_nsx.db.db.get_certificate",
            return_value=(self.CERT, encrypted_pkey)).start()

        self._init_plugin(password)

        # verify cert data was exported to CERTFILE
        expected = self.CERT + self.PKEY
        with open(self.CERTFILE, 'r') as f:
            actual = f.read()

        self.assertEqual(expected, actual)

        # delete CERTFILE
        os.remove(self.CERTFILE)

    def test_init_with_cert_decrypt_fails(self):
        """Verify loading plaintext PK from storage fails in encrypt mode"""

        mock.patch(
            "vmware_nsx.db.db.get_certificate",
            return_value=(self.CERT, self.PKEY)).start()

        self._tenant_id = test_plugin.TEST_TENANT_ID
        self._init_config('topsecret')

        # since PK in DB is not encrypted, we should fail to decrypt it on load
        self.assertRaises(nsx_exc.ClientCertificateException,
                          self._init_plugin)

    # TODO(annak): add test that verifies bad crypto data raises exception
    # when OPENSSL exception wrapper is available from NSXLIB
