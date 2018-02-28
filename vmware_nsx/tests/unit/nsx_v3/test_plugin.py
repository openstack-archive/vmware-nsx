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
from neutron.db import models_v2
from neutron.extensions import address_scope
from neutron.extensions import external_net
from neutron.extensions import extraroute
from neutron.extensions import l3
from neutron.extensions import l3_ext_gw_mode
from neutron.extensions import securitygroup as secgrp
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_address_scope
from neutron.tests.unit.extensions import test_extra_dhcp_opt as test_dhcpopts
from neutron.tests.unit.extensions import test_extraroute as test_ext_route
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from neutron.tests.unit.extensions \
    import test_l3_ext_gw_mode as test_ext_gw_mode
from neutron.tests.unit.scheduler \
    import test_dhcp_agent_scheduler as test_dhcpagent

from neutron_lib.api.definitions import address_scope as addr_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.callbacks import exceptions as nc_exc
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import uuidutils

from vmware_nsx.api_client import exception as api_exc
from vmware_nsx.common import utils
from vmware_nsx.plugins.nsx_v3 import plugin as nsx_plugin
from vmware_nsx.services.lbaas.nsx_v3 import lb_driver_v2
from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.extensions import test_metadata
from vmware_nsxlib.tests.unit.v3 import mocks as nsx_v3_mocks
from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.v3 import exceptions as nsxlib_exc


PLUGIN_NAME = 'vmware_nsx.plugin.NsxV3Plugin'
NSX_TZ_NAME = 'default transport zone'
NSX_DHCP_PROFILE_ID = 'default dhcp profile'
NSX_METADATA_PROXY_ID = 'default metadata proxy'
NSX_SWITCH_PROFILE = 'dummy switch profile'


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

    def _return_same(key, *args, **kwargs):
        return key

    mock.patch(
        "vmware_nsxlib.v3.core_resources.NsxLibSwitchingProfile."
        "find_by_display_name",
        return_value=[fake_profile]
    ).start()

    mock.patch(
        "vmware_nsxlib.v3.router.RouterLib.validate_tier0").start()

    mock.patch(
        "vmware_nsxlib.v3.core_resources.NsxLibSwitchingProfile."
        "create_port_mirror_profile",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.core_resources.NsxLibBridgeCluster."
        "get_id_by_name_or_id",
        return_value=uuidutils.generate_uuid()).start()

    mock.patch(
        "vmware_nsxlib.v3.core_resources.NsxLibTransportZone."
        "get_id_by_name_or_id",
        return_value=uuidutils.generate_uuid()).start()

    mock.patch(
        "vmware_nsxlib.v3.core_resources.NsxLibBridgeEndpoint.create",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.security.NsxLibNsGroup.find_by_display_name",
    ).start()

    mock.patch(
        "vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.create",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.core_resources.NsxLibDhcpProfile."
        "get_id_by_name_or_id",
        return_value=NSX_DHCP_PROFILE_ID).start()

    mock.patch(
        "vmware_nsxlib.v3.core_resources.NsxLibMetadataProxy."
        "get_id_by_name_or_id",
        side_effect=_return_same).start()

    mock.patch(
        "vmware_nsxlib.v3.resources.LogicalPort.create",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.core_resources.NsxLibLogicalRouter.create",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.resources.LogicalDhcpServer.create",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.resources.LogicalDhcpServer.create_binding",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.core_resources.NsxLibLogicalRouter."
        "get_firewall_section_id",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.NsxLib.get_version",
        return_value='1.1.0').start()

    mock.patch(
        "vmware_nsxlib.v3.load_balancer.Service.get_router_lb_service",
        return_value=None).start()


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

    def mock_plugin_methods(self):
        # mock unnecessary call which causes spawn
        mock_process_security_group_logging = mock.patch.object(
            nsx_plugin.NsxV3Plugin, '_process_security_group_logging')
        mock_process_security_group_logging.start()
        # need to mock the global placeholder. This is due to the fact that
        # the generic security group tests assume that there is just one
        # security group.
        mock_ensure_global_sg_placeholder = mock.patch.object(
            nsx_plugin.NsxV3Plugin, '_ensure_global_sg_placeholder')
        mock_ensure_global_sg_placeholder.start()

    def setUp(self, plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):

        self._patchers = []

        _mock_nsx_backend_calls()
        self.setup_conf_overrides()
        self.mock_plugin_methods()
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

    def test_network_failure_rollback(self):
        cfg.CONF.set_override('native_dhcp_metadata', True, 'nsx_v3')
        self.plugin = directory.get_plugin()
        with mock.patch.object(self.plugin.nsxlib.logical_port, 'create',
                               side_effect=api_exc.NsxApiException):
            self.network()
            ctx = context.get_admin_context()
            networks = self.plugin.get_networks(ctx)
            self.assertListEqual([], networks)


class TestSubnetsV2(test_plugin.TestSubnetsV2, NsxV3PluginTestCaseMixin):

    def test_create_subnet_with_shared_address_space(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '100.64.0.0/16'}}
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.create_subnet,
                              context.get_admin_context(), data)

    def test_subnet_update_ipv4_and_ipv6_pd_v6stateless_subnets(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_subnet_update_ipv4_and_ipv6_pd_slaac_subnets(self):
        self.skipTest('Multiple fixed ips on a port are not supported')


class TestPortsV2(test_plugin.TestPortsV2, NsxV3PluginTestCaseMixin,
                  test_bindings.PortBindingsTestCase,
                  test_bindings.PortBindingsHostTestCaseMixin,
                  test_bindings.PortBindingsVnicTestCaseMixin):

    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = True

    def setUp(self):
        cfg.CONF.set_override('switching_profiles', [NSX_SWITCH_PROFILE],
                              'nsx_v3')
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

    def _test_create_illegal_port_with_qos_fail(self, device_owner):
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24'):
                policy_id = uuidutils.generate_uuid()
                data = {'port': {'network_id': network['network']['id'],
                                 'tenant_id': self._tenant_id,
                                 'device_owner': device_owner,
                                 'qos_policy_id': policy_id}}
                # Cannot add qos policy to this type of port
                self.assertRaises(n_exc.InvalidInput,
                          self.plugin.create_port, self.ctx, data)

    def test_create_router_port_with_qos_fail(self):
        self._test_create_illegal_port_with_qos_fail(
            'network:router_interface')

    def test_create_dhcp_port_with_qos_fail(self):
        self._test_create_illegal_port_with_qos_fail('network:dhcp')

    def _test_update_illegal_port_with_qos_fail(self, device_owner):
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
                                'device_owner': device_owner}
                # Cannot add qos policy to a router interface port
                self.assertRaises(n_exc.InvalidInput,
                          self.plugin.update_port, self.ctx, port['id'], data)

    def test_update_router_port_with_qos_fail(self):
        self._test_update_illegal_port_with_qos_fail(
            'network:router_interface')

    def test_update_dhcp_port_with_qos_fail(self):
        self._test_update_illegal_port_with_qos_fail('network:dhcp')

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

    def test_port_failure_rollback_dhcp_exception(self):
        cfg.CONF.set_override('native_dhcp_metadata', True, 'nsx_v3')
        self.plugin = directory.get_plugin()
        with mock.patch.object(self.plugin, '_add_dhcp_binding',
                               side_effect=nsxlib_exc.ManagerError):
            self.port()
            ctx = context.get_admin_context()
            networks = self.plugin.get_ports(ctx)
            self.assertListEqual([], networks)

    def test_update_port_add_additional_ip(self):
        """Test update of port with additional IP fails."""
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                data = {'port': {'admin_state_up': False,
                                 'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id']},
                                               {'subnet_id':
                                                subnet['subnet']['id']}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = req.get_response(self.api)
                self.assertEqual(exc.HTTPBadRequest.code,
                                 res.status_int)

    def test_create_port_additional_ip(self):
        """Test that creation of port with additional IP fails."""
        with self.subnet() as subnet:
            data = {'port': {'network_id': subnet['subnet']['network_id'],
                             'tenant_id': subnet['subnet']['tenant_id'],
                             'fixed_ips': [{'subnet_id':
                                            subnet['subnet']['id']},
                                           {'subnet_id':
                                            subnet['subnet']['id']}]}}
            port_req = self.new_create_request('ports', data)
            res = port_req.get_response(self.api)
            self.assertEqual(exc.HTTPBadRequest.code,
                             res.status_int)

    def test_create_port_with_switching_profiles(self):
        """Tests that nsx ports get the configures switching profiles"""
        self.plugin = directory.get_plugin()
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'p1',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'mac_address': '00:00:00:00:00:01'}
                    }
            with mock.patch.object(self.plugin.nsxlib.logical_port, 'create',
                                   return_value={'id': 'fake'}) as nsx_create:
                self.plugin.create_port(self.ctx, data)
                expected_prof = self.plugin.get_default_az().\
                    switching_profiles_objs[0]
                actual_profs = nsx_create.call_args[1]['switch_profile_ids']
                # the ports switching profiles should start with the
                # configured one
                self.assertEqual(expected_prof, actual_profs[0])

    def test_update_port_update_ip_address_only(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_update_port_with_new_ipv6_slaac_subnet_in_fixed_ips(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_update_port_mac_v6_slaac(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_requested_subnet_id_v4_and_v6(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_requested_invalid_fixed_ips(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_requested_subnet_id_v4_and_v6_slaac(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_range_allocation(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_create_port_anticipating_allocation(self):
        self.skipTest('Multiple fixed ips on a port are not supported')


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
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            addr_apidef.RESOURCE_ATTRIBUTE_MAP)
        return (l3.L3.get_resources() +
                address_scope.Address_scope.get_resources())

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


class L3NatTest(test_l3_plugin.L3BaseForIntTests, NsxV3PluginTestCaseMixin,
                test_address_scope.AddressScopeTestCase):

    def _restore_l3_attribute_map(self):
        l3.RESOURCE_ATTRIBUTE_MAP = self._l3_attribute_map_bk

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None,
              service_plugins=None):
        self._l3_attribute_map_bk = backup_l3_attribute_map()
        cfg.CONF.set_override('api_extensions_path', vmware.NSXEXT_PATH)
        cfg.CONF.set_default('max_routes', 3)
        self.addCleanup(restore_l3_attribute_map, self._l3_attribute_map_bk)
        ext_mgr = ext_mgr or TestL3ExtensionManager()
        mock_nsx_version = mock.patch.object(nsx_plugin.utils,
                                             'is_nsx_version_2_0_0',
                                             new=lambda v: True)
        mock_nsx_version.start()

        super(L3NatTest, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        self.plugin_instance = directory.get_plugin()
        self._plugin_name = "%s.%s" % (
            self.plugin_instance.__module__,
            self.plugin_instance.__class__.__name__)
        self._plugin_class = self.plugin_instance.__class__

    def test_floatingip_create_different_fixed_ip_same_port(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_router_add_interface_multiple_ipv4_subnet_port_returns_400(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_router_add_interface_multiple_ipv6_subnet_port(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_floatingip_update_different_fixed_ip_same_port(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_create_multiple_floatingips_same_fixed_ip_same_port(self):
        self.skipTest('Multiple fixed ips on a port are not supported')


class TestL3NatTestCase(L3NatTest,
                        test_l3_plugin.L3NatDBIntTestCase,
                        test_ext_route.ExtraRouteDBTestCaseBase,
                        test_metadata.MetaDataTestCase):

    block_dhcp_notifier = False

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

    def test_floatingip_update_subnet_gateway_disabled(self):
        self.skipTest('not supported')

    def test_router_delete_with_lb_service(self):
        # Create the LB object - here the delete callback is registered
        lb_driver = lb_driver_v2.EdgeLoadbalancerDriverV2()
        with self.router() as router:
            with mock.patch('vmware_nsxlib.v3.load_balancer.Service.'
                            'get_router_lb_service'):
                self.assertRaises(nc_exc.CallbackFailure,
                                  self.plugin_instance.delete_router,
                                  context.get_admin_context(),
                                  router['router']['id'])
        # Unregister callback
        lb_driver._unsubscribe_router_delete_callback()

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

    def _test_create_subnetpool(self, prefixes, expected=None,
                                admin=False, **kwargs):
        keys = kwargs.copy()
        keys.setdefault('tenant_id', self._tenant_id)
        with self.subnetpool(prefixes, admin, **keys) as subnetpool:
            self._validate_resource(subnetpool, keys, 'subnetpool')
            if expected:
                self._compare_resource(subnetpool, expected, 'subnetpool')
        return subnetpool

    def _update_router_enable_snat(self, router_id, network_id, enable_snat):
        return self._update('routers', router_id,
                            {'router': {'external_gateway_info':
                                        {'network_id': network_id,
                                         'enable_snat': enable_snat}}})

    def test_router_no_snat_with_different_address_scope(self):
        """Test that if the router has no snat, you cannot add an interface
        from a different address scope than the gateway.
        """
        # create an external network on one address scope
        with self.address_scope(name='as1') as addr_scope, \
            self.network() as ext_net:
            self._set_net_external(ext_net['network']['id'])
            as_id = addr_scope['address_scope']['id']
            subnet = netaddr.IPNetwork('10.10.10.0/24')
            subnetpool = self._test_create_subnetpool(
                [subnet.cidr], name='sp1',
                min_prefixlen='24', address_scope_id=as_id)
            subnetpool_id = subnetpool['subnetpool']['id']
            data = {'subnet': {
                    'network_id': ext_net['network']['id'],
                    'subnetpool_id': subnetpool_id,
                    'ip_version': 4,
                    'enable_dhcp': False,
                    'tenant_id': ext_net['network']['tenant_id']}}
            req = self.new_create_request('subnets', data)
            ext_subnet = self.deserialize(self.fmt, req.get_response(self.api))

            # create a regular network on another address scope
            with self.address_scope(name='as2') as addr_scope2, \
                self.network() as net:
                as_id2 = addr_scope2['address_scope']['id']
                subnet2 = netaddr.IPNetwork('20.10.10.0/24')
                subnetpool2 = self._test_create_subnetpool(
                    [subnet2.cidr], name='sp2',
                    min_prefixlen='24', address_scope_id=as_id2)
                subnetpool_id2 = subnetpool2['subnetpool']['id']
                data = {'subnet': {
                        'network_id': net['network']['id'],
                        'subnetpool_id': subnetpool_id2,
                        'ip_version': 4,
                        'tenant_id': net['network']['tenant_id']}}
                req = self.new_create_request('subnets', data)
                int_subnet = self.deserialize(
                    self.fmt, req.get_response(self.api))

                # create a no snat router with this gateway
                with self.router() as r:
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        ext_subnet['subnet']['network_id'])
                    self._update_router_enable_snat(
                        r['router']['id'],
                        ext_subnet['subnet']['network_id'],
                        False)

                    # should fail adding the interface to the router
                    err_code = exc.HTTPBadRequest.code
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  int_subnet['subnet']['id'],
                                                  None,
                                                  err_code)

    def test_router_no_snat_with_same_address_scope(self):
        """Test that if the router has no snat, you can add an interface
        from the same address scope as the gateway.
        """
        # create an external network on one address scope
        with self.address_scope(name='as1') as addr_scope, \
            self.network() as ext_net:
            self._set_net_external(ext_net['network']['id'])
            as_id = addr_scope['address_scope']['id']
            subnet = netaddr.IPNetwork('10.10.10.0/21')
            subnetpool = self._test_create_subnetpool(
                [subnet.cidr], name='sp1',
                min_prefixlen='24', address_scope_id=as_id)
            subnetpool_id = subnetpool['subnetpool']['id']
            data = {'subnet': {
                    'network_id': ext_net['network']['id'],
                    'subnetpool_id': subnetpool_id,
                    'ip_version': 4,
                    'enable_dhcp': False,
                    'tenant_id': ext_net['network']['tenant_id']}}
            req = self.new_create_request('subnets', data)
            ext_subnet = self.deserialize(self.fmt, req.get_response(self.api))

            # create a regular network on the same address scope
            with self.network() as net:
                data = {'subnet': {
                        'network_id': net['network']['id'],
                        'subnetpool_id': subnetpool_id,
                        'ip_version': 4,
                        'tenant_id': net['network']['tenant_id']}}
                req = self.new_create_request('subnets', data)
                int_subnet = self.deserialize(
                    self.fmt, req.get_response(self.api))

                # create a no snat router with this gateway
                with self.router() as r:
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        ext_subnet['subnet']['network_id'])
                    self._update_router_enable_snat(
                        r['router']['id'],
                        ext_subnet['subnet']['network_id'],
                        False)

                    # should succeed adding the interface to the router
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  int_subnet['subnet']['id'],
                                                  None)

    def _mock_add_snat_rule(self):
        return mock.patch("vmware_nsxlib.v3.router.RouterLib."
                          "add_gw_snat_rule")

    def _mock_del_snat_rule(self):
        return mock.patch("vmware_nsxlib.v3.router.RouterLib."
                          "delete_gw_snat_rule_by_source")

    def _prepare_external_subnet_on_address_scope(self,
                                                  ext_net,
                                                  address_scope):

        self._set_net_external(ext_net['network']['id'])
        as_id = address_scope['address_scope']['id']
        subnet = netaddr.IPNetwork('10.10.10.0/21')
        subnetpool = self._test_create_subnetpool(
            [subnet.cidr], name='sp1',
            min_prefixlen='24', address_scope_id=as_id)
        subnetpool_id = subnetpool['subnetpool']['id']
        data = {'subnet': {
                'network_id': ext_net['network']['id'],
                'subnetpool_id': subnetpool_id,
                'ip_version': 4,
                'enable_dhcp': False,
                'tenant_id': ext_net['network']['tenant_id']}}
        req = self.new_create_request('subnets', data)
        ext_subnet = self.deserialize(self.fmt, req.get_response(self.api))
        return ext_subnet['subnet']

    def _create_subnet_and_assert_snat_rules(self, subnetpool_id,
                                             router_id,
                                             assert_snat_deleted=False,
                                             assert_snat_added=False):
        # create a regular network on the given subnet pool
        with self.network() as net:
            data = {'subnet': {
                    'network_id': net['network']['id'],
                    'subnetpool_id': subnetpool_id,
                    'ip_version': 4,
                    'tenant_id': net['network']['tenant_id']}}
            req = self.new_create_request('subnets', data)
            int_subnet = self.deserialize(
                self.fmt, req.get_response(self.api))

            with self._mock_add_snat_rule() as add_nat,\
                self._mock_del_snat_rule() as delete_nat:
                # Add the interface
                self._router_interface_action(
                    'add',
                    router_id,
                    int_subnet['subnet']['id'],
                    None)

                if assert_snat_deleted:
                    delete_nat.assert_called()
                else:
                    delete_nat.assert_not_called()

                if assert_snat_added:
                    add_nat.assert_called()
                else:
                    add_nat.assert_not_called()

    def test_router_address_scope_snat_rules(self):
        """Test that if the router interface had the same address scope
        as the gateway - snat rule is not added.
        """
        # create an external network on one address scope
        with self.address_scope(name='as1') as addr_scope, \
            self.network() as ext_net:
            ext_subnet = self._prepare_external_subnet_on_address_scope(
                ext_net, addr_scope)

            # create a router with this gateway
            with self.router() as r:
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    ext_subnet['network_id'])

            # create a regular network on same address scope
            # and verify no snat change
            as_id = addr_scope['address_scope']['id']
            subnet = netaddr.IPNetwork('30.10.10.0/24')
            subnetpool = self._test_create_subnetpool(
                [subnet.cidr], name='sp2',
                min_prefixlen='24', address_scope_id=as_id)
            as_id = addr_scope['address_scope']['id']
            subnetpool_id = subnetpool['subnetpool']['id']
            self._create_subnet_and_assert_snat_rules(
                subnetpool_id, r['router']['id'])

            # create a regular network on a different address scope
            # and verify snat rules are added
            with self.address_scope(name='as2') as addr_scope2:
                as2_id = addr_scope2['address_scope']['id']
                subnet2 = netaddr.IPNetwork('20.10.10.0/24')
                subnetpool2 = self._test_create_subnetpool(
                    [subnet2.cidr], name='sp2',
                    min_prefixlen='24', address_scope_id=as2_id)
                subnetpool2_id = subnetpool2['subnetpool']['id']

                self._create_subnet_and_assert_snat_rules(
                    subnetpool2_id, r['router']['id'],
                    assert_snat_added=True)

    def _test_router_address_scope_change(self, change_gw=False):
        """When subnetpool address scope changes, and router that was
        originally under same address scope, results having different
        address scopes, relevant snat rules are added.
        """
        # create an external network on one address scope
        with self.address_scope(name='as1') as addr_scope, \
            self.network() as ext_net:
            ext_subnet = self._prepare_external_subnet_on_address_scope(
                ext_net, addr_scope)

            # create a router with this gateway
            with self.router() as r:
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    ext_subnet['network_id'])

            # create a regular network on same address scope
            # and verify no snat change
            as_id = addr_scope['address_scope']['id']
            subnet2 = netaddr.IPNetwork('40.10.10.0/24')
            subnetpool2 = self._test_create_subnetpool(
                [subnet2.cidr], name='sp2',
                min_prefixlen='24', address_scope_id=as_id)
            subnetpool2_id = subnetpool2['subnetpool']['id']

            self._create_subnet_and_assert_snat_rules(
                subnetpool2_id, r['router']['id'])

            # change address scope of the first subnetpool
            with self.address_scope(name='as2') as addr_scope2,\
                self._mock_add_snat_rule() as add_nat:

                as2_id = addr_scope2['address_scope']['id']
                data = {'subnetpool': {
                        'address_scope_id': as2_id}}

                if change_gw:
                    subnetpool_to_update = ext_subnet['subnetpool_id']
                else:
                    subnetpool_to_update = subnetpool2_id

                req = self.new_update_request('subnetpools', data,
                                              subnetpool_to_update)
                req.get_response(self.api)

                add_nat.assert_called_once()

    def test_router_address_scope_change(self):
        self._test_router_address_scope_change()

    def test_router_address_scope_gw_change(self):
        self._test_router_address_scope_change(change_gw=True)

    def _test_3leg_router_address_scope_change(self, change_gw=False,
                                               change_2gw=False):
        """Test address scope change scenarios with router that covers
        3 address scopes
        """
        # create an external network on one address scope
        with self.address_scope(name='as1') as as1, \
            self.address_scope(name='as2') as as2, \
            self.address_scope(name='as3') as as3, \
            self.network() as ext_net:
            ext_subnet = self._prepare_external_subnet_on_address_scope(
                ext_net, as1)
            as1_id = as1['address_scope']['id']

            # create a router with this gateway
            with self.router() as r:
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    ext_subnet['network_id'])

            # create a regular network on address scope 2
            # and verify snat change
            as2_id = as2['address_scope']['id']
            subnet2 = netaddr.IPNetwork('20.10.10.0/24')
            subnetpool2 = self._test_create_subnetpool(
                [subnet2.cidr], name='sp2',
                min_prefixlen='24', address_scope_id=as2_id)
            subnetpool2_id = subnetpool2['subnetpool']['id']
            self._create_subnet_and_assert_snat_rules(
                subnetpool2_id, r['router']['id'], assert_snat_added=True)

            # create a regular network on address scope 3
            # verify no snat change
            as3_id = as3['address_scope']['id']
            subnet3 = netaddr.IPNetwork('30.10.10.0/24')
            subnetpool3 = self._test_create_subnetpool(
                [subnet3.cidr], name='sp2',
                min_prefixlen='24', address_scope_id=as3_id)
            subnetpool3_id = subnetpool3['subnetpool']['id']
            self._create_subnet_and_assert_snat_rules(
                subnetpool3_id, r['router']['id'], assert_snat_added=True)

            with self._mock_add_snat_rule() as add_nat, \
                self._mock_del_snat_rule() as del_nat:

                if change_gw:
                    # change address scope of GW subnet
                    subnetpool_to_update = ext_subnet['subnetpool_id']
                else:
                    subnetpool_to_update = subnetpool2_id

                if change_2gw:
                    # change subnet2 to be in GW address scope
                    target_as = as1_id
                else:
                    target_as = as3_id

                data = {'subnetpool': {
                        'address_scope_id': target_as}}

                req = self.new_update_request('subnetpools', data,
                                              subnetpool_to_update)
                req.get_response(self.api)

                if change_gw:
                    # The test changed address scope of gw subnet.
                    # Both previous rules should be deleted,
                    # and one new rule for subnet2 should be added
                    del_nat.assert_called()
                    self.assertEqual(2, del_nat.call_count)
                    add_nat.assert_called_once()
                else:
                    if change_2gw:
                        # The test changed address scope of subnet2 to be
                        # same as GW address scope.
                        # Snat rule for as2 will be deleted. No effect on as3
                        # rule.
                        del_nat.assert_called_once()
                    else:
                        # The test changed address scope of subnet2 to
                        # as3. Affected snat rule should be re-created.
                        del_nat.assert_called_once()
                        add_nat.assert_called_once()

    def test_3leg_router_address_scope_change(self):
        self._test_3leg_router_address_scope_change()

    def test_3leg_router_address_scope_change_to_gw(self):
        self._test_3leg_router_address_scope_change(change_2gw=True)

    def test_3leg_router_gw_address_scope_change(self):
        self._test_3leg_router_address_scope_change(change_gw=True)

    def test_subnetpool_router_address_scope_change_no_effect(self):
        """When all router interfaces are allocated from same subnetpool,
        changing address scope on this subnetpool should not affect snat rules.
        """
        # create an external network on one address scope
        with self.address_scope(name='as1') as addr_scope, \
            self.network() as ext_net:
            ext_subnet = self._prepare_external_subnet_on_address_scope(
                ext_net, addr_scope)

            # create a router with this gateway
            with self.router() as r:
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    ext_subnet['network_id'])

            # create a regular network on same address scope
            # and verify no snat change
            self._create_subnet_and_assert_snat_rules(
                ext_subnet['subnetpool_id'], r['router']['id'])

            with self.address_scope(name='as2') as addr_scope2,\
                self._mock_add_snat_rule() as add_nat,\
                self._mock_del_snat_rule() as delete_nat:

                as2_id = addr_scope2['address_scope']['id']
                # change address scope of the subnetpool
                data = {'subnetpool': {
                        'address_scope_id': as2_id}}
                req = self.new_update_request('subnetpools', data,
                                              ext_subnet['subnetpool_id'])
                req.get_response(self.api)

                add_nat.assert_not_called()
                delete_nat.assert_not_called()

    def _test_route_update_illegal(self, destination):
        routes = [{'destination': destination, 'nexthop': '10.0.1.3'}]
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                fixed_ip_data = [{'ip_address': '10.0.1.2'}]
                with self.port(subnet=s, fixed_ips=fixed_ip_data) as p:
                    self._router_interface_action(
                        'add', r['router']['id'], None, p['port']['id'])
                    self._update('routers', r['router']['id'],
                                 {'router': {'routes': routes}},
                                 expected_code=400)

    def test_route_update_illegal(self):
        self._test_route_update_illegal('0.0.0.0/0')
        self._test_route_update_illegal('0.0.0.0/16')


class ExtGwModeTestCase(test_ext_gw_mode.ExtGwModeIntTestCase,
                        L3NatTest):
    def test_router_gateway_set_fail_after_port_create(self):
        self.skipTest("TBD")
