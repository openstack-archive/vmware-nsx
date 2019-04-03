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

import decorator

import mock
import netaddr
from neutron.db import models_v2
from neutron.db import securitygroups_db as sg_db
from neutron.extensions import address_scope
from neutron.extensions import l3
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
from neutron.tests.unit import testlib_api
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import extraroute as xroute_apidef
from neutron_lib.api.definitions import l3_ext_gw_mode as l3_egm_apidef
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import exceptions as nc_exc
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as plugin_utils
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_utils import uuidutils
from webob import exc

from vmware_nsx.api_client import exception as api_exc
from vmware_nsx.common import utils
from vmware_nsx.plugins.nsx_v3 import plugin as nsx_plugin
from vmware_nsx.services.lbaas.nsx_v3.v2 import lb_driver_v2
from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.common_plugin import common_v3
from vmware_nsx.tests.unit.extensions import test_metadata
from vmware_nsxlib.tests.unit.v3 import mocks as nsx_v3_mocks
from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.v3 import exceptions as nsxlib_exc


PLUGIN_NAME = 'vmware_nsx.plugin.NsxV3Plugin'
NSX_TZ_NAME = 'default transport zone'
NSX_DHCP_PROFILE_ID = 'default dhcp profile'
NSX_METADATA_PROXY_ID = 'default metadata proxy'
NSX_SWITCH_PROFILE = 'dummy switch profile'
NSX_DHCP_RELAY_SRV = 'dhcp relay srv'
NSX_EDGE_CLUSTER_UUID = 'dummy edge cluster'


def _mock_create_firewall_rules(*args):
    # NOTE(arosen): the code in the neutron plugin expects the
    # neutron rule id as the display_name.
    rules = args[4]
    return {
        'rules': [
            {'display_name': rule['id'], 'id': uuidutils.generate_uuid()}
            for rule in rules
        ]}


def _return_id_key(*args, **kwargs):
    return {'id': uuidutils.generate_uuid()}


def _return_id_key_list(*args, **kwargs):
    return [{'id': uuidutils.generate_uuid()}]


def _mock_nsx_backend_calls():
    mock.patch("vmware_nsxlib.v3.client.NSX3Client").start()

    fake_profile = {'key': 'FakeKey',
                    'resource_type': 'FakeResource',
                    'id': uuidutils.generate_uuid()}

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
        "vmware_nsxlib.v3.core_resources.NsxLibBridgeEndpoint.create",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.security.NsxLibNsGroup.find_by_display_name",
        side_effect=_return_id_key_list).start()

    mock.patch(
        "vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.create",
        side_effect=_return_id_key).start()

    mock.patch(
        "vmware_nsxlib.v3.core_resources.NsxLibDhcpProfile."
        "get_id_by_name_or_id",
        return_value=NSX_DHCP_PROFILE_ID).start()

    mock.patch(
        "vmware_nsxlib.v3.core_resources.NsxLibDhcpRelayService."
        "get_id_by_name_or_id",
        return_value=NSX_DHCP_RELAY_SRV).start()

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
        return_value='2.4.0').start()

    mock.patch(
        "vmware_nsxlib.v3.load_balancer.Service.get_router_lb_service",
        return_value=None).start()

    mock.patch('vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
               'get_transport_type', return_value='OVERLAY').start()


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
        # need to mock the global placeholder. This is due to the fact that
        # the generic security group tests assume that there is just one
        # security group.
        mock_ensure_global_sg_placeholder = mock.patch.object(
            nsx_plugin.NsxV3Plugin, '_ensure_global_sg_placeholder')
        mock_ensure_global_sg_placeholder.start()
        mock.patch(
            'neutron_lib.rpc.Connection.consume_in_threads',
            return_value=[]).start()

        mock.patch.object(nsx_plugin.NsxV3Plugin,
                          '_cleanup_duplicates').start()

    def setUp(self, plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None, **kwargs):

        self._patchers = []

        _mock_nsx_backend_calls()
        self.setup_conf_overrides()
        self.mock_get_edge_cluster = mock.patch.object(
            nsx_plugin.NsxV3Plugin, '_get_edge_cluster',
            return_value=NSX_EDGE_CLUSTER_UUID)
        self.mock_get_edge_cluster.start()
        self.mock_plugin_methods()
        # ignoring the given plugin and use the nsx-v3 one
        if not plugin.endswith('NsxTVDPlugin'):
            plugin = PLUGIN_NAME
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
        if extnet_apidef.EXTERNAL in kwargs:
            arg_list = (extnet_apidef.EXTERNAL, ) + (arg_list or ())

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

    def _initialize_azs(self):
        self.plugin.init_availability_zones()
        self.plugin._translate_configured_names_to_uuids()

    def _enable_native_dhcp_md(self):
        cfg.CONF.set_override('native_dhcp_metadata', True, 'nsx_v3')
        cfg.CONF.set_override('dhcp_agent_notification', False)
        self.plugin._init_dhcp_metadata()

    def _enable_dhcp_relay(self):
        # Add the relay service to the config and availability zones
        cfg.CONF.set_override('dhcp_relay_service', NSX_DHCP_RELAY_SRV,
                              'nsx_v3')
        mock_nsx_version = mock.patch.object(
            self.plugin.nsxlib, 'feature_supported', return_value=True)
        mock_nsx_version.start()
        self._initialize_azs()
        self._enable_native_dhcp_md()


class TestNetworksV2(test_plugin.TestNetworksV2, NsxV3PluginTestCaseMixin):

    def setUp(self, plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        # add vlan transparent to the configuration
        cfg.CONF.set_override('vlan_transparent', True)
        super(TestNetworksV2, self).setUp(plugin=plugin,
                                          ext_mgr=ext_mgr)

    def tearDown(self):
        super(TestNetworksV2, self).tearDown()

    @mock.patch.object(nsx_plugin.NsxV3Plugin, 'validate_availability_zones')
    def test_create_network_with_availability_zone(self, mock_validate_az):
        name = 'net-with-zone'
        zone = ['zone1']

        mock_validate_az.return_value = None
        with self.network(name=name, availability_zone_hints=zone) as net:
            az_hints = net['network']['availability_zone_hints']
            self.assertListEqual(az_hints, zone)

    def test_network_failure_rollback(self):
        self._enable_native_dhcp_md()
        self.plugin = directory.get_plugin()
        with mock.patch.object(self.plugin.nsxlib.logical_port, 'create',
                               side_effect=api_exc.NsxApiException):
            self.network()
            ctx = context.get_admin_context()
            networks = self.plugin.get_networks(ctx)
            self.assertListEqual([], networks)

    def test_create_provider_flat_network(self):
        providernet_args = {pnet.NETWORK_TYPE: 'flat'}
        with mock.patch('vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.'
                        'create', side_effect=_return_id_key) as nsx_create, \
            mock.patch('vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.'
                       'delete') as nsx_delete, \
            mock.patch('vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
                       'get_transport_type', return_value='VLAN'),\
            self.network(name='flat_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE, )) as net:
            self.assertEqual('flat', net['network'].get(pnet.NETWORK_TYPE))
            # make sure the network is created at the backend
            nsx_create.assert_called_once()

            # Delete the network and make sure it is deleted from the backend
            req = self.new_delete_request('networks', net['network']['id'])
            res = req.get_response(self.api)
            self.assertEqual(exc.HTTPNoContent.code, res.status_int)
            nsx_delete.assert_called_once()

    def test_create_provider_flat_network_with_physical_net(self):
        physical_network = nsx_v3_mocks.DEFAULT_TIER0_ROUTER_UUID
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: physical_network}
        with mock.patch(
            'vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
            'get_transport_type', return_value='VLAN'),\
            self.network(name='flat_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE,
                                   pnet.PHYSICAL_NETWORK)) as net:
            self.assertEqual('flat', net['network'].get(pnet.NETWORK_TYPE))

    def test_create_provider_flat_network_with_vlan(self):
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.SEGMENTATION_ID: 11}
        with mock.patch('vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
                        'get_transport_type', return_value='VLAN'):
            result = self._create_network(fmt='json', name='bad_flat_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(pnet.NETWORK_TYPE,
                                                    pnet.SEGMENTATION_ID))
            data = self.deserialize('json', result)
            # should fail
            self.assertEqual('InvalidInput', data['NeutronError']['type'])

    def test_create_provider_geneve_network(self):
        providernet_args = {pnet.NETWORK_TYPE: 'geneve'}
        with mock.patch('vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.'
                        'create', side_effect=_return_id_key) as nsx_create, \
            mock.patch('vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.'
                       'delete') as nsx_delete, \
            mock.patch('vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
                       'get_transport_type', return_value='OVERLAY'),\
            self.network(name='geneve_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE, )) as net:
            self.assertEqual('geneve', net['network'].get(pnet.NETWORK_TYPE))
            # make sure the network is created at the backend
            nsx_create.assert_called_once()

            # Delete the network and make sure it is deleted from the backend
            req = self.new_delete_request('networks', net['network']['id'])
            res = req.get_response(self.api)
            self.assertEqual(exc.HTTPNoContent.code, res.status_int)
            nsx_delete.assert_called_once()

    def test_create_provider_geneve_network_with_physical_net(self):
        physical_network = nsx_v3_mocks.DEFAULT_TIER0_ROUTER_UUID
        providernet_args = {pnet.NETWORK_TYPE: 'geneve',
                            pnet.PHYSICAL_NETWORK: physical_network}
        with mock.patch(
            'vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
            'get_transport_type', return_value='OVERLAY'),\
            self.network(name='geneve_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE, )) as net:
            self.assertEqual('geneve', net['network'].get(pnet.NETWORK_TYPE))

    def test_create_provider_geneve_network_with_vlan(self):
        providernet_args = {pnet.NETWORK_TYPE: 'geneve',
                            pnet.SEGMENTATION_ID: 11}
        with mock.patch(
            'vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
            'get_transport_type', return_value='OVERLAY'):
            result = self._create_network(fmt='json', name='bad_geneve_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(pnet.NETWORK_TYPE,
                                                    pnet.SEGMENTATION_ID))
            data = self.deserialize('json', result)
            # should fail
            self.assertEqual('InvalidInput', data['NeutronError']['type'])

    def test_create_provider_vlan_network(self):
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 11}
        with mock.patch('vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.'
                        'create', side_effect=_return_id_key) as nsx_create, \
            mock.patch('vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.'
                       'delete') as nsx_delete, \
            mock.patch('vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
                       'get_transport_type', return_value='VLAN'),\
            self.network(name='vlan_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE,
                                   pnet.SEGMENTATION_ID)) as net:
            self.assertEqual('vlan', net['network'].get(pnet.NETWORK_TYPE))
            # make sure the network is created at the backend
            nsx_create.assert_called_once()

            # Delete the network and make sure it is deleted from the backend
            req = self.new_delete_request('networks', net['network']['id'])
            res = req.get_response(self.api)
            self.assertEqual(exc.HTTPNoContent.code, res.status_int)
            nsx_delete.assert_called_once()

    def test_create_provider_nsx_network(self):
        physical_network = 'Fake logical switch'
        providernet_args = {pnet.NETWORK_TYPE: 'nsx-net',
                            pnet.PHYSICAL_NETWORK: physical_network}

        with mock.patch(
            'vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.create',
            side_effect=nsxlib_exc.ResourceNotFound) as nsx_create, \
            mock.patch('vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.'
                       'delete') as nsx_delete, \
            self.network(name='nsx_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE,
                                   pnet.PHYSICAL_NETWORK)) as net:
            self.assertEqual('nsx-net', net['network'].get(pnet.NETWORK_TYPE))
            self.assertEqual(physical_network,
                             net['network'].get(pnet.PHYSICAL_NETWORK))
            # make sure the network is NOT created at the backend
            nsx_create.assert_not_called()

            # Delete the network. It should NOT deleted from the backend
            req = self.new_delete_request('networks', net['network']['id'])
            res = req.get_response(self.api)
            self.assertEqual(exc.HTTPNoContent.code, res.status_int)
            nsx_delete.assert_not_called()

    def test_create_provider_bad_nsx_network(self):
        physical_network = 'Bad logical switch'
        providernet_args = {pnet.NETWORK_TYPE: 'nsx-net',
                            pnet.PHYSICAL_NETWORK: physical_network}
        with mock.patch(
            "vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.get",
            side_effect=nsxlib_exc.ResourceNotFound):
            result = self._create_network(fmt='json', name='bad_nsx_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(pnet.NETWORK_TYPE,
                                                    pnet.PHYSICAL_NETWORK))
            data = self.deserialize('json', result)
            # should fail
            self.assertEqual('InvalidInput', data['NeutronError']['type'])

    def test_create_ens_network_with_no_port_sec(self):
        cfg.CONF.set_override('ens_support', True, 'nsx_v3')
        providernet_args = {psec.PORTSECURITY: False}
        with mock.patch("vmware_nsxlib.v3.core_resources.NsxLibTransportZone."
                        "get_host_switch_mode", return_value="ENS"),\
            mock.patch(
            "vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.get",
            return_value={'transport_zone_id': 'xxx'}):

            result = self._create_network(fmt='json', name='ens_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(psec.PORTSECURITY,))
            res = self.deserialize('json', result)
            # should succeed, and net should have port security disabled
            self.assertFalse(res['network']['port_security_enabled'])

    def test_create_ens_network_with_port_sec(self):
        cfg.CONF.set_override('ens_support', True, 'nsx_v3')
        providernet_args = {psec.PORTSECURITY: True}
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value='2.3.0'),\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibTransportZone."
                       "get_host_switch_mode", return_value="ENS"),\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch."
                       "get", return_value={'transport_zone_id': 'xxx'}):
            result = self._create_network(fmt='json', name='ens_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(psec.PORTSECURITY,))
            res = self.deserialize('json', result)
            # should fail
            self.assertEqual('NsxENSPortSecurity',
                             res['NeutronError']['type'])

    def test_create_ens_network_with_port_sec_supported(self):
        cfg.CONF.set_override('ens_support', True, 'nsx_v3')
        providernet_args = {psec.PORTSECURITY: True}
        with mock.patch("vmware_nsxlib.v3.core_resources.NsxLibTransportZone."
                       "get_host_switch_mode", return_value="ENS"),\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch."
                       "get", return_value={'transport_zone_id': 'xxx'}):
            result = self._create_network(fmt='json', name='ens_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(psec.PORTSECURITY,))
            res = self.deserialize('json', result)
            # should succeed
            self.assertTrue(res['network'][psec.PORTSECURITY])

    def test_create_ens_network_disable_default_port_security(self):
        cfg.CONF.set_override('ens_support', True, 'nsx_v3')
        cfg.CONF.set_override('disable_port_security_for_ens', True, 'nsx_v3')
        mock_ens = mock.patch('vmware_nsxlib.v3'
                              '.core_resources.NsxLibTransportZone'
                              '.get_host_switch_mode', return_value='ENS')
        mock_tz = mock.patch('vmware_nsxlib.v3'
                             '.core_resources.NsxLibLogicalSwitch.get',
                             return_value={'transport_zone_id': 'xxx'})
        mock_tt = mock.patch('vmware_nsxlib.v3'
                             '.core_resources.NsxLibTransportZone'
                             '.get_transport_type', return_value='VLAN')
        data = {'network': {
                'name': 'portsec_net',
                'admin_state_up': True,
                'shared': False,
                'tenant_id': 'some_tenant',
                'provider:network_type': 'flat',
                'provider:physical_network': 'xxx',
                'port_security_enabled': True}}
        with mock_ens, mock_tz, mock_tt:
                self.plugin.create_network(context.get_admin_context(), data)

    def test_create_ens_network_with_qos(self):
        cfg.CONF.set_override('ens_support', True, 'nsx_v3')
        mock_ens = mock.patch('vmware_nsxlib.v3'
                              '.core_resources.NsxLibTransportZone'
                              '.get_host_switch_mode', return_value='ENS')
        mock_tz = mock.patch('vmware_nsxlib.v3'
                             '.core_resources.NsxLibLogicalSwitch.get',
                             return_value={'transport_zone_id': 'xxx'})
        mock_tt = mock.patch('vmware_nsxlib.v3'
                             '.core_resources.NsxLibTransportZone'
                             '.get_transport_type', return_value='VLAN')
        policy_id = uuidutils.generate_uuid()
        data = {'network': {
                'name': 'qos_net',
                'tenant_id': 'some_tenant',
                'provider:network_type': 'flat',
                'provider:physical_network': 'xxx',
                'qos_policy_id': policy_id,
                'port_security_enabled': False}}
        with mock_ens, mock_tz, mock_tt,\
            mock.patch.object(self.plugin, '_validate_qos_policy_id'):
                self.assertRaises(n_exc.InvalidInput,
                                  self.plugin.create_network,
                                  context.get_admin_context(), data)

    def test_update_ens_network_with_qos(self):
        cfg.CONF.set_override('ens_support', True, 'nsx_v3')
        mock_ens = mock.patch('vmware_nsxlib.v3'
                              '.core_resources.NsxLibTransportZone'
                              '.get_host_switch_mode', return_value='ENS')
        mock_tz = mock.patch('vmware_nsxlib.v3'
                             '.core_resources.NsxLibLogicalSwitch.get',
                             return_value={'transport_zone_id': 'xxx'})
        mock_tt = mock.patch('vmware_nsxlib.v3'
                             '.core_resources.NsxLibTransportZone'
                             '.get_transport_type', return_value='VLAN')
        data = {'network': {
                'name': 'qos_net',
                'tenant_id': 'some_tenant',
                'provider:network_type': 'flat',
                'provider:physical_network': 'xxx',
                'admin_state_up': True,
                'shared': False,
                'port_security_enabled': False}}
        with mock_ens, mock_tz, mock_tt,\
            mock.patch.object(self.plugin, '_validate_qos_policy_id'):
            network = self.plugin.create_network(context.get_admin_context(),
                                                 data)
            policy_id = uuidutils.generate_uuid()
            data = {'network': {
                    'id': network['id'],
                    'admin_state_up': True,
                    'shared': False,
                    'port_security_enabled': False,
                    'tenant_id': 'some_tenant',
                    'qos_policy_id': policy_id}}
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.update_network,
                              context.get_admin_context(),
                              network['id'], data)

    def test_update_ens_network(self):
        cfg.CONF.set_override('ens_support', True, 'nsx_v3')
        providernet_args = {psec.PORTSECURITY: False}
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value='2.3.0'),\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibTransportZone."
                       "get_host_switch_mode", return_value="ENS"),\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch."
                       "get", return_value={'transport_zone_id': 'xxx'}):
            result = self._create_network(fmt='json', name='ens_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(psec.PORTSECURITY,))
            net = self.deserialize('json', result)
            net_id = net['network']['id']
            args = {'network': {psec.PORTSECURITY: True}}
            req = self.new_update_request('networks', args,
                                          net_id, fmt='json')
            res = self.deserialize('json', req.get_response(self.api))
            # should fail
            self.assertEqual('NsxENSPortSecurity',
                             res['NeutronError']['type'])

    def test_update_ens_network_psec_supported(self):
        cfg.CONF.set_override('ens_support', True, 'nsx_v3')
        providernet_args = {psec.PORTSECURITY: False}
        with mock.patch("vmware_nsxlib.v3.core_resources.NsxLibTransportZone."
                        "get_host_switch_mode", return_value="ENS"),\
            mock.patch(
            "vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.get",
            return_value={'transport_zone_id': 'xxx'}):

            result = self._create_network(fmt='json', name='ens_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(psec.PORTSECURITY,))
            net = self.deserialize('json', result)
            net_id = net['network']['id']
            args = {'network': {psec.PORTSECURITY: True}}
            req = self.new_update_request('networks', args,
                                          net_id, fmt='json')
            res = self.deserialize('json', req.get_response(self.api))
            # should succeed
            self.assertTrue(res['network'][psec.PORTSECURITY])

    def test_create_transparent_vlan_network(self):
        providernet_args = {vlan_apidef.VLANTRANSPARENT: True}
        with mock.patch(
            'vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
            'get_transport_type', return_value='OVERLAY'),\
            self.network(name='vt_net',
                         providernet_args=providernet_args,
                         arg_list=(vlan_apidef.VLANTRANSPARENT, )) as net:
            self.assertTrue(net['network'].get(vlan_apidef.VLANTRANSPARENT))

    def test_create_provider_vlan_network_with_transparent(self):
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            vlan_apidef.VLANTRANSPARENT: True}
        with mock.patch('vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
                       'get_transport_type', return_value='VLAN'):
            result = self._create_network(fmt='json', name='badvlan_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(
                                              pnet.NETWORK_TYPE,
                                              pnet.SEGMENTATION_ID,
                                              vlan_apidef.VLANTRANSPARENT))
            data = self.deserialize('json', result)
            self.assertEqual('vlan', data['network'].get(pnet.NETWORK_TYPE))

    def _test_generate_tag(self, vlan_id):
        net_type = 'vlan'
        name = 'phys_net'
        plugin = directory.get_plugin()
        plugin._network_vlans = plugin_utils.parse_network_vlan_ranges(
                       cfg.CONF.nsx_v3.network_vlan_ranges)
        expected = [('subnets', []), ('name', name),
                    ('admin_state_up', True),
                    ('status', 'ACTIVE'),
                    ('shared', False),
                    (pnet.NETWORK_TYPE, net_type),
                    (pnet.PHYSICAL_NETWORK,
                     'fb69d878-958e-4f32-84e4-50286f26226b'),
                    (pnet.SEGMENTATION_ID, vlan_id)]
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK:
                                'fb69d878-958e-4f32-84e4-50286f26226b'}

        with mock.patch('vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
                        'get_transport_type', return_value='VLAN'):
            with self.network(name=name, providernet_args=providernet_args,
                              arg_list=(pnet.NETWORK_TYPE,
                                        pnet.PHYSICAL_NETWORK)) as net:
                for k, v in expected:
                        self.assertEqual(net['network'][k], v)

    def test_create_phys_vlan_generate(self):
        cfg.CONF.set_override('network_vlan_ranges',
                              'fb69d878-958e-4f32-84e4-50286f26226b',
                              'nsx_v3')
        self._test_generate_tag(1)

    def test_create_phys_vlan_generate_range(self):
        cfg.CONF.set_override('network_vlan_ranges',
                              'fb69d878-958e-4f32-84e4-'
                              '50286f26226b:100:110',
                              'nsx_v3')
        self._test_generate_tag(100)

    def test_create_phys_vlan_network_outofrange_returns_503(self):
        cfg.CONF.set_override('network_vlan_ranges',
                              'fb69d878-958e-4f32-84e4-'
                              '50286f26226b:9:10',
                              'nsx_v3')
        self._test_generate_tag(9)
        self._test_generate_tag(10)
        with testlib_api.ExpectedException(exc.HTTPClientError) as ctx_manager:
            self._test_generate_tag(11)

        self.assertEqual(ctx_manager.exception.code, 503)

    def test_update_external_flag_on_net(self):
        with self.network() as net:
            # should fail to update the network to external
            args = {'network': {'router:external': 'True'}}
            req = self.new_update_request('networks', args,
                                          net['network']['id'], fmt='json')
            res = self.deserialize('json', req.get_response(self.api))
            self.assertEqual('InvalidInput',
                             res['NeutronError']['type'])

    def test_network_update_external(self):
        # This plugin does not support updating the external flag of a network
        self.skipTest("UnSupported")

    def test_network_update_external_failure(self):
        data = {'network': {'name': 'net1',
                            'router:external': 'True',
                            'tenant_id': 'tenant_one',
                            'provider:physical_network': 'stam'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        ext_net_id = network['network']['id']

        # should fail to update the network to non-external
        args = {'network': {'router:external': 'False'}}
        req = self.new_update_request('networks', args,
                                      ext_net_id, fmt='json')
        res = self.deserialize('json', req.get_response(self.api))
        self.assertEqual('InvalidInput',
                         res['NeutronError']['type'])

    def test_update_network_rollback(self):
        with self.network() as net:
            # Fail the backend update
            with mock.patch("vmware_nsxlib.v3.core_resources."
                            "NsxLibLogicalSwitch.update",
                            side_effect=nsxlib_exc.ManagerError):
                args = {'network': {'description': 'test rollback'}}
                req = self.new_update_request('networks', args,
                                              net['network']['id'], fmt='json')
                res = self.deserialize('json', req.get_response(self.api))
                # should fail with the nsxlib error (meaning that the rollback
                # did not fail)
                self.assertEqual('ManagerError',
                                 res['NeutronError']['type'])


class TestSubnetsV2(test_plugin.TestSubnetsV2, NsxV3PluginTestCaseMixin):

    def test_create_subnet_with_shared_address_space(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '100.64.0.0/16',
                               'name': 'sub1',
                               'enable_dhcp': False,
                               'dns_nameservers': None,
                               'allocation_pools': None,
                               'tenant_id': 'tenant_one',
                               'host_routes': None,
                               'ip_version': 4}}
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.create_subnet,
                              context.get_admin_context(), data)

    def _create_external_network(self):
        data = {'network': {'name': 'net1',
                            'router:external': 'True',
                            'tenant_id': 'tenant_one',
                            'provider:physical_network': 'stam'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        return network

    def test_create_subnet_with_conflicting_t0_address(self):
        network = self._create_external_network()
        data = {'subnet': {'network_id': network['network']['id'],
                           'cidr': '172.20.1.0/24',
                           'name': 'sub1',
                           'enable_dhcp': False,
                           'dns_nameservers': None,
                           'allocation_pools': None,
                           'tenant_id': 'tenant_one',
                           'host_routes': None,
                           'ip_version': 4}}
        ports = [{'subnets': [{'ip_addresses': [u'172.20.1.60'],
                               'prefix_length': 24}],
                  'resource_type': 'LogicalRouterUpLinkPort'}]
        with mock.patch.object(self.plugin.nsxlib.logical_router_port,
                               'get_by_router_id',
                               return_value=ports):
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.create_subnet,
                              context.get_admin_context(), data)

    def test_subnet_update_ipv4_and_ipv6_pd_v6stateless_subnets(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_subnet_update_ipv4_and_ipv6_pd_slaac_subnets(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_subnet_native_dhcp_subnet_enabled(self):
        self._enable_native_dhcp_md()
        with self.network() as network:
            with mock.patch.object(self.plugin,
                                   '_enable_native_dhcp') as enable_dhcp,\
                self.subnet(network=network, enable_dhcp=True):
                # Native dhcp should be set for this subnet
                self.assertTrue(enable_dhcp.called)

    def test_subnet_native_dhcp_subnet_disabled(self):
        self._enable_native_dhcp_md()
        with self.network() as network:
            with mock.patch.object(self.plugin,
                                   '_enable_native_dhcp') as enable_dhcp,\
                self.subnet(network=network, enable_dhcp=False):
                # Native dhcp should not be set for this subnet
                self.assertFalse(enable_dhcp.called)

    def test_subnet_native_dhcp_with_relay(self):
        """Verify that the relay service is added to the router interface"""
        self._enable_dhcp_relay()
        with self.network() as network:
            with mock.patch.object(self.plugin,
                                  '_enable_native_dhcp') as enable_dhcp,\
                self.subnet(network=network, enable_dhcp=True):
                # Native dhcp should not be set for this subnet
                self.assertFalse(enable_dhcp.called)

    def test_subnet_native_dhcp_flat_subnet_disabled(self):
        self._enable_native_dhcp_md()
        providernet_args = {pnet.NETWORK_TYPE: 'flat'}
        with mock.patch('vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
                        'get_transport_type', return_value='VLAN'):
            with self.network(name='flat_net',
                              providernet_args=providernet_args,
                              arg_list=(pnet.NETWORK_TYPE, )) as network:
                data = {'subnet': {'network_id': network['network']['id'],
                                   'cidr': '172.20.1.0/24',
                                   'name': 'sub1',
                                   'enable_dhcp': False,
                                   'dns_nameservers': None,
                                   'allocation_pools': None,
                                   'tenant_id': 'tenant_one',
                                   'host_routes': None,
                                   'ip_version': 4}}
                self.plugin.create_subnet(
                    context.get_admin_context(), data)

    def test_subnet_native_dhcp_flat_subnet_enabled(self):
        self._enable_native_dhcp_md()
        providernet_args = {pnet.NETWORK_TYPE: 'flat'}
        with mock.patch('vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
                        'get_transport_type', return_value='VLAN'):
            with self.network(name='flat_net',
                             providernet_args=providernet_args,
                             arg_list=(pnet.NETWORK_TYPE, )) as network:
                data = {'subnet': {'network_id': network['network']['id'],
                                   'cidr': '172.20.1.0/24',
                                   'name': 'sub1',
                                   'enable_dhcp': True,
                                   'dns_nameservers': None,
                                   'allocation_pools': None,
                                   'tenant_id': 'tenant_one',
                                   'host_routes': None,
                                   'ip_version': 4}}
                self.assertRaises(n_exc.InvalidInput,
                                  self.plugin.create_subnet,
                                  context.get_admin_context(), data)

    def test_fail_create_static_routes_per_subnet_over_limit(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '10.0.0.0/16',
                               'name': 'sub1',
                               'dns_nameservers': None,
                               'allocation_pools': None,
                               'tenant_id': 'tenant_one',
                               'enable_dhcp': False,
                               'ip_version': 4}}
            count = 1
            host_routes = []
            while count < 28:
                host_routes.append("'host_routes': [{'destination': "
                                   "'135.207.0.0/%s', 'nexthop': "
                                   "'1.2.3.%s'}]" % (count, count))
                count += 1
            data['subnet']['host_routes'] = host_routes
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.create_subnet,
                              context.get_admin_context(), data)

    def test_create_subnet_disable_dhcp_with_host_route_fails(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '172.20.1.0/24',
                               'name': 'sub1',
                               'dns_nameservers': None,
                               'allocation_pools': None,
                               'tenant_id': 'tenant_one',
                               'enable_dhcp': False,
                               'host_routes': [{
                                    'destination': '135.207.0.0/16',
                                    'nexthop': '1.2.3.4'}],
                               'ip_version': 4}}
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.create_subnet,
                              context.get_admin_context(), data)

    def test_update_subnet_disable_dhcp_with_host_route_fails(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'cidr': '172.20.1.0/24',
                               'name': 'sub1',
                               'dns_nameservers': None,
                               'allocation_pools': None,
                               'tenant_id': 'tenant_one',
                               'enable_dhcp': True,
                               'host_routes': [{
                                    'destination': '135.207.0.0/16',
                                    'nexthop': '1.2.3.4'}],
                               'ip_version': 4}}
            subnet = self.plugin.create_subnet(
                context.get_admin_context(), data)
            data['subnet']['enable_dhcp'] = False
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.update_subnet,
                              context.get_admin_context(), subnet['id'], data)


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

    def test_delete_dhcp_port(self):
        self._enable_native_dhcp_md()
        with self.subnet():
            pl = directory.get_plugin()
            ctx = context.Context(user_id=None, tenant_id=self._tenant_id,
                                  is_admin=False)
            ports = pl.get_ports(
                ctx, filters={'device_owner': [constants.DEVICE_OWNER_DHCP]})
            req = self.new_delete_request('ports', ports[0]['id'])
            res = req.get_response(self.api)
            self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

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

    def test_fail_update_lb_port_with_allowed_address_pairs(self):
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'pair_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': constants.DEVICE_OWNER_LOADBALANCERV2,
                        'fixed_ips': []}
                    }
            port = self.plugin.create_port(self.ctx, data)
            data['port']['allowed_address_pairs'] = '10.0.0.1'
            self.assertRaises(
                n_exc.InvalidInput,
                self.plugin.update_port, self.ctx, port['id'], data)

    def test_fail_create_allowed_address_pairs_over_limit(self):
        with self.network() as network,\
                self.subnet(network=network, enable_dhcp=True) as s1:
                    data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'pair_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [{'subnet_id': s1['subnet']['id']}]
                                }
                            }
                    count = 1
                    address_pairs = []
                    while count < 129:
                        address_pairs.append({'ip_address': '10.0.0.%s' %
                                                            count})
                        count += 1
                    data['port']['allowed_address_pairs'] = address_pairs
                    self.assertRaises(n_exc.InvalidInput,
                                      self.plugin.create_port, self.ctx, data)

    def test_fail_update_lb_port_with_fixed_ip(self):
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'pair_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': constants.DEVICE_OWNER_LOADBALANCERV2,
                        'fixed_ips': []}
                    }
            port = self.plugin.create_port(self.ctx, data)
            data['port']['fixed_ips'] = '10.0.0.1'
            self.assertRaises(
                n_exc.InvalidInput,
                self.plugin.update_port, self.ctx, port['id'], data)

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
            with mock.patch.object(self.plugin, '_get_qos_profile_id'),\
                mock.patch.object(self.plugin, '_validate_qos_policy_id'):
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
            with mock.patch.object(self.plugin, '_get_qos_profile_id'),\
                mock.patch.object(self.plugin, '_validate_qos_policy_id'):
                res = self.plugin.update_port(self.ctx, port['id'], data)
                self.assertEqual(policy_id, res['qos_policy_id'])
                # Get port should also return the qos policy id
                with mock.patch('vmware_nsx.services.qos.common.utils.'
                                'get_port_policy_id',
                                return_value=policy_id):
                    res = self.plugin.get_port(self.ctx, port['id'])
                    self.assertEqual(policy_id, res['qos_policy_id'])

                # now remove the qos from the port
                data['port']['qos_policy_id'] = None
                res = self.plugin.update_port(self.ctx, port['id'], data)
                self.assertIsNone(res['qos_policy_id'])

    def test_create_ext_port_with_qos_fail(self):
        with self._create_l3_ext_network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24'),\
                mock.patch.object(self.plugin, '_validate_qos_policy_id'):
                policy_id = uuidutils.generate_uuid()
                data = {'port': {'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'qos_policy_id': policy_id}}
                # Cannot add qos policy to a router port
                self.assertRaises(n_exc.InvalidInput,
                          self.plugin.create_port, self.ctx, data)

    def _test_create_illegal_port_with_qos_fail(self, device_owner):
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24'),\
                mock.patch.object(self.plugin, '_validate_qos_policy_id'):
                policy_id = uuidutils.generate_uuid()
                data = {'port': {'network_id': network['network']['id'],
                                 'tenant_id': self._tenant_id,
                                 'device_owner': device_owner,
                                 'qos_policy_id': policy_id}}
                # Cannot add qos policy to this type of port
                self.assertRaises(n_exc.InvalidInput,
                          self.plugin.create_port, self.ctx, data)

    def test_create_port_ens_with_qos_fail(self):
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24'):
                policy_id = uuidutils.generate_uuid()
                mock_ens = mock.patch('vmware_nsxlib.v3'
                                      '.core_resources.NsxLibTransportZone'
                                      '.get_host_switch_mode',
                                      return_value='ENS')
                mock_tz = mock.patch('vmware_nsxlib.v3'
                                     '.core_resources'
                                     '.NsxLibLogicalSwitch.get',
                                     return_value={
                                          'transport_zone_id': 'xxx'})
                mock_tt = mock.patch('vmware_nsxlib.v3'
                                     '.core_resources.NsxLibTransportZone'
                                     '.get_transport_type',
                                     return_value='VLAN')
                data = {'port': {
                    'network_id': network['network']['id'],
                    'tenant_id': self._tenant_id,
                    'name': 'qos_port',
                    'admin_state_up': True,
                    'device_id': 'fake_device',
                    'device_owner': 'fake_owner',
                    'fixed_ips': [],
                    'port_security_enabled': False,
                    'mac_address': '00:00:00:00:00:01',
                    'qos_policy_id': policy_id}
                }
                # Cannot add qos policy to this type of port
                with mock_ens, mock_tz, mock_tt,\
                    mock.patch.object(self.plugin, '_validate_qos_policy_id'):
                    self.assertRaises(n_exc.InvalidInput,
                                      self.plugin.create_port, self.ctx, data)

    def test_create_port_ens_with_sg(self):
        cfg.CONF.set_override('disable_port_security_for_ens', True, 'nsx_v3')
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24'):
                mock_ens = mock.patch('vmware_nsxlib.v3'
                                      '.core_resources.NsxLibTransportZone'
                                      '.get_host_switch_mode',
                                      return_value='ENS')
                mock_tz = mock.patch('vmware_nsxlib.v3'
                                     '.core_resources'
                                     '.NsxLibLogicalSwitch.get',
                                     return_value={
                                          'transport_zone_id': 'xxx'})
                mock_tt = mock.patch('vmware_nsxlib.v3'
                                     '.core_resources.NsxLibTransportZone'
                                     '.get_transport_type',
                                     return_value='VLAN')
                data = {'port': {
                    'network_id': network['network']['id'],
                    'tenant_id': self._tenant_id,
                    'name': 'sg_port',
                    'admin_state_up': True,
                    'device_id': 'fake_device',
                    'device_owner': 'fake_owner',
                    'fixed_ips': [],
                    'mac_address': '00:00:00:00:00:01',
                    'port_security_enabled': True}
                }
                with mock_ens, mock_tz, mock_tt:
                    self.plugin.create_port(self.ctx, data)

    def test_update_port_ens_with_qos_fail(self):
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24'):
                policy_id = uuidutils.generate_uuid()
                mock_ens = mock.patch('vmware_nsxlib.v3'
                                      '.core_resources.NsxLibTransportZone'
                                      '.get_host_switch_mode',
                                      return_value='ENS')
                mock_tz = mock.patch('vmware_nsxlib.v3'
                                     '.core_resources'
                                     '.NsxLibLogicalSwitch.get',
                                     return_value={
                                          'transport_zone_id': 'xxx'})
                mock_tt = mock.patch('vmware_nsxlib.v3'
                                     '.core_resources.NsxLibTransportZone'
                                     '.get_transport_type',
                                     return_value='VLAN')
                data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'qos_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'port_security_enabled': False,
                        'mac_address': '00:00:00:00:00:01'}
                        }
                with mock_ens, mock_tz, mock_tt,\
                    mock.patch.object(self.plugin, '_validate_qos_policy_id'):
                    port = self.plugin.create_port(self.ctx, data)
                    data['port'] = {'qos_policy_id': policy_id}
                    self.assertRaises(n_exc.InvalidInput,
                                      self.plugin.update_port,
                                      self.ctx, port['id'], data)

    def test_create_port_with_mac_learning_true(self):
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'qos_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'port_security_enabled': False,
                        'mac_address': '00:00:00:00:00:01',
                        'mac_learning_enabled': True}
                    }
            port = self.plugin.create_port(self.ctx, data)
            self.assertTrue(port['mac_learning_enabled'])

    def test_create_port_with_mac_learning_false(self):
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'qos_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'port_security_enabled': False,
                        'mac_address': '00:00:00:00:00:01',
                        'mac_learning_enabled': False}
                    }
            port = self.plugin.create_port(self.ctx, data)
            self.assertFalse(port['mac_learning_enabled'])

    def test_update_port_with_mac_learning_true(self):
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'qos_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'port_security_enabled': False,
                        'mac_address': '00:00:00:00:00:01'}
                    }
            port = self.plugin.create_port(self.ctx, data)
            data['port']['mac_learning_enabled'] = True
            update_res = self.plugin.update_port(self.ctx, port['id'], data)
            self.assertTrue(update_res['mac_learning_enabled'])

    def test_update_port_with_mac_learning_false(self):
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'qos_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [],
                        'port_security_enabled': False,
                        'mac_address': '00:00:00:00:00:01'}
                    }
            port = self.plugin.create_port(self.ctx, data)
            data['port']['mac_learning_enabled'] = False
            update_res = self.plugin.update_port(self.ctx, port['id'], data)
            self.assertFalse(update_res['mac_learning_enabled'])

    def test_update_port_with_mac_learning_failes(self):
        with self.network() as network:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'qos_port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': constants.DEVICE_OWNER_FLOATINGIP,
                        'fixed_ips': [],
                        'port_security_enabled': False,
                        'mac_address': '00:00:00:00:00:01'}
                    }
            port = self.plugin.create_port(self.ctx, data)
            data['port']['mac_learning_enabled'] = True
            self.assertRaises(
                n_exc.InvalidInput,
                self.plugin.update_port, self.ctx, port['id'], data)

    def test_create_router_port_with_qos_fail(self):
        self._test_create_illegal_port_with_qos_fail(
            'network:router_interface')

    def test_create_dhcp_port_with_qos_fail(self):
        self._test_create_illegal_port_with_qos_fail('network:dhcp')

    def _test_update_illegal_port_with_qos_fail(self, device_owner):
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24'),\
                mock.patch.object(self.plugin, '_validate_qos_policy_id'):
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
                '_get_qos_profile_id') as get_profile,\
                mock.patch('vmware_nsx.services.qos.common.utils.'
                           'get_network_policy_id', return_value=policy_id),\
                mock.patch.object(self.plugin, '_validate_qos_policy_id'):
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
                '_get_qos_profile_id') as get_profile,\
                mock.patch('vmware_nsx.services.qos.common.utils.'
                           'get_network_policy_id', return_value=policy_id),\
                mock.patch.object(self.plugin, '_validate_qos_policy_id'):
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

    def test_list_ports_filtered_by_security_groups(self):
        ctx = context.get_admin_context()
        with self.port() as port1, self.port() as port2:
            query_params = "security_groups=%s" % (
                           port1['port']['security_groups'][0])
            ports_data = self._list('ports', query_params=query_params)
            self.assertEqual(set([port1['port']['id'], port2['port']['id']]),
                             set([port['id'] for port in ports_data['ports']]))
            query_params = "security_groups=%s&id=%s" % (
                           port1['port']['security_groups'][0],
                           port1['port']['id'])
            ports_data = self._list('ports', query_params=query_params)
            self.assertEqual(port1['port']['id'], ports_data['ports'][0]['id'])
            self.assertEqual(1, len(ports_data['ports']))
            temp_sg = {'security_group': {'tenant_id': 'some_tenant',
                                          'name': '', 'description': 's'}}
            sg_dbMixin = sg_db.SecurityGroupDbMixin()
            sg = sg_dbMixin.create_security_group(ctx, temp_sg)
            sg_dbMixin._delete_port_security_group_bindings(
                ctx, port2['port']['id'])
            sg_dbMixin._create_port_security_group_binding(
                ctx, port2['port']['id'], sg['id'])
            port2['port']['security_groups'][0] = sg['id']
            query_params = "security_groups=%s" % (
                           port1['port']['security_groups'][0])
            ports_data = self._list('ports', query_params=query_params)
            self.assertEqual(port1['port']['id'], ports_data['ports'][0]['id'])
            self.assertEqual(1, len(ports_data['ports']))
            query_params = "security_groups=%s" % (
                           (port2['port']['security_groups'][0]))
            ports_data = self._list('ports', query_params=query_params)
            self.assertEqual(port2['port']['id'], ports_data['ports'][0]['id'])

    def test_port_failure_rollback_dhcp_exception(self):
        self._enable_native_dhcp_md()
        self.plugin = directory.get_plugin()
        with mock.patch.object(self.plugin, '_add_dhcp_binding',
                               side_effect=nsxlib_exc.ManagerError):
            self.port()
            ctx = context.get_admin_context()
            networks = self.plugin.get_ports(ctx)
            self.assertListEqual([], networks)

    def test_port_DB_failure_rollback_dhcp_exception(self):
        self._enable_native_dhcp_md()
        self.plugin = directory.get_plugin()
        with mock.patch('vmware_nsx.db.db.add_neutron_nsx_dhcp_binding',
                        side_effect=db_exc.DBError),\
            mock.patch.object(self.plugin, '_enable_native_dhcp'),\
            mock.patch('vmware_nsx.db.db.get_nsx_service_binding'),\
            self.network() as network,\
            self.subnet(network, cidr='10.0.1.0/24') as subnet:
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'p1',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': 'fake_owner',
                        'fixed_ips': [{'subnet_id':
                                       subnet['subnet']['id'],
                                       'ip_address': '10.0.1.2'}],
                        'mac_address': '00:00:00:00:00:01'}
                    }
            # making sure the port creation succeeded anyway
            created_port = self.plugin.create_port(self.ctx, data)
            self.assertEqual('fake_device', created_port['device_id'])

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

    def test_create_ens_port_with_no_port_sec(self):
        with self.subnet() as subnet,\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibTransportZone."
                       "get_host_switch_mode", return_value="ENS"),\
            mock.patch(
            "vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.get",
            return_value={'transport_zone_id': 'xxx'}):
            args = {'port': {'network_id': subnet['subnet']['network_id'],
                             'tenant_id': subnet['subnet']['tenant_id'],
                             'fixed_ips': [{'subnet_id':
                                            subnet['subnet']['id']}],
                             psec.PORTSECURITY: False}}
            port_req = self.new_create_request('ports', args)
            port = self.deserialize(self.fmt, port_req.get_response(self.api))
            self.assertFalse(port['port']['port_security_enabled'])

    def test_create_ens_port_with_port_sec(self):
        with self.subnet() as subnet,\
            mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                       return_value='2.3.0'),\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibTransportZone."
                       "get_host_switch_mode", return_value="ENS"),\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch."
                       "get", return_value={'transport_zone_id': 'xxx'}):
            args = {'port': {'network_id': subnet['subnet']['network_id'],
                             'tenant_id': subnet['subnet']['tenant_id'],
                             'fixed_ips': [{'subnet_id':
                                            subnet['subnet']['id']}],
                             psec.PORTSECURITY: True}}
            port_req = self.new_create_request('ports', args)
            res = self.deserialize('json', port_req.get_response(self.api))
            # should fail
            self.assertEqual('NsxENSPortSecurity',
                             res['NeutronError']['type'])

    def test_create_ens_port_with_port_sec_supported(self):
        with self.subnet() as subnet,\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibTransportZone."
                       "get_host_switch_mode", return_value="ENS"),\
            mock.patch(
            "vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch.get",
            return_value={'transport_zone_id': 'xxx'}):
            args = {'port': {'network_id': subnet['subnet']['network_id'],
                             'tenant_id': subnet['subnet']['tenant_id'],
                             'fixed_ips': [{'subnet_id':
                                            subnet['subnet']['id']}],
                             psec.PORTSECURITY: True}}
            port_req = self.new_create_request('ports', args)
            res = self.deserialize('json', port_req.get_response(self.api))
            # should succeed
            self.assertTrue(res['port'][psec.PORTSECURITY])

    def test_update_ens_port(self):
        with self.subnet() as subnet,\
            mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                       return_value='2.3.0'),\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibTransportZone."
                       "get_host_switch_mode", return_value="ENS"),\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch."
                       "get", return_value={'transport_zone_id': 'xxx'}):
            args = {'port': {'network_id': subnet['subnet']['network_id'],
                             'tenant_id': subnet['subnet']['tenant_id'],
                             'fixed_ips': [{'subnet_id':
                                            subnet['subnet']['id']}],
                             psec.PORTSECURITY: False}}
            port_req = self.new_create_request('ports', args)
            port = self.deserialize(self.fmt, port_req.get_response(self.api))
            port_id = port['port']['id']
            args = {'port': {psec.PORTSECURITY: True}}
            req = self.new_update_request('ports', args, port_id)
            res = self.deserialize('json', req.get_response(self.api))
            # should fail
            self.assertEqual('NsxENSPortSecurity',
                             res['NeutronError']['type'])

    def test_update_ens_port_psec_supported(self):
        with self.subnet() as subnet,\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibTransportZone."
                       "get_host_switch_mode", return_value="ENS"),\
            mock.patch("vmware_nsxlib.v3.core_resources.NsxLibLogicalSwitch."
                       "get", return_value={'transport_zone_id': 'xxx'}):
            args = {'port': {'network_id': subnet['subnet']['network_id'],
                             'tenant_id': subnet['subnet']['tenant_id'],
                             'fixed_ips': [{'subnet_id':
                                            subnet['subnet']['id']}],
                             psec.PORTSECURITY: False}}
            port_req = self.new_create_request('ports', args)
            port = self.deserialize(self.fmt, port_req.get_response(self.api))
            port_id = port['port']['id']
            args = {'port': {psec.PORTSECURITY: True}}
            req = self.new_update_request('ports', args, port_id)
            res = self.deserialize('json', req.get_response(self.api))
            # should succeed
            self.assertTrue(res['port'][psec.PORTSECURITY])

    def test_update_dhcp_port_device_owner(self):
        self._enable_native_dhcp_md()
        with self.subnet():
            pl = directory.get_plugin()
            ctx = context.Context(user_id=None, tenant_id=self._tenant_id,
                                  is_admin=False)
            ports = pl.get_ports(
                ctx, filters={'device_owner': [constants.DEVICE_OWNER_DHCP]})
            port_id = ports[0]['id']
            args = {'port': {'admin_state_up': False,
                             'fixed_ips': [],
                             'device_owner': 'abcd'}}

            req = self.new_update_request('ports', args, port_id)
            res = self.deserialize('json', req.get_response(self.api))
            # should fail
            self.assertEqual('InvalidInput',
                             res['NeutronError']['type'])

    def test_update_port_update_ip_address_only(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_update_port_with_new_ipv6_slaac_subnet_in_fixed_ips(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_update_port_mac_v6_slaac(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_requested_invalid_fixed_ips(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_requested_subnet_id_v4_and_v6_slaac(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_range_allocation(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_create_port_anticipating_allocation(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_ip_allocation_for_ipv6_2_subnet_slaac_mode(self):
        self.skipTest('Only one ipv6 subnet per network is supported')

    def test_create_port_with_multiple_ipv4_and_ipv6_subnets(self):
        self.skipTest('Only one ipv6 subnet per network is supported')

    def test_create_compute_port_with_relay_no_router(self):
        """Compute port creation should fail

        if a network with dhcp relay is not connected to a router
        """
        self._enable_dhcp_relay()
        with self.network() as network, \
            self.subnet(network=network, enable_dhcp=True) as s1:
            device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'X'
            data = {'port': {
                        'network_id': network['network']['id'],
                        'tenant_id': self._tenant_id,
                        'name': 'port',
                        'admin_state_up': True,
                        'device_id': 'fake_device',
                        'device_owner': device_owner,
                        'fixed_ips': [{'subnet_id': s1['subnet']['id']}],
                        'mac_address': '00:00:00:00:00:01'}
                    }
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.create_port,
                              self.ctx, data)

    def _test_create_direct_network(self, vlan_id=0):
        net_type = vlan_id and 'vlan' or 'flat'
        name = 'direct_net'
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: 'tzuuid'}
        if vlan_id:
            providernet_args[pnet.SEGMENTATION_ID] = vlan_id

        mock_tt = mock.patch('vmware_nsxlib.v3'
                             '.core_resources.NsxLibTransportZone'
                             '.get_transport_type',
                             return_value='VLAN')
        mock_tt.start()
        return self.network(name=name,
                            providernet_args=providernet_args,
                            arg_list=(pnet.NETWORK_TYPE,
                                      pnet.PHYSICAL_NETWORK,
                                      pnet.SEGMENTATION_ID))

    def _test_create_port_vnic_direct(self, vlan_id):
        with self._test_create_direct_network(vlan_id=vlan_id) as network:
            # Check that port security conflicts
            kwargs = {portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT,
                      psec.PORTSECURITY: True}
            net_id = network['network']['id']
            res = self._create_port(self.fmt, net_id=net_id,
                                    arg_list=(portbindings.VNIC_TYPE,
                                              psec.PORTSECURITY),
                                    **kwargs)
            self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

            # Check that security group conflicts
            kwargs = {portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT,
                      'security_groups': [
                          '4cd70774-cc67-4a87-9b39-7d1db38eb087'],
                      psec.PORTSECURITY: False}
            net_id = network['network']['id']
            res = self._create_port(self.fmt, net_id=net_id,
                                    arg_list=(portbindings.VNIC_TYPE,
                                              psec.PORTSECURITY),
                                    **kwargs)
            self.assertEqual(res.status_int, exc.HTTPBadRequest.code)

            # All is kosher so we can create the port
            kwargs = {portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT}
            net_id = network['network']['id']
            res = self._create_port(self.fmt, net_id=net_id,
                                    arg_list=(portbindings.VNIC_TYPE,),
                                    **kwargs)
            port = self.deserialize('json', res)
            self.assertEqual("direct", port['port'][portbindings.VNIC_TYPE])
            self.assertEqual("dvs", port['port'][portbindings.VIF_TYPE])
            self.assertEqual(
                vlan_id,
                port['port'][portbindings.VIF_DETAILS]['segmentation-id'])

            # try to get the same port
            req = self.new_show_request('ports', port['port']['id'], self.fmt)
            sport = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual("dvs", sport['port'][portbindings.VIF_TYPE])
            self.assertEqual("direct", sport['port'][portbindings.VNIC_TYPE])
            self.assertEqual(
                vlan_id,
                sport['port'][portbindings.VIF_DETAILS]['segmentation-id'])

    def test_create_port_vnic_direct_flat(self):
        self._test_create_port_vnic_direct(0)

    def test_create_port_vnic_direct_vlan(self):
        self._test_create_port_vnic_direct(10)

    def test_create_port_vnic_direct_invalid_network(self):
        with self.network(name='not vlan/flat') as net:
            kwargs = {portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT,
                      psec.PORTSECURITY: False}
            net_id = net['network']['id']
            res = self._create_port(self.fmt, net_id=net_id,
                                    arg_list=(portbindings.VNIC_TYPE,
                                              psec.PORTSECURITY),
                                    **kwargs)
            self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_update_vnic_direct(self):
        with self._test_create_direct_network(vlan_id=7) as network:
            with self.subnet(network=network) as subnet:
                with self.port(subnet=subnet) as port:
                    # need to do two updates as the update for port security
                    # disabled requires that it can only change 2 items
                    data = {'port': {psec.PORTSECURITY: False,
                                     'security_groups': []}}
                    req = self.new_update_request('ports',
                                                  data, port['port']['id'])
                    res = self.deserialize('json', req.get_response(self.api))
                    self.assertEqual(portbindings.VNIC_NORMAL,
                                     res['port'][portbindings.VNIC_TYPE])

                    data = {'port': {portbindings.VNIC_TYPE:
                                     portbindings.VNIC_DIRECT}}

                    req = self.new_update_request('ports',
                                                  data, port['port']['id'])
                    res = self.deserialize('json', req.get_response(self.api))
                    self.assertEqual(portbindings.VNIC_DIRECT,
                                     res['port'][portbindings.VNIC_TYPE])

    def test_port_invalid_vnic_type(self):
        with self._test_create_direct_network(vlan_id=7) as network:
            kwargs = {portbindings.VNIC_TYPE: 'invalid',
                      psec.PORTSECURITY: False}
            net_id = network['network']['id']
            res = self._create_port(self.fmt, net_id=net_id,
                                    arg_list=(portbindings.VNIC_TYPE,
                                              psec.PORTSECURITY),
                                    **kwargs)
            self.assertEqual(res.status_int, exc.HTTPBadRequest.code)


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
        l3.L3().update_attributes_map(
            l3_egm_apidef.RESOURCE_ATTRIBUTE_MAP)
        l3.L3().update_attributes_map(
            xroute_apidef.RESOURCE_ATTRIBUTE_MAP)
        return (l3.L3.get_resources() +
                address_scope.Address_scope.get_resources())

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class L3NatTest(test_l3_plugin.L3BaseForIntTests, NsxV3PluginTestCaseMixin,
                common_v3.FixExternalNetBaseTest,
                test_address_scope.AddressScopeTestCase):

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None,
              service_plugins=None):
        cfg.CONF.set_override('api_extensions_path', vmware.NSXEXT_PATH)
        cfg.CONF.set_default('max_routes', 3)
        ext_mgr = ext_mgr or TestL3ExtensionManager()
        mock_nsx_version = mock.patch.object(nsx_plugin.utils,
                                             'is_nsx_version_2_0_0',
                                             new=lambda v: True)
        mock_nsx_version.start()
        # Make sure the LB callback is not called on router deletion
        self.lb_mock1 = mock.patch(
            "vmware_nsx.services.lbaas.nsx_v3.v2.lb_driver_v2."
            "EdgeLoadbalancerDriverV2._check_lb_service_on_router")
        self.lb_mock1.start()
        self.lb_mock2 = mock.patch(
            "vmware_nsx.services.lbaas.nsx_v3.v2.lb_driver_v2."
            "EdgeLoadbalancerDriverV2._check_lb_service_on_router_interface")
        self.lb_mock2.start()

        super(L3NatTest, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        self.plugin_instance = directory.get_plugin()
        self._plugin_name = "%s.%s" % (
            self.plugin_instance.__module__,
            self.plugin_instance.__class__.__name__)
        self._plugin_class = self.plugin_instance.__class__
        self.plugin_instance.fwaas_callbacks = None

        self.original_subnet = self.subnet
        self.original_network = self.network

    def _set_net_external(self, net_id):
        # This action is not supported by the V3 plugin
        pass

    def external_network(self, name='net1',
                         admin_state_up=True,
                         fmt=None, **kwargs):
        if not name:
            name = 'l3_ext_net'
        physical_network = nsx_v3_mocks.DEFAULT_TIER0_ROUTER_UUID
        net_type = utils.NetworkTypes.L3_EXT
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: physical_network}
        return self.original_network(name=name,
                                     admin_state_up=admin_state_up,
                                     fmt=fmt,
                                     router__external=True,
                                     providernet_args=providernet_args,
                                     arg_list=(pnet.NETWORK_TYPE,
                                         pnet.PHYSICAL_NETWORK))

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
        self.subnet_calls = []

    def _test_create_l3_ext_network(
            self, physical_network=nsx_v3_mocks.DEFAULT_TIER0_ROUTER_UUID):
        name = 'l3_ext_net'
        net_type = utils.NetworkTypes.L3_EXT
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (extnet_apidef.EXTERNAL, True),
                    (pnet.NETWORK_TYPE, net_type),
                    (pnet.PHYSICAL_NETWORK, physical_network)]
        with self._create_l3_ext_network(physical_network) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    @common_v3.with_external_subnet
    def test_router_update_gateway_with_external_ip_used_by_gw(self):
        super(TestL3NatTestCase,
              self).test_router_update_gateway_with_external_ip_used_by_gw()

    @common_v3.with_external_subnet
    def test_router_update_gateway_with_invalid_external_ip(self):
        super(TestL3NatTestCase,
              self).test_router_update_gateway_with_invalid_external_ip()

    @common_v3.with_external_subnet
    def test_router_update_gateway_with_invalid_external_subnet(self):
        super(TestL3NatTestCase,
              self).test_router_update_gateway_with_invalid_external_subnet()

    @common_v3.with_external_network
    def test_router_update_gateway_with_different_external_subnet(self):
        super(TestL3NatTestCase,
              self).test_router_update_gateway_with_different_external_subnet()

    @common_v3.with_external_subnet_once
    def test_router_update_gateway_with_existed_floatingip(self):
        with self.subnet(cidr='20.0.0.0/24') as subnet:
            self._set_net_external(subnet['subnet']['network_id'])
            with self.floatingip_with_assoc() as fip:
                self._add_external_gateway_to_router(
                    fip['floatingip']['router_id'],
                    subnet['subnet']['network_id'],
                    expected_code=exc.HTTPConflict.code)

    @common_v3.with_external_network
    def test_router_update_gateway_add_multiple_prefixes_ipv6(self):
        super(TestL3NatTestCase,
              self).test_router_update_gateway_add_multiple_prefixes_ipv6()

    @common_v3.with_external_network
    def test_router_concurrent_delete_upon_subnet_create(self):
        super(TestL3NatTestCase,
              self).test_router_concurrent_delete_upon_subnet_create()

    @common_v3.with_external_network
    def test_router_update_gateway_upon_subnet_create_ipv6(self):
        super(TestL3NatTestCase,
              self).test_router_update_gateway_upon_subnet_create_ipv6()

    @common_v3.with_external_subnet
    def test_router_add_gateway_dup_subnet2_returns_400(self):
        super(TestL3NatTestCase,
              self).test_router_add_gateway_dup_subnet2_returns_400()

    @common_v3.with_external_subnet
    def test_router_update_gateway(self):
        super(TestL3NatTestCase,
              self).test_router_update_gateway()

    @common_v3.with_external_subnet
    def test_router_create_with_gwinfo(self):
        super(TestL3NatTestCase,
              self).test_router_create_with_gwinfo()

    @common_v3.with_external_subnet
    def test_router_clear_gateway_callback_failure_returns_409(self):
        super(TestL3NatTestCase,
              self).test_router_clear_gateway_callback_failure_returns_409()

    @common_v3.with_external_subnet
    def test_router_create_with_gwinfo_ext_ip(self):
        super(TestL3NatTestCase,
              self).test_router_create_with_gwinfo_ext_ip()

    @common_v3.with_external_network
    def test_router_create_with_gwinfo_ext_ip_subnet(self):
        super(TestL3NatTestCase,
              self).test_router_create_with_gwinfo_ext_ip_subnet()

    @common_v3.with_external_subnet_second_time
    def test_router_delete_with_floatingip_existed_returns_409(self):
        super(TestL3NatTestCase,
              self).test_router_delete_with_floatingip_existed_returns_409()

    @common_v3.with_external_subnet
    def test_router_add_and_remove_gateway_tenant_ctx(self):
        super(TestL3NatTestCase,
              self).test_router_add_and_remove_gateway_tenant_ctx()

    @common_v3.with_external_subnet
    def test_router_add_and_remove_gateway(self):
        super(TestL3NatTestCase,
              self).test_router_add_and_remove_gateway()

    def test_router_update_gateway_upon_subnet_create_max_ips_ipv6(self):
        self.skipTest('not supported')

    def test_router_add_gateway_multiple_subnets_ipv6(self):
        self.skipTest('multiple ipv6 subnets not supported')

    def test__notify_gateway_port_ip_changed(self):
        self.skipTest('not supported')

    def test__notify_gateway_port_ip_not_changed(self):
        self.skipTest('not supported')

    def test_floatingip_via_router_interface_returns_201(self):
        self.skipTest('not supported')

    def test_floatingip_via_router_interface_returns_404(self):
        self.skipTest('not supported')

    @common_v3.with_external_subnet
    def test_floatingip_list_with_sort(self):
        super(TestL3NatTestCase,
              self).test_floatingip_list_with_sort()

    @common_v3.with_external_subnet_once
    def test_floatingip_with_assoc_fails(self):
        super(TestL3NatTestCase,
              self).test_floatingip_with_assoc_fails()

    @common_v3.with_external_subnet_second_time
    def test_floatingip_update_same_fixed_ip_same_port(self):
        super(TestL3NatTestCase,
              self).test_floatingip_update_same_fixed_ip_same_port()

    @common_v3.with_external_subnet
    def test_floatingip_list_with_pagination_reverse(self):
        super(TestL3NatTestCase,
              self).test_floatingip_list_with_pagination_reverse()

    @common_v3.with_external_subnet_once
    def test_floatingip_association_on_unowned_router(self):
        super(TestL3NatTestCase,
              self).test_floatingip_association_on_unowned_router()

    @common_v3.with_external_network
    def test_delete_ext_net_with_disassociated_floating_ips(self):
        super(TestL3NatTestCase,
              self).test_delete_ext_net_with_disassociated_floating_ips()

    @common_v3.with_external_network
    def test_create_floatingip_with_subnet_and_invalid_fip_address(self):
        super(
            TestL3NatTestCase,
            self).test_create_floatingip_with_subnet_and_invalid_fip_address()

    @common_v3.with_external_subnet
    def test_create_floatingip_with_duplicated_specific_ip(self):
        super(TestL3NatTestCase,
              self).test_create_floatingip_with_duplicated_specific_ip()

    @common_v3.with_external_subnet
    def test_create_floatingip_with_subnet_id_non_admin(self):
        super(TestL3NatTestCase,
              self).test_create_floatingip_with_subnet_id_non_admin()

    @common_v3.with_external_subnet
    def test_floatingip_list_with_pagination(self):
        super(TestL3NatTestCase,
              self).test_floatingip_list_with_pagination()

    @common_v3.with_external_subnet
    def test_create_floatingips_native_quotas(self):
        super(TestL3NatTestCase,
              self).test_create_floatingips_native_quotas()

    @common_v3.with_external_network
    def test_create_floatingip_with_multisubnet_id(self):
        super(TestL3NatTestCase,
              self).test_create_floatingip_with_multisubnet_id()

    @common_v3.with_external_network
    def test_create_floatingip_with_subnet_id_and_fip_address(self):
        super(TestL3NatTestCase,
              self).test_create_floatingip_with_subnet_id_and_fip_address()

    @common_v3.with_external_subnet
    def test_create_floatingip_with_specific_ip(self):
        super(TestL3NatTestCase,
              self).test_create_floatingip_with_specific_ip()

    @common_v3.with_external_network
    def test_create_floatingip_ipv6_and_ipv4_network_creates_ipv4(self):
        super(TestL3NatTestCase,
              self).test_create_floatingip_ipv6_and_ipv4_network_creates_ipv4()

    @common_v3.with_external_subnet_once
    def test_create_floatingip_non_admin_context_agent_notification(self):
        super(
            TestL3NatTestCase,
            self).test_create_floatingip_non_admin_context_agent_notification()

    @common_v3.with_external_subnet
    def test_create_floatingip_no_ext_gateway_return_404(self):
        super(TestL3NatTestCase,
              self).test_create_floatingip_no_ext_gateway_return_404()

    @common_v3.with_external_subnet
    def test_create_floatingip_with_specific_ip_out_of_allocation(self):
        super(TestL3NatTestCase,
              self).test_create_floatingip_with_specific_ip_out_of_allocation()

    @common_v3.with_external_subnet_third_time
    def test_floatingip_update_different_router(self):
        super(TestL3NatTestCase,
              self).test_floatingip_update_different_router()

    def test_router_add_gateway_notifications(self):
        with self.router() as r,\
            self._create_l3_ext_network() as ext_net,\
            self.subnet(network=ext_net):
            with mock.patch.object(registry, 'notify') as notify:
                self._add_external_gateway_to_router(
                    r['router']['id'], ext_net['network']['id'])
                expected = [mock.call(
                                resources.ROUTER_GATEWAY,
                                events.AFTER_CREATE, mock.ANY,
                                context=mock.ANY, gw_ips=mock.ANY,
                                network_id=mock.ANY, router_id=mock.ANY)]
                notify.assert_has_calls(expected)

    def test_create_l3_ext_network_with_default_tier0(self):
        self._test_create_l3_ext_network()

    def test_floatingip_update(self):
        super(TestL3NatTestCase, self).test_floatingip_update(
            expected_status=constants.FLOATINGIP_STATUS_DOWN)

    @common_v3.with_external_subnet_second_time
    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)

    def test_network_update_external(self):
        # This plugin does not support updating the external flag of a network
        self.skipTest('not supported')

    def test_network_update_external_failure(self):
        # This plugin does not support updating the external flag of a network
        # This is tested with a different test
        self.skipTest('not supported')

    def test_router_add_gateway_dup_subnet1_returns_400(self):
        self.skipTest('not supported')

    def test_router_add_interface_dup_subnet2_returns_400(self):
        self.skipTest('not supported')

    def test_router_add_interface_ipv6_port_existing_network_returns_400(self):
        self.skipTest('multiple ipv6 subnets not supported')

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

    def test_router_add_interface_by_port_other_tenant_address_out_of_pool(
        self):
        # multiple fixed ips per port are not supported
        self.skipTest('not supported')

    def test_router_add_interface_by_port_other_tenant_address_in_pool(self):
        # multiple fixed ips per port are not supported
        self.skipTest('not supported')

    def test_router_add_interface_by_port_admin_address_out_of_pool(self):
        # multiple fixed ips per port are not supported
        self.skipTest('not supported')

    def test_router_delete_with_lb_service(self):
        self.lb_mock1.stop()
        self.lb_mock2.stop()
        # Create the LB object - here the delete callback is registered
        lb_driver = lb_driver_v2.EdgeLoadbalancerDriverV2()
        with self.router() as router:
            with mock.patch('vmware_nsxlib.v3.load_balancer.Service.'
                            'get_router_lb_service'),\
                mock.patch('vmware_nsx.db.db.get_nsx_router_id',
                           return_value=1):
                self.assertRaises(nc_exc.CallbackFailure,
                                  self.plugin_instance.delete_router,
                                  context.get_admin_context(),
                                  router['router']['id'])
        # Unregister callback
        lb_driver._unsubscribe_router_delete_callback()
        self.lb_mock1.start()
        self.lb_mock2.start()

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
            self._create_l3_ext_network() as ext_net,\
            self.subnet(network=ext_net) as ext_subnet,\
            self.subnet(cidr='11.0.0.0/24') as s1:
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
            with self._create_l3_ext_network() as ext_net,\
                self.subnet(network=ext_net, cidr='10.0.1.0/24') as s:
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

                updates = {'admin_state_up': False}
                self.assertRaises(n_exc.InvalidInput,
                                  self.plugin_instance.update_router,
                                  context.get_admin_context(),
                                  r['router']['id'],
                                  {'router': updates})

                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                gw_info = body['router']['external_gateway_info']
                self.assertIsNone(gw_info)

    def test_router_on_vlan_net(self):
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 10}
        with mock.patch('vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
                       'get_transport_type', return_value='VLAN'):
            result = self._create_network(fmt='json', name='badvlan_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(
                                              pnet.NETWORK_TYPE,
                                              pnet.SEGMENTATION_ID))
            vlan_network = self.deserialize('json', result)
            with self.router() as r1,\
                self._create_l3_ext_network() as ext_net,\
                self.subnet(network=ext_net) as ext_subnet,\
                self.subnet(cidr='11.0.0.0/24', network=vlan_network) as s1:
                # adding a vlan interface with no GW should fail
                self._router_interface_action(
                    'add', r1['router']['id'],
                    s1['subnet']['id'], None,
                    expected_code=400)
                # adding GW
                self._add_external_gateway_to_router(
                    r1['router']['id'],
                    ext_subnet['subnet']['network_id'])
                # adding the vlan interface
                self._router_interface_action(
                    'add', r1['router']['id'],
                    s1['subnet']['id'], None)

                # adding a floating ip
                with self.port(subnet=s1) as p:
                    fip_res = self._create_floatingip(
                        self.fmt,
                        ext_subnet['subnet']['network_id'],
                        subnet_id=ext_subnet['subnet']['id'],
                        port_id=p['port']['id'])
                    fip = self.deserialize(self.fmt, fip_res)
                    self.assertEqual(p['port']['id'],
                                     fip['floatingip']['port_id'])

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
            self._create_l3_ext_network() as ext_net:
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
            self._create_l3_ext_network() as ext_net:
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

    def _mock_add_remove_service_router(self):
        return mock.patch("vmware_nsxlib.v3.core_resources."
                          "NsxLibLogicalRouter.update")

    def _mock_del_snat_rule(self):
        return mock.patch("vmware_nsxlib.v3.router.RouterLib."
                          "delete_gw_snat_rule_by_source")

    def _prepare_external_subnet_on_address_scope(self,
                                                  ext_net,
                                                  address_scope):
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

    def test_add_service_router_enable_snat(self):
        with self.address_scope(name='as1') as addr_scope, \
                self._create_l3_ext_network() as ext_net:
            ext_subnet = self._prepare_external_subnet_on_address_scope(
                ext_net, addr_scope)

            # create a router with this gateway
            with self.router() as r, \
                mock.patch("vmware_nsxlib.v3.router.RouterLib."
                           "has_service_router", return_value=False),\
                self._mock_add_remove_service_router() as change_sr:
                router_id = r['router']['id']
                self._add_external_gateway_to_router(
                    router_id, ext_subnet['network_id'])
                # Checking that router update is being called with
                # edge_cluster_uuid, for creating a service router
                change_sr.assert_called_once_with(
                    mock.ANY, edge_cluster_id=NSX_EDGE_CLUSTER_UUID,
                    enable_standby_relocation=True)

    def test_remove_service_router_disable_snat(self):
        with self.address_scope(name='as1') as addr_scope, \
                self._create_l3_ext_network() as ext_net:
            ext_subnet = self._prepare_external_subnet_on_address_scope(
                ext_net, addr_scope)

            # create a router with this gateway, disable snat
            with self.router() as r:
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    ext_subnet['network_id'])
                with mock.patch("vmware_nsxlib.v3.router.RouterLib."
                                "has_service_router", return_value=True),\
                    self._mock_add_remove_service_router() as change_sr:
                    self._update_router_enable_snat(
                        r['router']['id'],
                        ext_subnet['network_id'],
                        False)
                    # Checking that router update is being called
                    # and setting edge_cluster_uuid to None, for service
                    # router removal.
                    change_sr.assert_called_once_with(
                        mock.ANY, edge_cluster_id=None,
                        enable_standby_relocation=False)

    def test_router_address_scope_snat_rules(self):
        """Test that if the router interface had the same address scope
        as the gateway - snat rule is not added.
        """
        # create an external network on one address scope
        with self.address_scope(name='as1') as addr_scope, \
            self._create_l3_ext_network() as ext_net:
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
            self._create_l3_ext_network() as ext_net:
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
            self._create_l3_ext_network() as ext_net:
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
            self._create_l3_ext_network() as ext_net:
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

    def test_router_admin_state(self):
        """It is not allowed to set the router admin-state to down"""
        with self.router() as r:
            self._update('routers', r['router']['id'],
                         {'router': {'admin_state_up': False}},
                         expected_code=exc.HTTPBadRequest.code)

    def test_router_dhcp_relay_dhcp_enabled(self):
        """Verify that the relay service is added to the router interface"""
        self._enable_dhcp_relay()
        with self.network() as network:
            with mock.patch.object(self.plugin,
                                  'validate_router_dhcp_relay'),\
                self.subnet(network=network, enable_dhcp=True) as s1,\
                self.router() as r1,\
                mock.patch.object(self.plugin.nsxlib.logical_router_port,
                                  'update') as mock_update_port:
                self._router_interface_action('add', r1['router']['id'],
                                              s1['subnet']['id'], None)
                mock_update_port.assert_called_once_with(
                    mock.ANY,
                    relay_service_uuid=NSX_DHCP_RELAY_SRV,
                    subnets=mock.ANY)

    def test_router_dhcp_relay_dhcp_disabled(self):
        """Verify that the relay service is not added to the router interface

        If the subnet do not have enabled dhcp
        """
        self._enable_dhcp_relay()
        with self.network() as network:
            with mock.patch.object(self.plugin,
                                  'validate_router_dhcp_relay'),\
                self.subnet(network=network, enable_dhcp=False) as s1,\
                self.router() as r1,\
                mock.patch.object(self.plugin.nsxlib.logical_router_port,
                                  'update') as mock_update_port:
                self._router_interface_action('add', r1['router']['id'],
                                              s1['subnet']['id'], None)
                mock_update_port.assert_called_once_with(
                    mock.ANY,
                    relay_service_uuid=None,
                    subnets=mock.ANY)

    def test_router_dhcp_relay_no_ipam(self):
        """Verify that a router cannot be created with relay and no ipam"""
        # Add the relay service to the config and availability zones
        self._enable_dhcp_relay()
        self.assertRaises(n_exc.InvalidInput,
                          self.plugin_instance.create_router,
                          context.get_admin_context(),
                          {'router': {'name': 'rtr'}})

    def test_router_add_gateway_no_subnet_forbidden(self):
        with self.router() as r:
            with self._create_l3_ext_network() as n:
                self._add_external_gateway_to_router(
                    r['router']['id'], n['network']['id'],
                    expected_code=exc.HTTPBadRequest.code)

    def test_router_add_gateway_no_subnet(self):
        self.skipTest('No support for no subnet gateway set')

    @mock.patch.object(nsx_plugin.NsxV3Plugin, 'validate_availability_zones')
    def test_create_router_with_availability_zone(self, mock_validate_az):
        name = 'rtr-with-zone'
        zone = ['zone1']
        mock_validate_az.return_value = None
        with self.router(name=name, availability_zone_hints=zone) as rtr:
            az_hints = rtr['router']['availability_zone_hints']
            self.assertListEqual(zone, az_hints)

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

    def test_update_router_distinct_edge_cluster(self):
        self.mock_get_edge_cluster.stop()
        edge_cluster = uuidutils.generate_uuid()
        mock.patch(
            "vmware_nsxlib.v3.core_resources.NsxLibEdgeCluster."
            "get_id_by_name_or_id",
            return_value=edge_cluster).start()
        cfg.CONF.set_override('edge_cluster', edge_cluster, 'nsx_v3')
        self._initialize_azs()
        with self.address_scope(name='as1') as addr_scope, \
                self._create_l3_ext_network() as ext_net:
            ext_subnet = self._prepare_external_subnet_on_address_scope(
                ext_net, addr_scope)

            # create a router with this gateway
            with self.router() as r, \
                mock.patch("vmware_nsxlib.v3.router.RouterLib."
                           "has_service_router", return_value=False),\
                self._mock_add_remove_service_router() as change_sr:
                router_id = r['router']['id']
                self._add_external_gateway_to_router(
                    router_id, ext_subnet['network_id'])
                change_sr.assert_called_once_with(
                    mock.ANY, edge_cluster_id=edge_cluster,
                    enable_standby_relocation=True)
        self.mock_get_edge_cluster.start()

    def test_router_add_interface_cidr_overlapped_with_gateway(self):
        with self.router() as r,\
            self._create_l3_ext_network() as ext_net,\
            self.subnet(cidr='10.0.1.0/24') as s1,\
            self.subnet(network=ext_net, cidr='10.0.0.0/16',
                        enable_dhcp=False) as s2:
            self._add_external_gateway_to_router(
                r['router']['id'],
                s2['subnet']['network_id'])
            res = self._router_interface_action(
                'add', r['router']['id'],
                s1['subnet']['id'], None,
                expected_code=exc.HTTPBadRequest.code)
            self.assertIn('NeutronError', res)

    def test_router_add_gateway_overlapped_with_interface_cidr(self):
        with self.router() as r,\
            self._create_l3_ext_network() as ext_net,\
            self.subnet(cidr='10.0.1.0/24') as s1,\
            self.subnet(network=ext_net, cidr='10.0.0.0/16',
                        enable_dhcp=False) as s2:
            self._router_interface_action(
                'add', r['router']['id'],
                s1['subnet']['id'], None)
            res = self._add_external_gateway_to_router(
                r['router']['id'],
                s2['subnet']['network_id'],
                expected_code=exc.HTTPBadRequest.code)
            self.assertIn('NeutronError', res)

    def test_router_add_interface_by_port_cidr_overlapped_with_gateway(self):
        with self.router() as r,\
            self._create_l3_ext_network() as ext_net,\
            self.subnet(cidr='10.0.1.0/24') as s1,\
            self.subnet(network=ext_net, cidr='10.0.0.0/16',
                        enable_dhcp=False) as s2,\
            self.port(subnet=s1) as p:
            self._add_external_gateway_to_router(
                r['router']['id'],
                s2['subnet']['network_id'])

            res = self._router_interface_action(
                'add', r['router']['id'],
                None,
                p['port']['id'],
                expected_code=exc.HTTPBadRequest.code)
            self.assertIn('NeutronError', res)


class ExtGwModeTestCase(test_ext_gw_mode.ExtGwModeIntTestCase,
                        L3NatTest):
    def test_router_gateway_set_fail_after_port_create(self):
        self.skipTest("TBD")

    # Override subnet/network creation in some tests to create external
    # networks immediately instead of updating it post creation, which the
    # v3 plugin does not support
    @decorator.decorator
    def with_external_subnet(f, *args, **kwargs):
        obj = args[0]
        obj.subnet = obj.external_subnet
        result = f(*args, **kwargs)
        obj.subnet = obj.original_subnet
        return result

    @common_v3.with_external_subnet
    def _test_router_update_ext_gwinfo(self, snat_input_value,
                                       snat_expected_value=False,
                                       expected_http_code=exc.HTTPOk.code):
        return super(ExtGwModeTestCase, self)._test_router_update_ext_gwinfo(
              snat_input_value,
              snat_expected_value=snat_expected_value,
              expected_http_code=expected_http_code)

    @common_v3.with_external_subnet
    def test_router_gateway_set_retry(self):
        super(ExtGwModeTestCase, self).test_router_gateway_set_retry()

    @common_v3.with_external_subnet
    def _test_router_create_show_ext_gwinfo(self, *args, **kwargs):
        return super(ExtGwModeTestCase,
                     self)._test_router_create_show_ext_gwinfo(*args, **kwargs)
