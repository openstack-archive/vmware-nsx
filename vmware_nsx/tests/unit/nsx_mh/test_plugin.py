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
import copy

import mock
from neutron.extensions import l3
from neutron.extensions import securitygroup as secgrp
from neutron.tests.unit import _test_extension_portbindings as test_bindings
import neutron.tests.unit.db.test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_extra_dhcp_opt as test_dhcpopts
import neutron.tests.unit.extensions.test_l3 as test_l3_plugin
import neutron.tests.unit.extensions.test_l3_ext_gw_mode as test_ext_gw_mode
import neutron.tests.unit.extensions.test_securitygroup as ext_sg
from neutron.tests.unit import testlib_api
from neutron_lib.api.definitions import dvr as dvr_apidef
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import l3_ext_gw_mode as l3_egm_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as ntn_exc
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import uuidutils
from sqlalchemy import exc as sql_exc
import webob.exc

from vmware_nsx.api_client import exception as api_exc
from vmware_nsx.api_client import version as ver_module
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import sync
from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.nsxlib import mh as nsxlib
from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.extensions import test_metadata
from vmware_nsx.tests.unit.nsx_mh.apiclient import fake
from vmware_nsx.tests.unit import test_utils

LOG = log.getLogger(__name__)


class NsxPluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

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

        attrs = kwargs
        if providernet_args:
            attrs.update(providernet_args)
        for arg in (('admin_state_up', 'tenant_id', 'shared') +
                    (arg_list or ())):
            # Arg must be present
            if arg in kwargs:
                data['network'][arg] = kwargs[arg]
        network_req = self.new_create_request('networks', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            network_req.environ['neutron.context'] = context.Context(
                '', tenant_id)
        return network_req.get_response(self.api)

    def setUp(self,
              plugin=vmware.PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        test_utils.override_nsx_ini_test()
        # mock api client
        self.fc = fake.FakeClient(vmware.STUBS_PATH)
        self.mock_nsx = mock.patch(vmware.NSXAPI_NAME, autospec=True)
        self.mock_instance = self.mock_nsx.start()
        # Avoid runs of the synchronizer looping call
        patch_sync = mock.patch.object(sync, '_start_loopingcall')
        patch_sync.start()

        # Emulate tests against NSX 2.x
        self.mock_instance.return_value.get_version.return_value = (
            ver_module.Version("2.9"))
        self.mock_instance.return_value.request.side_effect = (
            self.fc.fake_request)
        super(NsxPluginV2TestCase, self).setUp(plugin=plugin,
                                               ext_mgr=ext_mgr)
        # Newly created port's status is always 'DOWN' till NSX wires them.
        self.port_create_status = constants.PORT_STATUS_DOWN
        cfg.CONF.set_override('metadata_mode', None, 'NSX')
        self.addCleanup(self.fc.reset_all)


class TestBasicGet(test_plugin.TestBasicGet, NsxPluginV2TestCase):
    pass


class TestV2HTTPResponse(test_plugin.TestV2HTTPResponse, NsxPluginV2TestCase):
    pass


class TestPortsV2(NsxPluginV2TestCase,
                  test_plugin.TestPortsV2,
                  test_bindings.PortBindingsTestCase,
                  test_bindings.PortBindingsHostTestCaseMixin,
                  test_bindings.PortBindingsVnicTestCaseMixin):

    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = True

    def _test_exhaust_ports(self, providernet_args=None):
        with self.network(name='testnet',
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK,
                                    pnet.SEGMENTATION_ID)) as net:
            with self.subnet(network=net) as sub:
                with self.port(subnet=sub):
                    # creating another port should see an exception
                    self._create_port('json', net['network']['id'], 400)

    def test_exhaust_ports_overlay_network(self):
        cfg.CONF.set_override('max_lp_per_overlay_ls', 1, group='NSX')
        self._test_exhaust_ports()

    def test_exhaust_ports_bridged_network(self):
        cfg.CONF.set_override('max_lp_per_bridged_ls', 1, group="NSX")
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'tzuuid'}
        self._test_exhaust_ports(providernet_args=providernet_args)

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

    def test_create_port_name_exceeds_40_chars(self):
        name = 'this_is_a_port_whose_name_is_longer_than_40_chars'
        with self.port(name=name) as port:
            # Assert the neutron name is not truncated
            self.assertEqual(name, port['port']['name'])

    def _verify_no_orphan_left(self, net_id):
        # Verify no port exists on net
        # ie: cleanup on db was successful
        query_params = "network_id=%s" % net_id
        self._test_list_resources('port', [],
                                  query_params=query_params)
        # Also verify no orphan port was left on nsx
        # no port should be there at all
        self.assertFalse(self.fc._fake_lswitch_lport_dict)

    def test_create_port_nsx_error_no_orphan_left(self):
        with mock.patch.object(nsxlib.switch, 'create_lport',
                               side_effect=api_exc.NsxApiException):
            with self.network() as net:
                net_id = net['network']['id']
                self._create_port(self.fmt, net_id,
                                  webob.exc.HTTPInternalServerError.code)
                self._verify_no_orphan_left(net_id)

    def test_create_port_neutron_error_no_orphan_left(self):
        with mock.patch.object(nsx_db, 'add_neutron_nsx_port_mapping',
                               side_effect=ntn_exc.NeutronException):
            with self.network() as net:
                net_id = net['network']['id']
                self._create_port(self.fmt, net_id,
                                  webob.exc.HTTPInternalServerError.code)
                self._verify_no_orphan_left(net_id)

    def test_create_port_db_error_no_orphan_left(self):
        db_exception = db_exc.DBError(
            inner_exception=sql_exc.IntegrityError(mock.ANY,
                                                   mock.ANY,
                                                   mock.ANY))
        with mock.patch.object(nsx_db, 'add_neutron_nsx_port_mapping',
                               side_effect=db_exception):
            with self.network() as net:
                with self.port(device_owner=constants.DEVICE_OWNER_DHCP):
                    self._verify_no_orphan_left(net['network']['id'])

    def test_create_port_maintenance_returns_503(self):
        with self.network() as net:
            with mock.patch.object(nsxlib, 'do_request',
                                   side_effect=nsx_exc.MaintenanceInProgress):
                data = {'port': {'network_id': net['network']['id'],
                                 'admin_state_up': False,
                                 'fixed_ips': [],
                                 'tenant_id': self._tenant_id}}
                plugin = directory.get_plugin()
                with mock.patch.object(plugin, 'get_network',
                                       return_value=net['network']):
                    port_req = self.new_create_request('ports', data, self.fmt)
                    res = port_req.get_response(self.api)
                    self.assertEqual(webob.exc.HTTPServiceUnavailable.code,
                                     res.status_int)


class TestNetworksV2(test_plugin.TestNetworksV2, NsxPluginV2TestCase):

    def test_create_network_vlan_transparent(self):
        self.skipTest("Currently no support in plugin for this")

    def _test_create_bridge_network(self, vlan_id=0):
        net_type = 'vlan' if vlan_id else 'flat'
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

    def test_create_l3_ext_network_fails_if_not_external(self):
        net_type = 'l3_ext'
        name = 'l3_ext_net'
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: 'l3gwuuid',
                            pnet.SEGMENTATION_ID: 123}
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            with self.network(name=name,
                              providernet_args=providernet_args,
                              arg_list=(pnet.NETWORK_TYPE,
                                        pnet.PHYSICAL_NETWORK,
                                        pnet.SEGMENTATION_ID)):
                pass
        self.assertEqual(ctx_manager.exception.code,
                         webob.exc.HTTPBadRequest.code)

    def test_list_networks_filter_by_id(self):
        # We add this unit test to cover some logic specific to the
        # nsx plugin
        with self.network(name='net1') as net1:
            with self.network(name='net2') as net2:
                query_params = 'id=%s' % net1['network']['id']
                self._test_list_resources('network', [net1],
                                          query_params=query_params)
                query_params += '&id=%s' % net2['network']['id']
                self._test_list_resources('network', [net1, net2],
                                          query_params=query_params)

    def test_delete_network_after_removing_subet(self):
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

    def test_create_network_maintenance_returns_503(self):
        data = {'network': {'name': 'foo',
                            'admin_state_up': True,
                            'tenant_id': self._tenant_id}}
        with mock.patch.object(nsxlib, 'do_request',
                               side_effect=nsx_exc.MaintenanceInProgress):
            net_req = self.new_create_request('networks', data, self.fmt)
            res = net_req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPServiceUnavailable.code,
                             res.status_int)

    def test_update_network_with_admin_false(self):
        data = {'network': {'admin_state_up': False}}
        with self.network() as net:
            plugin = directory.get_plugin()
            self.assertRaises(NotImplementedError,
                              plugin.update_network,
                              context.get_admin_context(),
                              net['network']['id'], data)

    def test_update_network_with_name_calls_nsx(self):
        with mock.patch.object(
            nsxlib.switch, 'update_lswitch') as update_lswitch_mock:
            # don't worry about deleting this network, do not use
            # context manager
            ctx = context.get_admin_context()
            # Because of commit 79c9712 a tenant must be specified otherwise
            # the unit test will fail
            ctx.tenant_id = 'whatever'
            plugin = directory.get_plugin()
            net = plugin.create_network(
                ctx, {'network': {'name': 'xxx',
                                  'admin_state_up': True,
                                  'shared': False,
                                  'tenant_id': ctx.tenant_id,
                                  'port_security_enabled': True}})
            plugin.update_network(ctx, net['id'],
                                  {'network': {'name': 'yyy'}})
        update_lswitch_mock.assert_called_once_with(
            mock.ANY, mock.ANY, 'yyy')


class SecurityGroupsTestCase(ext_sg.SecurityGroupDBTestCase):

    def setUp(self):
        test_utils.override_nsx_ini_test()
        # mock nsx api client
        self.fc = fake.FakeClient(vmware.STUBS_PATH)
        self.mock_nsx = mock.patch(vmware.NSXAPI_NAME, autospec=True)
        instance = self.mock_nsx.start()
        instance.return_value.login.return_value = "the_cookie"
        # Avoid runs of the synchronizer looping call
        patch_sync = mock.patch.object(sync, '_start_loopingcall')
        patch_sync.start()

        instance.return_value.request.side_effect = self.fc.fake_request
        super(SecurityGroupsTestCase, self).setUp(vmware.PLUGIN_NAME)
        self.plugin = directory.get_plugin()


class TestSecurityGroup(ext_sg.TestSecurityGroups, SecurityGroupsTestCase):

    def test_create_security_group_name_exceeds_40_chars(self):
        name = 'this_is_a_secgroup_whose_name_is_longer_than_40_chars'
        with self.security_group(name=name) as sg:
            # Assert Neutron name is not truncated
            self.assertEqual(sg['security_group']['name'], name)

    def test_create_security_group_rule_bad_input(self):
        name = 'foo security group'
        description = 'foo description'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            protocol = 200
            min_range = 32
            max_range = 4343
            rule = self._build_security_group_rule(
                security_group_id, 'ingress', protocol,
                min_range, max_range)
            res = self._create_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(res.status_int, 400)

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

    def test_create_security_group_rule_icmpv6_legacy_protocol_name(self):
        self.skipTest('not supported')

    def test_create_security_group_rule_protocol_as_number_range(self):
        self.skipTest('not supported')

    def test_create_security_group_rule_protocol_as_number_with_port(self):
        self.skipTest('not supported')


class TestL3ExtensionManager(object):

    def get_resources(self):
        # Simulate extension of L3 attribute map
        l3.L3().update_attributes_map(
            l3_egm_apidef.RESOURCE_ATTRIBUTE_MAP)
        l3.L3().update_attributes_map(
            dvr_apidef.RESOURCE_ATTRIBUTE_MAP)
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestL3SecGrpExtensionManager(TestL3ExtensionManager):
    """A fake extension manager for L3 and Security Group extensions.

    Includes also NSX specific L3 attributes.
    """

    def get_resources(self):
        resources = super(TestL3SecGrpExtensionManager,
                          self).get_resources()
        resources.extend(secgrp.Securitygroup.get_resources())
        return resources


class L3NatTest(test_l3_plugin.L3BaseForIntTests, NsxPluginV2TestCase):

    def setUp(self, plugin=vmware.PLUGIN_NAME, ext_mgr=None,
              service_plugins=None):
        cfg.CONF.set_override('api_extensions_path', vmware.NSXEXT_PATH)
        ext_mgr = ext_mgr or TestL3ExtensionManager()
        super(L3NatTest, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        plugin_instance = directory.get_plugin()
        self._plugin_name = "%s.%s" % (
            plugin_instance.__module__,
            plugin_instance.__class__.__name__)
        self._plugin_class = plugin_instance.__class__

    def _create_l3_ext_network(self, vlan_id=None):
        name = 'l3_ext_net'
        net_type = utils.NetworkTypes.L3_EXT
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: 'l3_gw_uuid'}
        if vlan_id:
            providernet_args[pnet.SEGMENTATION_ID] = vlan_id
        return self.network(name=name,
                            router__external=True,
                            providernet_args=providernet_args,
                            arg_list=(pnet.NETWORK_TYPE,
                                      pnet.PHYSICAL_NETWORK,
                                      pnet.SEGMENTATION_ID))


class TestL3NatTestCase(L3NatTest,
                        test_l3_plugin.L3NatDBIntTestCase,
                        NsxPluginV2TestCase,
                        test_metadata.MetaDataTestCase):

    def _test_create_l3_ext_network(self, vlan_id=0):
        name = 'l3_ext_net'
        net_type = utils.NetworkTypes.L3_EXT
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (extnet_apidef.EXTERNAL, True),
                    (pnet.NETWORK_TYPE, net_type),
                    (pnet.PHYSICAL_NETWORK, 'l3_gw_uuid'),
                    (pnet.SEGMENTATION_ID, vlan_id)]
        with self._create_l3_ext_network(vlan_id) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def _nsx_validate_ext_gw(self, router_id, l3_gw_uuid, vlan_id):
        """Verify data on fake NSX API client in order to validate
        plugin did set them properly
        """
        # First find the NSX router ID
        ctx = context.get_admin_context()
        nsx_router_id = nsx_db.get_nsx_router_id(ctx.session, router_id)
        ports = [port for port in self.fc._fake_lrouter_lport_dict.values()
                 if (port['lr_uuid'] == nsx_router_id and
                     port['att_type'] == "L3GatewayAttachment")]
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]['attachment_gwsvc_uuid'], l3_gw_uuid)
        self.assertEqual(ports[0].get('vlan_id'), vlan_id)

    def test_create_l3_ext_network_without_vlan(self):
        self._test_create_l3_ext_network()

    def _test_router_create_with_gwinfo_and_l3_ext_net(self, vlan_id=None,
                                                       validate_ext_gw=True):
        with self._create_l3_ext_network(vlan_id) as net:
            with self.subnet(network=net) as s:
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
                    self._nsx_validate_ext_gw(router['router']['id'],
                                              'l3_gw_uuid', vlan_id)

    def test_router_create_with_gwinfo_and_l3_ext_net(self):
        self._test_router_create_with_gwinfo_and_l3_ext_net()

    def test_router_create_with_gwinfo_and_l3_ext_net_with_vlan(self):
        self._test_router_create_with_gwinfo_and_l3_ext_net(444)

    def _test_router_create_with_distributed(self, dist_input, dist_expected,
                                             version='3.1', return_code=201):
        self.mock_instance.return_value.get_version.return_value = (
            ver_module.Version(version))

        data = {'tenant_id': 'whatever'}
        data['name'] = 'router1'
        data['distributed'] = dist_input
        router_req = self.new_create_request(
            'routers', {'router': data}, self.fmt)
        res = router_req.get_response(self.ext_api)
        self.assertEqual(return_code, res.status_int)
        if res.status_int == 201:
            router = self.deserialize(self.fmt, res)
            self.assertIn('distributed', router['router'])
            self.assertEqual(dist_expected,
                             router['router']['distributed'])

    def test_router_create_distributed_with_3_1(self):
        self._test_router_create_with_distributed(True, True)

    def test_router_create_distributed_with_new_nsx_versions(self):
        with mock.patch.object(nsxlib.router, 'create_explicit_route_lrouter'):
            self._test_router_create_with_distributed(True, True, '3.2')
            self._test_router_create_with_distributed(True, True, '4.0')
            self._test_router_create_with_distributed(True, True, '4.1')

    def test_router_create_not_distributed(self):
        self._test_router_create_with_distributed(False, False)

    def test_router_create_distributed_unspecified(self):
        self._test_router_create_with_distributed(None, False)

    def test_router_create_distributed_returns_400(self):
        self._test_router_create_with_distributed(True, None, '3.0', 400)

    def test_router_create_on_obsolete_platform(self):

        def obsolete_response(*args, **kwargs):
            response = (nsxlib.router.
                        _create_implicit_routing_lrouter(*args, **kwargs))
            response.pop('distributed')
            return response

        with mock.patch.object(
            nsxlib.router, 'create_lrouter', new=obsolete_response):
            self._test_router_create_with_distributed(None, False, '2.2')

    def _create_router_with_gw_info_for_test(self, subnet):
        data = {'router': {'tenant_id': 'whatever',
                           'name': 'router1',
                           'external_gateway_info':
                           {'network_id': subnet['subnet']['network_id']}}}
        router_req = self.new_create_request(
            'routers', data, self.fmt)
        return router_req.get_response(self.ext_api)

    def test_router_create_nsx_error_returns_500(self, vlan_id=None):
        with mock.patch.object(nsxlib.router,
                               'create_router_lport',
                               side_effect=api_exc.NsxApiException):
            with self._create_l3_ext_network(vlan_id) as net:
                with self.subnet(network=net) as s:
                    res = self._create_router_with_gw_info_for_test(s)
                    self.assertEqual(
                        webob.exc.HTTPInternalServerError.code,
                        res.status_int)

    def test_router_add_gateway_invalid_network_returns_404(self):
        # NOTE(salv-orlando): This unit test has been overridden
        # as the nsx plugin support the ext_gw_mode extension
        # which mandates an uuid for the external network identifier
        with self.router() as r:
            self._add_external_gateway_to_router(
                r['router']['id'],
                uuidutils.generate_uuid(),
                expected_code=webob.exc.HTTPNotFound.code)

    def _verify_router_rollback(self):
        # Check that nothing is left on DB
        # TODO(salv-orlando): Verify whehter this is thread-safe
        # w.r.t. sqllite and parallel testing
        self._test_list_resources('router', [])
        # Check that router is not in NSX
        self.assertFalse(self.fc._fake_lrouter_dict)

    # TODO(asarfaty): make this test pass with the new enginefacade
    def skip_test_router_create_with_gw_info_neutron_fail_does_rollback(self):
        # Simulate get subnet error while building list of ips with prefix
        with mock.patch.object(self._plugin_class,
                               '_build_ip_address_list',
                               side_effect=ntn_exc.SubnetNotFound(
                                   subnet_id='xxx')):
            with self._create_l3_ext_network() as net:
                with self.subnet(network=net) as s:
                    res = self._create_router_with_gw_info_for_test(s)
                    self.assertEqual(
                        webob.exc.HTTPNotFound.code,
                        res.status_int)
                    self._verify_router_rollback()

    def test_router_create_with_gw_info_nsx_fail_does_rollback(self):
        # Simulate error while fetching nsx router gw port
        with mock.patch.object(self._plugin_class,
                               '_find_router_gw_port',
                               side_effect=api_exc.NsxApiException):
            with self._create_l3_ext_network() as net:
                with self.subnet(network=net) as s:
                    res = self._create_router_with_gw_info_for_test(s)
                    self.assertEqual(
                        webob.exc.HTTPInternalServerError.code,
                        res.status_int)
                    self._verify_router_rollback()

    def _test_router_update_gateway_on_l3_ext_net(self, vlan_id=None,
                                                  validate_ext_gw=True):
        with self.router() as r:
            with self.subnet() as s1:
                with self._create_l3_ext_network(vlan_id) as net:
                    with self.subnet(network=net) as s2:
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
                                self._nsx_validate_ext_gw(
                                    body['router']['id'],
                                    'l3_gw_uuid', vlan_id)
                        finally:
                            # Cleanup
                            self._remove_external_gateway_from_router(
                                r['router']['id'],
                                s2['subnet']['network_id'])

    def test_router_update_gateway_on_l3_ext_net(self):
        self._test_router_update_gateway_on_l3_ext_net()

    def test_router_update_gateway_on_l3_ext_net_with_vlan(self):
        self._test_router_update_gateway_on_l3_ext_net(444)

    def test_router_list_by_tenant_id(self):
        with self.router(), self.router():
            with self.router(tenant_id='custom') as router1:
                self._test_list_resources('router', [router1],
                                          query_params="tenant_id=custom")

    def test_create_l3_ext_network_with_vlan(self):
        self._test_create_l3_ext_network(666)

    def test_floatingip_with_assoc_fails(self):
        self._test_floatingip_with_assoc_fails(
            "%s.%s" % (self._plugin_name, "_update_fip_assoc"))

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)

    def test_create_router_name_exceeds_40_chars(self):
        name = 'this_is_a_router_whose_name_is_longer_than_40_chars'
        with self.router(name=name) as rtr:
            # Assert Neutron name is not truncated
            self.assertEqual(rtr['router']['name'], name)

    def test_router_add_interface_port(self):
        orig_update_port = self.plugin.update_port
        with self.router() as r, (
            self.port()) as p, (
                mock.patch.object(self.plugin, 'update_port')) as update_port:
            update_port.side_effect = orig_update_port
            body = self._router_interface_action('add',
                                                 r['router']['id'],
                                                 None,
                                                 p['port']['id'])
            self.assertIn('port_id', body)
            self.assertEqual(p['port']['id'], body['port_id'])
            expected_port_update = {'port_security_enabled': False,
                                    'security_groups': []}
            update_port.assert_any_call(
                mock.ANY, p['port']['id'], {'port': expected_port_update})
            # fetch port and confirm device_id
            body = self._show('ports', p['port']['id'])
            self.assertEqual(r['router']['id'], body['port']['device_id'])

            # clean-up
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          None,
                                          p['port']['id'])

    def _test_floatingip_update(self, expected_status):
        super(TestL3NatTestCase, self).test_floatingip_update(
            expected_status)

    def test_floatingip_update(self):
        self._test_floatingip_update(constants.FLOATINGIP_STATUS_DOWN)

    def test_floatingip_disassociate(self):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            plugin = directory.get_plugin()
            with mock.patch.object(plugin, 'notify_routers_updated') as notify:
                with self.floatingip_no_assoc(private_sub) as fip:
                    port_id = p['port']['id']
                    body = self._update('floatingips', fip['floatingip']['id'],
                                        {'floatingip': {'port_id': port_id}})
                    self.assertEqual(body['floatingip']['port_id'], port_id)
                    # Floating IP status should be active
                    self.assertEqual(constants.FLOATINGIP_STATUS_ACTIVE,
                                     body['floatingip']['status'])
                    # Disassociate
                    body = self._update('floatingips', fip['floatingip']['id'],
                                        {'floatingip': {'port_id': None}})
                    body = self._show('floatingips', fip['floatingip']['id'])
                    self.assertIsNone(body['floatingip']['port_id'])
                    self.assertIsNone(body['floatingip']['fixed_ip_address'])
                    # Floating IP status should be down
                    self.assertEqual(constants.FLOATINGIP_STATUS_DOWN,
                                     body['floatingip']['status'])

                # check that notification was not requested
                self.assertFalse(notify.called)

    def test_create_router_maintenance_returns_503(self):
        with self._create_l3_ext_network() as net:
            with self.subnet(network=net) as s:
                with mock.patch.object(
                    nsxlib,
                    'do_request',
                    side_effect=nsx_exc.MaintenanceInProgress):
                    data = {'router': {'tenant_id': 'whatever'}}
                    data['router']['name'] = 'router1'
                    data['router']['external_gateway_info'] = {
                        'network_id': s['subnet']['network_id']}
                    router_req = self.new_create_request(
                        'routers', data, self.fmt)
                    res = router_req.get_response(self.ext_api)
                    self.assertEqual(webob.exc.HTTPServiceUnavailable.code,
                                     res.status_int)

    def test_router_add_interface_port_removes_security_group(self):
        with self.router() as r:
            with self.port(do_delete=False) as p:
                body = self._router_interface_action('add',
                                                     r['router']['id'],
                                                     None,
                                                     p['port']['id'])
                self.assertIn('port_id', body)
                self.assertEqual(body['port_id'], p['port']['id'])

                # fetch port and confirm no security-group on it.
                body = self._show('ports', p['port']['id'])
                self.assertEqual(body['port']['security_groups'], [])
                self.assertFalse(body['port']['port_security_enabled'])
                # clean-up
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              None,
                                              p['port']['id'])

    def test_update_subnet_gateway_for_external_net(self):
        plugin = directory.get_plugin()
        port_mock = {'uuid': uuidutils.generate_uuid()}
        with mock.patch.object(plugin, '_find_router_gw_port',
                               return_value=port_mock):
            super(TestL3NatTestCase,
                  self).test_update_subnet_gateway_for_external_net()

    def test_floatingip_update_to_same_port_id_twice(self):
        self.skipTest('Plugin changes floating port status')

    def test_floating_port_status_not_applicable(self):
        self.skipTest('Plugin changes floating port status')

    def test_create_router_gateway_fails(self):
        self.skipTest('not supported')

    def test_first_floatingip_associate_notification(self):
        self.skipTest('not supported')

    def test_floatingip_disassociate_notification(self):
        self.skipTest('not supported')

    def test_metadata_network_with_update_subnet_dhcp_enable(self):
        self.skipTest('not supported')

    def test_metadata_network_with_update_subnet_dhcp_disable(self):
        self.skipTest('not supported')

    def test_floatingip_via_router_interface_returns_404(self):
        self.skipTest('not supported')

    def test_floatingip_via_router_interface_returns_201(self):
        self.skipTest('not supported')

    def test_floatingip_update_subnet_gateway_disabled(self):
        self.skipTest('not supported')

    def test__notify_gateway_port_ip_changed(self):
        self.skipTest('not supported')


class ExtGwModeTestCase(NsxPluginV2TestCase,
                        test_ext_gw_mode.ExtGwModeIntTestCase):
    def test_router_gateway_set_fail_after_port_create(self):
        self.skipTest("TBD")


class NeutronNsxOutOfSync(NsxPluginV2TestCase,
                          test_l3_plugin.L3NatTestCaseMixin,
                          ext_sg.SecurityGroupsTestCase):

    def setUp(self):
        super(NeutronNsxOutOfSync, self).setUp(
            ext_mgr=TestL3SecGrpExtensionManager())

    def test_delete_network_not_in_nsx(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        self.fc._fake_lswitch_dict.clear()
        req = self.new_delete_request('networks', net1['network']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)

    def test_show_network_not_in_nsx(self):
        res = self._create_network('json', 'net1', True)
        net = self.deserialize('json', res)
        self.fc._fake_lswitch_dict.clear()
        req = self.new_show_request('networks', net['network']['id'],
                                    fields=['id', 'status'])
        net = self.deserialize('json', req.get_response(self.api))
        self.assertEqual(net['network']['status'],
                         constants.NET_STATUS_ERROR)

    def test_delete_port_not_in_nsx(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        res = self._create_port('json', net1['network']['id'])
        port = self.deserialize('json', res)
        self.fc._fake_lswitch_lport_dict.clear()
        req = self.new_delete_request('ports', port['port']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)

    def test_show_port_not_in_nsx(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        res = self._create_port('json', net1['network']['id'])
        port = self.deserialize('json', res)
        self.fc._fake_lswitch_lport_dict.clear()
        self.fc._fake_lswitch_lportstatus_dict.clear()
        req = self.new_show_request('ports', port['port']['id'],
                                    fields=['id', 'status'])
        net = self.deserialize('json', req.get_response(self.api))
        self.assertEqual(net['port']['status'],
                         constants.PORT_STATUS_ERROR)

    def test_create_port_on_network_not_in_nsx(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        self.fc._fake_lswitch_dict.clear()
        res = self._create_port('json', net1['network']['id'])
        port = self.deserialize('json', res)
        self.assertEqual(port['port']['status'], constants.PORT_STATUS_ERROR)

    def test_update_port_not_in_nsx(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        res = self._create_port('json', net1['network']['id'])
        port = self.deserialize('json', res)
        self.fc._fake_lswitch_lport_dict.clear()
        data = {'port': {'name': 'error_port'}}
        req = self.new_update_request('ports', data, port['port']['id'])
        port = self.deserialize('json', req.get_response(self.api))
        self.assertEqual(port['port']['status'], constants.PORT_STATUS_ERROR)
        self.assertEqual(port['port']['name'], 'error_port')

    def test_delete_port_and_network_not_in_nsx(self):
        res = self._create_network('json', 'net1', True)
        net1 = self.deserialize('json', res)
        res = self._create_port('json', net1['network']['id'])
        port = self.deserialize('json', res)
        self.fc._fake_lswitch_dict.clear()
        self.fc._fake_lswitch_lport_dict.clear()
        req = self.new_delete_request('ports', port['port']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)
        req = self.new_delete_request('networks', net1['network']['id'])
        res = req.get_response(self.api)
        self.assertEqual(res.status_int, 204)

    def test_delete_router_not_in_nsx(self):
        res = self._create_router('json', 'tenant')
        router = self.deserialize('json', res)
        self.fc._fake_lrouter_dict.clear()
        req = self.new_delete_request('routers', router['router']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 204)

    def test_show_router_not_in_nsx(self):
        res = self._create_router('json', 'tenant')
        router = self.deserialize('json', res)
        self.fc._fake_lrouter_dict.clear()
        req = self.new_show_request('routers', router['router']['id'],
                                    fields=['id', 'status'])
        router = self.deserialize('json', req.get_response(self.ext_api))
        self.assertEqual(router['router']['status'],
                         constants.NET_STATUS_ERROR)

    def _create_network_and_subnet(self, cidr, external=False):
        net_res = self._create_network('json', 'ext_net', True)
        net = self.deserialize('json', net_res)
        net_id = net['network']['id']
        if external:
            self._update('networks', net_id,
                         {'network': {extnet_apidef.EXTERNAL: True}})
        sub_res = self._create_subnet('json', net_id, cidr)
        sub = self.deserialize('json', sub_res)
        return net_id, sub['subnet']['id']

    def test_clear_gateway_nat_rule_not_in_nsx(self):
        # Create external network and subnet
        ext_net_id = self._create_network_and_subnet('1.1.1.0/24', True)[0]
        # Create internal network and subnet
        int_sub_id = self._create_network_and_subnet('10.0.0.0/24')[1]
        res = self._create_router('json', 'tenant')
        router = self.deserialize('json', res)
        # Add interface to router (needed to generate NAT rule)
        req = self.new_action_request(
            'routers',
            {'subnet_id': int_sub_id},
            router['router']['id'],
            "add_router_interface")
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 200)
        # Set gateway for router
        req = self.new_update_request(
            'routers',
            {'router': {'external_gateway_info':
                        {'network_id': ext_net_id}}},
            router['router']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 200)
        # Delete NAT rule from NSX, clear gateway
        # and verify operation still succeeds
        self.fc._fake_lrouter_nat_dict.clear()
        req = self.new_update_request(
            'routers',
            {'router': {'external_gateway_info': {}}},
            router['router']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 200)

    def _test_remove_router_interface_nsx_out_of_sync(self, unsync_action):
        # Create external network and subnet
        ext_net_id = self._create_network_and_subnet('1.1.1.0/24', True)[0]
        # Create internal network and subnet
        int_sub_id = self._create_network_and_subnet('10.0.0.0/24')[1]
        res = self._create_router('json', 'tenant')
        router = self.deserialize('json', res)
        # Set gateway and add interface to router (needed to generate NAT rule)
        req = self.new_update_request(
            'routers',
            {'router': {'external_gateway_info':
                        {'network_id': ext_net_id}}},
            router['router']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 200)
        req = self.new_action_request(
            'routers',
            {'subnet_id': int_sub_id},
            router['router']['id'],
            "add_router_interface")
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 200)
        unsync_action()
        req = self.new_action_request(
            'routers',
            {'subnet_id': int_sub_id},
            router['router']['id'],
            "remove_router_interface")
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 200)

    def test_remove_router_interface_not_in_nsx(self):

        def unsync_action():
            self.fc._fake_lrouter_dict.clear()
            self.fc._fake_lrouter_nat_dict.clear()

        self._test_remove_router_interface_nsx_out_of_sync(unsync_action)

    def test_remove_router_interface_nat_rule_not_in_nsx(self):
        self._test_remove_router_interface_nsx_out_of_sync(
            self.fc._fake_lrouter_nat_dict.clear)

    def test_remove_router_interface_duplicate_nat_rules_in_nsx(self):

        def unsync_action():
            # duplicate every entry in the nat rule dict
            tmp = copy.deepcopy(self.fc._fake_lrouter_nat_dict)
            for (_rule_id, rule) in tmp.items():
                _uuid = uuidutils.generate_uuid()
                self.fc._fake_lrouter_nat_dict[_uuid] = rule

        self._test_remove_router_interface_nsx_out_of_sync(unsync_action)

    def test_update_router_not_in_nsx(self):
        res = self._create_router('json', 'tenant')
        router = self.deserialize('json', res)
        self.fc._fake_lrouter_dict.clear()
        req = self.new_update_request(
            'routers',
            {'router': {'name': 'goo'}},
            router['router']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 500)
        req = self.new_show_request('routers', router['router']['id'])
        router = self.deserialize('json', req.get_response(self.ext_api))
        self.assertEqual(router['router']['status'],
                         constants.NET_STATUS_ERROR)


class DHCPOptsTestCase(test_dhcpopts.TestExtraDhcpOpt, NsxPluginV2TestCase):

    def setUp(self, plugin=None):
        super(test_dhcpopts.ExtraDhcpOptDBTestCase, self).setUp(
            plugin=vmware.PLUGIN_NAME)
