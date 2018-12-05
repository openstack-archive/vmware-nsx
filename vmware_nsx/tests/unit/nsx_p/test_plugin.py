# Copyright (c) 2018 OpenStack Foundation.
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
from oslo_utils import uuidutils
from webob import exc

from neutron.extensions import securitygroup as secgrp
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from neutron.tests.unit.extensions import test_securitygroup

from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.plugins import directory

from vmware_nsx.common import utils
from vmware_nsx.tests.unit.common_plugin import common_v3
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import nsx_constants

PLUGIN_NAME = 'vmware_nsx.plugin.NsxPolicyPlugin'
NSX_OVERLAY_TZ_NAME = 'OVERLAY_TZ'
NSX_VLAN_TZ_NAME = 'VLAN_TZ'
DEFAULT_TIER0_ROUTER_UUID = "efad0078-9204-4b46-a2d8-d4dd31ed448f"


def _return_id_key(*args, **kwargs):
    return {'id': uuidutils.generate_uuid()}


def _return_id_key_list(*args, **kwargs):
    return [{'id': uuidutils.generate_uuid()}]


class NsxPPluginTestCaseMixin(
    test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self, plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None, **kwargs):

        self._mock_nsx_policy_backend_calls()
        self.setup_conf_overrides()
        super(NsxPPluginTestCaseMixin, self).setUp(plugin=plugin,
                                                   ext_mgr=ext_mgr)

    def _mock_nsx_policy_backend_calls(self):
        resource_list_result = {'results': [{'id': 'test',
                                             'display_name': 'test'}]}
        mock.patch(
            "vmware_nsxlib.v3.NsxPolicyLib.get_version",
            return_value=nsx_constants.NSX_VERSION_2_4_0).start()
        mock.patch(
            "vmware_nsxlib.v3.client.RESTClient.get").start()
        mock.patch(
            "vmware_nsxlib.v3.client.RESTClient.list",
            return_value=resource_list_result).start()
        mock.patch(
            "vmware_nsxlib.v3.client.RESTClient.patch").start()
        mock.patch(
            "vmware_nsxlib.v3.client.RESTClient.delete").start()
        mock.patch("vmware_nsxlib.v3.policy_resources."
                   "NsxPolicyCommunicationMapApi._get_last_seq_num",
                   return_value=-1).start()

    def setup_conf_overrides(self):
        cfg.CONF.set_override('default_overlay_tz', NSX_OVERLAY_TZ_NAME,
                              'nsx_p')
        cfg.CONF.set_override('default_vlan_tz', NSX_VLAN_TZ_NAME, 'nsx_p')

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


class NsxPTestNetworks(test_db_base_plugin_v2.TestNetworksV2,
                       NsxPPluginTestCaseMixin):

    def setUp(self, plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(NsxPTestNetworks, self).setUp(plugin=plugin,
                                            ext_mgr=ext_mgr)

    def tearDown(self):
        super(NsxPTestNetworks, self).tearDown()

    def test_create_provider_flat_network(self):
        providernet_args = {pnet.NETWORK_TYPE: 'flat'}
        with mock.patch('vmware_nsxlib.v3.policy_resources.'
                        'NsxPolicySegmentApi.create_or_overwrite',
                        side_effect=_return_id_key) as nsx_create, \
            mock.patch('vmware_nsxlib.v3.policy_resources.NsxPolicySegmentApi.'
                       'delete') as nsx_delete, \
            mock.patch('vmware_nsxlib.v3.policy_resources.'
                       'NsxPolicyTransportZoneApi.get_transport_type',
                       return_value=nsx_constants.TRANSPORT_TYPE_VLAN), \
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
        physical_network = DEFAULT_TIER0_ROUTER_UUID
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: physical_network}
        with mock.patch(
            'vmware_nsxlib.v3.policy_resources.NsxPolicyTransportZoneApi.'
            'get_transport_type',
            return_value=nsx_constants.TRANSPORT_TYPE_VLAN), \
            self.network(name='flat_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE,
                                   pnet.PHYSICAL_NETWORK)) as net:
            self.assertEqual('flat', net['network'].get(pnet.NETWORK_TYPE))

    def test_create_provider_flat_network_with_vlan(self):
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.SEGMENTATION_ID: 11}
        with mock.patch(
            'vmware_nsxlib.v3.policy_resources.NsxPolicyTransportZoneApi.'
            'get_transport_type',
            return_value=nsx_constants.TRANSPORT_TYPE_VLAN):
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
        with mock.patch('vmware_nsxlib.v3.policy_resources.'
                        'NsxPolicySegmentApi.create_or_overwrite',
                        side_effect=_return_id_key) as nsx_create, \
            mock.patch('vmware_nsxlib.v3.policy_resources.NsxPolicySegmentApi.'
                       'delete') as nsx_delete, \
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
        physical_network = DEFAULT_TIER0_ROUTER_UUID
        providernet_args = {pnet.NETWORK_TYPE: 'geneve',
                            pnet.PHYSICAL_NETWORK: physical_network}
        with mock.patch(
            'vmware_nsxlib.v3.policy_resources.NsxPolicyTransportZoneApi.'
            'get_transport_type',
            return_value=nsx_constants.TRANSPORT_TYPE_OVERLAY),\
            self.network(name='geneve_net',
                         providernet_args=providernet_args,
                         arg_list=(pnet.NETWORK_TYPE, )) as net:
            self.assertEqual('geneve', net['network'].get(pnet.NETWORK_TYPE))

    def test_create_provider_geneve_network_with_vlan(self):
        providernet_args = {pnet.NETWORK_TYPE: 'geneve',
                            pnet.SEGMENTATION_ID: 11}
        with mock.patch(
            'vmware_nsxlib.v3.policy_resources.NsxPolicyTransportZoneApi.'
            'get_transport_type',
            return_value=nsx_constants.TRANSPORT_TYPE_OVERLAY):
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
        with mock.patch('vmware_nsxlib.v3.policy_resources.'
                        'NsxPolicySegmentApi.create_or_overwrite',
                        side_effect=_return_id_key) as nsx_create, \
            mock.patch('vmware_nsxlib.v3.policy_resources.NsxPolicySegmentApi.'
                       'delete') as nsx_delete, \
            mock.patch('vmware_nsxlib.v3.policy_resources.'
                       'NsxPolicyTransportZoneApi.get_transport_type',
                       return_value=nsx_constants.TRANSPORT_TYPE_VLAN), \
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
            'vmware_nsxlib.v3.policy_resources.NsxPolicySegmentApi.'
            'create_or_overwrite',
            side_effect=nsxlib_exc.ResourceNotFound) as nsx_create, \
            mock.patch('vmware_nsxlib.v3.policy_resources.NsxPolicySegmentApi.'
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
            "vmware_nsxlib.v3.policy_resources.NsxPolicySegmentApi.get",
            side_effect=nsxlib_exc.ResourceNotFound):
            result = self._create_network(fmt='json', name='bad_nsx_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(pnet.NETWORK_TYPE,
                                                    pnet.PHYSICAL_NETWORK))
            data = self.deserialize('json', result)
            # should fail
            self.assertEqual('InvalidInput', data['NeutronError']['type'])

    def test_create_transparent_vlan_network(self):
        providernet_args = {vlan_apidef.VLANTRANSPARENT: True}
        with mock.patch('vmware_nsxlib.v3.policy_resources.'
                        'NsxPolicyTransportZoneApi.get_transport_type',
                        return_value=nsx_constants.TRANSPORT_TYPE_OVERLAY), \
            self.network(name='vt_net',
                         providernet_args=providernet_args,
                         arg_list=(vlan_apidef.VLANTRANSPARENT, )) as net:
            self.assertTrue(net['network'].get(vlan_apidef.VLANTRANSPARENT))

    def test_create_provider_vlan_network_with_transparent(self):
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            vlan_apidef.VLANTRANSPARENT: True}
        with mock.patch('vmware_nsxlib.v3.policy_resources.'
                        'NsxPolicyTransportZoneApi.get_transport_type',
                        return_value=nsx_constants.TRANSPORT_TYPE_VLAN):
            result = self._create_network(fmt='json', name='badvlan_net',
                                          admin_state_up=True,
                                          providernet_args=providernet_args,
                                          arg_list=(
                                              pnet.NETWORK_TYPE,
                                              pnet.SEGMENTATION_ID,
                                              vlan_apidef.VLANTRANSPARENT))
            data = self.deserialize('json', result)
            self.assertEqual('vlan', data['network'].get(pnet.NETWORK_TYPE))

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


class NsxPTestPorts(test_db_base_plugin_v2.TestPortsV2,
                    NsxPPluginTestCaseMixin):
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

    def test_update_port_add_additional_ip(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

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


class NsxPTestSecurityGroup(NsxPPluginTestCaseMixin,
                            test_securitygroup.TestSecurityGroups,
                            test_securitygroup.SecurityGroupDBTestCase):

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None):
        super(NsxPTestSecurityGroup, self).setUp(plugin=plugin,
                                                 ext_mgr=ext_mgr)

    def test_create_security_group_rule_icmp_with_type_and_code(self):
        """No non-zero icmp codes are currently supported by the NSX"""
        self.skipTest('not supported')

    def test_create_security_group_rule_icmp_with_type(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            remote_ip_prefix = "10.0.0.0/24"
            protocol = "icmp"
            # port_range_min (ICMP type) is greater than port_range_max
            # (ICMP code) in order to confirm min <= max port check is
            # not called for ICMP.
            port_range_min = 14
            port_range_max = None
            keys = [('remote_ip_prefix', remote_ip_prefix),
                    ('security_group_id', security_group_id),
                    ('direction', direction),
                    ('protocol', protocol),
                    ('port_range_min', port_range_min),
                    ('port_range_max', port_range_max)]
            with self.security_group_rule(security_group_id, direction,
                                          protocol, port_range_min,
                                          port_range_max,
                                          remote_ip_prefix) as rule:
                for k, v, in keys:
                    self.assertEqual(rule['security_group_rule'][k], v)

    def _test_create_direct_network(self, vlan_id=0):
        net_type = vlan_id and 'vlan' or 'flat'
        name = 'direct_net'
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: 'tzuuid'}
        if vlan_id:
            providernet_args[pnet.SEGMENTATION_ID] = vlan_id

        mock_tt = mock.patch('vmware_nsxlib.v3'
                             '.policy_resources.NsxPolicyTransportZoneApi'
                             '.get_transport_type',
                             return_value=nsx_constants.TRANSPORT_TYPE_VLAN)
        mock_tt.start()
        return self.network(name=name,
                            providernet_args=providernet_args,
                            arg_list=(pnet.NETWORK_TYPE,
                                      pnet.PHYSICAL_NETWORK,
                                      pnet.SEGMENTATION_ID))

    def _test_create_port_vnic_direct(self, vlan_id):
        with mock.patch('vmware_nsxlib.v3.policy_resources.'
                        'NsxPolicyTransportZoneApi.get_transport_type',
                        return_value=nsx_constants.TRANSPORT_TYPE_VLAN),\
            self._test_create_direct_network(vlan_id=vlan_id) as network:
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


class TestL3NatTestCase(common_v3.FixExternalNetBaseTest,
                        NsxPPluginTestCaseMixin,
                        test_l3_plugin.L3NatDBIntTestCase):

    # TODO(asarfaty): also add the tests from:
    # test_l3_plugin.L3BaseForIntTests
    # test_address_scope.AddressScopeTestCase
    # test_ext_route.ExtraRouteDBTestCaseBase
    def setUp(self, *args, **kwargs):
        super(TestL3NatTestCase, self).setUp(*args, **kwargs)
        self.original_subnet = self.subnet
        self.original_network = self.network

        self.plugin_instance = directory.get_plugin()
        self._plugin_name = "%s.%s" % (
            self.plugin_instance.__module__,
            self.plugin_instance.__class__.__name__)
        self._plugin_class = self.plugin_instance.__class__

    def external_network(self, name='net1',
                         admin_state_up=True,
                         fmt=None, **kwargs):
        if not name:
            name = 'l3_ext_net'
        physical_network = 'abc'
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

    def _create_l3_ext_network(self, physical_network='abc'):
        name = 'l3_ext_net'
        net_type = utils.NetworkTypes.L3_EXT
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: physical_network}
        return self.network(name=name,
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

    def test__notify_gateway_port_ip_changed(self):
        self.skipTest('not supported')

    def test__notify_gateway_port_ip_not_changed(self):
        self.skipTest('not supported')

    def test_floatingip_via_router_interface_returns_201(self):
        self.skipTest('not supported')

    def test_floatingip_via_router_interface_returns_404(self):
        self.skipTest('not supported')

    def test_network_update_external(self):
        # This plugin does not support updating the external flag of a network
        self.skipTest('not supported')

    def test_network_update_external_failure(self):
        # This plugin does not support updating the external flag of a network
        self.skipTest('not supported')

    def test_router_add_gateway_dup_subnet1_returns_400(self):
        self.skipTest('not supported')

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

    def test_floatingip_update_to_same_port_id_twice(self):
        self.skipTest('Plugin changes floating port status')

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

    def test_router_add_gateway_no_subnet(self):
        self.skipTest('No support for no subnet gateway set')

    def test_create_router_gateway_fails(self):
        self.skipTest('not supported')

    def test_router_remove_ipv6_subnet_from_interface(self):
        self.skipTest('not supported')

    def test_router_add_interface_multiple_ipv6_subnets_same_net(self):
        self.skipTest('not supported')

    def test_router_add_interface_multiple_ipv4_subnets(self):
        self.skipTest('not supported')

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
        super(TestL3NatTestCase,
              self).test_router_update_gateway_with_existed_floatingip()

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

    @common_v3.with_external_network
    def test_router_update_gateway_upon_subnet_create_max_ips_ipv6(self):
        super(
            TestL3NatTestCase,
            self).test_router_update_gateway_upon_subnet_create_max_ips_ipv6()

    @common_v3.with_external_subnet_second_time
    def test_router_add_interface_cidr_overlapped_with_gateway(self):
        super(TestL3NatTestCase,
              self).test_router_add_interface_cidr_overlapped_with_gateway()

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

    @common_v3.with_external_subnet_second_time
    def test_router_add_interface_by_port_cidr_overlapped_with_gateway(self):
        super(TestL3NatTestCase, self).\
            test_router_add_interface_by_port_cidr_overlapped_with_gateway()

    @common_v3.with_external_network
    def test_router_add_gateway_multiple_subnets_ipv6(self):
        super(TestL3NatTestCase,
              self).test_router_add_gateway_multiple_subnets_ipv6()

    @common_v3.with_external_subnet
    def test_router_add_and_remove_gateway(self):
        super(TestL3NatTestCase,
              self).test_router_add_and_remove_gateway()

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

    def test_floatingip_update(self):
        super(TestL3NatTestCase, self).test_floatingip_update(
            expected_status=constants.FLOATINGIP_STATUS_DOWN)

    @common_v3.with_external_subnet_second_time
    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)

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

    def test_router_add_gateway_no_subnet_forbidden(self):
        with self.router() as r:
            with self._create_l3_ext_network() as n:
                self._add_external_gateway_to_router(
                    r['router']['id'], n['network']['id'],
                    expected_code=exc.HTTPBadRequest.code)
