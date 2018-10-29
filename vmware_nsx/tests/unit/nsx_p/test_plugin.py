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

from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_securitygroup

from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from neutron_lib import context

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

    # Temporarily skip all port related tests until the plugin supports it
    def test_update_port_with_security_group(self):
        self.skipTest('Temporarily not supported')
