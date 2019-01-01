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

from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.extensions import securitygroup as secgrp
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory

from vmware_nsx.common import config
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.extensions import advancedserviceproviders as as_providers
from vmware_nsx.plugins.nsx_v3 import availability_zones as nsx_az
from vmware_nsx.tests.unit.nsx_v3 import test_plugin
from vmware_nsxlib.v3 import core_resources
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import resources as nsx_resources


def set_az_in_config(name, metadata_proxy="metadata_proxy1",
                     dhcp_profile="dhcp_profile1",
                     native_metadata_route="2.2.2.2",
                     dns_domain='aaaa',
                     nameservers=['bbbb']):
    group_name = 'az:%s' % name
    cfg.CONF.set_override('availability_zones', [name], group="nsx_v3")
    config.register_nsxv3_azs(cfg.CONF, [name])
    cfg.CONF.set_override("metadata_proxy", metadata_proxy,
                          group=group_name)
    cfg.CONF.set_override("dhcp_profile", dhcp_profile,
                          group=group_name)
    cfg.CONF.set_override("native_metadata_route", native_metadata_route,
                          group=group_name)
    cfg.CONF.set_override("dns_domain", dns_domain,
                          group=group_name)
    cfg.CONF.set_override("nameservers", nameservers,
                          group=group_name)


class NsxNativeDhcpTestCase(test_plugin.NsxV3PluginTestCaseMixin):

    def setUp(self):
        super(NsxNativeDhcpTestCase, self).setUp()
        self._orig_dhcp_agent_notification = cfg.CONF.dhcp_agent_notification
        self._orig_native_dhcp_metadata = cfg.CONF.nsx_v3.native_dhcp_metadata
        cfg.CONF.set_override('dhcp_agent_notification', False)
        cfg.CONF.set_override('native_dhcp_metadata', True, 'nsx_v3')
        self._az_name = 'zone1'
        self.az_metadata_route = '3.3.3.3'
        set_az_in_config(self._az_name,
                         native_metadata_route=self.az_metadata_route)
        self._patcher = mock.patch.object(core_resources.NsxLibDhcpProfile,
                                          'get')
        self._patcher.start()
        # Need to run some plugin init methods manually because plugin was
        # started before setUp() overrides CONF.nsx_v3.native_dhcp_metadata.
        self._initialize_azs()
        self.plugin._init_dhcp_metadata()

    def tearDown(self):
        self._patcher.stop()
        cfg.CONF.set_override('dhcp_agent_notification',
                              self._orig_dhcp_agent_notification)
        cfg.CONF.set_override('native_dhcp_metadata',
                              self._orig_native_dhcp_metadata, 'nsx_v3')
        super(NsxNativeDhcpTestCase, self).tearDown()

    def _make_subnet_data(self,
                          name=None,
                          network_id=None,
                          cidr=None,
                          gateway_ip=None,
                          tenant_id=None,
                          allocation_pools=None,
                          enable_dhcp=True,
                          dns_nameservers=None,
                          ip_version=4,
                          host_routes=None,
                          shared=False):
        return {'subnet': {
            'name': name,
            'network_id': network_id,
            'cidr': cidr,
            'gateway_ip': gateway_ip,
            'tenant_id': tenant_id,
            'allocation_pools': allocation_pools,
            'ip_version': ip_version,
            'enable_dhcp': enable_dhcp,
            'dns_nameservers': dns_nameservers,
            'host_routes': host_routes,
            'shared': shared}}

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

        with mock.patch(
            'vmware_nsxlib.v3.resources.LogicalDhcpServer.update_binding'
        ) as update_dhcp_binding:
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
        # Test if dhcp_agent_notification and dhcp_profile are
        # configured correctly.
        orig_dhcp_agent_notification = cfg.CONF.dhcp_agent_notification
        cfg.CONF.set_override('dhcp_agent_notification', True)
        self.assertRaises(nsx_exc.NsxPluginException,
                          self.plugin._init_dhcp_metadata)
        cfg.CONF.set_override('dhcp_agent_notification',
                              orig_dhcp_agent_notification)
        orig_dhcp_profile_uuid = cfg.CONF.nsx_v3.dhcp_profile
        cfg.CONF.set_override('dhcp_profile', '', 'nsx_v3')
        self.assertRaises(cfg.RequiredOptError,
                          self.plugin._translate_configured_names_to_uuids)
        cfg.CONF.set_override('dhcp_profile', orig_dhcp_profile_uuid,
                              'nsx_v3')

    def test_dhcp_service_with_create_network(self):
        # Test if DHCP service is disabled on a network when it is created.
        with self.network() as network:
            self._verify_dhcp_service(network['network']['id'],
                                      network['network']['tenant_id'], False)

    def test_dhcp_service_with_delete_dhcp_network(self):
        # Test if DHCP service is disabled when directly deleting a network
        # with a DHCP-enabled subnet.
        with self.network() as network:
            with self.subnet(network=network, enable_dhcp=True):
                self.plugin.delete_network(context.get_admin_context(),
                                           network['network']['id'])
                self._verify_dhcp_service(network['network']['id'],
                                          network['network']['tenant_id'],
                                          False)

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

    def test_dhcp_service_with_create_dhcp_subnet_bulk(self):
        # Test if DHCP service is enabled on all networks after a
        # create_subnet_bulk operation.
        with self.network() as network1, self.network() as network2:
            subnet1 = self._make_subnet_data(
                network_id=network1['network']['id'], cidr='10.0.0.0/24',
                tenant_id=network1['network']['tenant_id'])
            subnet2 = self._make_subnet_data(
                network_id=network2['network']['id'], cidr='20.0.0.0/24',
                tenant_id=network2['network']['tenant_id'])
            subnets = {'subnets': [subnet1, subnet2]}

            with mock.patch.object(self.plugin, '_post_create_subnet'
                                   ) as post_create_subnet:
                self.plugin.create_subnet_bulk(
                    context.get_admin_context(), subnets)
                # Check if post_create function has been called for
                # both subnets.
                self.assertEqual(len(subnets['subnets']),
                                 post_create_subnet.call_count)

            # Check if the bindings to backend DHCP entries are created.
            dhcp_service = nsx_db.get_nsx_service_binding(
                context.get_admin_context().session,
                network1['network']['id'], nsx_constants.SERVICE_DHCP)
            self.assertTrue(dhcp_service)
            dhcp_service = nsx_db.get_nsx_service_binding(
                context.get_admin_context().session,
                network2['network']['id'], nsx_constants.SERVICE_DHCP)
            self.assertTrue(dhcp_service)

    def test_dhcp_service_with_create_dhcp_subnet_bulk_failure(self):
        # Test if user-provided rollback function is invoked when
        # exception occurred during a create_subnet_bulk operation.
        with self.network() as network1, self.network() as network2:
            subnet1 = self._make_subnet_data(
                network_id=network1['network']['id'], cidr='10.0.0.0/24',
                tenant_id=network1['network']['tenant_id'])
            subnet2 = self._make_subnet_data(
                network_id=network2['network']['id'], cidr='20.0.0.0/24',
                tenant_id=network2['network']['tenant_id'])
            subnets = {'subnets': [subnet1, subnet2]}

            # Inject an exception on the second create_subnet call.
            orig_create_subnet = self.plugin.create_subnet
            with mock.patch.object(self.plugin,
                                   'create_subnet') as create_subnet:
                def side_effect(*args, **kwargs):
                    return self._fail_second_call(
                        create_subnet, orig_create_subnet, *args, **kwargs)
                create_subnet.side_effect = side_effect

                with mock.patch.object(self.plugin,
                                       '_rollback_subnet') as rollback_subnet:
                    try:
                        self.plugin.create_subnet_bulk(
                            context.get_admin_context(), subnets)
                    except Exception:
                        pass
                    # Check if rollback function has been called for
                    # the subnet in the first network.
                    rollback_subnet.assert_called_once_with(mock.ANY, mock.ANY)
                    subnet_arg = rollback_subnet.call_args[0][0]
                    self.assertEqual(network1['network']['id'],
                                     subnet_arg['network_id'])

                # Check if the bindings to backend DHCP entries are removed.
                dhcp_service = nsx_db.get_nsx_service_binding(
                    context.get_admin_context().session,
                    network1['network']['id'], nsx_constants.SERVICE_DHCP)
                self.assertFalse(dhcp_service)
                dhcp_service = nsx_db.get_nsx_service_binding(
                    context.get_admin_context().session,
                    network2['network']['id'], nsx_constants.SERVICE_DHCP)
                self.assertFalse(dhcp_service)

    def test_dhcp_service_with_create_dhcp_subnet_in_vlan_network(self):
        # Test if a DHCP-enabled subnet cannot be created in a vlan network.
        # on nsx version that does not support it
        povidernet_args = {pnet.NETWORK_TYPE: 'vlan',
                           pnet.PHYSICAL_NETWORK: 'tzuuid',
                           pnet.SEGMENTATION_ID: 100}
        with mock.patch(
            'vmware_nsxlib.v3.core_resources.NsxLibTransportZone.'
            'get_transport_type', return_value='VLAN'),\
            mock.patch.object(self.plugin.nsxlib, 'feature_supported',
                              return_value=False),\
            self.network(providernet_args=povidernet_args,
                         arg_list=(pnet.NETWORK_TYPE,
                                   pnet.PHYSICAL_NETWORK,
                                   pnet.SEGMENTATION_ID)) as network:
            subnet = {'subnet': {'network_id': network['network']['id'],
                                 'cidr': '10.0.0.0/24',
                                 'enable_dhcp': True}}
            self.assertRaises(
                n_exc.InvalidInput, self.plugin.create_subnet,
                context.get_admin_context(), subnet)

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
                                          network['network']['tenant_id'],
                                          False)
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
                        {'network': '%s' %
                         cfg.CONF.nsx_v3.native_metadata_route,
                         'next_hop': '0.0.0.0'},
                        {'network': '%s' %
                         cfg.CONF.nsx_v3.native_metadata_route,
                         'next_hop': ip},
                        {'network': subnet['subnet']['cidr'],
                         'next_hop': '0.0.0.0'},
                        {'network': '0.0.0.0/0',
                         'next_hop': subnet['subnet']['gateway_ip']}]}}
                    create_dhcp_binding.assert_called_once_with(
                        dhcp_service['nsx_service_id'],
                        port['port']['mac_address'], ip, hostname,
                        cfg.CONF.nsx_v3.dhcp_lease_time, options,
                        subnet['subnet']['gateway_ip'])

    def test_dhcp_binding_with_create_port_with_opts(self):
        # Test if DHCP binding is added when a compute port is created
        # with extra options.
        opt_name = 'interface-mtu'
        opt_code = 26
        opt_val = '9000'
        with mock.patch.object(nsx_resources.LogicalDhcpServer,
                               'create_binding',
                               return_value={"id": uuidutils.generate_uuid()}
                               ) as create_dhcp_binding:
            with self.subnet(enable_dhcp=True) as subnet:
                device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
                device_id = uuidutils.generate_uuid()
                extra_dhcp_opts = [{'opt_name': opt_name,
                                    'opt_value': opt_val}]
                with self.port(subnet=subnet, device_owner=device_owner,
                               device_id=device_id,
                               extra_dhcp_opts=extra_dhcp_opts,
                               arg_list=('extra_dhcp_opts',)) as port:
                    dhcp_service = nsx_db.get_nsx_service_binding(
                        context.get_admin_context().session,
                        subnet['subnet']['network_id'],
                        nsx_constants.SERVICE_DHCP)
                    ip = port['port']['fixed_ips'][0]['ip_address']
                    hostname = 'host-%s' % ip.replace('.', '-')
                    options = {'option121': {'static_routes': [
                        {'network': '%s' %
                         cfg.CONF.nsx_v3.native_metadata_route,
                         'next_hop': '0.0.0.0'},
                        {'network': '%s' %
                         cfg.CONF.nsx_v3.native_metadata_route,
                         'next_hop': ip},
                        {'network': subnet['subnet']['cidr'],
                         'next_hop': '0.0.0.0'},
                        {'network': '0.0.0.0/0',
                         'next_hop': subnet['subnet']['gateway_ip']}]},
                        'others': [{'code': opt_code, 'values': [opt_val]}]}
                    create_dhcp_binding.assert_called_once_with(
                        dhcp_service['nsx_service_id'],
                        port['port']['mac_address'], ip, hostname,
                        cfg.CONF.nsx_v3.dhcp_lease_time, options,
                        subnet['subnet']['gateway_ip'])

    def test_dhcp_binding_with_create_port_with_opts121(self):
        # Test if DHCP binding is added when a compute port is created
        # with extra option121.
        with mock.patch.object(nsx_resources.LogicalDhcpServer,
                               'create_binding',
                               return_value={"id": uuidutils.generate_uuid()}
                               ) as create_dhcp_binding:
            with self.subnet(enable_dhcp=True) as subnet:
                device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
                device_id = uuidutils.generate_uuid()
                extra_dhcp_opts = [{'opt_name': 'classless-static-route',
                                    'opt_value': '1.0.0.0/24,1.2.3.4'}]
                with self.port(subnet=subnet, device_owner=device_owner,
                               device_id=device_id,
                               extra_dhcp_opts=extra_dhcp_opts,
                               arg_list=('extra_dhcp_opts',)) as port:
                    dhcp_service = nsx_db.get_nsx_service_binding(
                        context.get_admin_context().session,
                        subnet['subnet']['network_id'],
                        nsx_constants.SERVICE_DHCP)
                    ip = port['port']['fixed_ips'][0]['ip_address']
                    hostname = 'host-%s' % ip.replace('.', '-')
                    options = {'option121': {'static_routes': [
                        {'network': '%s' %
                         cfg.CONF.nsx_v3.native_metadata_route,
                         'next_hop': '0.0.0.0'},
                        {'network': '%s' %
                         cfg.CONF.nsx_v3.native_metadata_route,
                         'next_hop': ip},
                        {'network': subnet['subnet']['cidr'],
                         'next_hop': '0.0.0.0'},
                        {'network': '0.0.0.0/0',
                         'next_hop': subnet['subnet']['gateway_ip']},
                        {'network': '1.0.0.0/24',
                         'next_hop': '1.2.3.4'}]}}
                    create_dhcp_binding.assert_called_once_with(
                        dhcp_service['nsx_service_id'],
                        port['port']['mac_address'], ip, hostname,
                        cfg.CONF.nsx_v3.dhcp_lease_time, options,
                        subnet['subnet']['gateway_ip'])

    def test_dhcp_binding_with_create_port_with_bad_opts(self):
        with self.subnet(enable_dhcp=True) as subnet:
            device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
            device_id = uuidutils.generate_uuid()
            ctx = context.get_admin_context()

            # Use illegal opt-name
            extra_dhcp_opts = [{'opt_name': 'Dummy',
                                'opt_value': 'Dummy'}]
            data = {'port': {
                'name': 'dummy',
                'network_id': subnet['subnet']['network_id'],
                'tenant_id': subnet['subnet']['tenant_id'],
                'device_owner': device_owner,
                'device_id': device_id,
                'extra_dhcp_opts': extra_dhcp_opts,
                'admin_state_up': True,
                'fixed_ips': [],
                'mac_address': '00:00:00:00:00:01',
            }}
            self.assertRaises(n_exc.InvalidInput,
                self.plugin.create_port, ctx, data)

            # Use illegal option121 value
            extra_dhcp_opts = [{'opt_name': 'classless-static-route',
                                'opt_value': '1.0.0.0/24,5.5.5.5,cc'}]
            data['port']['extra_dhcp_opts'] = extra_dhcp_opts
            self.assertRaises(n_exc.InvalidInput,
                self.plugin.create_port, ctx, data)

    def test_dhcp_binding_with_disable_enable_dhcp(self):
        # Test if DHCP binding is preserved after DHCP is disabled and
        # re-enabled on a subnet.
        with self.subnet(enable_dhcp=True) as subnet:
            device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'None'
            device_id = uuidutils.generate_uuid()
            with self.port(subnet=subnet, device_owner=device_owner,
                           device_id=device_id) as port:
                ip = port['port']['fixed_ips'][0]['ip_address']
                dhcp_bindings = nsx_db.get_nsx_dhcp_bindings(
                    context.get_admin_context().session, port['port']['id'])
                dhcp_service = dhcp_bindings[0]['nsx_service_id']
                self.assertEqual(1, len(dhcp_bindings))
                self.assertEqual(ip, dhcp_bindings[0]['ip_address'])
                # Disable DHCP on subnet.
                data = {'subnet': {'enable_dhcp': False}}
                self.plugin.update_subnet(context.get_admin_context(),
                                          subnet['subnet']['id'], data)
                dhcp_bindings = nsx_db.get_nsx_dhcp_bindings(
                    context.get_admin_context().session, port['port']['id'])
                self.assertEqual([], dhcp_bindings)
                # Re-enable DHCP on subnet.
                data = {'subnet': {'enable_dhcp': True}}
                self.plugin.update_subnet(context.get_admin_context(),
                                          subnet['subnet']['id'], data)
                dhcp_bindings = nsx_db.get_nsx_dhcp_bindings(
                    context.get_admin_context().session, port['port']['id'])
                self.assertEqual(1, len(dhcp_bindings))
                self.assertEqual(ip, dhcp_bindings[0]['ip_address'])
                # The DHCP service ID should be different because a new
                # logical DHCP server is created for re-enabling DHCP.
                self.assertNotEqual(dhcp_service,
                                    dhcp_bindings[0]['nsx_service_id'])

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
                               {'network': '%s' %
                                cfg.CONF.nsx_v3.native_metadata_route,
                                'next_hop': '0.0.0.0'},
                               {'network': '%s' %
                                cfg.CONF.nsx_v3.native_metadata_route,
                                'next_hop': new_ip},
                               {'network': subnet['subnet']['cidr'],
                                'next_hop': '0.0.0.0'},
                               {'network': constants.IPv4_ANY,
                                'next_hop': subnet['subnet']['gateway_ip']}]}}}
            self._verify_dhcp_binding(subnet, port_data, update_data,
                                      assert_data)

    def test_dhcp_binding_with_update_port_mac(self):
        # Test if DHCP binding is updated when the Mac of the associated
        # compute port is changed.
        with self.subnet(enable_dhcp=True) as subnet:
            port_data = {'mac_address': '11:22:33:44:55:66'}
            new_mac = '22:33:44:55:66:77'
            update_data = {'port': {'mac_address': new_mac}}
            assert_data = {'mac_address': new_mac,
                           'options': {'option121': {'static_routes': [
                               {'network': '%s' %
                                cfg.CONF.nsx_v3.native_metadata_route,
                                'next_hop': '0.0.0.0'},
                               {'network': '%s' %
                                cfg.CONF.nsx_v3.native_metadata_route,
                                'next_hop': mock.ANY},
                               {'network': subnet['subnet']['cidr'],
                                'next_hop': '0.0.0.0'},
                               {'network': constants.IPv4_ANY,
                                'next_hop': subnet['subnet']['gateway_ip']}]}}}
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
                               {'network': '%s' %
                                cfg.CONF.nsx_v3.native_metadata_route,
                                'next_hop': '0.0.0.0'},
                               {'network': '%s' %
                                cfg.CONF.nsx_v3.native_metadata_route,
                                'next_hop': new_ip},
                               {'network': subnet['subnet']['cidr'],
                                'next_hop': '0.0.0.0'},
                               {'network': constants.IPv4_ANY,
                                'next_hop': subnet['subnet']['gateway_ip']}]}}}
            self._verify_dhcp_binding(subnet, port_data, update_data,
                                      assert_data)

    def test_update_port_with_update_dhcp_opt(self):
        # Test updating extra-dhcp-opts via port update.
        with self.subnet(cidr='10.0.0.0/24', enable_dhcp=True) as subnet:
            mac_address = '11:22:33:44:55:66'
            ip_addr = '10.0.0.3'
            port_data = {'arg_list': ('extra_dhcp_opts',),
                         'mac_address': mac_address,
                         'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                                        'ip_address': ip_addr}],
                         'extra_dhcp_opts': [
                              {'opt_name': 'interface-mtu',
                               'opt_value': '9000'}]}
            update_data = {'port': {'extra_dhcp_opts': [
                              {'opt_name': 'interface-mtu',
                               'opt_value': '9002'}]}}
            assert_data = {'mac_address': mac_address,
                           'ip_address': ip_addr,
                           'options': {'option121': {'static_routes': [
                               {'network': '%s' %
                                cfg.CONF.nsx_v3.native_metadata_route,
                                'next_hop': '0.0.0.0'},
                               {'network': '%s' %
                                cfg.CONF.nsx_v3.native_metadata_route,
                                'next_hop': ip_addr},
                               {'network': subnet['subnet']['cidr'],
                                'next_hop': '0.0.0.0'},
                               {'network': constants.IPv4_ANY,
                                'next_hop': subnet['subnet']['gateway_ip']}]},
                                'others': [{'code': 26, 'values': ['9002']}]}}
            self._verify_dhcp_binding(subnet, port_data, update_data,
                                      assert_data)

    def test_update_port_with_adding_dhcp_opt(self):
        # Test adding extra-dhcp-opts via port update.
        with self.subnet(cidr='10.0.0.0/24', enable_dhcp=True) as subnet:
            mac_address = '11:22:33:44:55:66'
            ip_addr = '10.0.0.3'
            port_data = {'arg_list': ('extra_dhcp_opts',),
                         'mac_address': mac_address,
                         'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                                        'ip_address': ip_addr}],
                         'extra_dhcp_opts': [
                              {'opt_name': 'nis-domain',
                               'opt_value': 'abc'}]}
            update_data = {'port': {'extra_dhcp_opts': [
                              {'opt_name': 'interface-mtu',
                               'opt_value': '9002'}]}}
            assert_data = {'mac_address': mac_address,
                           'ip_address': ip_addr,
                           'options': {'option121': {'static_routes': [
                               {'network': '%s' %
                                cfg.CONF.nsx_v3.native_metadata_route,
                                'next_hop': '0.0.0.0'},
                               {'network': '%s' %
                                cfg.CONF.nsx_v3.native_metadata_route,
                                'next_hop': ip_addr},
                               {'network': subnet['subnet']['cidr'],
                                'next_hop': '0.0.0.0'},
                               {'network': constants.IPv4_ANY,
                                'next_hop': subnet['subnet']['gateway_ip']}]},
                                'others': [{'code': 26, 'values': ['9002']},
                                           {'code': 40, 'values': ['abc']}]}}
            self._verify_dhcp_binding(subnet, port_data, update_data,
                                      assert_data)

    def test_update_port_with_deleting_dhcp_opt(self):
        # Test adding extra-dhcp-opts via port update.
        with self.subnet(cidr='10.0.0.0/24', enable_dhcp=True) as subnet:
            mac_address = '11:22:33:44:55:66'
            ip_addr = '10.0.0.3'
            port_data = {'arg_list': ('extra_dhcp_opts',),
                         'mac_address': mac_address,
                         'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                                        'ip_address': ip_addr}],
                         'extra_dhcp_opts': [
                              {'opt_name': 'nis-domain',
                               'opt_value': 'abc'},
                              {'opt_name': 'interface-mtu',
                               'opt_value': '9002'}]}
            update_data = {'port': {'extra_dhcp_opts': [
                              {'opt_name': 'interface-mtu',
                               'opt_value': None}]}}
            assert_data = {'mac_address': mac_address,
                           'ip_address': ip_addr,
                           'options': {'option121': {'static_routes': [
                               {'network': '%s' %
                                cfg.CONF.nsx_v3.native_metadata_route,
                                'next_hop': '0.0.0.0'},
                               {'network': '%s' %
                                cfg.CONF.nsx_v3.native_metadata_route,
                                'next_hop': ip_addr},
                               {'network': subnet['subnet']['cidr'],
                                'next_hop': '0.0.0.0'},
                               {'network': constants.IPv4_ANY,
                                'next_hop': subnet['subnet']['gateway_ip']}]},
                                'others': [{'code': 40, 'values': ['abc']}]}}
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

    def test_create_network_with_bad_az_hint(self):
        p = directory.get_plugin()
        ctx = context.get_admin_context()
        data = {'network': {
                'name': 'test-az',
                'tenant_id': self._tenant_id,
                'port_security_enabled': False,
                'admin_state_up': True,
                'shared': False,
                'availability_zone_hints': ['bad_hint']
                }}
        self.assertRaises(n_exc.NeutronException,
                          p.create_network,
                          ctx, data)

    def test_create_network_with_az_hint(self):
        p = directory.get_plugin()
        ctx = context.get_admin_context()

        data = {'network': {
                'name': 'test-az',
                'tenant_id': self._tenant_id,
                'port_security_enabled': False,
                'admin_state_up': True,
                'shared': False,
                'availability_zone_hints': [self._az_name]
                }}

        # network creation should succeed
        net = p.create_network(ctx, data)
        self.assertEqual([self._az_name],
                         net['availability_zone_hints'])
        self.assertEqual([self._az_name],
                         net['availability_zones'])

    def test_create_network_with_no_az_hint(self):
        p = directory.get_plugin()
        ctx = context.get_admin_context()

        data = {'network': {
                'name': 'test-az',
                'tenant_id': self._tenant_id,
                'port_security_enabled': False,
                'admin_state_up': True,
                'shared': False
                }}

        # network creation should succeed
        net = p.create_network(ctx, data)
        self.assertEqual([],
                         net['availability_zone_hints'])
        self.assertEqual([nsx_az.DEFAULT_NAME],
                         net['availability_zones'])

    def test_dhcp_service_with_create_az_network(self):
        # Test if DHCP service is disabled on a network when it is created.
        with self.network(availability_zone_hints=[self._az_name],
                          arg_list=('availability_zone_hints',)) as network:
            self._verify_dhcp_service(network['network']['id'],
                                      network['network']['tenant_id'], False)

    def test_dhcp_binding_with_create_az_port(self):
        # Test if DHCP binding is added when a compute port is created.
        with mock.patch.object(nsx_resources.LogicalDhcpServer,
                               'create_binding',
                               return_value={"id": uuidutils.generate_uuid()}
                               ) as create_dhcp_binding:
            with self.network(
                availability_zone_hints=[self._az_name],
                arg_list=('availability_zone_hints',)) as network:
                with self.subnet(enable_dhcp=True, network=network) as subnet:
                    device_owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'X'
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
                            {'network': '%s' %
                             self.az_metadata_route,
                             'next_hop': '0.0.0.0'},
                            {'network': '%s' %
                             self.az_metadata_route,
                             'next_hop': ip},
                            {'network': subnet['subnet']['cidr'],
                             'next_hop': '0.0.0.0'},
                            {'network': '0.0.0.0/0',
                             'next_hop': subnet['subnet']['gateway_ip']}]}}
                        create_dhcp_binding.assert_called_once_with(
                            dhcp_service['nsx_service_id'],
                            port['port']['mac_address'], ip, hostname,
                            cfg.CONF.nsx_v3.dhcp_lease_time, options,
                            subnet['subnet']['gateway_ip'])

    def test_create_subnet_with_dhcp_port(self):
        with self.subnet(enable_dhcp=True) as subnet:
            # find the dhcp port and verify it has port security disabled
            ports = self.plugin.get_ports(
                context.get_admin_context())
            self.assertEqual(1, len(ports))
            self.assertEqual('network:dhcp', ports[0]['device_owner'])
            self.assertEqual(subnet['subnet']['network_id'],
                             ports[0]['network_id'])
            self.assertEqual(False, ports[0]['port_security_enabled'])


class NsxNativeMetadataTestCase(test_plugin.NsxV3PluginTestCaseMixin):

    def setUp(self):
        super(NsxNativeMetadataTestCase, self).setUp()
        self._orig_dhcp_agent_notification = cfg.CONF.dhcp_agent_notification
        self._orig_native_dhcp_metadata = cfg.CONF.nsx_v3.native_dhcp_metadata
        cfg.CONF.set_override('dhcp_agent_notification', False)
        cfg.CONF.set_override('native_dhcp_metadata', True, 'nsx_v3')
        self._az_name = 'zone1'
        self._az_metadata_proxy = 'dummy'
        set_az_in_config(self._az_name, metadata_proxy=self._az_metadata_proxy)
        self._patcher = mock.patch.object(core_resources.NsxLibMetadataProxy,
                                          'get')
        self._patcher.start()
        self._initialize_azs()
        self.plugin._init_dhcp_metadata()

    def tearDown(self):
        self._patcher.stop()
        cfg.CONF.set_override('dhcp_agent_notification',
                              self._orig_dhcp_agent_notification)
        cfg.CONF.set_override('native_dhcp_metadata',
                              self._orig_native_dhcp_metadata, 'nsx_v3')
        super(NsxNativeMetadataTestCase, self).tearDown()

    def test_metadata_proxy_configuration(self):
        # Test if dhcp_agent_notification and metadata_proxy are
        # configured correctly.
        orig_dhcp_agent_notification = cfg.CONF.dhcp_agent_notification
        cfg.CONF.set_override('dhcp_agent_notification', True)
        self.assertRaises(nsx_exc.NsxPluginException,
                          self.plugin._init_dhcp_metadata)
        cfg.CONF.set_override('dhcp_agent_notification',
                              orig_dhcp_agent_notification)
        orig_metadata_proxy_uuid = cfg.CONF.nsx_v3.metadata_proxy
        cfg.CONF.set_override('metadata_proxy', '', 'nsx_v3')
        self.assertRaises(cfg.RequiredOptError,
                          self.plugin._translate_configured_names_to_uuids)
        cfg.CONF.set_override('metadata_proxy', orig_metadata_proxy_uuid,
                              'nsx_v3')

    def test_metadata_proxy_with_create_network(self):
        # Test if native metadata proxy is enabled on a network when it is
        # created.
        with mock.patch.object(nsx_resources.LogicalPort,
                               'create') as create_logical_port:
            with self.network() as network:
                nsx_net_id = self.plugin._get_network_nsx_id(
                    context.get_admin_context(), network['network']['id'])
                tags = self.plugin.nsxlib.build_v3_tags_payload(
                    network['network'], resource_type='os-neutron-net-id',
                    project_name=None)
                name = utils.get_name_and_uuid('%s-%s' % (
                    'mdproxy', network['network']['name'] or 'network'),
                                               network['network']['id'])
                create_logical_port.assert_called_once_with(
                    nsx_net_id, cfg.CONF.nsx_v3.metadata_proxy,
                    tags=tags, name=name,
                    attachment_type=nsx_constants.ATTACHMENT_MDPROXY)

    def test_metadata_proxy_with_create_az_network(self):
        # Test if native metadata proxy is enabled on a network when it is
        # created.
        with mock.patch.object(nsx_resources.LogicalPort,
                               'create') as create_logical_port:
            with self.network(
                availability_zone_hints=[self._az_name],
                arg_list=('availability_zone_hints',)) as network:
                nsx_net_id = self.plugin._get_network_nsx_id(
                    context.get_admin_context(), network['network']['id'])
                tags = self.plugin.nsxlib.build_v3_tags_payload(
                    network['network'], resource_type='os-neutron-net-id',
                    project_name=None)
                name = utils.get_name_and_uuid('%s-%s' % (
                    'mdproxy', network['network']['name'] or 'network'),
                                               network['network']['id'])
                create_logical_port.assert_called_once_with(
                    nsx_net_id, self._az_metadata_proxy,
                    tags=tags, name=name,
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
