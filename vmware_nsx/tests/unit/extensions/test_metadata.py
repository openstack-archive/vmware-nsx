# Copyright 2015 VMware, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import mock
import netaddr
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_config import cfg
import webob.exc

from vmware_nsx.api_client import exception as api_exc
from vmware_nsx.common import config


class MetaDataTestCase(object):

    def _metadata_setup(self, mode=config.MetadataModes.DIRECT,
                        on_demand=False):
        cfg.CONF.set_override('metadata_mode', mode, self.plugin.cfg_group)
        if hasattr(getattr(cfg.CONF, self.plugin.cfg_group),
                   'metadata_on_demand'):
            cfg.CONF.set_override('metadata_on_demand', on_demand,
                                  self.plugin.cfg_group)

    def _metadata_teardown(self):
        cfg.CONF.set_override('metadata_mode', None, self.plugin.cfg_group)
        if hasattr(getattr(cfg.CONF, self.plugin.cfg_group),
                   'metadata_on_demand'):
            cfg.CONF.set_override('metadata_on_demand', False,
                                  self.plugin.cfg_group)

    def _check_metadata(self, expected_subnets, expected_ports):
        subnets = self._list('subnets')['subnets']
        self.assertEqual(len(subnets), expected_subnets)
        meta_net_id, meta_sub_id = None, None
        meta_cidr = netaddr.IPNetwork('169.254.0.0/16')
        for subnet in subnets:
            cidr = netaddr.IPNetwork(subnet['cidr'])
            if meta_cidr == cidr or meta_cidr in cidr.supernet(16):
                meta_sub_id = subnet['id']
                meta_net_id = subnet['network_id']
                break
        ports = self._list(
            'ports',
            query_params='network_id=%s' % meta_net_id)['ports']
        self.assertEqual(len(ports), expected_ports)
        meta_port_id = ports[0]['id'] if ports else None
        return meta_net_id, meta_sub_id, meta_port_id

    def test_router_add_interface_subnet_with_metadata_access(self):
        self._metadata_setup()
        self.test_router_add_interface_subnet()
        self._metadata_teardown()

    def test_router_add_interface_port_with_metadata_access(self):
        self._metadata_setup()
        self.test_router_add_interface_port()
        self._metadata_teardown()

    def test_router_add_interface_dupsubnet_returns_400_with_metadata(self):
        self._metadata_setup()
        self.test_router_add_interface_dup_subnet1_returns_400()
        self._metadata_teardown()

    def test_router_add_interface_overlapped_cidr_returns_400_with(self):
        self._metadata_setup()
        self.test_router_add_interface_overlapped_cidr_returns_400()
        self._metadata_teardown()

    def test_router_remove_interface_inuse_returns_409_with_metadata(self):
        self._metadata_setup()
        self.test_router_remove_interface_inuse_returns_409()
        self._metadata_teardown()

    def test_router_remove_iface_wrong_sub_returns_400_with_metadata(self):
        self._metadata_setup()
        self.test_router_remove_interface_wrong_subnet_returns_400()
        self._metadata_teardown()

    def test_router_delete_with_metadata_access(self):
        self._metadata_setup()
        self.test_router_delete()
        self._metadata_teardown()

    def test_router_delete_with_port_existed_returns_409_with_metadata(self):
        self._metadata_setup()
        self.test_router_delete_with_port_existed_returns_409()
        self._metadata_teardown()

    def test_delete_port_with_metadata(self):
        self._metadata_setup(config.MetadataModes.INDIRECT)
        with self.subnet() as s:
            with self.port(subnet=s, fixed_ips=[], device_id='1234',
                           device_owner=constants.DEVICE_OWNER_DHCP) as port:
                self._delete('ports', port['port']['id'])
        self._metadata_teardown()

    def test_metadatata_network_created_with_router_interface_add(self):
        self._metadata_setup()
        with mock.patch.object(self._plugin_class, 'schedule_network') as f:
            with self.router() as r:
                with self.subnet() as s:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  None)
                    r_ports = self._list('ports')['ports']
                    self.assertEqual(len(r_ports), 2)
                    ips = []
                    for port in r_ports:
                        ips.extend([netaddr.IPAddress(fixed_ip['ip_address'])
                                    for fixed_ip in port['fixed_ips']])
                    meta_cidr = netaddr.IPNetwork('169.254.0.0/16')
                    self.assertTrue(any([ip in meta_cidr for ip in ips]))
                    # Needed to avoid 409.
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s['subnet']['id'],
                                                  None)
            # Verify that there has been a schedule_network all for the
            # metadata network
            expected_net_name = 'meta-%s' % r['router']['id']
            found = False
            for call in f.call_args_list:
                # The network data are the last of the positional arguments
                net_dict = call[0][-1]
                if net_dict['name'] == expected_net_name:
                    self.assertFalse(net_dict['port_security_enabled'])
                    self.assertFalse(net_dict['shared'])
                    self.assertFalse(net_dict['tenant_id'])
                    found = True
                    break
            else:
                self.fail("Expected schedule_network call for metadata "
                          "network %s not found" % expected_net_name)
            self.assertTrue(found)
        self._metadata_teardown()

    def test_metadata_network_create_rollback_on_create_subnet_failure(self):
        self._metadata_setup()
        with self.router() as r:
            with self.subnet() as s:
                # Raise a NeutronException (eg: NotFound).
                with mock.patch.object(self._plugin_class,
                                       'create_subnet',
                                       side_effect=n_exc.NotFound):
                    self._router_interface_action(
                        'add', r['router']['id'], s['subnet']['id'], None)
                # Ensure metadata network was removed.
                nets = self._list('networks')['networks']
                self.assertEqual(len(nets), 1)
                # Needed to avoid 409.
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
        self._metadata_teardown()

    def test_metadata_network_create_rollback_on_add_rtr_iface_failure(self):
        self._metadata_setup()
        with self.router() as r:
            with self.subnet() as s:
                # Save function being mocked.
                real_func = self._plugin_class.add_router_interface
                plugin_instance = directory.get_plugin()

                # Raise a NeutronException when adding metadata subnet
                # to router.
                def side_effect(*args):
                    if args[-1]['subnet_id'] == s['subnet']['id']:
                        # Do the real thing.
                        return real_func(plugin_instance, *args)
                    # Otherwise raise.
                    raise api_exc.NsxApiException()

                with mock.patch.object(self._plugin_class,
                                       'add_router_interface',
                                       side_effect=side_effect):
                    self._router_interface_action(
                        'add', r['router']['id'], s['subnet']['id'], None)
                # Ensure metadata network was removed.
                nets = self._list('networks')['networks']
                self.assertEqual(len(nets), 1)
                # Needed to avoid 409.
                self._router_interface_action('remove',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None)
        self._metadata_teardown()

    def test_metadata_network_removed_with_router_interface_remove(self):
        self._metadata_setup()
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add', r['router']['id'],
                                              s['subnet']['id'], None)
                meta_net_id, meta_sub_id, meta_port_id = self._check_metadata(
                    expected_subnets=2, expected_ports=1)
                self._router_interface_action('remove', r['router']['id'],
                                              s['subnet']['id'], None)
                self._show('networks', meta_net_id,
                           webob.exc.HTTPNotFound.code)
                self._show('ports', meta_port_id,
                           webob.exc.HTTPNotFound.code)
                self._show('subnets', meta_sub_id,
                           webob.exc.HTTPNotFound.code)
        self._metadata_teardown()

    def test_metadata_network_remove_rollback_on_failure(self):
        self._metadata_setup()
        with self.router() as r:
            with self.subnet() as s:
                self._router_interface_action('add', r['router']['id'],
                                              s['subnet']['id'], None)
                networks = self._list('networks')['networks']
                for network in networks:
                    if network['id'] != s['subnet']['network_id']:
                        meta_net_id = network['id']
                ports = self._list(
                    'ports',
                    query_params='network_id=%s' % meta_net_id)['ports']
                meta_port_id = ports[0]['id']
                # Save function being mocked.
                real_func = self._plugin_class.remove_router_interface
                plugin_instance = directory.get_plugin()

                # Raise a NeutronException when removing metadata subnet
                # from router.
                def side_effect(*args):
                    if args[-1].get('subnet_id') == s['subnet']['id']:
                        # Do the real thing.
                        return real_func(plugin_instance, *args)
                    # Otherwise raise.
                    raise api_exc.NsxApiException()

                with mock.patch.object(self._plugin_class,
                                       'remove_router_interface',
                                       side_effect=side_effect):
                    self._router_interface_action('remove', r['router']['id'],
                                                  s['subnet']['id'], None)
                # Metadata network and subnet should still be there.
                self._show('networks', meta_net_id,
                           webob.exc.HTTPOk.code)
                self._show('ports', meta_port_id,
                           webob.exc.HTTPOk.code)
        self._metadata_teardown()

    def test_metadata_network_with_update_subnet_dhcp_enable(self):
        self._metadata_setup(on_demand=True)
        with self.router() as r:
            # Create a DHCP-disabled subnet.
            with self.subnet(enable_dhcp=False) as s:
                self._router_interface_action('add', r['router']['id'],
                                              s['subnet']['id'], None)
                meta_net_id, meta_sub_id, meta_port_id = self._check_metadata(
                    expected_subnets=2, expected_ports=1)
                # Update subnet to DHCP-enabled.
                data = {'subnet': {'enable_dhcp': True}}
                req = self.new_update_request('subnets', data,
                                              s['subnet']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertEqual(True, res['subnet']['enable_dhcp'])
                self._check_metadata(expected_subnets=1, expected_ports=0)
                self._show('networks', meta_net_id,
                           webob.exc.HTTPNotFound.code)
                self._show('ports', meta_port_id,
                           webob.exc.HTTPNotFound.code)
                self._show('subnets', meta_sub_id,
                           webob.exc.HTTPNotFound.code)
        self._metadata_teardown()

    def test_metadata_network_with_update_subnet_dhcp_disable(self):
        self._metadata_setup(on_demand=True)
        with self.router() as r:
            # Create a DHCP-enabled subnet.
            with self.subnet(enable_dhcp=True) as s:
                self._router_interface_action('add', r['router']['id'],
                                              s['subnet']['id'], None)
                self._check_metadata(expected_subnets=1, expected_ports=0)
                # Update subnet to DHCP-disabled.
                data = {'subnet': {'enable_dhcp': False}}
                req = self.new_update_request('subnets', data,
                                              s['subnet']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertEqual(False, res['subnet']['enable_dhcp'])
                meta_net_id, meta_sub_id, meta_port_id = self._check_metadata(
                    expected_subnets=2, expected_ports=1)
                self._show('networks', meta_net_id,
                           webob.exc.HTTPOk.code)
                self._show('ports', meta_port_id,
                           webob.exc.HTTPOk.code)
                self._show('subnets', meta_sub_id,
                           webob.exc.HTTPOk.code)
        self._metadata_teardown()

    def test_metadata_dhcp_host_route(self):
        self._metadata_setup(config.MetadataModes.INDIRECT)
        subnets = self._list('subnets')['subnets']
        with self.subnet() as s:
            with self.port(subnet=s, device_id='1234',
                           device_owner=constants.DEVICE_OWNER_DHCP) as port:
                subnets = self._list('subnets')['subnets']
                self.assertEqual(len(subnets), 1)
                subnet_ip_net = netaddr.IPNetwork(s['subnet']['cidr'])
                self.assertIn(netaddr.IPAddress(
                                  subnets[0]['host_routes'][0]['nexthop']),
                              subnet_ip_net)
                self.assertEqual(subnets[0]['host_routes'][0]['destination'],
                                 '169.254.169.254/32')
            self._delete('ports', port['port']['id'])
            subnets = self._list('subnets')['subnets']
            # Test that route is deleted after dhcp port is removed.
            self.assertEqual(len(subnets[0]['host_routes']), 0)
        self._metadata_teardown()
