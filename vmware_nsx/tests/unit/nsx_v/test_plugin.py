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

import contextlib
import copy

from eventlet import greenthread
import mock
import netaddr
from neutron.api.v2 import attributes
from neutron.extensions import address_scope
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import dvr as dist_router
from neutron.extensions import external_net
from neutron.extensions import l3
from neutron.extensions import l3_ext_gw_mode
from neutron.extensions import l3_flavors
from neutron.extensions import router_availability_zone
from neutron.extensions import securitygroup as secgrp
from neutron.plugins.common import utils
from neutron.tests.unit import _test_extension_portbindings as test_bindings
import neutron.tests.unit.db.test_allowedaddresspairs_db as test_addr_pair
import neutron.tests.unit.db.test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import base as extension
from neutron.tests.unit.extensions import test_address_scope
from neutron.tests.unit.extensions import test_extra_dhcp_opt as test_dhcpopts
import neutron.tests.unit.extensions.test_l3 as test_l3_plugin
import neutron.tests.unit.extensions.test_l3_ext_gw_mode as test_ext_gw_mode
import neutron.tests.unit.extensions.test_portsecurity as test_psec
import neutron.tests.unit.extensions.test_securitygroup as ext_sg
from neutron.tests.unit import testlib_api
from neutron_lib.api.definitions import address_scope as addr_apidef
from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from neutron_lib.services.qos import constants as qos_consts
from neutron_lib.utils import helpers
from neutron_lib.utils import net
from oslo_config import cfg
from oslo_utils import uuidutils
import six
import webob.exc

from vmware_nsx._i18n import _
from vmware_nsx.common import config
from vmware_nsx.common import exceptions as nsxv_exc
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils as c_utils
from vmware_nsx.db import nsxv_db
from vmware_nsx.dvs import dvs
from vmware_nsx.dvs import dvs_utils
from vmware_nsx.extensions import routersize as router_size
from vmware_nsx.extensions import routertype as router_type
from vmware_nsx.extensions import securitygrouplogging
from vmware_nsx.extensions import vnicindex as ext_vnic_idx
from vmware_nsx.plugins.nsx_v import availability_zones as nsx_az
from vmware_nsx.plugins.nsx_v.drivers import (
    distributed_router_driver as dist_router_driver)
from vmware_nsx.plugins.nsx_v.drivers import (
    exclusive_router_driver as ex_router_driver)
from vmware_nsx.plugins.nsx_v.drivers import (
    shared_router_driver as router_driver)
from vmware_nsx.plugins.nsx_v import md_proxy
from vmware_nsx.plugins.nsx_v.vshield.common import constants as vcns_const
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as vcns_exc
from vmware_nsx.plugins.nsx_v.vshield import edge_appliance_driver
from vmware_nsx.plugins.nsx_v.vshield import edge_firewall_driver
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.services.qos.nsx_v import utils as qos_utils
from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.extensions import test_vnic_index
from vmware_nsx.tests.unit.nsx_v.vshield import fake_vcns
from vmware_nsx.tests.unit import test_utils

PLUGIN_NAME = 'vmware_nsx.plugin.NsxVPlugin'

_uuid = uuidutils.generate_uuid


def set_az_in_config(name, resource_pool_id="respool-7",
                     datastore_id="datastore-7",
                     edge_ha=False, ha_datastore_id=None):
    group_name = 'az:%s' % name
    cfg.CONF.set_override('availability_zones', [name], group="nsxv")
    config.register_nsxv_azs(cfg.CONF, [name])
    cfg.CONF.set_override("resource_pool_id", resource_pool_id,
                          group=group_name)
    cfg.CONF.set_override("datastore_id", datastore_id,
                          group=group_name)
    cfg.CONF.set_override("edge_ha", edge_ha,
                          group=group_name)
    cfg.CONF.set_override("ha_datastore_id", ha_datastore_id,
                          group=group_name)


class NsxVPluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

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

        attrs = kwargs
        if providernet_args:
            attrs.update(providernet_args)
        for arg in (('admin_state_up', 'tenant_id', 'shared') +
                    (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs:
                data['network'][arg] = kwargs[arg]
        network_req = self.new_create_request('networks', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            network_req.environ['neutron.context'] = context.Context(
                '', tenant_id)
        return network_req.get_response(self.api)

    @mock.patch.object(edge_utils.EdgeManager, '_deploy_edge')
    def setUp(self, mock_deploy_edge,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        test_utils.override_nsx_ini_test()
        mock_vcns = mock.patch(vmware.VCNS_NAME, autospec=True)
        mock_vcns_instance = mock_vcns.start()
        self.fc2 = fake_vcns.FakeVcns()
        mock_vcns_instance.return_value = self.fc2
        edge_utils.query_dhcp_service_config = mock.Mock(return_value=[])
        self.mock_create_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'create_dhcp_edge_service'))
        self.mock_create_dhcp_service.start()
        mock_update_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'update_dhcp_edge_service'))
        mock_update_dhcp_service.start()
        mock_delete_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'delete_dhcp_edge_service'))
        mock_delete_dhcp_service.start()
        mock_check_backup_edge_pools = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, '_check_backup_edge_pools'))
        mock_check_backup_edge_pools.start()
        mock_deploy_backup_edges_at_backend = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, '_deploy_backup_edges_at_backend'))
        mock_deploy_backup_edges_at_backend.start()
        mock_process_security_group_logging = mock.patch(
            'vmware_nsx.plugin.NsxVPlugin.'
            '_process_security_groups_rules_logging')
        mock_process_security_group_logging.start()

        self.default_res_pool = 'respool-28'
        cfg.CONF.set_override("resource_pool_id", self.default_res_pool,
                              group="nsxv")
        set_az_in_config('az7')
        if service_plugins is not None:
            # override the service plugins only if specified directly
            super(NsxVPluginV2TestCase, self).setUp(
                plugin=plugin,
                service_plugins=service_plugins,
                ext_mgr=ext_mgr)
        else:
            super(NsxVPluginV2TestCase, self).setUp(
                plugin=plugin,
                ext_mgr=ext_mgr)
        self.addCleanup(self.fc2.reset_all)
        plugin_instance = directory.get_plugin()
        plugin_instance.real_get_edge = plugin_instance._get_edge_id_by_rtr_id
        plugin_instance._get_edge_id_by_rtr_id = mock.Mock()
        plugin_instance._get_edge_id_by_rtr_id.return_value = False
        plugin_instance._get_edge_id_and_az_by_rtr_id = mock.Mock()
        plugin_instance._get_edge_id_and_az_by_rtr_id.return_value = (
            False, False)
        # call init_complete manually. The event is not called in unit tests
        plugin_instance.init_complete(None, None, {})

    def _get_core_plugin_with_dvs(self):
        # enable dvs features to allow policy with QOS
        cfg.CONF.set_default('use_dvs_features', True, 'nsxv')
        plugin = directory.get_plugin()
        with mock.patch.object(dvs_utils, 'dvs_create_session'):
            plugin._vcm = dvs.VCManager()
        return plugin

    def test_get_vlan_network_name(self):
        p = directory.get_plugin()
        net_id = uuidutils.generate_uuid()
        dvs_id = 'dvs-10'
        net = {'name': '',
               'id': net_id}
        # Empty net['name'] should yield dvs_id-net_id as a name for the
        # port group.
        expected = '%s-%s' % (dvs_id, net_id)
        self.assertEqual(expected,
                         p._get_vlan_network_name(net, dvs_id))
        # If network name is provided then it should yield
        # dvs_id-net_name-net_id as a name for the port group.
        net = {'name': 'pele',
               'id': net_id}
        expected = '%s-%s-%s' % (dvs_id, 'pele', net_id)
        self.assertEqual(expected,
                         p._get_vlan_network_name(net, dvs_id))
        name = 'X' * 500
        net = {'name': name,
               'id': net_id}
        expected = '%s-%s-%s' % (dvs_id, name[:36], net_id)
        self.assertEqual(expected,
                         p._get_vlan_network_name(net, dvs_id))

    def test_get_vlan_network_name_with_net_name_missing(self):
        p = directory.get_plugin()
        net_id = uuidutils.generate_uuid()
        dvs_id = 'dvs-10'
        net = {'id': net_id}
        # Missing net['name'] should yield dvs_id-net_id as a name for the
        # port group.
        expected = '%s-%s' % (dvs_id, net_id)
        self.assertEqual(expected,
                         p._get_vlan_network_name(net, dvs_id))


class TestNetworksV2(test_plugin.TestNetworksV2, NsxVPluginV2TestCase):

    def _test_create_bridge_network(self, vlan_id=0):
        net_type = vlan_id and 'vlan' or 'flat'
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

    def _test_generate_tag(self, vlan_id):
        net_type = 'vlan'
        name = 'bridge_net'
        plugin = directory.get_plugin()
        plugin._network_vlans = utils.parse_network_vlan_ranges(
            cfg.CONF.nsxv.network_vlan_ranges)
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (pnet.NETWORK_TYPE, net_type),
                    (pnet.PHYSICAL_NETWORK, 'dvs-70'),
                    (pnet.SEGMENTATION_ID, vlan_id)]
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: 'dvs-70'}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_bridge_vlan_generate(self):
        cfg.CONF.set_default('network_vlan_ranges', 'dvs-70', 'nsxv')
        self._test_generate_tag(1)

    def test_create_bridge_vlan_generate_range(self):
        cfg.CONF.set_default('network_vlan_ranges', 'dvs-70:100:110', 'nsxv')
        self._test_generate_tag(100)

    def test_create_bridge_vlan_network_outofrange_returns_400(self):
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_bridge_network(vlan_id=5000)
        self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_external_portgroup_network(self):
        name = 'ext_net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (external_net.EXTERNAL, True),
                    (pnet.NETWORK_TYPE, 'portgroup'),
                    (pnet.PHYSICAL_NETWORK, 'tzuuid')]
        providernet_args = {pnet.NETWORK_TYPE: 'portgroup',
                            pnet.PHYSICAL_NETWORK: 'tzuuid',
                            external_net.EXTERNAL: True}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK,
                                    external_net.EXTERNAL)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_portgroup_network(self):
        name = 'pg_net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (pnet.NETWORK_TYPE, 'portgroup'),
                    (pnet.PHYSICAL_NETWORK, 'tzuuid')]
        providernet_args = {pnet.NETWORK_TYPE: 'portgroup',
                            pnet.PHYSICAL_NETWORK: 'tzuuid'}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

            # try to create another one on the same physical net will failure
            res = self._create_network(
                self.fmt, name, True,
                providernet_args=providernet_args,
                arg_list=(pnet.NETWORK_TYPE,
                          pnet.PHYSICAL_NETWORK))
            data = self.deserialize(self.fmt, res)
            self.assertIn('NeutronError', data)

    def test_delete_network_after_removing_subnet(self):
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

    def test_update_network_with_admin_false(self):
        data = {'network': {'admin_state_up': False}}
        with self.network() as net:
            plugin = directory.get_plugin()
            self.assertRaises(NotImplementedError,
                              plugin.update_network,
                              context.get_admin_context(),
                              net['network']['id'], data)

    def test_create_extend_dvs_provider_network(self):
        name = 'provider_net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (pnet.NETWORK_TYPE, 'flat'),
                    (pnet.PHYSICAL_NETWORK, 'dvs-uuid')]
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_same_vlan_network_with_different_dvs(self):
        name = 'dvs-provider-net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (pnet.NETWORK_TYPE, 'vlan'),
                    (pnet.SEGMENTATION_ID, 43),
                    (pnet.PHYSICAL_NETWORK, 'dvs-uuid-1')]
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 43,
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid-1'}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.SEGMENTATION_ID,
                                    pnet.PHYSICAL_NETWORK)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

            expected_same_vlan = [(pnet.NETWORK_TYPE, 'vlan'),
                                  (pnet.SEGMENTATION_ID, 43),
                                  (pnet.PHYSICAL_NETWORK, 'dvs-uuid-2')]
            providernet_args_1 = {pnet.NETWORK_TYPE: 'vlan',
                                  pnet.SEGMENTATION_ID: 43,
                                  pnet.PHYSICAL_NETWORK: 'dvs-uuid-2'}
            with self.network(name=name,
                              providernet_args=providernet_args_1,
                              arg_list=(pnet.NETWORK_TYPE,
                                        pnet.SEGMENTATION_ID,
                                        pnet.PHYSICAL_NETWORK)) as net1:
                for k, v in expected_same_vlan:
                    self.assertEqual(net1['network'][k], v)

    def test_create_vlan_network_with_multiple_dvs(self):
        name = 'multi-dvs-vlan-net'
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 100,
                            pnet.PHYSICAL_NETWORK: 'dvs-1, dvs-2, dvs-3'}
        p = directory.get_plugin()
        with mock.patch.object(
            p, '_create_vlan_network_at_backend',
            # Return three netmorefs as side effect
            side_effect=[_uuid(), _uuid(), _uuid()]) as vlan_net_call:
            with self.network(name=name,
                              providernet_args=providernet_args,
                              arg_list=(pnet.NETWORK_TYPE,
                                        pnet.SEGMENTATION_ID,
                                        pnet.PHYSICAL_NETWORK)):
                # _create_vlan_network_at_backend is expected to be called
                # three times since we have three DVS IDs in the physical
                # network attribute.
                self.assertEqual(3, vlan_net_call.call_count)

    def test_create_vlan_network_with_multiple_dvs_backend_failure(self):
        net_data = {'name': 'vlan-net',
                    'tenant_id': self._tenant_id,
                    pnet.NETWORK_TYPE: 'vlan',
                    pnet.SEGMENTATION_ID: 100,
                    pnet.PHYSICAL_NETWORK: 'dvs-1, dvs-2, dvs-3'}
        network = {'network': net_data}
        p = directory.get_plugin()
        with mock.patch.object(
            p, '_create_vlan_network_at_backend',
            # Return two successful netmorefs and fail on the backend
            # for the third netmoref creation as side effect.
            side_effect=[_uuid(), _uuid(),
                         nsxv_exc.NsxPluginException(err_msg='')]):
            with mock.patch.object(
                p, '_delete_backend_network') as delete_net_call:
                self.assertRaises(nsxv_exc.NsxPluginException,
                                  p.create_network,
                                  context.get_admin_context(),
                                  network)
                # Two successfully created port groups should be rolled back
                # on the failure of third port group creation.
                self.assertEqual(2, delete_net_call.call_count)

    def test_create_vlan_network_with_multiple_dvs_not_found_failure(self):
        net_data = {'name': 'vlan-net',
                    'tenant_id': self._tenant_id,
                    pnet.NETWORK_TYPE: 'vlan',
                    pnet.SEGMENTATION_ID: 100,
                    pnet.PHYSICAL_NETWORK: 'dvs-1, dvs-2, dvs-3'}
        network = {'network': net_data}
        p = directory.get_plugin()
        with mock.patch.object(
            p, '_validate_provider_create',
            side_effect=[nsxv_exc.NsxResourceNotFound(res_id='dvs-2',
                                                      res_name='dvs_id')]):
            with mock.patch.object(
                p, '_create_vlan_network_at_backend') as create_net_call:
                self.assertRaises(nsxv_exc.NsxResourceNotFound,
                                  p.create_network,
                                  context.get_admin_context(),
                                  network)
                # Verify no port group is created on the backend.
                self.assertEqual(0, create_net_call.call_count)

    def test_create_vlan_network_with_multiple_dvs_ignore_duplicate_dvs(self):
        name = 'multi-dvs-vlan-net'
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 100,
                            pnet.PHYSICAL_NETWORK: 'dvs-1, dvs-2, dvs-1'}
        p = directory.get_plugin()
        with mock.patch.object(
            p, '_create_vlan_network_at_backend',
            # Return two netmorefs as side effect
            side_effect=[_uuid(), _uuid()]) as vlan_net_call:
            with self.network(name=name,
                              providernet_args=providernet_args,
                              arg_list=(pnet.NETWORK_TYPE,
                                        pnet.SEGMENTATION_ID,
                                        pnet.PHYSICAL_NETWORK)):
                # _create_vlan_network_at_backend is expected to be called
                # two times since we have only two unique DVS IDs in the
                # physical network attribute.
                self.assertEqual(2, vlan_net_call.call_count)

    def test_update_vlan_network_with_multiple_dvs(self):
        name = 'multi-dvs-vlan-net'
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 100,
                            pnet.PHYSICAL_NETWORK: 'dvs-1, dvs-2'}
        p = directory.get_plugin()
        with mock.patch.object(
            p, '_create_vlan_network_at_backend',
            # Return three netmorefs as side effect
            side_effect=[_uuid(), _uuid(), _uuid()]) as vlan_net_call:
            with self.network(name=name,
                              providernet_args=providernet_args,
                              arg_list=(pnet.NETWORK_TYPE,
                                        pnet.SEGMENTATION_ID,
                                        pnet.PHYSICAL_NETWORK)) as net:
                # _create_vlan_network_at_backend is expected to be called
                # 2 times since we have 2 DVS IDs in the physical
                # network attribute.
                self.assertEqual(2, vlan_net_call.call_count)
                self.assertEqual('dvs-1, dvs-2',
                                 net['network'][pnet.PHYSICAL_NETWORK])
                # Add another dvs
                data = {'network': {pnet.PHYSICAL_NETWORK: 'dvs-3'}}
                req = self.new_update_request('networks', data,
                                              net['network']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(3, vlan_net_call.call_count)
                self.assertEqual('dvs-1, dvs-2, dvs-3',
                                 res['network'][pnet.PHYSICAL_NETWORK])

                # make sure it is updates also in the DB
                req = self.new_show_request('networks', net['network']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual('dvs-1, dvs-2, dvs-3',
                                 res['network'][pnet.PHYSICAL_NETWORK])

                # update again - with no real change
                data = {'network': {pnet.PHYSICAL_NETWORK: 'dvs-3'}}
                req = self.new_update_request('networks', data,
                                              net['network']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(3, vlan_net_call.call_count)
                self.assertEqual('dvs-1, dvs-2, dvs-3',
                                 res['network'][pnet.PHYSICAL_NETWORK])

    def test_get_dvs_ids_for_multiple_dvs_vlan_network(self):
        p = directory.get_plugin()
        default_dvs = 'fake_dvs_id'
        # If no DVS-ID is provided as part of physical network, return
        # global DVS-ID configured in nsx.ini
        physical_network = constants.ATTR_NOT_SPECIFIED
        self.assertEqual(['fake_dvs_id'], p._get_dvs_ids(
            physical_network, default_dvs))
        # If DVS-IDs are provided as part of physical network as a comma
        # separated string, return them as a list of DVS-IDs.
        physical_network = 'dvs-1,dvs-2, dvs-3'
        expected_dvs_ids = ['dvs-1', 'dvs-2', 'dvs-3']
        self.assertEqual(expected_dvs_ids,
                         sorted(p._get_dvs_ids(physical_network, default_dvs)))
        # Ignore extra commas ',' in the physical_network attribute.
        physical_network = ',,,dvs-1,dvs-2,, dvs-3,'
        expected_dvs_ids = ['dvs-1', 'dvs-2', 'dvs-3']
        self.assertEqual(expected_dvs_ids,
                         sorted(p._get_dvs_ids(physical_network, default_dvs)))
        # Ignore duplicate DVS-IDs in the physical_network attribute.
        physical_network = ',,,dvs-1,dvs-2,, dvs-2,'
        expected_dvs_ids = ['dvs-1', 'dvs-2']
        self.assertEqual(expected_dvs_ids,
                         sorted(p._get_dvs_ids(physical_network, default_dvs)))

    def test_create_vxlan_with_tz_provider_network(self):
        name = 'provider_net_vxlan'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (pnet.NETWORK_TYPE, 'vxlan'),
                    (pnet.PHYSICAL_NETWORK, 'vdnscope-2')]
        providernet_args = {pnet.NETWORK_TYPE: 'vxlan',
                            pnet.PHYSICAL_NETWORK: 'vdnscope-2'}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_vxlan_with_tz_provider_network_not_found_fail(self):
        name = 'provider_net_vxlan'
        data = {'network': {
                   'name': name,
                   'tenant_id': self._tenant_id,
                   pnet.SEGMENTATION_ID: constants.ATTR_NOT_SPECIFIED,
                   pnet.NETWORK_TYPE: 'vxlan',
                   pnet.PHYSICAL_NETWORK: 'vdnscope-2'}}
        p = directory.get_plugin()
        with mock.patch.object(p.nsx_v.vcns, 'validate_vdn_scope',
                               side_effect=[False]):
            self.assertRaises(nsxv_exc.NsxResourceNotFound,
                              p.create_network,
                              context.get_admin_context(),
                              data)

    def test_create_network_with_qos_no_dvs_fail(self):
        # network creation should fail if the qos policy parameter exists,
        # and no use_dvs_features configured
        data = {'network': {
                   'name': 'test-qos',
                   'tenant_id': self._tenant_id,
                   'qos_policy_id': _uuid()}}
        plugin = directory.get_plugin()
        self.assertRaises(n_exc.InvalidInput,
                          plugin.create_network,
                          context.get_admin_context(),
                          data)

    def test_update_network_with_qos_no_dvs_fail(self):
        # network update should fail if the qos policy parameter exists,
        # and no use_dvs_features configured
        data = {'network': {'qos_policy_id': _uuid()}}
        with self.network() as net:
            plugin = directory.get_plugin()
            self.assertRaises(n_exc.InvalidInput,
                              plugin.update_network,
                              context.get_admin_context(),
                              net['network']['id'], data)

    @mock.patch.object(dvs.DvsManager, 'update_port_groups_config')
    @mock.patch.object(qos_utils.NsxVQosRule, '_init_from_policy_id')
    def test_create_network_with_qos_policy(self,
                                            fake_init_from_policy,
                                            fake_dvs_update):
        # enable dvs features to allow policy with QOS
        plugin = self._get_core_plugin_with_dvs()
        ctx = context.get_admin_context()

        # Mark init as complete, as otherwise QoS won't be called
        plugin.init_is_complete = True

        # fake policy id
        policy_id = _uuid()
        data = {'network': {
                'name': 'test-qos',
                'tenant_id': self._tenant_id,
                'qos_policy_id': policy_id,
                'port_security_enabled': False,
                'admin_state_up': False,
                'shared': False
                }}
        with mock.patch('vmware_nsx.services.qos.common.utils.'
                        'get_network_policy_id',
                        return_value=policy_id):
            # create the network - should succeed and translate the policy id
            net = plugin.create_network(ctx, data)
            self.assertEqual(policy_id, net[qos_consts.QOS_POLICY_ID])
            fake_init_from_policy.assert_called_once_with(ctx, policy_id)
            self.assertTrue(fake_dvs_update.called)

            # Get network should also return the qos policy id
            net2 = plugin.get_network(ctx, net['id'])
            self.assertEqual(policy_id, net2[qos_consts.QOS_POLICY_ID])

    @mock.patch.object(dvs.DvsManager, 'update_port_groups_config')
    @mock.patch.object(qos_utils.NsxVQosRule, '_init_from_policy_id')
    def test_update_network_with_qos_policy(self,
                                            fake_init_from_policy,
                                            fake_dvs_update):
        # enable dvs features to allow policy with QOS
        plugin = self._get_core_plugin_with_dvs()
        ctx = context.get_admin_context()

        # create the network without qos policy
        data = {'network': {
                'name': 'test-qos',
                'tenant_id': self._tenant_id,
                'port_security_enabled': False,
                'admin_state_up': True,
                'shared': False
                }}
        net = plugin.create_network(ctx, data)

        # fake policy id
        policy_id = _uuid()
        data['network']['qos_policy_id'] = policy_id
        # update the network - should succeed and translate the policy id
        with mock.patch('vmware_nsx.services.qos.common.utils.'
                        'get_network_policy_id',
                        return_value=policy_id):
            res = plugin.update_network(ctx, net['id'], data)
            self.assertEqual(policy_id, res[qos_consts.QOS_POLICY_ID])
            fake_init_from_policy.assert_called_once_with(ctx, policy_id)
            self.assertTrue(fake_dvs_update.called)

            # Get network should also return the qos policy id
            net2 = plugin.get_network(ctx, net['id'])
            self.assertEqual(policy_id, net2[qos_consts.QOS_POLICY_ID])

    def test_create_network_with_bad_az_hint(self):
        p = directory.get_plugin()
        ctx = context.get_admin_context()
        data = {'network': {
                'name': 'test-qos',
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
        az_name = 'az7'
        set_az_in_config(az_name)
        p = directory.get_plugin()
        p._availability_zones_data = nsx_az.NsxVAvailabilityZones()
        ctx = context.get_admin_context()

        data = {'network': {
                'name': 'test-qos',
                'tenant_id': self._tenant_id,
                'port_security_enabled': False,
                'admin_state_up': True,
                'shared': False,
                'availability_zone_hints': [az_name]
                }}

        # network creation should succeed
        net = p.create_network(ctx, data)
        self.assertEqual([az_name],
                         net['availability_zone_hints'])
        # the availability zone is still empty until subnet creation
        self.assertEqual([],
                         net['availability_zones'])


class TestVnicIndex(NsxVPluginV2TestCase,
                    test_vnic_index.VnicIndexDbTestCase):
    def test_update_port_twice_with_the_same_index(self):
        """Tests that updates which does not modify the port vnic
        index association do not produce any errors
        """
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                res = self._port_index_update(port['port']['id'], 2)
                self.assertEqual(2, res['port'][ext_vnic_idx.VNIC_INDEX])
                res = self._port_index_update(port['port']['id'], 2)
                self.assertEqual(2, res['port'][ext_vnic_idx.VNIC_INDEX])


class TestPortsV2(NsxVPluginV2TestCase,
                  test_plugin.TestPortsV2,
                  test_bindings.PortBindingsTestCase,
                  test_bindings.PortBindingsHostTestCaseMixin,
                  test_bindings.PortBindingsVnicTestCaseMixin):

    VIF_TYPE = nsx_constants.VIF_TYPE_DVS
    HAS_PORT_FILTER = True

    def test_is_mac_in_use(self):
        ctx = context.get_admin_context()
        with self.port() as port:
            net_id = port['port']['network_id']
            mac = port['port']['mac_address']
            self.assertTrue(self.plugin._is_mac_in_use(ctx, net_id, mac))
            mac2 = '00:22:00:44:00:66'  # other mac, same network
            self.assertFalse(self.plugin._is_mac_in_use(ctx, net_id, mac2))
            net_id2 = port['port']['id']  # other net uuid, same mac
            self.assertTrue(self.plugin._is_mac_in_use(ctx, net_id2, mac))

    def test_duplicate_mac_generation(self):
        # simulate duplicate mac generation to make sure DBDuplicate is retried
        responses = ['12:34:56:78:00:00', '12:34:56:78:00:00',
                     '12:34:56:78:00:01']
        with mock.patch.object(net, 'get_random_mac',
                               side_effect=responses) as grand_mac:
            with self.subnet(enable_dhcp=False) as s:
                with self.port(subnet=s) as p1, self.port(subnet=s) as p2:
                    self.assertEqual('12:34:56:78:00:00',
                                     p1['port']['mac_address'])
                    self.assertEqual('12:34:56:78:00:01',
                                     p2['port']['mac_address'])
                    self.assertEqual(3, grand_mac.call_count)

    def test_get_ports_count(self):
        with self.port(), self.port(), self.port(), self.port() as p:
            tenid = p['port']['tenant_id']
            ctx = context.Context(user_id=None, tenant_id=tenid,
                                  is_admin=False)
            pl = directory.get_plugin()
            count = pl.get_ports_count(ctx, filters={'tenant_id': [tenid]})
            # Each port above has subnet => we have an additional port
            # for DHCP
            self.assertEqual(8, count)

    def test_requested_ips_only(self):
        with self.subnet(enable_dhcp=False) as subnet:
            fixed_ip_data = [{'ip_address': '10.0.0.2',
                             'subnet_id': subnet['subnet']['id']}]
            with self.port(subnet=subnet, fixed_ips=fixed_ip_data) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual('10.0.0.2', ips[0]['ip_address'])
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                ips_only = ['10.0.0.18', '10.0.0.20', '10.0.0.22', '10.0.0.21',
                            '10.0.0.3', '10.0.0.17', '10.0.0.19']
                ports_to_delete = []
                for i in ips_only:
                    kwargs = {"fixed_ips": [{'ip_address': i}]}
                    net_id = port['port']['network_id']
                    res = self._create_port(self.fmt, net_id=net_id, **kwargs)
                    port = self.deserialize(self.fmt, res)
                    ports_to_delete.append(port)
                    ips = port['port']['fixed_ips']
                    self.assertEqual(1, len(ips))
                    self.assertEqual(i, ips[0]['ip_address'])
                    self.assertEqual(subnet['subnet']['id'],
                                     ips[0]['subnet_id'])
                for p in ports_to_delete:
                    self._delete('ports', p['port']['id'])

    def test_delete_network_port_exists_owned_by_network_race(self):
        self.skipTest('Skip need to address in future')

    def test_create_port_with_too_many_fixed_ips(self):
        self.skipTest('DHCP only supports one binding')

    def test_create_port_invalid_fixed_ip_address_v6_pd_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_port_invalid_fixed_ip_address_v6_pd_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_port_invalid_subnet_v6_pd_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_port_mac_v6_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_port_invalid_fixed_ip_address_v6_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_port_excluding_ipv6_slaac_subnet_from_fixed_ips(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_requested_subnet_id_v6_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_ip_allocation_for_ipv6_subnet_slaac_address_mode(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_requested_fixed_ip_address_v6_slaac_router_iface(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_port_with_ipv6_slaac_subnet_in_fixed_ips(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_requested_invalid_fixed_ip_address_v6_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_delete_port_with_ipv6_slaac_address(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_ip_allocation_for_ipv6_2_subnet_slaac_mode(self):
        self.skipTest('No DHCP v6 Support yet')

    def _test_create_port_with_ipv6_subnet_in_fixed_ips(self, addr_mode,
                                                        ipv6_pd=False):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_port_with_new_ipv6_slaac_subnet_in_fixed_ips(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_port_anticipating_allocation(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_update_port_mac_ip(self):
        with self.subnet(enable_dhcp=False) as subnet:
            updated_fixed_ips = [{'subnet_id': subnet['subnet']['id'],
                              'ip_address': '10.0.0.3'}]
            self.check_update_port_mac(subnet=subnet,
                                       updated_fixed_ips=updated_fixed_ips)

    def test_list_ports(self):
        # for this test we need to enable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet) as port1,\
                self.port(subnet) as port2,\
                self.port(subnet) as port3:
            self._test_list_resources('port', [port1, port2, port3])

    def test_list_ports_public_network(self):
        with self.network(shared=True) as network:
            with self.subnet(network, enable_dhcp=False) as subnet,\
                    self.port(subnet, tenant_id='tenant_1') as port1,\
                    self.port(subnet, tenant_id='tenant_2') as port2:

                # Admin request - must return both ports
                self._test_list_resources('port', [port1, port2])
                # Tenant_1 request - must return single port
                q_context = context.Context('', 'tenant_1')
                self._test_list_resources('port', [port1],
                                          neutron_context=q_context)
                # Tenant_2 request - must return single port
                q_context = context.Context('', 'tenant_2')
                self._test_list_resources('port', [port2],
                                          neutron_context=q_context)

    def test_list_ports_with_pagination_emulated(self):
        helper_patcher = mock.patch(
            'neutron.api.v2.base.Controller._get_pagination_helper',
            new=test_plugin._fake_get_pagination_helper)
        helper_patcher.start()
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, mac_address='00:00:00:00:00:01') as port1,\
                self.port(subnet, mac_address='00:00:00:00:00:02') as port2,\
                self.port(subnet, mac_address='00:00:00:00:00:03') as port3:
            self._test_list_with_pagination('port',
                                            (port1, port2, port3),
                                            ('mac_address', 'asc'), 2, 2)

    def test_list_ports_with_pagination_native(self):
        if self._skip_native_pagination:
            self.skipTest("Skip test for not implemented pagination feature")
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, mac_address='00:00:00:00:00:01') as port1,\
                self.port(subnet, mac_address='00:00:00:00:00:02') as port2,\
                self.port(subnet, mac_address='00:00:00:00:00:03') as port3:
            self._test_list_with_pagination('port',
                                            (port1, port2, port3),
                                            ('mac_address', 'asc'), 2, 2)

    def test_list_ports_with_sort_emulated(self):
        helper_patcher = mock.patch(
            'neutron.api.v2.base.Controller._get_sorting_helper',
            new=test_plugin._fake_get_sorting_helper)
        helper_patcher.start()
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, admin_state_up='True',
                          mac_address='00:00:00:00:00:01') as port1,\
                self.port(subnet, admin_state_up='False',
                          mac_address='00:00:00:00:00:02') as port2,\
                self.port(subnet, admin_state_up='False',
                          mac_address='00:00:00:00:00:03') as port3:

            self._test_list_with_sort('port', (port3, port2, port1),
                                      [('admin_state_up', 'asc'),
                                      ('mac_address', 'desc')])

    def test_list_ports_with_sort_native(self):
        if self._skip_native_sorting:
            self.skipTest("Skip test for not implemented sorting feature")
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, admin_state_up='True',
                          mac_address='00:00:00:00:00:01') as port1,\
                self.port(subnet, admin_state_up='False',
                          mac_address='00:00:00:00:00:02') as port2,\
                self.port(subnet, admin_state_up='False',
                          mac_address='00:00:00:00:00:03') as port3:

            self._test_list_with_sort('port', (port3, port2, port1),
                                      [('admin_state_up', 'asc'),
                                      ('mac_address', 'desc')])

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

    def _update_port_index(self, port_id, device_id, index):
        data = {'port': {'device_id': device_id, 'vnic_index': index}}
        req = self.new_update_request('ports',
                                      data, port_id)
        res = self.deserialize('json', req.get_response(self.api))
        return res

    @mock.patch.object(edge_utils.EdgeManager, 'delete_dhcp_binding')
    def _test_update_port_index_and_spoofguard(
        self, ip_version, subnet_cidr, port_ip, port_mac, ipv6_lla,
        delete_dhcp_binding):
        q_context = context.Context('', 'tenant_1')
        device_id = _uuid()
        with self.subnet(ip_version=ip_version,
                         enable_dhcp=(False if ip_version == 6 else True),
                         cidr=subnet_cidr,
                         gateway_ip=None) as subnet:
            fixed_ip_data = [{'ip_address': port_ip,
                              'subnet_id': subnet['subnet']['id']}]
            with self.port(subnet=subnet,
                           device_id=device_id,
                           mac_address=port_mac,
                           fixed_ips=fixed_ip_data,
                           device_owner='compute:None') as port:
                self.assertIsNone(port['port']['vnic_index'])

                self.fc2.approve_assigned_addresses = (
                    mock.Mock().approve_assigned_addresses)
                self.fc2.publish_assigned_addresses = (
                    mock.Mock().publish_assigned_addresses)
                self.fc2.inactivate_vnic_assigned_addresses = (
                    mock.Mock().inactivate_vnic_assigned_addresses)
                vnic_index = 3
                res = self._update_port_index(
                    port['port']['id'], device_id, vnic_index)
                self.assertEqual(vnic_index, res['port']['vnic_index'])

                policy_id = nsxv_db.get_spoofguard_policy_id(
                    q_context.session, port['port']['network_id'])
                vnic_id = '%s.%03d' % (device_id, vnic_index)

                # Verify that the spoofguard policy assigned and published
                expected_ips = [port_ip]
                if ipv6_lla:
                    expected_ips.append(ipv6_lla)
                (self.fc2.approve_assigned_addresses.
                 assert_called_once_with(policy_id, vnic_id, port_mac,
                                         expected_ips))
                (self.fc2.publish_assigned_addresses.
                 assert_called_once_with(policy_id, vnic_id))

                # Updating the vnic_index to None implies the vnic does
                # no longer obtain the addresses associated with this port,
                # we need to inactivate previous addresses configurations for
                # this vnic in the context of this network spoofguard policy.
                res = self._update_port_index(port['port']['id'], '', None)

                (self.fc2.inactivate_vnic_assigned_addresses.
                 assert_called_once_with(policy_id, vnic_id))
                self.assertTrue(delete_dhcp_binding.called)

    def test_update_port_index(self):
        ip_version = 4
        subnet_cidr = '10.0.0.0/24'
        port_ip = '10.0.0.8'
        port_mac = '00:00:00:00:00:02'
        ipv6_lla = None
        self._test_update_port_index_and_spoofguard(
            ip_version,
            subnet_cidr,
            port_ip,
            port_mac,
            ipv6_lla)

    def test_update_port_index_ipv6(self):
        ip_version = 6
        subnet_cidr = 'ae80::/64'
        port_mac = '00:00:00:00:00:02'
        ipv6_lla = 'fe80::200:ff:fe00:2'
        port_ip = 'ae80::2'
        self._test_update_port_index_and_spoofguard(
            ip_version,
            subnet_cidr,
            port_ip,
            port_mac,
            ipv6_lla)

    def test_update_port_with_compute_device_owner(self):
        """
        Test that DHCP binding is created when ports 'device_owner'
        is updated to compute, for example when attaching an interface to a
        instance with existing port.
        """
        with self.port() as port:
            with mock.patch(PLUGIN_NAME + '._create_dhcp_static_binding'):
                update = {'port': {'device_owner'}}
                self.new_update_request('ports',
                                        update, port['port']['id'])

    def test_no_more_port_exception(self):
        with self.subnet(enable_dhcp=False, cidr='10.0.0.0/31',
                         gateway_ip=None) as subnet:
            id = subnet['subnet']['network_id']
            res = self._create_port(self.fmt, id)
            data = self.deserialize(self.fmt, res)
            msg = str(n_exc.IpAddressGenerationFailure(net_id=id))
            self.assertEqual(data['NeutronError']['message'], msg)
            self.assertEqual(res.status_int, webob.exc.HTTPConflict.code)

    def test_ports_vif_host(self):
        cfg.CONF.set_default('allow_overlapping_ips', True)
        host_arg = {portbindings.HOST_ID: self.hostname}
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, name='name1',
                          arg_list=(portbindings.HOST_ID,), **host_arg),\
                self.port(subnet, name='name2'):
            ctx = context.get_admin_context()
            ports = self._list('ports', neutron_context=ctx)['ports']
            self.assertEqual(2, len(ports))
            for port in ports:
                if port['name'] == 'name1':
                    self._check_response_portbindings_host(port)
                else:
                    self.assertFalse(port[portbindings.HOST_ID])
            # By default user is admin - now test non admin user
            ctx = context.Context(user_id=None,
                                  tenant_id=self._tenant_id,
                                  is_admin=False)
            ports = self._list('ports', neutron_context=ctx)['ports']
            self.assertEqual(2, len(ports))
            for non_admin_port in ports:
                self._check_response_no_portbindings_host(non_admin_port)

    def test_ports_vif_host_update(self):
        cfg.CONF.set_default('allow_overlapping_ips', True)
        host_arg = {portbindings.HOST_ID: self.hostname}
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, name='name1',
                          arg_list=(portbindings.HOST_ID,),
                          **host_arg) as port1,\
                self.port(subnet, name='name2') as port2:
            data = {'port': {portbindings.HOST_ID: 'testhosttemp'}}
            req = self.new_update_request(
                'ports', data, port1['port']['id'])
            req.get_response(self.api)
            req = self.new_update_request(
                'ports', data, port2['port']['id'])
            ctx = context.get_admin_context()
            req.get_response(self.api)
            ports = self._list('ports', neutron_context=ctx)['ports']
        self.assertEqual(2, len(ports))
        for port in ports:
            self.assertEqual('testhosttemp', port[portbindings.HOST_ID])

    def test_ports_vif_details(self):
        plugin = directory.get_plugin()
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet), self.port(subnet):
            ctx = context.get_admin_context()
            ports = plugin.get_ports(ctx)
            self.assertEqual(len(ports), 2)
            for port in ports:
                self._check_response_portbindings(port)
            # By default user is admin - now test non admin user
            ctx = self._get_non_admin_context()
            ports = self._list('ports', neutron_context=ctx)['ports']
            self.assertEqual(len(ports), 2)
            for non_admin_port in ports:
                self._check_response_no_portbindings(non_admin_port)

    def test_ports_vnic_type(self):
        cfg.CONF.set_default('allow_overlapping_ips', True)
        vnic_arg = {portbindings.VNIC_TYPE: self.vnic_type}
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, name='name1',
                          arg_list=(portbindings.VNIC_TYPE,), **vnic_arg),\
                self.port(subnet, name='name2'):
            ctx = context.get_admin_context()
            ports = self._list('ports', neutron_context=ctx)['ports']
            self.assertEqual(2, len(ports))
            for port in ports:
                if port['name'] == 'name1':
                    self._check_response_portbindings_vnic_type(port)
                else:
                    self.assertEqual(portbindings.VNIC_NORMAL,
                                     port[portbindings.VNIC_TYPE])
            # By default user is admin - now test non admin user
            ctx = context.Context(user_id=None,
                                  tenant_id=self._tenant_id,
                                  is_admin=False)
            ports = self._list('ports', neutron_context=ctx)['ports']
            self.assertEqual(2, len(ports))
            for non_admin_port in ports:
                self._check_response_portbindings_vnic_type(non_admin_port)

    def test_ports_vnic_type_list(self):
        cfg.CONF.set_default('allow_overlapping_ips', True)
        vnic_arg = {portbindings.VNIC_TYPE: self.vnic_type}
        with self.subnet(enable_dhcp=False) as subnet,\
                self.port(subnet, name='name1',
                          arg_list=(portbindings.VNIC_TYPE,),
                          **vnic_arg) as port1,\
                self.port(subnet, name='name2') as port2,\
                self.port(subnet, name='name3',
                          arg_list=(portbindings.VNIC_TYPE,),
                          **vnic_arg) as port3:

            self._test_list_resources('port', (port1, port2, port3),
                                      query_params='%s=%s' % (
                                          portbindings.VNIC_TYPE,
                                          self.vnic_type))

    def test_range_allocation(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_requested_subnet_id_v4_and_v6(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_update_port_update_ip(self):
        """Test update of port IP.

        Check that a configured IP 10.0.0.2 is replaced by 10.0.0.10.
        """
        with self.subnet(enable_dhcp=False) as subnet:
            fixed_ip_data = [{'ip_address': '10.0.0.2',
                             'subnet_id': subnet['subnet']['id']}]
            with self.port(subnet=subnet, fixed_ips=fixed_ip_data) as port:
                ips = port['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual('10.0.0.2', ips[0]['ip_address'])
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': "10.0.0.10"}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                ips = res['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual('10.0.0.10', ips[0]['ip_address'])
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])

    def test_update_port_update_ips(self):
        """Update IP and associate new IP on port.

        Check a port update with the specified subnet_id's. A IP address
        will be allocated for each subnet_id.
        """
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet) as port:
                data = {'port': {'admin_state_up': False,
                                 'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': '10.0.0.3'}]}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertEqual(data['port']['admin_state_up'],
                                 res['port']['admin_state_up'])
                ips = res['port']['fixed_ips']
                self.assertEqual(1, len(ips))
                self.assertEqual('10.0.0.3', ips[0]['ip_address'], '10.0.0.3')
                self.assertEqual(ips[0]['subnet_id'], subnet['subnet']['id'])

    def test_update_port_update_ip_dhcp(self):
        #Test updating a port IP when the device owner is DHCP
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet,
                           device_owner=constants.DEVICE_OWNER_DHCP) as port:
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': "10.0.0.10"}]}}
                plugin = directory.get_plugin()
                ctx = context.get_admin_context()
                with mock.patch.object(
                    plugin.edge_manager,
                    'update_dhcp_edge_service') as update_dhcp:
                    plugin.update_port(ctx, port['port']['id'], data)
                    self.assertTrue(update_dhcp.called)

    def test_update_port_update_ip_compute(self):
        #Test that updating a port IP succeed if the device owner starts
        #with compute.
        owner = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'xxx'
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet, device_id=_uuid(),
                           device_owner=owner) as port:
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': "10.0.0.10"}]}}
                plugin = directory.get_plugin()
                with mock.patch.object(
                    plugin.edge_manager,
                    'delete_dhcp_binding') as delete_dhcp:
                    with mock.patch.object(
                        plugin.edge_manager,
                        'create_static_binding') as create_static:
                        with mock.patch.object(
                            plugin.edge_manager,
                            'create_dhcp_bindings') as create_dhcp:
                            plugin.update_port(context.get_admin_context(),
                                               port['port']['id'], data)
                            self.assertTrue(delete_dhcp.called)
                            self.assertTrue(create_static.called)
                            self.assertTrue(create_dhcp.called)

    def test_update_port_update_ip_and_owner_fail(self):
        #Test that updating a port IP and device owner at the same
        #transaction fails
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet,
                           device_owner='aaa') as port:
                data = {'port': {'device_owner': 'bbb',
                                 'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': "10.0.0.10"}]}}
                plugin = directory.get_plugin()
                self.assertRaises(n_exc.BadRequest,
                                  plugin.update_port,
                                  context.get_admin_context(),
                                  port['port']['id'], data)

    def test_update_port_update_ip_router(self):
        #Test that updating a port IP succeed if the device owner is a router
        owner = constants.DEVICE_OWNER_ROUTER_GW
        router_id = _uuid()
        old_ip = '10.0.0.3'
        new_ip = '10.0.0.10'
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet, device_id=router_id,
                           device_owner=owner,
                           fixed_ips=[{'ip_address': old_ip}]) as port:
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': new_ip}]}}
                plugin = directory.get_plugin()
                ctx = context.get_admin_context()
                router_obj = router_driver.RouterSharedDriver(plugin)
                with mock.patch.object(plugin, '_find_router_driver',
                                       return_value=router_obj):
                    with mock.patch.object(
                        router_obj,
                        'update_router_interface_ip') as update_router:
                        port_id = port['port']['id']
                        plugin.update_port(ctx, port_id, data)
                        net_id = port['port']['network_id']
                        update_router.assert_called_once_with(
                            ctx,
                            router_id,
                            port_id,
                            net_id,
                            old_ip,
                            new_ip, "255.255.255.0")

    def test_update_port_update_ip_unattached_router(self):
        #Test that updating a port IP succeed if the device owner is a router
        #and the shared router is not attached to any edge yet
        owner = constants.DEVICE_OWNER_ROUTER_GW
        router_id = _uuid()
        old_ip = '10.0.0.3'
        new_ip = '10.0.0.10'
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet, device_id=router_id,
                           device_owner=owner,
                           fixed_ips=[{'ip_address': old_ip}]) as port:
                data = {'port': {'fixed_ips': [{'subnet_id':
                                                subnet['subnet']['id'],
                                                'ip_address': new_ip}]}}
                plugin = directory.get_plugin()
                ctx = context.get_admin_context()
                router_obj = router_driver.RouterSharedDriver(plugin)
                with mock.patch.object(plugin, '_find_router_driver',
                                       return_value=router_obj):
                    # make sure the router will not be attached to an edge
                    with mock.patch.object(
                        edge_utils, 'get_router_edge_id',
                        return_value=None):
                        port_id = port['port']['id']
                        # The actual test here is that this call does not
                        # raise an exception
                        new_port = plugin.update_port(ctx, port_id, data)
                        ips = new_port['fixed_ips']
                        self.assertEqual(len(ips), 1)
                        self.assertEqual(ips[0]['ip_address'], new_ip)
                        self.assertEqual(ips[0]['subnet_id'],
                                         subnet['subnet']['id'])

    def test_update_port_delete_ip_router(self):
        #Test that deleting a port IP succeed if the device owner is a router
        owner = constants.DEVICE_OWNER_ROUTER_GW
        router_id = _uuid()
        old_ip = '10.0.0.3'
        with self.subnet(enable_dhcp=False) as subnet:
            with self.port(subnet=subnet, device_id=router_id,
                           device_owner=owner,
                           fixed_ips=[{'ip_address': old_ip}]) as port:
                data = {'port': {'fixed_ips': []}}
                plugin = directory.get_plugin()
                ctx = context.get_admin_context()
                router_obj = router_driver.RouterSharedDriver(plugin)
                with mock.patch.object(plugin, '_find_router_driver',
                                       return_value=router_obj):
                    with mock.patch.object(
                        router_obj,
                        'update_router_interface_ip') as update_router:
                        port_id = port['port']['id']
                        plugin.update_port(ctx, port_id, data)
                        net_id = port['port']['network_id']
                        update_router.assert_called_once_with(
                            ctx,
                            router_id,
                            port_id,
                            net_id,
                            old_ip,
                            None, None)

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
                self.assertEqual(webob.exc.HTTPBadRequest.code,
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
            self.assertEqual(webob.exc.HTTPBadRequest.code,
                             res.status_int)

    def test_update_port_update_ip_address_only(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_requested_invalid_fixed_ips(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_requested_subnet_id_v4_and_v6_slaac(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_update_dhcp_port_with_exceeding_fixed_ips(self):
        self.skipTest('Updating dhcp port IP is not supported')

    def test_create_router_port_ipv4_and_ipv6_slaac_no_fixed_ips(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_port_with_multiple_ipv4_and_ipv6_subnets(self):
        # This test should fail as the NSX-v plugin should cause Neutron to
        # return a 400 status code
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            super(TestPortsV2, self).\
                test_create_port_with_multiple_ipv4_and_ipv6_subnets()
            self.assertEqual(ctx_manager.exception.code, 400)

    def test_list_ports_for_network_owner(self):
        with self.network(tenant_id='tenant_1') as network:
            with self.subnet(network, enable_dhcp=False) as subnet:
                with self.port(subnet, tenant_id='tenant_1') as port1,\
                        self.port(subnet, tenant_id='tenant_2') as port2:
                    # network owner request, should return all ports
                    port_res = self._list_ports(
                        'json', set_context=True, tenant_id='tenant_1')
                    port_list = self.deserialize('json', port_res)['ports']
                    port_ids = [p['id'] for p in port_list]
                    self.assertEqual(2, len(port_list))
                    self.assertIn(port1['port']['id'], port_ids)
                    self.assertIn(port2['port']['id'], port_ids)

                    # another tenant request, only return ports belong to it
                    port_res = self._list_ports(
                        'json', set_context=True, tenant_id='tenant_2')
                    port_list = self.deserialize('json', port_res)['ports']
                    port_ids = [p['id'] for p in port_list]
                    self.assertEqual(1, len(port_list))
                    self.assertNotIn(port1['port']['id'], port_ids)
                    self.assertIn(port2['port']['id'], port_ids)

    def test_mac_duplication(self):
        # create 2 networks
        res = self._create_network(fmt=self.fmt, name='net1',
                                   admin_state_up=True)
        network1 = self.deserialize(self.fmt, res)
        net1_id = network1['network']['id']

        res = self._create_network(fmt=self.fmt, name='net2',
                                   admin_state_up=True)
        network2 = self.deserialize(self.fmt, res)
        net2_id = network2['network']['id']

        # create a port on the first network
        mac = '33:00:00:00:00:01'
        res = self._create_port(self.fmt, net_id=net1_id,
                                arg_list=('mac_address',),
                                mac_address=mac)
        port1 = self.deserialize('json', res)
        self.assertEqual(mac, port1['port']['mac_address'])

        # creating another port on a different network with the same mac
        # should fail
        res = self._create_port(self.fmt, net_id=net2_id,
                                arg_list=('mac_address',),
                                mac_address=mac)
        port2 = self.deserialize('json', res)
        self.assertEqual("MacAddressInUse", port2['NeutronError']['type'])

    def _test_create_direct_network(self, vlan_id=0):
        net_type = vlan_id and 'vlan' or 'flat'
        name = 'direct_net'
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: 'tzuuid'}
        if vlan_id:
            providernet_args[pnet.SEGMENTATION_ID] = vlan_id
        return self.network(name=name,
                            providernet_args=providernet_args,
                            arg_list=(pnet.NETWORK_TYPE,
                                      pnet.PHYSICAL_NETWORK,
                                      pnet.SEGMENTATION_ID))

    def test_create_port_vnic_direct(self):
        with self._test_create_direct_network(vlan_id=7) as network:
            # Check that port security conflicts
            kwargs = {'binding:vnic_type': 'direct'}
            net_id = network['network']['id']
            res = self._create_port(self.fmt, net_id=net_id,
                                    arg_list=(portbindings.VNIC_TYPE,),
                                    **kwargs)
            self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

            # Check that security group conflicts
            kwargs = {'binding:vnic_type': 'direct',
                      'security_groups':
                          ['4cd70774-cc67-4a87-9b39-7d1db38eb087'],
                      'port_security_enabled': False}
            net_id = network['network']['id']
            res = self._create_port(self.fmt, net_id=net_id,
                                    arg_list=(portbindings.VNIC_TYPE,
                                              'port_security_enabled'),
                                    **kwargs)
            self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

            # All is kosher so we can create the port
            kwargs = {'binding:vnic_type': 'direct',
                      'port_security_enabled': False}
            net_id = network['network']['id']
            res = self._create_port(self.fmt, net_id=net_id,
                                    arg_list=(portbindings.VNIC_TYPE,
                                              'port_security_enabled'),
                                    **kwargs)
            port = self.deserialize('json', res)
            self.assertEqual("direct", port['port']['binding:vnic_type'])

    def test_create_port_vnic_direct_invalid_network(self):
        with self.network(name='not vlan/flat') as net:
            kwargs = {'binding:vnic_type': 'direct',
                      'port_security_enabled': False}
            net_id = net['network']['id']
            res = self._create_port(self.fmt, net_id=net_id,
                                    arg_list=(portbindings.VNIC_TYPE,
                                              'port_security_enabled'),
                                    **kwargs)
            self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

    def test_update_vnic_direct(self):
        with self._test_create_direct_network(vlan_id=7) as network:
            with self.subnet(network=network) as subnet:
                with self.port(subnet=subnet) as port:
                    # need to do two updates as the update for port security
                    # disabled requires that it can only change 2 items
                    data = {'port': {'port_security_enabled': False,
                                     'security_groups': []}}
                    req = self.new_update_request('ports',
                                                  data, port['port']['id'])
                    res = self.deserialize('json', req.get_response(self.api))
                    self.assertEqual('normal',
                                     res['port']['binding:vnic_type'])
                    data = {'port': {'binding:vnic_type': 'direct'}}
                    req = self.new_update_request('ports',
                                                  data, port['port']['id'])
                    res = self.deserialize('json', req.get_response(self.api))
                    self.assertEqual('direct',
                                     res['port']['binding:vnic_type'])

    def test_delete_network_port_exists_owned_by_network_port_not_found(self):
        """Tests that we continue to gracefully delete the network even if
        a neutron:dhcp-owned port was deleted concurrently.
        """
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        network_id = network['network']['id']
        self._create_port(self.fmt, network_id,
                          device_owner=constants.DEVICE_OWNER_DHCP)
        # Raise PortNotFound when trying to delete the port to simulate a
        # concurrent delete race; note that we actually have to delete the port
        # "out of band" otherwise deleting the network will fail because of
        # constraints in the data model.
        plugin = directory.get_plugin()
        orig_delete = plugin.delete_port

        def fake_delete_port(context, id, force_delete_dhcp=False):
            # Delete the port for real from the database and then raise
            # PortNotFound to simulate the race.
            self.assertIsNone(orig_delete(
                context, id,
                force_delete_dhcp=force_delete_dhcp))
            raise n_exc.PortNotFound(port_id=id)

        p = mock.patch.object(plugin, 'delete_port')
        mock_del_port = p.start()
        mock_del_port.side_effect = fake_delete_port
        req = self.new_delete_request('networks', network_id)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPNoContent.code, res.status_int)

    def test_create_port_sec_disabled_and_provider_rule(self):
        with self.network() as network:
            kwargs = {'provider_security_groups': [uuidutils.generate_uuid()],
                      'port_security_enabled': False}
            res = self._create_port(self.fmt,
                                    network['network']['id'],
                                    arg_list=('provider_security_groups',
                                              'port_security_enabled'),
                                **kwargs)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_update_port_sec_disabled_and_provider_rule(self):
        with self.port() as port:
            with mock.patch(
                PLUGIN_NAME + '._get_provider_security_groups_on_port'):
                data = {'port': {'port_security_enabled': False}}
                req = self.new_update_request('ports',
                                              data, port['port']['id'])
                res = self.deserialize('json', req.get_response(self.api))
        self.assertEqual("PortSecurityAndIPRequiredForSecurityGroups",
                         res['NeutronError']['type'])


class TestSubnetsV2(NsxVPluginV2TestCase,
                    test_plugin.TestSubnetsV2):
    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(TestSubnetsV2, self).setUp()
        self.context = context.get_admin_context()

    def _test_subnet_update_ipv4_and_ipv6_pd_subnets(self, ra_addr_mode):
        self.skipTest('No DHCP v6 Support yet')

    def test__subnet_ipv6_not_supported(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                               'gateway': 'fe80::1',
                               'cidr': '2607:f0d0:1002:51::/64',
                               'ip_version': '6',
                               'tenant_id': network['network']['tenant_id']}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(res.status_int, webob.exc.HTTPClientError.code)

    def test_create_subnet_ipv6_gw_is_nw_end_addr_returns_201(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_out_of_cidr_global(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_pd_gw_values(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_slaac_with_port_on_network(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_slaac_with_snat_intf_on_network(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_dhcpv6_stateless_with_port_on_network(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_slaac_with_dhcp_port_on_network(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_delete_subnet_ipv6_slaac_port_exists(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_slaac_with_router_intf_on_network(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_out_of_cidr_lla(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_subnet_inconsistent_ipv6_hostroute_dst_v4(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_only_ip_version_v6(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_subnet_ipv6_address_mode_fails(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_with_v6_allocation_pool(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_with_v6_pd_allocation_pool(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_subnet_ipv6_ra_mode_fails(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_delete_subnet_ipv6_slaac_router_port_exists(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_subnet_inconsistent_ipv6_hostroute_np_v4(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_subnet_inconsistent_ipv6_gatewayv4(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_subnet_ipv6_attributes_fails(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_subnet_ipv6_cannot_disable_dhcp(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_V6_pd_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_V6_pd_stateless(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_V6_pd_statefull(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_V6_pd_no_mode(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_slaac_with_ip_already_allocated(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_dhcpv6_stateless_with_ip_already_allocated(self):
        self.skipTest('No DHCP v6 Support yet')

    def _create_subnet_bulk(self, fmt, number, net_id, name,
                            ip_version=4, **kwargs):
        base_data = {'subnet': {'network_id': net_id,
                                'ip_version': ip_version,
                                'enable_dhcp': False,
                                'tenant_id': self._tenant_id}}
        # auto-generate cidrs as they should not overlap
        overrides = dict((k, v)
                         for (k, v) in zip(range(number),
                                           [{'cidr': "10.0.%s.0/24" % num}
                                            for num in range(number)]))
        kwargs.update({'override': overrides})
        return self._create_bulk(fmt, number, 'subnet', base_data, **kwargs)

    def test_create_subnet_nonzero_cidr(self):
            awkward_cidrs = [{'nonezero': '10.129.122.5/8',
                              'corrected': '10.0.0.0/8'},
                             {'nonezero': '11.129.122.5/15',
                              'corrected': '11.128.0.0/15'},
                             {'nonezero': '12.129.122.5/16',
                              'corrected': '12.129.0.0/16'},
                             {'nonezero': '13.129.122.5/18',
                              'corrected': '13.129.64.0/18'},
                             {'nonezero': '14.129.122.5/22',
                              'corrected': '14.129.120.0/22'},
                             {'nonezero': '15.129.122.5/24',
                              'corrected': '15.129.122.0/24'},
                             {'nonezero': '16.129.122.5/28',
                              'corrected': '16.129.122.0/28'}, ]

            for cidr in awkward_cidrs:
                with self.subnet(enable_dhcp=False,
                                 cidr=cidr['nonezero']) as subnet:
                    # the API should accept and correct these cidrs for users
                    self.assertEqual(cidr['corrected'],
                                     subnet['subnet']['cidr'])

            with self.subnet(enable_dhcp=False, cidr='17.129.122.5/32',
                             gateway_ip=None) as subnet:
                self.assertEqual('17.129.122.5/32', subnet['subnet']['cidr'])

    def test_create_subnet_ipv6_attributes(self):
        # Expected to fail for now as we don't support IPv6 for NSXv
        cidr = "fe80::/80"
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(cidr=cidr)
            self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_subnet_with_different_dhcp_server(self):
        self.mock_create_dhcp_service.stop()
        name = 'dvs-provider-net'
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 43,
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
        with self.network(name=name, do_delete=False,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.SEGMENTATION_ID,
                                    pnet.PHYSICAL_NETWORK)) as net:
            self._test_create_subnet(network=net, cidr='10.0.0.0/24')
            dhcp_router_id = (vcns_const.DHCP_EDGE_PREFIX +
                              net['network']['id'])[:36]
            dhcp_server_id = nsxv_db.get_nsxv_router_binding(
                self.context.session, dhcp_router_id)['edge_id']
            providernet_args_1 = {pnet.NETWORK_TYPE: 'vlan',
                                  pnet.SEGMENTATION_ID: 43,
                                  pnet.PHYSICAL_NETWORK: 'dvs-uuid-1'}
            with self.network(name=name, do_delete=False,
                              providernet_args=providernet_args_1,
                              arg_list=(pnet.NETWORK_TYPE,
                                        pnet.SEGMENTATION_ID,
                                        pnet.PHYSICAL_NETWORK)) as net1:
                self._test_create_subnet(network=net1, cidr='10.0.1.0/24')
                router_id = (vcns_const.DHCP_EDGE_PREFIX +
                             net1['network']['id'])[:36]
                dhcp_server_id_1 = nsxv_db.get_nsxv_router_binding(
                    self.context.session, router_id)['edge_id']
                self.assertNotEqual(dhcp_server_id, dhcp_server_id_1)

    def test_create_subnet_with_different_dhcp_by_flat_net(self):
        self.mock_create_dhcp_service.stop()
        name = 'flat-net'
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
        with self.network(name=name, do_delete=False,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK)) as net:
            self._test_create_subnet(network=net, cidr='10.0.0.0/24')
            dhcp_router_id = (vcns_const.DHCP_EDGE_PREFIX +
                              net['network']['id'])[:36]
            dhcp_server_id = nsxv_db.get_nsxv_router_binding(
                self.context.session, dhcp_router_id)['edge_id']
            providernet_args_1 = {pnet.NETWORK_TYPE: 'flat',
                                  pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
            with self.network(name=name, do_delete=False,
                              providernet_args=providernet_args_1,
                              arg_list=(pnet.NETWORK_TYPE,
                                        pnet.PHYSICAL_NETWORK)) as net1:
                self._test_create_subnet(network=net1, cidr='10.0.1.0/24')
                router_id = (vcns_const.DHCP_EDGE_PREFIX +
                             net1['network']['id'])[:36]
                dhcp_server_id_1 = nsxv_db.get_nsxv_router_binding(
                    self.context.session, router_id)['edge_id']
                self.assertNotEqual(dhcp_server_id, dhcp_server_id_1)

    def test_create_subnet_ipv6_slaac_with_db_reference_error(self):
        self.skipTest('Currently not supported')

    def test_create_subnet_ipv6_slaac_with_port_not_found(self):
        self.skipTest('Currently not supported')

    def test_create_subnet_ipv6_gw_values(self):
        # This test should fail with response code 400 as IPv6 subnets with
        # DHCP are not supported by this plugin
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            super(TestSubnetsV2, self).test_create_subnet_ipv6_gw_values()
            self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_subnet_only_ip_version_v6_old(self):
        self.skipTest('Currently not supported')

    def test_create_subnet_reserved_network(self):
        self.mock_create_dhcp_service.stop()
        name = 'overlap-reserved-net'
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            with self.network(name=name, do_delete=False,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.SEGMENTATION_ID,
                                    pnet.PHYSICAL_NETWORK)) as net:
                self._test_create_subnet(network=net,
                                         cidr='169.254.128.128/25')
                self.assertEqual(ctx_manager.exception.code, 400)


class TestSubnetPoolsV2(NsxVPluginV2TestCase, test_plugin.TestSubnetsV2):
    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(TestSubnetPoolsV2, self).setUp()
        self.context = context.get_admin_context()

    def test_subnet_update_ipv4_and_ipv6_pd_slaac_subnets(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_subnet_update_ipv4_and_ipv6_pd_v6stateless_subnets(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_gw_is_nw_end_addr_returns_201(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_out_of_cidr_global(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_V6_pd_stateless(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_V6_pd_slaac(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_ipv6_slaac_with_ip_already_allocated(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_dhcpv6_stateless_with_ip_already_allocated(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_subnet_dhcpv6_stateless_with_port_on_network(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_gw_values(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_out_of_cidr_lla(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_pd_gw_values(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_slaac_with_db_reference_error(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_slaac_with_port_not_found(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_slaac_with_dhcp_port_on_network(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_slaac_with_port_on_network(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_slaac_with_router_intf_on_network(self):
        self.skipTest('Not supported')

    def test_create_subnet_ipv6_slaac_with_snat_intf_on_network(self):
        self.skipTest('Not supported')

    def test_create_subnet_only_ip_version_v6(self):
        self.skipTest('Not supported')

    def test_create_subnet_with_v6_allocation_pool(self):
        self.skipTest('Not supported')

    def test_create_subnet_with_v6_pd_allocation_pool(self):
        self.skipTest('Not supported')

    def test_delete_subnet_ipv6_slaac_port_exists(self):
        self.skipTest('Not supported')

    def test_delete_subnet_ipv6_slaac_router_port_exists(self):
        self.skipTest('Not supported')

    def test_update_subnet_inconsistent_ipv6_gatewayv4(self):
        self.skipTest('Not supported')

    def test_update_subnet_inconsistent_ipv6_hostroute_dst_v4(self):
        self.skipTest('Not supported')

    def test_update_subnet_inconsistent_ipv6_hostroute_np_v4(self):
        self.skipTest('Not supported')

    def test_update_subnet_ipv6_address_mode_fails(self):
        self.skipTest('Not supported')

    def test_update_subnet_ipv6_attributes_fails(self):
        self.skipTest('Not supported')

    def test_update_subnet_ipv6_cannot_disable_dhcp(self):
        self.skipTest('Not supported')

    def test_update_subnet_ipv6_ra_mode_fails(self):
        self.skipTest('Not supported')

    def test_create_subnet_only_ip_version_v6_old(self):
        self.skipTest('Currently not supported')


class TestBasicGet(test_plugin.TestBasicGet, NsxVPluginV2TestCase):
    pass


class TestV2HTTPResponse(test_plugin.TestV2HTTPResponse, NsxVPluginV2TestCase):
    pass


class TestL3ExtensionManager(object):

    def get_resources(self):
        # Simulate extension of L3 attribute map
        # First apply attribute extensions
        for key in l3.RESOURCE_ATTRIBUTE_MAP.keys():
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                l3_ext_gw_mode.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                dist_router.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                router_type.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                router_size.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                router_availability_zone.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                l3_flavors.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
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


class L3NatTest(test_l3_plugin.L3BaseForIntTests, NsxVPluginV2TestCase):

    def _restore_l3_attribute_map(self):
        l3.RESOURCE_ATTRIBUTE_MAP = self._l3_attribute_map_bk

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None, service_plugins=None):
        self._l3_attribute_map_bk = {}
        for item in l3.RESOURCE_ATTRIBUTE_MAP:
            self._l3_attribute_map_bk[item] = (
                l3.RESOURCE_ATTRIBUTE_MAP[item].copy())
        cfg.CONF.set_override('task_status_check_interval', 200, group="nsxv")

        cfg.CONF.set_override('api_extensions_path', vmware.NSXEXT_PATH)
        l3_attribute_map_bk = backup_l3_attribute_map()
        self.addCleanup(restore_l3_attribute_map, l3_attribute_map_bk)
        ext_mgr = ext_mgr or TestL3ExtensionManager()
        super(L3NatTest, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        self.plugin_instance = directory.get_plugin()
        self._plugin_name = "%s.%s" % (
            self.plugin_instance.__module__,
            self.plugin_instance.__class__.__name__)
        self._plugin_class = self.plugin_instance.__class__

    def tearDown(self):
        plugin = directory.get_plugin()
        _manager = plugin.nsx_v.task_manager
        # wait max ~10 seconds for all tasks to be finished
        for i in range(100):
            if not _manager.has_pending_task():
                break
            greenthread.sleep(0.1)
        if _manager.has_pending_task():
            _manager.show_pending_tasks()
            raise Exception(_("Tasks not completed"))
        _manager.stop()
        # Ensure the manager thread has been stopped
        self.assertIsNone(_manager._thread)
        super(L3NatTest, self).tearDown()

    def _create_l3_ext_network(self, vlan_id=None):
        name = 'l3_ext_net'
        return self.network(name=name,
                            router__external=True)

    def _create_router(self, fmt, tenant_id, name=None,
                       admin_state_up=None, set_context=False,
                       arg_list=None, **kwargs):
        tenant_id = tenant_id or _uuid()
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up:
            data['router']['admin_state_up'] = admin_state_up
        for arg in (('admin_state_up', 'tenant_id')
                   + (arg_list or ())):
            # Arg must be present and not empty
            if kwargs.get(arg):
                data['router'][arg] = kwargs[arg]
        router_req = self.new_create_request('routers', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            router_req.environ['neutron.context'] = context.Context(
                '', tenant_id)

        return router_req.get_response(self.ext_api)

    def _make_router(self, fmt, tenant_id, name=None, admin_state_up=None,
                     external_gateway_info=None, set_context=False,
                     arg_list=None, **kwargs):
        if external_gateway_info:
            arg_list = ('external_gateway_info', ) + (arg_list or ())
        res = self._create_router(fmt, tenant_id, name,
                                  admin_state_up, set_context,
                                  arg_list=arg_list,
                                  external_gateway_info=external_gateway_info,
                                  **kwargs)
        return self.deserialize(fmt, res)

    @contextlib.contextmanager
    def router(self, name=None, admin_state_up=True,
               fmt=None, tenant_id=None,
               external_gateway_info=None, set_context=False,
               **kwargs):
        # avoid name duplication of edge
        if not name:
            name = _uuid()
        router = self._make_router(fmt or self.fmt, tenant_id, name,
                                   admin_state_up, external_gateway_info,
                                   set_context, **kwargs)
        yield router

    def _recursive_sort_list(self, lst):
        sorted_list = []
        for ele in lst:
            if isinstance(ele, list):
                sorted_list.append(self._recursive_sort_list(ele))
            elif isinstance(ele, dict):
                sorted_list.append(self._recursive_sort_dict(ele))
            else:
                sorted_list.append(ele)
        return sorted(sorted_list, key=helpers.safe_sort_key)

    def _recursive_sort_dict(self, dct):
        sorted_dict = {}
        for k, v in dct.items():
            if isinstance(v, list):
                sorted_dict[k] = self._recursive_sort_list(v)
            elif isinstance(v, dict):
                sorted_dict[k] = self._recursive_sort_dict(v)
            else:
                sorted_dict[k] = v
        return sorted_dict

    def _update_router_enable_snat(self, router_id, network_id, enable_snat):
        return self._update('routers', router_id,
                            {'router': {'external_gateway_info':
                                        {'network_id': network_id,
                                         'enable_snat': enable_snat}}})

    def test_floatingip_association_on_unowned_router(self):
        self.skipTest("Currently no support in plugin for this")

    def test_router_add_gateway_no_subnet(self):
        self.skipTest('No support for no subnet gateway set')

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

    def _set_net_external(self, net_id):
        self._update('networks', net_id,
                     {'network': {external_net.EXTERNAL: True}})

    def _add_external_gateway_to_router(self, router_id, network_id,
                                        expected_code=webob.exc.HTTPOk.code,
                                        neutron_context=None, ext_ips=None):
        ext_ips = ext_ips or []
        body = {'router':
                {'external_gateway_info': {'network_id': network_id}}}
        if ext_ips:
            body['router']['external_gateway_info'][
                'external_fixed_ips'] = ext_ips
        return self._update('routers', router_id, body,
                            expected_code=expected_code,
                            neutron_context=neutron_context)

    def test_router_add_gateway_no_subnet_forbidden(self):
        with self.router() as r:
            with self.network() as n:
                self._set_net_external(n['network']['id'])
                self._add_external_gateway_to_router(
                    r['router']['id'], n['network']['id'],
                    expected_code=webob.exc.HTTPBadRequest.code)


class L3NatTestCaseBase(test_l3_plugin.L3NatTestCaseMixin):

    def test_create_floatingip_with_specific_ip(self):
        with self.subnet(cidr='10.0.0.0/24',
                         enable_dhcp=False) as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            fp = self._make_floatingip(self.fmt, network_id,
                                       floating_ip='10.0.0.10')
            self.assertEqual('10.0.0.10',
                             fp['floatingip']['floating_ip_address'])

    def test_floatingip_same_external_and_internal(self):
        # Select router with subnet's gateway_ip for floatingip when
        # routers connected to same subnet and external network.
        with self.subnet(cidr="10.0.0.0/24", enable_dhcp=False) as exs,\
                self.subnet(cidr="12.0.0.0/24",
                            gateway_ip="12.0.0.50",
                            enable_dhcp=False) as ins:
            network_ex_id = exs['subnet']['network_id']
            self._set_net_external(network_ex_id)

            r2i_fixed_ips = [{'ip_address': '12.0.0.2'}]
            with self.router() as r1,\
                    self.router() as r2,\
                    self.port(subnet=ins,
                              fixed_ips=r2i_fixed_ips) as r2i_port:
                self._add_external_gateway_to_router(
                    r1['router']['id'],
                    network_ex_id)
                self._router_interface_action('add', r2['router']['id'],
                                              None,
                                              r2i_port['port']['id'])
                self._router_interface_action('add', r1['router']['id'],
                                              ins['subnet']['id'],
                                              None)
                self._add_external_gateway_to_router(
                    r2['router']['id'],
                    network_ex_id)

                with self.port(subnet=ins,
                               fixed_ips=[{'ip_address': '12.0.0.8'}]
                               ) as private_port:

                    fp = self._make_floatingip(self.fmt, network_ex_id,
                                            private_port['port']['id'])
                    self.assertEqual(r1['router']['id'],
                                     fp['floatingip']['router_id'])

    def test_create_floatingip_with_specific_ip_out_of_allocation(self):
        with self.subnet(cidr='10.0.0.0/24',
                         allocation_pools=[
                             {'start': '10.0.0.10', 'end': '10.0.0.20'}],
                         enable_dhcp=False) as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            fp = self._make_floatingip(self.fmt, network_id,
                                       floating_ip='10.0.0.30')
            self.assertEqual('10.0.0.30',
                             fp['floatingip']['floating_ip_address'])

    def test_create_floatingip_with_specific_ip_non_admin(self):
        ctx = context.Context('user_id', 'tenant_id')

        with self.subnet(cidr='10.0.0.0/24',
                         enable_dhcp=False) as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            self._make_floatingip(self.fmt, network_id,
                                  set_context=ctx,
                                  floating_ip='10.0.0.10',
                                  http_status=webob.exc.HTTPForbidden.code)

    def test_create_floatingip_with_specific_ip_out_of_subnet(self):

        with self.subnet(cidr='10.0.0.0/24',
                         enable_dhcp=False) as s:
            network_id = s['subnet']['network_id']
            self._set_net_external(network_id)
            self._make_floatingip(self.fmt, network_id,
                                  floating_ip='10.0.1.10',
                                  http_status=webob.exc.HTTPBadRequest.code)

    def test_floatingip_multi_external_one_internal(self):
        with self.subnet(cidr="10.0.0.0/24", enable_dhcp=False) as exs1,\
                self.subnet(cidr="11.0.0.0/24", enable_dhcp=False) as exs2,\
                self.subnet(cidr="12.0.0.0/24", enable_dhcp=False) as ins1:
            network_ex_id1 = exs1['subnet']['network_id']
            network_ex_id2 = exs2['subnet']['network_id']
            self._set_net_external(network_ex_id1)
            self._set_net_external(network_ex_id2)

            r2i_fixed_ips = [{'ip_address': '12.0.0.2'}]
            with self.router() as r1,\
                    self.router() as r2,\
                    self.port(subnet=ins1,
                              fixed_ips=r2i_fixed_ips) as r2i_port:
                self._add_external_gateway_to_router(
                    r1['router']['id'],
                    network_ex_id1)
                self._router_interface_action('add', r1['router']['id'],
                                              ins1['subnet']['id'],
                                              None)
                self._add_external_gateway_to_router(
                    r2['router']['id'],
                    network_ex_id2)
                self._router_interface_action('add', r2['router']['id'],
                                              None,
                                              r2i_port['port']['id'])

                with self.port(subnet=ins1,
                               fixed_ips=[{'ip_address': '12.0.0.3'}]
                               ) as private_port:

                    fp1 = self._make_floatingip(self.fmt, network_ex_id1,
                                            private_port['port']['id'])
                    fp2 = self._make_floatingip(self.fmt, network_ex_id2,
                                            private_port['port']['id'])
                    self.assertEqual(fp1['floatingip']['router_id'],
                                     r1['router']['id'])
                    self.assertEqual(fp2['floatingip']['router_id'],
                                     r2['router']['id'])

    def test_create_floatingip_with_multisubnet_id(self):
        with self.network() as network:
            self._set_net_external(network['network']['id'])
            with self.subnet(network,
                             enable_dhcp=False,
                             cidr='10.0.12.0/24') as subnet1:
                with self.subnet(network,
                                 enable_dhcp=False,
                                 cidr='10.0.13.0/24') as subnet2:
                    with self.router():
                        res = self._create_floatingip(
                            self.fmt,
                            subnet1['subnet']['network_id'],
                            subnet_id=subnet1['subnet']['id'])
                        fip1 = self.deserialize(self.fmt, res)
                        res = self._create_floatingip(
                            self.fmt,
                            subnet1['subnet']['network_id'],
                            subnet_id=subnet2['subnet']['id'])
                        fip2 = self.deserialize(self.fmt, res)
        self.assertTrue(
            fip1['floatingip']['floating_ip_address'].startswith('10.0.12'))
        self.assertTrue(
            fip2['floatingip']['floating_ip_address'].startswith('10.0.13'))

    def test_create_floatingip_with_wrong_subnet_id(self):
        with self.network() as network1:
            self._set_net_external(network1['network']['id'])
            with self.subnet(network1,
                             enable_dhcp=False,
                             cidr='10.0.12.0/24') as subnet1:
                with self.network() as network2:
                    self._set_net_external(network2['network']['id'])
                    with self.subnet(network2,
                                     enable_dhcp=False,
                                     cidr='10.0.13.0/24') as subnet2:
                        with self.router():
                            res = self._create_floatingip(
                                self.fmt,
                                subnet1['subnet']['network_id'],
                                subnet_id=subnet2['subnet']['id'])
        self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

    @mock.patch.object(edge_utils, "update_firewall")
    def test_router_set_gateway_with_nosnat(self, mock):
        expected_fw = [{'action': 'allow',
                        'enabled': True,
                        'name': 'Subnet Rule',
                        'source_ip_address': [],
                        'destination_ip_address': []}]
        nosnat_fw = [{'action': 'allow',
                      'enabled': True,
                      'name': 'No SNAT Rule',
                      'source_vnic_groups': ["external"],
                      'destination_ip_address': []}]

        with self.router() as r1,\
                self.subnet() as ext_subnet,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(cidr='12.0.0.0/24') as s2:
            self._set_net_external(ext_subnet['subnet']['network_id'])

            self._router_interface_action(
                'add', r1['router']['id'],
                s1['subnet']['id'], None)
            expected_fw[0]['source_ip_address'] = ['11.0.0.0/24']
            expected_fw[0]['destination_ip_address'] = ['11.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(self._recursive_sort_list(expected_fw),
                             self._recursive_sort_list(fw_rules))
            self._add_external_gateway_to_router(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'])
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(self._recursive_sort_list(expected_fw),
                             self._recursive_sort_list(fw_rules))
            self._update_router_enable_snat(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'],
                False)
            nosnat_fw[0]['destination_ip_address'] = ['11.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw + nosnat_fw),
                self._recursive_sort_list(fw_rules))
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            expected_fw[0]['source_ip_address'] = ['12.0.0.0/24',
                                                   '11.0.0.0/24']
            expected_fw[0]['destination_ip_address'] = ['12.0.0.0/24',
                                                        '11.0.0.0/24']
            nosnat_fw[0]['destination_ip_address'] = ['11.0.0.0/24',
                                                      '12.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw + nosnat_fw),
                self._recursive_sort_list(fw_rules))
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            expected_fw[0]['source_ip_address'] = ['12.0.0.0/24']
            expected_fw[0]['destination_ip_address'] = ['12.0.0.0/24']
            nosnat_fw[0]['destination_ip_address'] = ['12.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw + nosnat_fw),
                self._recursive_sort_list(fw_rules))
            self._update_router_enable_snat(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'],
                True)
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw),
                self._recursive_sort_list(fw_rules))
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._remove_external_gateway_from_router(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'])

    def test_router_add_interface_port_bad_tenant_returns_404(self):
        self.skipTest('TBD')

    def test_router_add_interface_subnet_with_bad_tenant_returns_404(self):
        self.skipTest('TBD')

    def test_create_floatingip_ipv6_only_network_returns_400(self):
        with self.subnet(cidr="2001:db8::/48", ip_version=6,
                         enable_dhcp=False) as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            res = self._create_floatingip(
                self.fmt,
                public_sub['subnet']['network_id'])
            self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

    def test_create_floatingip_ipv6_and_ipv4_network_creates_ipv4(self):
        with self.network() as n,\
                self.subnet(cidr="2001:db8::/48", ip_version=6, network=n,
                            enable_dhcp=False),\
                self.subnet(cidr="192.168.1.0/24", ip_version=4, network=n,
                            enable_dhcp=False):
            self._set_net_external(n['network']['id'])
            fip = self._make_floatingip(self.fmt, n['network']['id'])
            fip_set = netaddr.IPSet(netaddr.IPNetwork("192.168.1.0/24"))
            fip_ip = fip['floatingip']['floating_ip_address']
            self.assertIn(netaddr.IPAddress(fip_ip), fip_set)

    def test_create_floatingip_with_assoc_to_ipv6_subnet(self):
        with self.subnet() as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.subnet(cidr="2001:db8::/48",
                             ip_version=6, enable_dhcp=False) as private_sub:
                with self.port(subnet=private_sub) as private_port:
                    res = self._create_floatingip(
                        self.fmt,
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'])
                    self.assertEqual(res.status_int,
                                     webob.exc.HTTPBadRequest.code)

    def test_create_floatingip_with_assoc_to_ipv4_and_ipv6_port(self):
        with self.network() as n,\
                self.subnet(cidr='10.0.0.0/24', network=n) as s4,\
                self.subnet(cidr='2001:db8::/64', ip_version=6, network=n,
                            enable_dhcp=False),\
                self.port(subnet=s4) as p:
            self.assertEqual(len(p['port']['fixed_ips']), 2)
            ipv4_address = next(i['ip_address'] for i in
                    p['port']['fixed_ips'] if
                    netaddr.IPAddress(i['ip_address']).version == 4)
            with self.floatingip_with_assoc(port_id=p['port']['id']) as fip:
                self.assertEqual(fip['floatingip']['fixed_ip_address'],
                                 ipv4_address)
                floating_ip = netaddr.IPAddress(
                        fip['floatingip']['floating_ip_address'])
                self.assertEqual(floating_ip.version, 4)

    def test_router_add_interface_multiple_ipv6_subnets_same_net(self):
        """Test router-interface-add for multiple ipv6 subnets on a network.

        Verify that adding multiple ipv6 subnets from the same network
        to a router places them all on the same router interface.
        """
        with self.router() as r, self.network() as n:
            with (self.subnet(network=n, cidr='fd00::1/64',
                              enable_dhcp=False, ip_version=6)
                  ) as s1, self.subnet(network=n, cidr='fd01::1/64',
                                       ip_version=6, enable_dhcp=False) as s2:
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s1['subnet']['id'],
                                                         None)
                    pid1 = body['port_id']
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s2['subnet']['id'],
                                                         None)
                    pid2 = body['port_id']
                    self.assertEqual(pid1, pid2)
                    port = self._show('ports', pid1)
                    self.assertEqual(2, len(port['port']['fixed_ips']))
                    port_subnet_ids = [fip['subnet_id'] for fip in
                                       port['port']['fixed_ips']]
                    self.assertIn(s1['subnet']['id'], port_subnet_ids)
                    self.assertIn(s2['subnet']['id'], port_subnet_ids)
                    self._router_interface_action('remove', r['router']['id'],
                                                  s1['subnet']['id'], None)
                    self._router_interface_action('remove', r['router']['id'],
                                                  s2['subnet']['id'], None)

    def test_router_add_interface_multiple_ipv6_subnets_different_net(self):
        """Test router-interface-add for ipv6 subnets on different networks.

        Verify that adding multiple ipv6 subnets from different networks
        to a router places them on different router interfaces.
        """
        with self.router() as r, self.network() as n1, self.network() as n2:
            with (self.subnet(network=n1, cidr='fd00::1/64',
                              enable_dhcp=False, ip_version=6)
                  ) as s1, self.subnet(network=n2, cidr='fd01::1/64',
                                       ip_version=6, enable_dhcp=False) as s2:
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s1['subnet']['id'],
                                                         None)
                    pid1 = body['port_id']
                    body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s2['subnet']['id'],
                                                         None)
                    pid2 = body['port_id']
                    self.assertNotEqual(pid1, pid2)
                    self._router_interface_action('remove', r['router']['id'],
                                                  s1['subnet']['id'], None)
                    self._router_interface_action('remove', r['router']['id'],
                                                  s2['subnet']['id'], None)

    def test_router_add_interface_ipv6_port_existing_network_returns_400(self):
        """Ensure unique IPv6 router ports per network id.
        Adding a router port containing one or more IPv6 subnets with the same
        network id as an existing router port should fail. This is so
        there is no ambiguity regarding on which port to add an IPv6 subnet
        when executing router-interface-add with a subnet and no port.
        """
        with self.network() as n, self.router() as r:
            with self.subnet(network=n, cidr='fd00::/64',
                             ip_version=6, enable_dhcp=False) as s1, (
                 self.subnet(network=n, cidr='fd01::/64',
                             ip_version=6, enable_dhcp=False)) as s2:
                with self.port(subnet=s1) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)
                    exp_code = webob.exc.HTTPBadRequest.code
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'],
                                                  expected_code=exp_code)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)

    def test_router_add_interface_ipv6_subnet_without_gateway_ip(self):
        with self.router() as r:
            with self.subnet(ip_version=6, cidr='fe80::/64',
                             gateway_ip=None, enable_dhcp=False) as s:
                error_code = webob.exc.HTTPBadRequest.code
                self._router_interface_action('add',
                                              r['router']['id'],
                                              s['subnet']['id'],
                                              None,
                                              expected_code=error_code)

    def test_subnet_dhcp_metadata_with_update(self):
        self.plugin_instance.metadata_proxy_handler = mock.Mock()
        with self.subnet(cidr="10.0.0.0/24", enable_dhcp=True) as s1:
            subnet_id = s1['subnet']['id']
            is_dhcp_meta = self.plugin_instance.is_dhcp_metadata(
                context.get_admin_context(), subnet_id)
            self.assertTrue(is_dhcp_meta)
            port_data = {'port': {'tenant_id': s1['subnet']['tenant_id'],
                                  'network_id': s1['subnet']['network_id'],
                                  'device_owner': 'compute:None'}}
            req = self.new_create_request(
                'ports', port_data).get_response(self.api)
            port_req = self.deserialize(self.fmt, req)
            subnet_data = {'subnet': {'enable_dhcp': False}}
            self.new_update_request(
                'subnets', subnet_data,
                s1['subnet']['id']).get_response(self.api)
            is_dhcp_meta = self.plugin_instance.is_dhcp_metadata(
                context.get_admin_context(), subnet_id)
            self.assertFalse(is_dhcp_meta)
            self.new_delete_request('ports', port_req['port']['id'])

    def test_router_delete_ipv6_slaac_subnet_inuse_returns_409(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_router_delete_dhcpv6_stateless_subnet_inuse_returns_409(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_router_add_iface_ipv6_ext_ra_subnet_returns_400(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_router_remove_ipv6_subnet_from_interface(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_router_update_gateway_add_multiple_prefixes_ipv6(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_router_concurrent_delete_upon_subnet_create(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_router_update_gateway_upon_subnet_create_ipv6(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_router_update_gateway_upon_subnet_create_max_ips_ipv6(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_floatingip_via_router_interface_returns_201(self):
        self.skipTest('not supported')

    def test_floatingip_via_router_interface_returns_404(self):
        self.skipTest('not supported')

    def test_floatingip_update_subnet_gateway_disabled(self):
        self.skipTest('not supported')


class IPv6ExpectedFailuresTestMixin(object):

    def test_router_add_interface_ipv6_subnet(self):
        self.skipTest('Not supported')

    def test_router_add_iface_ipv6_ext_ra_subnet_returns_400(self):
        # This returns a 400 too, but as an exception is raised the response
        # code need to be asserted differently
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            super(IPv6ExpectedFailuresTestMixin, self).\
                test_router_add_iface_ipv6_ext_ra_subnet_returns_400()
            self.assertEqual(ctx_manager.exception.code, 400)

    def test_router_add_gateway_multiple_subnets_ipv6(self):
        self.skipTest('not supported')


class TestExclusiveRouterTestCase(L3NatTest, L3NatTestCaseBase,
                                  test_l3_plugin.L3NatDBIntTestCase,
                                  IPv6ExpectedFailuresTestMixin,
                                  NsxVPluginV2TestCase,
                                  test_address_scope.AddressScopeTestCase):

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None, service_plugins=None):
        super(TestExclusiveRouterTestCase, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        self.plugin_instance.nsx_v.is_subnet_in_use = mock.Mock()
        self.plugin_instance.nsx_v.is_subnet_in_use.return_value = False
        self._default_tenant_id = self._tenant_id
        self._router_tenant_id = 'test-router-tenant'

    def _create_router(self, fmt, tenant_id, name=None,
                       admin_state_up=None, set_context=False,
                       arg_list=None, **kwargs):
        tenant_id = tenant_id or _uuid()
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up:
            data['router']['admin_state_up'] = admin_state_up
        for arg in (('admin_state_up', 'tenant_id') + (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs and kwargs[arg]:
                data['router'][arg] = kwargs[arg]

        data['router']['router_type'] = kwargs.get('router_type', 'exclusive')

        router_req = self.new_create_request('routers', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            router_req.environ['neutron.context'] = context.Context(
                '', tenant_id)

        return router_req.get_response(self.ext_api)

    def _test_create_l3_ext_network(self, vlan_id=0):
        name = 'l3_ext_net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (external_net.EXTERNAL, True)]
        with self._create_l3_ext_network(vlan_id) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_router_fail_at_the_backend(self):
        p = directory.get_plugin()
        edge_manager = p.edge_manager
        with mock.patch.object(edge_manager, 'create_lrouter',
                               side_effect=[n_exc.NeutronException]):
            router = {'router': {'admin_state_up': True,
                      'name': 'e161be1d-0d0d-4046-9823-5a593d94f72c',
                      'tenant_id': 'fake_tenant',
                      'router_type': 'exclusive'}}
            self.assertRaises(n_exc.NeutronException,
                              p.create_router,
                              context.get_admin_context(),
                              router)
            self._test_list_resources('router', ())

    def test_create_l3_ext_network_with_dhcp(self):
        with self._create_l3_ext_network() as net:
            with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
                with self.subnet(network=net):
                    self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_l3_ext_network_without_vlan(self):
        self._test_create_l3_ext_network()

    def _test_router_create_with_gwinfo_and_l3_ext_net(self, vlan_id=None,
                                                       validate_ext_gw=False,
                                                       router_ctx=None):
        tenant_id = self._router_tenant_id if router_ctx else self._tenant_id
        with self._create_l3_ext_network(vlan_id) as net:
            with self.subnet(network=net, enable_dhcp=False) as s:
                data = {'router': {'tenant_id': tenant_id}}
                data['router']['name'] = 'router1'
                data['router']['external_gateway_info'] = {
                    'network_id': s['subnet']['network_id']}
                router_req = self.new_create_request(
                    'routers', data, self.fmt, context=router_ctx)
                res = router_req.get_response(self.ext_api)
                router = self.deserialize(self.fmt, res)
                self.assertEqual(
                    s['subnet']['network_id'],
                    (router['router']['external_gateway_info']
                     ['network_id']))
                if validate_ext_gw:
                    pass

    def test_router_create_with_gwinfo_and_l3_ext_net(self):
        self._test_router_create_with_gwinfo_and_l3_ext_net()

    def test_router_create_with_gwinfo_and_l3_ext_net_with_vlan(self):
        self._test_router_create_with_gwinfo_and_l3_ext_net(444)

    def test_router_create_with_gwinfo_and_l3_ext_net_with_non_admin(self):
        ctx = context.Context(user_id=None,
                              tenant_id=self._router_tenant_id,
                              is_admin=False)
        self._test_router_create_with_gwinfo_and_l3_ext_net(router_ctx=ctx)

    def test_router_create_with_different_sizes(self):
        data = {'router': {
                    'tenant_id': 'whatever',
                    'name': 'test_router',
                    'router_type': 'exclusive'}}
        for size in ['compact', 'large', 'xlarge', 'quadlarge']:
            data['router']['router_size'] = size
            router_req = self.new_create_request('routers', data, self.fmt)
            res = router_req.get_response(self.ext_api)
            router = self.deserialize(self.fmt, res)
            self.assertEqual(size, router['router']['router_size'])

    def test_router_create_overriding_default_edge_size(self):
        data = {'router': {
                    'tenant_id': 'whatever',
                    'name': 'test_router',
                    'router_type': 'exclusive'}}
        cfg.CONF.set_override('exclusive_router_appliance_size',
                              'xlarge', group='nsxv')
        router_req = self.new_create_request('routers', data, self.fmt)
        res = router_req.get_response(self.ext_api)
        router = self.deserialize(self.fmt, res)
        self.assertEqual('xlarge', router['router']['router_size'])

    def test_router_add_gateway_invalid_network_returns_404(self):
        # NOTE(salv-orlando): This unit test has been overridden
        # as the nsx plugin support the ext_gw_mode extension
        # which mandates an uuid for the external network identifier
        with self.router() as r:
            self._add_external_gateway_to_router(
                r['router']['id'],
                uuidutils.generate_uuid(),
                expected_code=webob.exc.HTTPNotFound.code)

    def test_router_rename(self):
        with self.router(name='old_name') as r:
            with mock.patch.object(edge_appliance_driver.EdgeApplianceDriver,
                       'rename_edge') as edge_rename:
                new_name = 'new_name'
                router_id = r['router']['id']
                # get the edge of this router
                plugin = directory.get_plugin()
                router_obj = ex_router_driver.RouterExclusiveDriver(plugin)
                ctx = context.get_admin_context()
                edge_id = router_obj._get_edge_id_or_raise(ctx, router_id)

                # update the name

                body = self._update('routers', router_id,
                                    {'router': {'name': new_name}})
                self.assertEqual(new_name, body['router']['name'])
                edge_rename.assert_called_once_with(
                    edge_id,
                    new_name + '-' + router_id)

    def test_router_resize(self):
        with self.router() as r:
            with mock.patch.object(edge_appliance_driver.EdgeApplianceDriver,
                       'resize_edge') as edge_resize:
                new_size = 'large'
                router_id = r['router']['id']
                # get the edge of this router
                plugin = directory.get_plugin()
                router_obj = ex_router_driver.RouterExclusiveDriver(plugin)
                ctx = context.get_admin_context()
                edge_id = router_obj._get_edge_id_or_raise(ctx, router_id)

                # update the router size
                body = self._update('routers', router_id,
                                    {'router': {'router_size': new_size}})
                self.assertEqual(new_size, body['router']['router_size'])
                edge_resize.assert_called_once_with(edge_id, new_size)

    def _test_router_update_gateway_on_l3_ext_net(self, vlan_id=None,
                                                  validate_ext_gw=False,
                                                  distributed=False,
                                                  router_ctx=None):
        if router_ctx:
            self._tenant_id = self._router_tenant_id
        with self.router(
            arg_list=('distributed',), distributed=distributed,
            set_context=True,
            tenant_id=self._tenant_id) as r:
            self._tenant_id = self._default_tenant_id
            with self.subnet() as s1:
                with self._create_l3_ext_network(vlan_id) as net:
                    with self.subnet(network=net, enable_dhcp=False) as s2:
                        self._set_net_external(s1['subnet']['network_id'])
                        try:
                            self._add_external_gateway_to_router(
                                r['router']['id'],
                                s1['subnet']['network_id'],
                                neutron_context=router_ctx)
                            body = self._show('routers', r['router']['id'])
                            net_id = (body['router']
                                      ['external_gateway_info']['network_id'])
                            self.assertEqual(net_id,
                                             s1['subnet']['network_id'])
                            # Plug network with external mapping
                            self._set_net_external(s2['subnet']['network_id'])
                            self._add_external_gateway_to_router(
                                r['router']['id'],
                                s2['subnet']['network_id'],
                                neutron_context=router_ctx)
                            body = self._show('routers', r['router']['id'])
                            net_id = (body['router']
                                      ['external_gateway_info']['network_id'])
                            self.assertEqual(net_id,
                                             s2['subnet']['network_id'])
                            if validate_ext_gw:
                                pass
                        finally:
                            # Cleanup
                            self._remove_external_gateway_from_router(
                                r['router']['id'],
                                s2['subnet']['network_id'])

    def test_router_update_gateway_on_l3_ext_net(self):
        self._test_router_update_gateway_on_l3_ext_net()

    def test_router_update_gateway_on_l3_ext_net_with_non_admin(self):
        ctx = context.Context(user_id=None,
                              tenant_id=self._router_tenant_id,
                              is_admin=False)
        self._test_router_update_gateway_on_l3_ext_net(router_ctx=ctx)

    def test_router_update_gateway_on_l3_ext_net_with_vlan(self):
        self._test_router_update_gateway_on_l3_ext_net(444)

    def test_router_update_gateway_with_existing_floatingip(self):
        with self._create_l3_ext_network() as net:
            with self.subnet(network=net, enable_dhcp=False) as subnet:
                with self.floatingip_with_assoc() as fip:
                    self._add_external_gateway_to_router(
                        fip['floatingip']['router_id'],
                        subnet['subnet']['network_id'],
                        expected_code=webob.exc.HTTPConflict.code)

    def test_router_list_by_tenant_id(self):
        with self.router(), self.router():
            with self.router(tenant_id='custom') as router:
                self._test_list_resources('router', [router],
                                          query_params="tenant_id=custom")

    def test_create_l3_ext_network_with_vlan(self):
        self._test_create_l3_ext_network(666)

    def test_floatingip_with_assoc_fails(self):
        self._test_floatingip_with_assoc_fails(
            self._plugin_name + '._check_and_get_fip_assoc')

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)

    def test_floatingip_update(self):
        super(TestExclusiveRouterTestCase, self).test_floatingip_update(
            constants.FLOATINGIP_STATUS_DOWN)

    def test_floating_ip_no_snat(self):
        """Cannot add floating ips to a router with disabled snat"""
        with self.router() as r1,\
            self.subnet() as ext_subnet,\
            self.subnet(cidr='11.0.0.0/24') as s1,\
            self.port(subnet=s1) as private_port:
            # Add interfaces to the router
            self._router_interface_action(
                'add', r1['router']['id'],
                s1['subnet']['id'], None)
            self._set_net_external(ext_subnet['subnet']['network_id'])
            self._add_external_gateway_to_router(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'])
            # disable snat
            self._update_router_enable_snat(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'],
                False)
            # create a floating ip and associate it to the router should fail
            self.assertRaises(
                object,
                self._make_floatingip,
                self.fmt, ext_subnet['subnet']['network_id'],
                private_port['port']['id'])

            # now enable snat and try again
            self._update_router_enable_snat(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'],
                True)
            self._make_floatingip(
                self.fmt, ext_subnet['subnet']['network_id'],
                private_port['port']['id'])

            # now shouldn't be able to disable snat
            self.assertRaises(
                object,
                self._update_router_enable_snat,
                r1['router']['id'],
                ext_subnet['subnet']['network_id'],
                False)

    def test_floatingip_disassociate(self):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.floatingip_no_assoc(private_sub) as fip:
                self.assertEqual(fip['floatingip']['status'],
                                 constants.FLOATINGIP_STATUS_DOWN)
                port_id = p['port']['id']
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': port_id}})
                self.assertEqual(body['floatingip']['port_id'], port_id)
                self.assertEqual(body['floatingip']['status'],
                                 constants.FLOATINGIP_STATUS_ACTIVE)
                # Disassociate
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': None}})
                body = self._show('floatingips', fip['floatingip']['id'])
                self.assertIsNone(body['floatingip']['port_id'])
                self.assertIsNone(body['floatingip']['fixed_ip_address'])
                self.assertEqual(body['floatingip']['status'],
                                 constants.FLOATINGIP_STATUS_DOWN)

    def test_update_floatingip_with_edge_router_update_failure(self):
        p = directory.get_plugin()
        with self.subnet() as subnet,\
                self.port(subnet=subnet) as p1,\
                self.port(subnet=subnet) as p2:
            p1_id = p1['port']['id']
            p2_id = p2['port']['id']
            with self.floatingip_with_assoc(port_id=p1_id) as fip:
                with self._mock_edge_router_update_with_exception():
                    self.assertRaises(object,
                                      p.update_floatingip,
                                      context.get_admin_context(),
                                      fip['floatingip']['id'],
                                      floatingip={'floatingip':
                                                  {'port_id': p2_id}})
                res = self._list(
                    'floatingips', query_params="port_id=%s" % p1_id)
                self.assertEqual(len(res['floatingips']), 1)
                res = self._list(
                    'floatingips', query_params="port_id=%s" % p2_id)
                self.assertEqual(len(res['floatingips']), 0)

    def test_create_floatingip_with_edge_router_update_failure(self):
        p = directory.get_plugin()
        with self.subnet(cidr='200.0.0.0/24') as public_sub:
            public_network_id = public_sub['subnet']['network_id']
            self._set_net_external(public_network_id)
            with self.port() as private_port:
                port_id = private_port['port']['id']
                tenant_id = private_port['port']['tenant_id']
                subnet_id = private_port['port']['fixed_ips'][0]['subnet_id']
                with self.router() as r:
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  subnet_id,
                                                  None)
                    floatingip = {'floatingip': {
                                  'tenant_id': tenant_id,
                                  'floating_network_id': public_network_id,
                                  'port_id': port_id}}

                    with self._mock_edge_router_update_with_exception():
                        self.assertRaises(object,
                                          p.create_floatingip,
                                          context.get_admin_context(),
                                          floatingip=floatingip)
                        res = self._list(
                            'floatingips', query_params="port_id=%s" % port_id)
                        self.assertEqual(len(res['floatingips']), 0)
                    # Cleanup
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  subnet_id,
                                                  None)
                    self._remove_external_gateway_from_router(
                        r['router']['id'], public_network_id)

    @contextlib.contextmanager
    def _mock_edge_router_update_with_exception(self):
        nsx_router_update = PLUGIN_NAME + '._update_edge_router'
        with mock.patch(nsx_router_update) as update_edge:
            update_edge.side_effect = object()
            yield update_edge

    @mock.patch.object(edge_utils, "update_firewall")
    def test_router_interfaces_with_update_firewall(self, mock):
        s1_cidr = '10.0.0.0/24'
        s2_cidr = '11.0.0.0/24'
        with self.router() as r,\
                self.subnet(cidr=s1_cidr) as s1,\
                self.subnet(cidr=s2_cidr) as s2:

            self._router_interface_action('add',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            expected_cidrs = [s1_cidr, s2_cidr]
            expected_fw = [{'action': 'allow',
                            'enabled': True,
                            'name': 'Subnet Rule',
                            'source_ip_address': expected_cidrs,
                            'destination_ip_address': expected_cidrs}]
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(self._recursive_sort_list(expected_fw),
                             self._recursive_sort_list(fw_rules))
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s2['subnet']['id'],
                                          None)

    @mock.patch.object(edge_utils, "update_firewall")
    def test_router_interfaces_with_update_firewall_metadata(self, mock):
        self.plugin_instance.metadata_proxy_handler = mock.Mock()
        s1_cidr = '10.0.0.0/24'
        s2_cidr = '11.0.0.0/24'
        with self.router() as r,\
                self.subnet(cidr=s1_cidr) as s1,\
                self.subnet(cidr=s2_cidr) as s2:
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            # build the list of expected fw rules
            expected_cidrs = [s1_cidr, s2_cidr]
            fw_rule = {'action': 'allow',
                       'enabled': True,
                       'name': 'Subnet Rule',
                       'source_ip_address': expected_cidrs,
                       'destination_ip_address': expected_cidrs}
            vse_rule = {'action': 'allow',
                        'enabled': True,
                        'name': 'VSERule',
                        'source_vnic_groups': ['vse']}
            dest_intern = [md_proxy.INTERNAL_SUBNET]
            md_inter = {'action': 'deny',
                        'destination_ip_address': dest_intern,
                        'enabled': True,
                        'name': 'MDInterEdgeNet'}
            dest_srvip = [md_proxy.METADATA_IP_ADDR]
            md_srvip = {'action': 'allow',
                        'destination_ip_address': dest_srvip,
                        'destination_port': '80,443,8775',
                        'enabled': True,
                        'name': 'MDServiceIP',
                        'protocol': 'tcp'}
            expected_fw = [fw_rule,
                           vse_rule,
                           md_inter,
                           md_srvip]
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(self._recursive_sort_list(expected_fw),
                             self._recursive_sort_list(fw_rules))

            # Also test the md_srvip conversion:
            drv = edge_firewall_driver.EdgeFirewallDriver()
            rule = drv._convert_firewall_rule(md_srvip)
            exp_service = {'service': [{'port': [80, 443, 8775],
                                        'protocol': 'tcp'}]}
            exp_rule = {'action': 'accept',
                        'application': exp_service,
                        'destination': {'ipAddress': dest_srvip},
                        'enabled': True,
                        'name': 'MDServiceIP'}
            self.assertEqual(exp_rule, rule)

            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s2['subnet']['id'],
                                          None)

    @mock.patch.object(edge_utils, "update_firewall")
    def test_router_interfaces_with_update_firewall_metadata_conf(self, mock):
        """Test the metadata proxy firewall rule with configured ports
        """
        cfg.CONF.set_override('metadata_service_allowed_ports',
            ['55', ' 66 ', '55', '77'], group='nsxv')
        self.plugin_instance.metadata_proxy_handler = mock.Mock()
        s1_cidr = '10.0.0.0/24'
        with self.router() as r,\
                self.subnet(cidr=s1_cidr) as s1:
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            # build the expected fw rule
            # at this stage the string of ports is not sorted/unique/validated
            dest_srvip = [md_proxy.METADATA_IP_ADDR]
            rule_name = 'MDServiceIP'
            md_srvip = {'action': 'allow',
                        'destination_ip_address': dest_srvip,
                        'destination_port': '80,443,8775,55,66,55,77',
                        'enabled': True,
                        'name': rule_name,
                        'protocol': 'tcp'}
            # compare it to the rule with the same name
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            rule_found = False
            for fw_rule in fw_rules:
                if (validators.is_attr_set(fw_rule.get("name")) and
                    fw_rule['name'] == rule_name):
                    self.assertEqual(md_srvip, fw_rule)
                    rule_found = True
                    break
            self.assertTrue(rule_found)

            # Also test the rule conversion
            # Ports should be sorted & unique, and ignore non numeric values
            drv = edge_firewall_driver.EdgeFirewallDriver()
            rule = drv._convert_firewall_rule(md_srvip)
            exp_service = {'service': [{'port': [55, 66, 77, 80, 443, 8775],
                                        'protocol': 'tcp'}]}
            exp_rule = {'action': 'accept',
                        'application': exp_service,
                        'destination': {'ipAddress': dest_srvip},
                        'enabled': True,
                        'name': 'MDServiceIP'}
            self.assertEqual(exp_rule, rule)

    @mock.patch.object(edge_utils, "update_firewall")
    def test_router_interfaces_different_tenants_update_firewall(self, mock):
        tenant_id = _uuid()
        other_tenant_id = _uuid()
        s1_cidr = '10.0.0.0/24'
        s2_cidr = '11.0.0.0/24'
        with self.router(tenant_id=tenant_id) as r,\
                self.network(tenant_id=tenant_id) as n1,\
                self.network(tenant_id=other_tenant_id) as n2,\
                self.subnet(network=n1, cidr=s1_cidr) as s1,\
                self.subnet(network=n2, cidr=s2_cidr) as s2:

            self._router_interface_action('add',
                                          r['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None,
                                          tenant_id=tenant_id)
            expected_cidrs = [s1_cidr, s2_cidr]
            expected_fw = [{'action': 'allow',
                            'enabled': True,
                            'name': 'Subnet Rule',
                            'source_ip_address': expected_cidrs,
                            'destination_ip_address': expected_cidrs}]
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(self._recursive_sort_list(expected_fw),
                             self._recursive_sort_list(fw_rules))
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None,
                                          tenant_id=tenant_id)
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            expected_fw = []
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(expected_fw, fw_rules)

    def test_delete_ext_net_with_disassociated_floating_ips(self):
        with self.network() as net:
            net_id = net['network']['id']
            self._set_net_external(net_id)
            with self.subnet(network=net, enable_dhcp=False):
                self._make_floatingip(self.fmt, net_id)

    def test_create_router_gateway_fails(self):
        self.skipTest('not supported')

    def test_migrate_exclusive_router_to_shared(self):
        with self._create_l3_ext_network() as net:
            with self.subnet(network=net, enable_dhcp=False) as s:
                data = {'router': {'tenant_id': 'whatever'}}
                data['router']['name'] = 'router1'
                data['router']['external_gateway_info'] = {
                    'network_id': s['subnet']['network_id']}
                data['router']['router_type'] = 'exclusive'

                router_req = self.new_create_request('routers', data,
                                                     self.fmt)
                res = router_req.get_response(self.ext_api)
                router = self.deserialize(self.fmt, res)
                # update the router type:
                router_id = router['router']['id']
                self._update('routers', router_id,
                             {'router': {'router_type': 'shared'}})

                # get the updated router and check it's type
                body = self._show('routers', router_id)
                self.assertEqual('shared', body['router']['router_type'])

    def test_router_remove_interface_with_load_balancer(self):
        with self.router() as router, self.subnet() as subnet:
            fixed_ips = [{'subnet_id': subnet['subnet']['id']}]
            with self.port(subnet,
                           device_owner='neutron:LOADBALANCER',
                           fixed_ips=fixed_ips):
                expected_code = webob.exc.HTTPInternalServerError.code
                self._router_interface_action('remove',
                                              router['router']['id'],
                                              subnet['subnet']['id'],
                                              None,
                                              expected_code=expected_code)

    @mock.patch.object(edge_utils.EdgeManager,
                       'update_interface_addr')
    def test_router_update_gateway_with_different_external_subnet(self, mock):
        # This test calls the backend, so we need a mock for the edge_utils
        super(
            TestExclusiveRouterTestCase,
            self).test_router_update_gateway_with_different_external_subnet()

    @mock.patch.object(edge_utils.EdgeManager,
                       'update_interface_addr')
    def test_router_add_interface_multiple_ipv6_subnets_same_net(self, mock):
        # This test calls the backend, so we need a mock for the edge_utils
        super(
            TestExclusiveRouterTestCase,
            self).test_router_add_interface_multiple_ipv6_subnets_same_net()

    def _fake_rename_edge(self, edge_id, name):
        raise vcns_exc.VcnsApiException(
            status=400, header={'status': 200}, uri='fake_url', response='')

    def test_create_router_with_update_error(self):
        p = directory.get_plugin()

        # make sure there is an available edge so we will use backend update
        available_edge = {'edge_id': 'edge-11', 'router_id': 'fake_id'}
        nsxv_db.add_nsxv_router_binding(
            context.get_admin_context().session, available_edge['router_id'],
            available_edge['edge_id'], None, constants.ACTIVE)
        with mock.patch.object(p.edge_manager,
                               '_get_available_router_binding',
                               return_value=available_edge):
            # Mock for update_edge task failure
            with mock.patch.object(
                p.edge_manager.nsxv_manager, 'rename_edge',
                side_effect=self._fake_rename_edge):
                router = {'router': {'admin_state_up': True,
                          'name': 'e161be1d-0d0d-4046-9823-5a593d94f72c',
                          'tenant_id': 'fake_tenant',
                          'router_type': 'exclusive'}}
                # router creation should succeed
                returned_router = p.create_router(context.get_admin_context(),
                                                  router)
                # router status should be 'error'
                self.assertEqual(constants.ERROR, returned_router['status'])

                # check the same after get_router
                new_router = p.get_router(context.get_admin_context(),
                                          returned_router['id'])
                self.assertEqual(constants.ERROR, new_router['status'])

    def test_create_router_with_bad_az_hint(self):
        p = directory.get_plugin()
        router = {'router': {'admin_state_up': True,
                  'name': 'e161be1d-0d0d-4046-9823-5a593d94f72c',
                  'tenant_id': 'fake_tenant',
                  'router_type': 'exclusive',
                  'availability_zone_hints': ['bad_hint']}}
        self.assertRaises(n_exc.NeutronException,
                          p.create_router,
                          context.get_admin_context(),
                          router)

    def test_create_router_with_az_hint(self):
        az_name = 'az7'
        set_az_in_config(az_name)
        p = directory.get_plugin()
        p._availability_zones_data = nsx_az.NsxVAvailabilityZones()
        p._get_edge_id_by_rtr_id = p.real_get_edge

        router = {'router': {'admin_state_up': True,
                  'name': 'e161be1d-0d0d-4046-9823-5a593d94f72c',
                  'tenant_id': 'fake_tenant',
                  'router_type': 'exclusive',
                  'availability_zone_hints': [az_name]}}

        # router creation should succeed
        returned_router = p.create_router(context.get_admin_context(),
                                          router)
        self.assertEqual([az_name],
                         returned_router['availability_zone_hints'])
        self.assertEqual([az_name],
                         returned_router['availability_zones'])

    def test_floatingip_update_to_same_port_id_twice(self):
        self.skipTest('Plugin changes floating port status')

    def test_router_add_interface_ipv6_subnet(self):
        self.skipTest('Not supported')

    def test_router_add_gateway_multiple_subnets_ipv6(self):
        self.skipTest('not supported')

    def test_update_subnet_gateway_for_external_net(self):
        plugin = directory.get_plugin()
        router_obj = ex_router_driver.RouterExclusiveDriver(plugin)
        with mock.patch.object(plugin, '_find_router_driver',
                               return_value=router_obj):
            with mock.patch.object(router_obj,
                                   '_update_nexthop') as update_nexthop:
                super(TestExclusiveRouterTestCase,
                      self).test_update_subnet_gateway_for_external_net()
                self.assertTrue(update_nexthop.called)

    def _test_create_subnetpool(self, prefixes, expected=None,
                                admin=False, **kwargs):
        keys = kwargs.copy()
        keys.setdefault('tenant_id', self._tenant_id)
        with self.subnetpool(prefixes, admin, **keys) as subnetpool:
            self._validate_resource(subnetpool, keys, 'subnetpool')
            if expected:
                self._compare_resource(subnetpool, expected, 'subnetpool')
        return subnetpool

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
                    err_code = webob.exc.HTTPBadRequest.code
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  int_subnet['subnet']['id'],
                                                  None,
                                                  err_code)

    def _create_subnet_and_add_to_router(self, subnetpool_id, router_id):
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

            # Add the interface to the router
            self._router_interface_action(
                'add',
                router_id,
                int_subnet['subnet']['id'],
                None)
            return int_subnet

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
            # and create a no snat router with this gateway
            with self.router() as r:
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    ext_subnet['subnet']['network_id'])
                self._update_router_enable_snat(
                    r['router']['id'],
                    ext_subnet['subnet']['network_id'],
                    False)

                # should succeed adding the interface to the router
                self._create_subnet_and_add_to_router(
                    subnetpool_id, r['router']['id'])

    def test_router_address_scope_snat_rules(self):
        """Test that if the router interface had the same address scope
        as the gateway - snat rule is not added, but firewall rule is.
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
            # and create a router with this gateway
            with self.router() as r:
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    ext_subnet['subnet']['network_id'])

                # Add the interface to the router
                with mock.patch.object(
                    edge_utils, 'update_nat_rules') as update_nat,\
                    mock.patch.object(
                        edge_utils, 'update_firewall') as update_fw:

                    int_subnet = self._create_subnet_and_add_to_router(
                        subnetpool_id, r['router']['id'])

                    # make sure snat rules are not added
                    update_nat.assert_called_once_with(
                        mock.ANY, mock.ANY, r['router']['id'], [], [])

                    # check fw rules
                    fw_rules = update_fw.call_args[0][3][
                        'firewall_rule_list']
                    self.assertEqual(2, len(fw_rules))
                    self.assertEqual('Allocation Pool Rule',
                                     fw_rules[1]['name'])
                    self.assertEqual('allow', fw_rules[1]['action'])
                    self.assertEqual(
                        int_subnet['subnet']['cidr'],
                        fw_rules[1]['destination_ip_address'][0])
                    self.assertEqual('external',
                                     fw_rules[1]['source_vnic_groups'][0])

    def test_router_address_scope_fw_rules(self):
        """Test that if the router interfaces has different address scope
        there are separate fw rules
        """
        # create a router, networks, and address scopes
        with self.address_scope(name='as1') as addr_scope1, \
            self.address_scope(name='as2') as addr_scope2, \
            self.router() as r:

            as1_id = addr_scope1['address_scope']['id']
            as2_id = addr_scope2['address_scope']['id']
            pool1 = netaddr.IPNetwork('10.10.10.0/21')
            subnetpool1 = self._test_create_subnetpool(
                [pool1.cidr], name='sp1',
                min_prefixlen='24', address_scope_id=as1_id)
            pool2 = netaddr.IPNetwork('20.20.20.0/21')
            subnetpool2 = self._test_create_subnetpool(
                [pool2.cidr], name='sp2',
                min_prefixlen='24', address_scope_id=as2_id)
            subnetpool_id1 = subnetpool1['subnetpool']['id']
            subnetpool_id2 = subnetpool2['subnetpool']['id']

            # Add the interfaces to the router
            with mock.patch.object(
                edge_utils, 'update_nat_rules'),\
                mock.patch.object(edge_utils, 'update_firewall') as update_fw:
                # create subnets on the 2 subnet pools, and attach to router
                subnet1 = self._create_subnet_and_add_to_router(
                    subnetpool_id1, r['router']['id'])
                subnet2 = self._create_subnet_and_add_to_router(
                    subnetpool_id2, r['router']['id'])
                subnet3 = self._create_subnet_and_add_to_router(
                    subnetpool_id2, r['router']['id'])

                expected_rules = [
                    {'enabled': True,
                     'destination_ip_address': [subnet1['subnet']['cidr']],
                     'action': 'allow',
                     'name': 'Subnet Rule',
                     'source_ip_address': [subnet1['subnet']['cidr']]},
                    {'enabled': True,
                     'destination_ip_address': [subnet2['subnet']['cidr'],
                                                subnet3['subnet']['cidr']],
                     'action': 'allow',
                     'name': 'Subnet Rule',
                     'source_ip_address': [subnet2['subnet']['cidr'],
                                           subnet3['subnet']['cidr']]}]

                # check the final fw rules
                fw_rules = update_fw.call_args[0][3][
                    'firewall_rule_list']
                self.assertEqual(2, len(fw_rules))
                self.assertEqual(self._recursive_sort_list(expected_rules),
                                 self._recursive_sort_list(fw_rules))

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

            self._create_subnet_and_add_to_router(
                subnetpool2_id, r['router']['id'])

            # change address scope of the first subnetpool
            with self.address_scope(name='as2') as addr_scope2,\
                mock.patch.object(edge_utils, 'update_nat_rules') as update_nat,\
                mock.patch.object(edge_utils, 'update_firewall') as update_fw:

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

                # Verify that the snat & fw rule are being updated
                update_nat.assert_called_once()
                update_fw.assert_called_once()

    def test_router_address_scope_change(self):
        self._test_router_address_scope_change()

    def test_router_address_scope_gw_change(self):
        self._test_router_address_scope_change(change_gw=True)


class ExtGwModeTestCase(NsxVPluginV2TestCase,
                        test_ext_gw_mode.ExtGwModeIntTestCase):
    def test_router_gateway_set_fail_after_port_create(self):
        self.skipTest("TBD")


class NsxVSecurityGroupsTestCase(ext_sg.SecurityGroupDBTestCase):
    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        test_utils.override_nsx_ini_test()
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            securitygrouplogging.RESOURCE_ATTRIBUTE_MAP)
        mock_vcns = mock.patch(vmware.VCNS_NAME, autospec=True)
        mock_vcns_instance = mock_vcns.start()
        self.fc2 = fake_vcns.FakeVcns()
        mock_vcns_instance.return_value = self.fc2
        edge_utils.query_dhcp_service_config = mock.Mock(return_value=[])
        mock_create_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'create_dhcp_edge_service'))
        mock_create_dhcp_service.start()
        mock_update_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'update_dhcp_edge_service'))
        mock_update_dhcp_service.start()
        mock_delete_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'delete_dhcp_edge_service'))
        mock_delete_dhcp_service.start()
        mock_check_backup_edge_pools = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, '_check_backup_edge_pools'))
        mock_check_backup_edge_pools.start()
        mock_process_security_group_logging = mock.patch(
            'vmware_nsx.plugin.NsxVPlugin.'
            '_process_security_groups_rules_logging')
        mock_process_security_group_logging.start()

        c_utils.spawn_n = mock.Mock(side_effect=lambda f: f())
        super(NsxVSecurityGroupsTestCase, self).setUp(plugin=plugin,
                                                      ext_mgr=ext_mgr)
        self.plugin = directory.get_plugin()
        self.addCleanup(self.fc2.reset_all)


class NsxVTestSecurityGroup(ext_sg.TestSecurityGroups,
                            NsxVSecurityGroupsTestCase):

    @mock.patch.object(edge_utils.EdgeManager, '_deploy_edge')
    def setUp(self, mock_deploy,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):

        super(NsxVTestSecurityGroup, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        plugin_instance = directory.get_plugin()
        plugin_instance._get_edge_id_by_rtr_id = mock.Mock()
        plugin_instance._get_edge_id_by_rtr_id.return_value = False
        plugin_instance._get_edge_id_and_az_by_rtr_id = mock.Mock()
        plugin_instance._get_edge_id_and_az_by_rtr_id.return_value = (
            False, False)

    def test_list_ports_security_group(self):
        with self.network() as n:
            with self.subnet(n, enable_dhcp=False):
                self._create_port(self.fmt, n['network']['id'])
                req = self.new_list_request('ports')
                res = req.get_response(self.api)
                ports = self.deserialize(self.fmt, res)
                port = ports['ports'][0]
                self.assertEqual(len(port[secgrp.SECURITYGROUPS]), 1)
                self._delete('ports', port['id'])

    def test_vnic_security_group_membership(self):
        p = directory.get_plugin()
        self.fc2.add_member_to_security_group = (
            mock.Mock().add_member_to_security_group)
        self.fc2.remove_member_from_security_group = (
            mock.Mock().remove_member_from_security_group)
        nsx_sg_id = str(self.fc2._securitygroups['ids'])
        device_id = _uuid()
        port_index = 0
        # The expected vnic-id format by NsxV
        vnic_id = '%s.%03d' % (device_id, port_index)
        with self.port(device_id=device_id,
                       device_owner='compute:None') as port:
            (self.fc2.add_member_to_security_group
             .assert_called_once_with(p.sg_container_id, nsx_sg_id))
            self.fc2.add_member_to_security_group.reset_mock()
            data = {'port': {'vnic_index': port_index}}
            self.new_update_request('ports', data,
                                    port['port']['id']).get_response(self.api)
            # The vnic should be added as a member to the nsx-security-groups
            # which match the port security-groups
            (self.fc2.add_member_to_security_group
             .assert_called_once_with(nsx_sg_id, vnic_id))

        # The vnic should be removed from the nsx-security-groups which match
        # the deleted port security-groups
        #TODO(kobis): Port is not removed automatically
        # (self.fc2.remove_member_from_security_group
        #  .assert_called_once_with(nsx_sg_id, vnic_id))

    def test_create_secgroup_deleted_upon_fw_section_create_fail(self):
        _context = context.Context('', 'tenant_id')
        sg = {'security_group': {'name': 'default',
                                 'tenant_id': 'tenant_id',
                                 'description': ''}}
        expected_id = str(self.fc2._securitygroups['ids'])
        with mock.patch.object(self.fc2,
                               'create_section') as create_section:
            with mock.patch.object(self.fc2,
                                   'delete_security_group') as delete_sg:

                create_section.side_effect = webob.exc.HTTPInternalServerError
                self.assertRaises(webob.exc.HTTPInternalServerError,
                                  self.plugin.create_security_group,
                                  _context.elevated(), sg, default_sg=True)
                delete_sg.assert_called_once_with(expected_id)

    def test_create_security_group_rule_duplicate_rules(self):
        name = 'webservers'
        description = 'my webservers'
        with mock.patch.object(self.plugin.nsx_v.vcns,
                               'remove_rule_from_section') as rm_rule_mock:
            with self.security_group(name, description) as sg:
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    constants.PROTO_NAME_TCP, '22', '22')
                self._create_security_group_rule(self.fmt, rule)
                res = self._create_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)
        rm_rule_mock.assert_called_once_with(mock.ANY, mock.ANY)

    def test_create_security_group_rule_with_specific_id(self):
        # This test is aimed to test the security-group db mixin
        pass

    def _plugin_update_security_group(self, context, id, logging):
        data = {'security_group': {'logging': logging}}
        security_group = (
            self.plugin.update_security_group(context, id, data))
        return security_group

    def _plugin_create_security_group(self, context, logging=False):
        data = {'security_group': {'name': 'SG',
                                   'tenant_id': 'tenant_id',
                                   'description': ''}}
        if logging:
            data['security_group']['logging'] = True
        security_group = (
            self.plugin.create_security_group(context, data, False))
        return security_group

    def test_create_security_group_default_logging(self):
        _context = context.get_admin_context()
        sg = self._plugin_create_security_group(_context)
        self.assertFalse(sg['logging'])

    def test_create_security_group_with_logging(self):
        _context = context.get_admin_context()
        sg = self._plugin_create_security_group(_context, logging=True)
        self.assertTrue(sg['logging'])

    def test_update_security_group_with_logging(self):
        _context = context.get_admin_context()
        sg = self._plugin_create_security_group(_context)
        sg = self._plugin_update_security_group(_context, sg['id'], True)
        self.assertTrue(sg['logging'])


class TestVdrTestCase(L3NatTest, L3NatTestCaseBase,
                      test_l3_plugin.L3NatDBIntTestCase,
                      IPv6ExpectedFailuresTestMixin,
                      NsxVPluginV2TestCase):

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None, service_plugins=None):
        # init the availability zones in the configuration of the plugin
        self.az_name = 'az7'
        set_az_in_config(self.az_name)
        super(TestVdrTestCase, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        self.plugin_instance.nsx_v.is_subnet_in_use = mock.Mock()
        self.plugin_instance.nsx_v.is_subnet_in_use.return_value = False
        self._default_tenant_id = self._tenant_id
        self._router_tenant_id = 'test-router-tenant'

    @mock.patch.object(edge_utils.EdgeManager,
                       'update_interface_addr')
    def test_router_update_gateway_with_different_external_subnet(self, mock):
        # This test calls the backend, so we need a mock for the edge_utils
        super(
            TestVdrTestCase,
            self).test_router_update_gateway_with_different_external_subnet()

    def test_floatingip_multi_external_one_internal(self):
        self.skipTest('skipped')

    def test_router_add_gateway_multiple_subnets_ipv6(self):
        self.skipTest('not supported')

    def test_router_add_interface_ipv6_subnet(self):
        self.skipTest('Not supported')

    def test_router_add_interface_dup_subnet2_returns_400(self):
        self.skipTest('skipped')

    def test_floatingip_same_external_and_internal(self):
        self.skipTest('skipped')

    def test_create_router_fail_at_the_backend(self):
        p = directory.get_plugin()
        edge_manager = p.edge_manager
        with mock.patch.object(edge_manager, 'create_lrouter',
                               side_effect=[n_exc.NeutronException]):
            router = {'router': {'admin_state_up': True,
                      'name': 'e161be1d-0d0d-4046-9823-5a593d94f72c',
                      'tenant_id': 'fake_tenant',
                      'distributed': True}}
            self.assertRaises(n_exc.NeutronException,
                              p.create_router,
                              context.get_admin_context(),
                              router)
            self._test_list_resources('router', ())

    def test_update_port_device_id_to_different_tenants_router(self):
        self.skipTest('TBD')

    def test_router_add_and_remove_gateway_tenant_ctx(self):
        self.skipTest('TBD')

    def _create_router(self, fmt, tenant_id, name=None,
                       admin_state_up=None, set_context=False,
                       arg_list=None, **kwargs):
        tenant_id = tenant_id or _uuid()
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up:
            data['router']['admin_state_up'] = admin_state_up
        for arg in (('admin_state_up', 'tenant_id') + (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs and kwargs[arg]:
                data['router'][arg] = kwargs[arg]

        if 'distributed' in kwargs:
            data['router']['distributed'] = kwargs['distributed']
        else:
            data['router']['distributed'] = True
        if ('availability_zone_hints' in kwargs and
            kwargs['availability_zone_hints'] is not None):
            data['router']['availability_zone_hints'] = kwargs[
                'availability_zone_hints']

        if kwargs.get('router_type'):
            data['router']['router_type'] = kwargs.get('router_type')

        router_req = self.new_create_request('routers', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            router_req.environ['neutron.context'] = context.Context(
                '', tenant_id)

        return router_req.get_response(self.ext_api)

    def _test_router_plr_binding(self, expected_size='compact',
                                 availability_zone=None):
        """Test PLR router bindings

        Create a distributed router with an external network and check
        that the router was created as it should from the binding entry
        """
        # create a distributed router
        tenant_id = _uuid()
        router_ctx = context.Context('', tenant_id)
        az_hints = [availability_zone] if availability_zone else None
        res = self._create_router(self.fmt, tenant_id, distributed=True,
                                  availability_zone_hints=az_hints)
        r = self.deserialize(self.fmt, res)
        self.assertIn('router', r)

        with self._create_l3_ext_network() as net:
            with self.subnet(network=net, enable_dhcp=False) as s2:

                # Plug network with external mapping
                self._set_net_external(s2['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s2['subnet']['network_id'],
                    neutron_context=router_ctx)
                body = self._show('routers', r['router']['id'])
                net_id = (body['router']
                          ['external_gateway_info']['network_id'])
                self.assertEqual(net_id,
                                 s2['subnet']['network_id'])

                # make sure the plr router was created, with the expected data
                plr_id = self.plugin_instance.edge_manager.get_plr_by_tlr_id(
                    router_ctx, r['router']['id'])
                binding = nsxv_db.get_nsxv_router_binding(
                    router_ctx.session, plr_id)
                self.assertEqual(expected_size, binding['appliance_size'])
                self.assertEqual('ACTIVE', binding['status'])
                self.assertIsNotNone(binding['edge_id'])
                self.assertEqual('service', binding['edge_type'])
                self.assertTrue(binding['router_id'].startswith('plr'))
                if availability_zone:
                    self.assertEqual(
                        availability_zone, binding['availability_zone'])
                else:
                    self.assertEqual('default', binding['availability_zone'])

                # Cleanup
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s2['subnet']['network_id'])

    def test_router_plr_binding_default_size(self):
        self._test_router_plr_binding()

    def test_router_plr_binding_configured_size(self):
        cfg.CONF.set_override('exclusive_router_appliance_size',
                              'large', group="nsxv")
        self._test_router_plr_binding(expected_size='large')

    def test_router_plr_binding_default_az(self):
        self._test_router_plr_binding(availability_zone='default')

    def test_router_plr_binding_with_az(self):
        self._test_router_plr_binding(availability_zone=self.az_name)

    def test_router_binding_with_az(self):
        """Check distributed router creation with an availability zone
        """
        # create a distributed router
        tenant_id = _uuid()
        router_ctx = context.Context('', tenant_id)
        res = self._create_router(self.fmt, tenant_id, distributed=True,
                                  availability_zone_hints=[self.az_name])
        r = self.deserialize(self.fmt, res)
        self.assertIn('router', r)

        # check that we have an edge for this router, with the correct
        # availability zone
        binding = nsxv_db.get_nsxv_router_binding(
            router_ctx.session, r['router']['id'])

        self.assertEqual('compact', binding['appliance_size'])
        self.assertEqual('ACTIVE', binding['status'])
        self.assertIsNotNone(binding['edge_id'])
        self.assertEqual('vdr', binding['edge_type'])
        self.assertEqual(binding['router_id'], r['router']['id'])
        self.assertEqual(self.az_name, binding['availability_zone'])

    def _test_router_create_with_distributed(self, dist_input, dist_expected,
                                             return_code=201, **kwargs):
        data = {'tenant_id': 'whatever'}
        data['name'] = 'router1'
        data['distributed'] = dist_input
        for k, v in six.iteritems(kwargs):
            data[k] = v
        router_req = self.new_create_request(
            'routers', {'router': data}, self.fmt)
        res = router_req.get_response(self.ext_api)
        self.assertEqual(return_code, res.status_int)
        if res.status_int == 201:
            router = self.deserialize(self.fmt, res)
            self.assertIn('distributed', router['router'])
            if dist_input:
                self.assertNotIn('router_type', router['router'])
            self.assertEqual(dist_expected,
                             router['router']['distributed'])

    def test_create_router_fails_with_router_type(self):
        self._test_router_create_with_distributed(True, True,
                                                  return_code=400,
                                                  router_type="shared")

    def test_router_create_distributed(self):
        self._test_router_create_with_distributed(True, True)

    def test_router_create_not_distributed(self):
        self._test_router_create_with_distributed(False, False)

    def test_router_create_distributed_unspecified(self):
        self._test_router_create_with_distributed(None, False)

    def _test_create_router_with_az_hint(self, with_hint):
        # init the availability zones in the plugin
        az_name = 'az7'
        set_az_in_config(az_name)
        p = directory.get_plugin()
        p._availability_zones_data = nsx_az.NsxVAvailabilityZones()

        # create a router with/without hints
        router = {'router': {'admin_state_up': True,
                  'name': 'e161be1d-0d0d-4046-9823-5a593d94f72c',
                  'tenant_id': 'FAKE_TENANT',
                  'distributed': True}}
        if with_hint:
            router['router']['availability_zone_hints'] = [az_name]
        returned_router = p.create_router(context.get_admin_context(),
                                          router)
        # availability zones is still empty because the router is not attached
        if with_hint:
            self.assertEqual([az_name],
                             returned_router['availability_zone_hints'])
        else:
            self.assertEqual([],
                             returned_router['availability_zone_hints'])

        edge_id = edge_utils.get_router_edge_id(
            context.get_admin_context(), returned_router['id'])
        res_az = nsxv_db.get_edge_availability_zone(
            context.get_admin_context().session, edge_id)
        expected_az = az_name if with_hint else 'default'
        self.assertEqual(expected_az, res_az)

    def test_create_router_with_az_hint(self):
        self._test_create_router_with_az_hint(True)

    def test_create_router_without_az_hint(self):
        self._test_create_router_with_az_hint(False)

    def test_floatingip_with_assoc_fails(self):
        self._test_floatingip_with_assoc_fails(
            self._plugin_name + '._check_and_get_fip_assoc')

    def test_floatingip_update(self):
        super(TestVdrTestCase, self).test_floatingip_update(
            constants.FLOATINGIP_STATUS_DOWN)

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)

    def test_router_add_gateway_invalid_network_returns_404(self):
        with self.router() as r:
            self._add_external_gateway_to_router(
                r['router']['id'],
                uuidutils.generate_uuid(),
                expected_code=webob.exc.HTTPNotFound.code)

    def test_router_add_interfaces_with_multiple_subnets_on_same_network(self):
        with self.router() as r,\
                self.network() as n,\
                self.subnet(network=n) as s1,\
                self.subnet(network=n, cidr='11.0.0.0/24') as s2:
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            err_code = webob.exc.HTTPBadRequest.code
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s2['subnet']['id'],
                                          None,
                                          err_code)
            self._router_interface_action('remove',
                                          r['router']['id'],
                                          s1['subnet']['id'],
                                          None)

    def test_router_add_interface_with_external_net_fail(self):
        with self.router() as r,\
                self.network() as n,\
                self.subnet(network=n) as s:
            # Set the network as an external net
            net_id = n['network']['id']
            self._set_net_external(net_id)
            err_code = webob.exc.HTTPBadRequest.code
            self._router_interface_action('add',
                                          r['router']['id'],
                                          s['subnet']['id'],
                                          None,
                                          err_code)

    def test_different_type_routers_add_interfaces_on_same_network_pass(self):
        with self.router() as dist, \
            self.router(distributed=False, router_type='shared') as shared, \
            self.router(distributed=False, router_type='exclusive') as excl:
            with self.network() as n:
                with self.subnet(network=n) as s1, \
                    self.subnet(network=n, cidr='11.0.0.0/24') as s2, \
                    self.subnet(network=n, cidr='12.0.0.0/24') as s3:
                    self._router_interface_action('add',
                                                  shared['router']['id'],
                                                  s1['subnet']['id'],
                                                  None)
                    self._router_interface_action('add',
                                                  excl['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)
                    self._router_interface_action('add',
                                                  dist['router']['id'],
                                                  s3['subnet']['id'],
                                                  None)
                    self._router_interface_action('remove',
                                                  dist['router']['id'],
                                                  s3['subnet']['id'],
                                                  None)
                    self._router_interface_action('remove',
                                                  excl['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)
                    self._router_interface_action('remove',
                                                  shared['router']['id'],
                                                  s1['subnet']['id'],
                                                  None)

    def test_delete_ext_net_with_disassociated_floating_ips(self):
        with self.network() as net:
            net_id = net['network']['id']
            self._set_net_external(net_id)
            with self.subnet(network=net, enable_dhcp=False):
                self._make_floatingip(self.fmt, net_id)

    def test_router_update_type_fails(self):
        """Check distributed router cannot change it's type
        """
        # create a distributed router
        tenant_id = _uuid()
        res = self._create_router(self.fmt, tenant_id, distributed=True)
        r = self.deserialize(self.fmt, res)
        router_id = r['router']['id']

        # make sure changing the type fails
        self._update('routers', router_id,
                     {'router': {'router_type': 'shared'}},
                     expected_code=400)
        self._update('routers', router_id,
                     {'router': {'router_type': 'exclusive'}},
                     expected_code=400)
        self._update('routers', router_id,
                     {'router': {'distributed': False}},
                     expected_code=400)
        # make sure keeping the type is ok
        self._update('routers', router_id,
                     {'router': {'distributed': True}},
                     expected_code=200)

    def test_router_add_interface_multiple_ipv4_subnets(self):
        self.skipTest('TBD')

    def test_router_remove_ipv6_subnet_from_interface(self):
        self.skipTest('TBD')

    def test_router_add_interface_multiple_ipv6_subnets_same_net(self):
        self.skipTest('TBD')

    def test_router_add_interface_multiple_ipv6_subnets_different_net(self):
        self.skipTest('TBD')

    def test_create_router_gateway_fails(self):
        self.skipTest('not supported')

    def test_floatingip_update_to_same_port_id_twice(self):
        self.skipTest('Plugin changes floating port status')

    def test_update_subnet_gateway_for_external_net(self):
        plugin = directory.get_plugin()
        router_obj = dist_router_driver.RouterDistributedDriver(plugin)
        with mock.patch.object(plugin, '_find_router_driver',
                               return_value=router_obj):
            with mock.patch.object(router_obj,
                                   '_update_nexthop') as update_nexthop:
                super(TestVdrTestCase,
                      self).test_update_subnet_gateway_for_external_net()
                self.assertTrue(update_nexthop.called)


class TestNSXvAllowedAddressPairs(NsxVPluginV2TestCase,
                                  test_addr_pair.TestAllowedAddressPairs):

    def setUp(self, plugin=PLUGIN_NAME):
        super(TestNSXvAllowedAddressPairs, self).setUp(plugin=plugin)

    # NOTE: the tests below are skipped due to the fact that they update the
    # mac address. The NSX|V does not support address pairs when a MAC address
    # is configured.
    def test_create_port_allowed_address_pairs(self):
        pass

    def test_update_add_address_pairs(self):
        pass

    def test_equal_to_max_allowed_address_pair(self):
        pass

    def test_update_port_security_off_address_pairs(self):
        pass

    def test_create_port_security_true_allowed_address_pairs(self):
        pass

    def test_create_port_security_false_allowed_address_pairs(self):
        pass

    def _test_create_port_remove_allowed_address_pairs(self, update_value):
        pass

    def test_create_overlap_with_fixed_ip(self):
        pass

    def test_get_vlan_network_name(self):
        pass

    def test_create_port_with_cidr_address_pair(self):
        with self.network() as net:
            address_pairs = [{'mac_address': '00:00:00:00:00:01',
                              'ip_address': '192.168.1.0/24'}]
            self._create_port(self.fmt, net['network']['id'],
                            expected_res_status=webob.exc.HTTPBadRequest.code,
                            arg_list=(addr_pair.ADDRESS_PAIRS,),
                            allowed_address_pairs=address_pairs)


class TestNSXPortSecurity(test_psec.TestPortSecurity,
                          NsxVPluginV2TestCase):
    def setUp(self, plugin=PLUGIN_NAME):
        super(TestNSXPortSecurity, self).setUp(plugin=plugin)

    def test_create_port_fails_with_secgroup_and_port_security_false(self):
        # Security Groups can be used even when port-security is disabled
        pass

    def test_update_port_security_off_with_security_group(self):
        # Security Groups can be used even when port-security is disabled
        pass

    def test_create_port_with_security_group_and_net_sec_false(self):
        pass

    def _create_compute_port(self, network_name, device_id, port_security):
        # create a network without port security
        res = self._create_network('json', network_name, True)
        net = self.deserialize('json', res)

        # create a compute port with this network and a device
        res = self._create_port('json', net['network']['id'],
                                arg_list=('port_security_enabled',
                                          'device_id',
                                          'device_owner',),
                                port_security_enabled=port_security,
                                device_id=device_id,
                                device_owner='compute:None')
        return self.deserialize('json', res)

    def _add_vnic_to_port(self, port_id, add_exclude, vnic_index):
        """Add vnic to a port and check if the device was added to the
        exclude list
        """
        plugin = self._get_core_plugin_with_dvs()
        vm_moref = 'dummy_moref'
        with mock.patch.object(plugin._vcm, 'get_vm_moref',
                               return_value=vm_moref):
            with mock.patch.object(
                plugin.nsx_v.vcns,
                'add_vm_to_exclude_list') as exclude_list_add:
                data = {'port': {'vnic_index': vnic_index}}
                self.new_update_request(
                    'ports', data, port_id).get_response(self.api)
                if add_exclude:
                    # make sure the vm was added to the exclude list
                    exclude_list_add.assert_called_once_with(vm_moref)
                else:
                    self.assertFalse(exclude_list_add.called)

    def _del_vnic_from_port(self, port_id, del_exclude):
        """Delete the vnic & device id from the port and check if
        the device was removed from the exclude list
        """
        plugin = self._get_core_plugin_with_dvs()
        vm_moref = 'dummy_moref'
        with mock.patch.object(plugin._vcm, 'get_vm_moref',
                               return_value=vm_moref):
            with mock.patch.object(
                plugin.nsx_v.vcns,
                'delete_vm_from_exclude_list') as exclude_list_del:
                data = {'port': {'vnic_index': None, 'device_id': ''}}
                self.new_update_request(
                    'ports', data, port_id).get_response(self.api)
                if del_exclude:
                    # make sure the vm was added to the exclude list
                    exclude_list_del.assert_called_once_with(vm_moref)
                else:
                    self.assertFalse(exclude_list_del.called)

    def _del_port_with_vnic(self, port_id, del_exclude):
        """Delete port with vnic, and check if the device was removed
        from the exclude list
        """
        plugin = self._get_core_plugin_with_dvs()
        vm_moref = 'dummy_moref'
        with mock.patch.object(plugin._vcm, 'get_vm_moref',
                               return_value=vm_moref):
            with mock.patch.object(
                plugin.nsx_v.vcns,
                'delete_vm_from_exclude_list') as exclude_list_del:
                self.new_delete_request(
                    'ports', port_id).get_response(self.api)
                if del_exclude:
                    # make sure the vm was added to the exclude list
                    exclude_list_del.assert_called_once_with(vm_moref)
                else:
                    self.assertFalse(exclude_list_del.called)

    def test_update_port_no_security_with_vnic(self):
        device_id = _uuid()
        # create a compute port without port security
        port = self._create_compute_port('net1', device_id, False)

        # add vnic to the port
        self._add_vnic_to_port(port['port']['id'], True, 3)

        # delete vnic from the port
        self._del_vnic_from_port(port['port']['id'], True)

    def test_update_multiple_port_no_security_with_vnic(self):
        device_id = _uuid()
        # create a compute port without port security
        port1 = self._create_compute_port('net1', device_id, False)
        # add vnic to the port
        self._add_vnic_to_port(port1['port']['id'], True, 3)

        # create another compute port without port security on the same device
        port2 = self._create_compute_port('net2', device_id, False)
        # add vnic to the port (no need to add to exclude list again)
        self._add_vnic_to_port(port2['port']['id'], False, 4)

        # delete vnics from the port
        self._del_vnic_from_port(port1['port']['id'], False)
        self._del_vnic_from_port(port2['port']['id'], True)

    def test_update_mixed_port_no_security_with_vnic(self):
        device_id = _uuid()
        # create a compute port without port security
        port1 = self._create_compute_port('net1', device_id, True)
        # add vnic to the port
        self._add_vnic_to_port(port1['port']['id'], False, 3)

        irrelevant_device_id = _uuid()
        # create a compute port without port security for a different device
        port2 = self._create_compute_port('net1', irrelevant_device_id, True)
        # add vnic to the port
        self._add_vnic_to_port(port2['port']['id'], False, 3)

        # create another compute port without port security on the same device
        port3 = self._create_compute_port('net2', device_id, False)
        # add vnic to the port (no need to add to exclude list again)
        self._add_vnic_to_port(port3['port']['id'], True, 4)

        # delete vnics from the port
        self._del_vnic_from_port(port1['port']['id'], False)
        self._del_vnic_from_port(port3['port']['id'], True)
        self._del_vnic_from_port(port2['port']['id'], False)

    def test_delete_port_no_security_with_vnic(self):
        device_id = _uuid()
        # create a compute port without port security
        port = self._create_compute_port('net1', device_id, False)

        # add vnic to the port
        self._add_vnic_to_port(port['port']['id'], True, 3)

        # delete port with the vnic
        self._del_port_with_vnic(port['port']['id'], True)

    def test_delete_multiple_port_no_security_with_vnic(self):
        device_id = _uuid()
        # create a compute port without port security
        port1 = self._create_compute_port('net1', device_id, False)
        # add vnic to the port
        self._add_vnic_to_port(port1['port']['id'], True, 3)

        # create another compute port without port security on the same device
        port2 = self._create_compute_port('net2', device_id, False)
        # add vnic to the port (no need to add to exclude list again)
        self._add_vnic_to_port(port2['port']['id'], False, 4)

        # delete ports with the vnics
        self._del_port_with_vnic(port2['port']['id'], False)
        self._del_port_with_vnic(port1['port']['id'], True)

    def test_detach_port_no_sec(self):
        device_id = _uuid()
        # create a compute port without port security
        port = self._create_compute_port('net1', device_id, False)
        # add vnic to the port
        self._add_vnic_to_port(port['port']['id'], True, 3)

        # detach the port
        with mock.patch.object(
            self.fc2,
            'inactivate_vnic_assigned_addresses') as mock_inactivte:
            self._del_vnic_from_port(port['port']['id'], True)
            # inactivate spoofguard should not be called
            self.assertFalse(mock_inactivte.called)

    def test_detach_port_with_sec(self):
        device_id = _uuid()
        # create a compute port without port security
        port = self._create_compute_port('net1', device_id, True)
        # add vnic to the port
        self._add_vnic_to_port(port['port']['id'], False, 3)

        # detach the port
        with mock.patch.object(
            self.fc2,
            'inactivate_vnic_assigned_addresses') as mock_inactivte:
            self._del_vnic_from_port(port['port']['id'], False)
            # inactivate spoofguard should be called
            self.assertTrue(mock_inactivte.called)

    def _toggle_port_security(self, port_id, enable_port_security,
                              update_exclude):
        """Enable/disable port security on a port, and verify that the exclude
        list was updated as expected
        """
        plugin = self._get_core_plugin_with_dvs()
        vm_moref = 'dummy_moref'
        data = {'port': {'port_security_enabled': enable_port_security}}
        with mock.patch.object(plugin._vcm, 'get_vm_moref',
                               return_value=vm_moref):
            if enable_port_security:
                with mock.patch.object(
                    plugin.nsx_v.vcns,
                    'delete_vm_from_exclude_list') as exclude_list_del:
                    self.new_update_request(
                        'ports', data, port_id).get_response(self.api)
                    if update_exclude:
                        # make sure the vm was added to the exclude list
                        exclude_list_del.assert_called_once_with(vm_moref)
                    else:
                        self.assertFalse(exclude_list_del.called)
            else:
                with mock.patch.object(
                    plugin.nsx_v.vcns,
                    'add_vm_to_exclude_list') as exclude_list_add:
                    self.new_update_request(
                        'ports', data, port_id).get_response(self.api)
                    if update_exclude:
                        # make sure the vm was added to the exclude list
                        exclude_list_add.assert_called_once_with(vm_moref)
                    else:
                        self.assertFalse(exclude_list_add.called)

    def test_update_port_security_with_vnic(self):
        device_id = _uuid()
        # create a compute port without port security
        port = self._create_compute_port('net1', device_id, False)

        # add vnic to the port
        self._add_vnic_to_port(port['port']['id'], True, 3)

        # enable port security
        self._toggle_port_security(port['port']['id'], True, True)

        # disable port security
        self._toggle_port_security(port['port']['id'], False, True)

        # delete vnic from the port
        self._del_vnic_from_port(port['port']['id'], True)

    def test_update_multiple_port_security_with_vnic(self):
        device_id = _uuid()
        # create a compute port without port security
        port1 = self._create_compute_port('net1', device_id, False)

        # add vnic to the port
        self._add_vnic_to_port(port1['port']['id'], True, 3)

        # create another compute port without port security
        port2 = self._create_compute_port('net2', device_id, False)

        # add vnic to the port
        self._add_vnic_to_port(port2['port']['id'], False, 4)

        # enable port security on both ports
        self._toggle_port_security(port1['port']['id'], True, False)
        self._toggle_port_security(port2['port']['id'], True, True)

        # disable port security on both ports
        self._toggle_port_security(port1['port']['id'], False, True)
        self._toggle_port_security(port2['port']['id'], False, False)

    def test_service_insertion(self):
        # init the plugin mocks
        p = directory.get_plugin()
        self.fc2.add_member_to_security_group = (
            mock.Mock().add_member_to_security_group)
        self.fc2.remove_member_from_security_group = (
            mock.Mock().remove_member_from_security_group)

        # mock the service insertion handler
        p._si_handler = mock.Mock()
        p._si_handler.enabled = True
        p._si_handler.sg_id = '11'

        # create a compute port with port security
        device_id = _uuid()
        port = self._create_compute_port('net1', device_id, True)

        # add vnic to the port, and verify that the port was added to the
        # service insertion security group
        vnic_id = 3
        vnic_index = '%s.%03d' % (device_id, vnic_id)
        self.fc2.add_member_to_security_group.reset_mock()
        self._add_vnic_to_port(port['port']['id'], False, vnic_id)
        self.fc2.add_member_to_security_group.assert_any_call(
            p._si_handler.sg_id, vnic_index)

        # disable the port security and make sure it is removed from the
        # security group
        self.fc2.remove_member_from_security_group.reset_mock()
        self._toggle_port_security(port['port']['id'], False, True)
        self.fc2.remove_member_from_security_group.assert_any_call(
            p._si_handler.sg_id, vnic_index)

    def test_service_insertion_notify(self):
        # create a compute ports with/without port security
        device_id = _uuid()
        # create 2 compute ports with port security
        port1 = self._create_compute_port('net1', device_id, True)
        self._add_vnic_to_port(port1['port']['id'], False, 1)
        port2 = self._create_compute_port('net2', device_id, True)
        self._add_vnic_to_port(port2['port']['id'], False, 2)
        # create 1 compute port without port security
        port3 = self._create_compute_port('net3', device_id, False)
        self._add_vnic_to_port(port3['port']['id'], True, 3)

        # init the plugin mocks
        p = directory.get_plugin()
        self.fc2.add_member_to_security_group = (
            mock.Mock().add_member_to_security_group)

        # call the function (that should be called from the flow classifier
        # driver) and verify it adds all relevant ports to the group
        # Since it uses spawn_n, we should mock it.
        orig_spawn = c_utils.spawn_n
        c_utils.spawn_n = mock.Mock(side_effect=lambda f, x: f(x, None))
        p.add_vms_to_service_insertion(sg_id='aaa')
        # back to normal
        c_utils.spawn_n = orig_spawn
        self.assertEqual(2, self.fc2.add_member_to_security_group.call_count)

    def test_toggle_non_compute_port_security(self):
        # create a network without port security
        res = self._create_network('json', 'net1', True)
        net = self.deserialize('json', res)

        # create a port with this network and a device
        res = self._create_port('json', net['network']['id'],
                                arg_list=('port_security_enabled',),
                                port_security_enabled=True)
        port = self.deserialize('json', res)
        port_id = port['port']['id']

        # Disable port security
        data = {'port': {'port_security_enabled': False}}
        updated_port = self.deserialize(
            'json',
            self.new_update_request('ports', data,
                                    port_id).get_response(self.api))
        self.assertFalse(updated_port['port']['port_security_enabled'])
        shown_port = self.deserialize(
            'json',
            self.new_show_request('ports',
                                  port_id).get_response(self.api))
        self.assertFalse(shown_port['port']['port_security_enabled'])

        # Enable port security
        data = {'port': {'port_security_enabled': True}}
        updated_port = self.deserialize(
            'json',
            self.new_update_request('ports', data,
                                    port_id).get_response(self.api))
        self.assertTrue(updated_port['port']['port_security_enabled'])
        shown_port = self.deserialize(
            'json',
            self.new_show_request('ports',
                                  port_id).get_response(self.api))
        self.assertTrue(shown_port['port']['port_security_enabled'])


class TestSharedRouterTestCase(L3NatTest, L3NatTestCaseBase,
                               test_l3_plugin.L3NatTestCaseMixin,
                               NsxVPluginV2TestCase):

    def _create_router(self, fmt, tenant_id, name=None,
                       admin_state_up=None, set_context=False,
                       arg_list=None, **kwargs):
        tenant_id = tenant_id or _uuid()
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up:
            data['router']['admin_state_up'] = admin_state_up
        for arg in (('admin_state_up', 'tenant_id') + (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs and kwargs[arg]:
                data['router'][arg] = kwargs[arg]

        data['router']['router_type'] = kwargs.get('router_type', 'shared')

        router_req = self.new_create_request('routers', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            router_req.environ['neutron.context'] = context.Context(
                '', tenant_id)

        return router_req.get_response(self.ext_api)

    @mock.patch.object(edge_utils.EdgeManager,
                       'update_interface_addr')
    def test_router_add_interface_multiple_ipv6_subnets_same_net(self, mock):
        super(TestSharedRouterTestCase,
              self).test_router_add_interface_multiple_ipv6_subnets_same_net()

    def test_router_create_with_no_edge(self):
        name = 'router1'
        tenant_id = _uuid()
        expected_value = [('name', name), ('tenant_id', tenant_id),
                          ('admin_state_up', True), ('status', 'ACTIVE'),
                          ('external_gateway_info', None)]
        with self.router(name='router1', admin_state_up=True,
                         tenant_id=tenant_id) as router:
            for k, v in expected_value:
                self.assertEqual(router['router'][k], v)
            self.assertEqual(
                [],
                self.plugin_instance.edge_manager.get_routers_on_same_edge(
                    context.get_admin_context(), router['router']['id']))

    def test_router_create_with_size_fail_at_backend(self):
        data = {'router': {
                    'tenant_id': 'whatever',
                    'router_type': 'shared',
                    'router_size': 'large'}}
        router_req = self.new_create_request('routers', data, self.fmt)
        res = router_req.get_response(self.ext_api)
        router = self.deserialize(self.fmt, res)
        msg = ('Bad router request: '
               'Cannot specify router-size for shared router.')
        self.assertEqual("BadRequest", router['NeutronError']['type'])
        self.assertEqual(msg, router['NeutronError']['message'])

    def test_router_create_with_gwinfo_with_no_edge(self):
        with self._create_l3_ext_network() as net:
            with self.subnet(network=net, enable_dhcp=False) as s:
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
                self.assertEqual(
                    [],
                    self.plugin_instance.edge_manager.
                    get_routers_on_same_edge(
                        context.get_admin_context(),
                        router['router']['id']))

    def test_router_update_with_routes_fail(self):
        """Shared router currently does not support static routes
        """
        with self.router() as r:
            router_id = r['router']['id']
            body = self._show('routers', router_id)
            body['router']['routes'] = [{'destination': '5.5.5.5/32',
                                         'nexthop': '6.6.6.6'}]
            self._update('routers', router_id, body,
                         expected_code=400,
                         neutron_context=context.get_admin_context())

    def test_router_update_gateway_with_no_edge(self):
        with self.router() as r:
            with self.subnet() as s1:
                with self._create_l3_ext_network() as net:
                    with self.subnet(network=net, enable_dhcp=False) as s2:
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
                            self.assertEqual(
                                [],
                                self.plugin_instance.edge_manager.
                                get_routers_on_same_edge(
                                    context.get_admin_context(),
                                    r['router']['id']))
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
                            self.assertEqual(
                                [],
                                self.plugin_instance.edge_manager.
                                get_routers_on_same_edge(
                                    context.get_admin_context(),
                                    r['router']['id']))
                        finally:
                            # Cleanup
                            self._remove_external_gateway_from_router(
                                r['router']['id'],
                                s2['subnet']['network_id'])

    def test_router_update_gateway_with_existing_floatingip_with_edge(self):
        with self._create_l3_ext_network() as net:
            with self.subnet(network=net, enable_dhcp=False) as subnet:
                with self.floatingip_with_assoc() as fip:
                    self._add_external_gateway_to_router(
                        fip['floatingip']['router_id'],
                        subnet['subnet']['network_id'],
                        expected_code=webob.exc.HTTPConflict.code)
                    self.assertNotEqual(
                        [],
                        self.plugin_instance.edge_manager.
                        get_routers_on_same_edge(
                            context.get_admin_context(),
                            fip['floatingip']['router_id']))

    def test_router_set_gateway_with_interfaces_with_edge(self):
        with self.router() as r, self.subnet() as s1:
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
                self.assertEqual(
                    [],
                    self.plugin_instance.edge_manager.
                    get_routers_on_same_edge(
                        context.get_admin_context(),
                        r['router']['id']))

                with self.subnet(cidr='11.0.0.0/24') as s11:
                    with self.subnet(cidr='12.0.0.0/24') as s12:

                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      s11['subnet']['id'],
                                                      None)
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      s12['subnet']['id'],
                                                      None)
                        self.assertIsNotNone(
                            self.plugin_instance.edge_manager.
                            get_routers_on_same_edge(
                                context.get_admin_context(),
                                r['router']['id']))
                        self._router_interface_action('remove',
                                                      r['router']['id'],
                                                      s11['subnet']['id'],
                                                      None)
                        self.assertIsNotNone(
                            self.plugin_instance.edge_manager.
                            get_routers_on_same_edge(
                                context.get_admin_context(),
                                r['router']['id']))
                        self._router_interface_action('remove',
                                                      r['router']['id'],
                                                      s12['subnet']['id'],
                                                      None)
                        self.assertEqual(
                            [],
                            self.plugin_instance.edge_manager.
                            get_routers_on_same_edge(
                                context.get_admin_context(),
                                r['router']['id']))
            finally:
                # Cleanup
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s1['subnet']['network_id'])

    @mock.patch.object(edge_utils, "update_firewall")
    def test_routers_set_gateway_with_nosnat(self, mock):
        expected_fw1 = [{'action': 'allow',
                         'enabled': True,
                         'name': 'Subnet Rule',
                         'source_ip_address': [],
                         'destination_ip_address': []}]
        expected_fw2 = [{'action': 'allow',
                         'enabled': True,
                         'name': 'Subnet Rule',
                         'source_ip_address': [],
                         'destination_ip_address': []}]
        nosnat_fw1 = [{'action': 'allow',
                       'enabled': True,
                       'name': 'No SNAT Rule',
                       'source_vnic_groups': ["external"],
                       'destination_ip_address': []}]
        nosnat_fw2 = [{'action': 'allow',
                       'enabled': True,
                       'name': 'No SNAT Rule',
                       'source_vnic_groups': ["external"],
                       'destination_ip_address': []}]
        with self.router() as r1, self.router() as r2,\
                self.subnet() as ext_subnet,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(cidr='12.0.0.0/24') as s2:

            self._set_net_external(ext_subnet['subnet']['network_id'])
            self._router_interface_action(
                'add', r1['router']['id'],
                s1['subnet']['id'], None)
            expected_fw1[0]['source_ip_address'] = ['11.0.0.0/24']
            expected_fw1[0]['destination_ip_address'] = ['11.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(self._recursive_sort_list(expected_fw1),
                             self._recursive_sort_list(fw_rules))
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._add_external_gateway_to_router(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'])
            self._add_external_gateway_to_router(
                r2['router']['id'],
                ext_subnet['subnet']['network_id'])
            expected_fw2[0]['source_ip_address'] = ['12.0.0.0/24']
            expected_fw2[0]['destination_ip_address'] = ['12.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw1 + expected_fw2),
                self._recursive_sort_list(fw_rules))
            self._update_router_enable_snat(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'],
                False)
            nosnat_fw1[0]['destination_ip_address'] = ['11.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw1 + expected_fw2 +
                                          nosnat_fw1),
                self._recursive_sort_list(fw_rules))
            self._update_router_enable_snat(
                r2['router']['id'],
                ext_subnet['subnet']['network_id'],
                False)
            nosnat_fw2[0]['destination_ip_address'] = ['12.0.0.0/24']
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw1 + expected_fw2 +
                                          nosnat_fw1 + nosnat_fw2),
                self._recursive_sort_list(fw_rules))
            self._update_router_enable_snat(
                r2['router']['id'],
                ext_subnet['subnet']['network_id'],
                True)
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw1 + expected_fw2 +
                                          nosnat_fw1),
                self._recursive_sort_list(fw_rules))
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw1 + nosnat_fw1),
                self._recursive_sort_list(fw_rules))
            self._remove_external_gateway_from_router(
                r1['router']['id'],
                ext_subnet['subnet']['network_id'])
            fw_rules = mock.call_args[0][3]['firewall_rule_list']
            self.assertEqual(
                self._recursive_sort_list(expected_fw1),
                self._recursive_sort_list(fw_rules))
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._remove_external_gateway_from_router(
                r2['router']['id'],
                ext_subnet['subnet']['network_id'])

    def test_routers_with_interface_on_same_edge(self):
            with self.router() as r1, self.router() as r2,\
                    self.subnet(cidr='11.0.0.0/24') as s11,\
                    self.subnet(cidr='12.0.0.0/24') as s12:
                self._router_interface_action('add',
                                              r1['router']['id'],
                                              s11['subnet']['id'],
                                              None)
                self._router_interface_action('add',
                                              r2['router']['id'],
                                              s12['subnet']['id'],
                                              None)
                routers_expected = [r1['router']['id'], r2['router']['id']]
                routers_1 = (self.plugin_instance.edge_manager.
                             get_routers_on_same_edge(
                                 context.get_admin_context(),
                                 r1['router']['id']))
                self.assertEqual(set(routers_expected), set(routers_1))
                routers_2 = (self.plugin_instance.edge_manager.
                             get_routers_on_same_edge(
                                 context.get_admin_context(),
                                 r2['router']['id']))
                self.assertEqual(set(routers_expected), set(routers_2))
                self._router_interface_action('remove',
                                              r1['router']['id'],
                                              s11['subnet']['id'],
                                              None)
                self._router_interface_action('remove',
                                              r2['router']['id'],
                                              s12['subnet']['id'],
                                              None)

    def test_routers_with_overlap_interfaces(self):
        with self.router() as r1, self.router() as r2,\
                self.subnet(cidr='11.0.0.0/24') as s11,\
                self.subnet(cidr='11.0.0.0/24') as s12:
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s11['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s12['subnet']['id'],
                                          None)
            r1_expected = [r1['router']['id']]
            routers_1 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r1['router']['id']))
            self.assertEqual(r1_expected, routers_1)
            r2_expected = [r2['router']['id']]
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(r2_expected, routers_2)
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s11['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s12['subnet']['id'],
                                          None)

    def test_routers_with_overlap_interfaces_with_migration(self):
        with self.router() as r1, self.router() as r2,\
                self.subnet(cidr='11.0.0.0/24') as s11,\
                self.subnet(cidr='12.0.0.0/24') as s12,\
                self.subnet(cidr='11.0.0.0/24') as s13:
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s11['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s12['subnet']['id'],
                                          None)
            r1_expected = [r1['router']['id'], r2['router']['id']]
            routers_1 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r1['router']['id']))
            self.assertEqual(set(r1_expected), set(routers_1))
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s13['subnet']['id'],
                                          None)
            r1_expected = [r1['router']['id']]
            routers_1 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r1['router']['id']))
            self.assertEqual(r1_expected, routers_1)
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s11['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s12['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s13['subnet']['id'],
                                          None)

    def test_routers_with_different_subnet_on_same_network(self):
        with self.router() as r1, self.router() as r2,\
                self.network() as net,\
                self.subnet(network=net, cidr='12.0.0.0/24') as s1,\
                self.subnet(network=net, cidr='13.0.0.0/24') as s2:
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(1, len(routers_2))
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)

    def test_routers_with_different_subnet_on_same_network_migration(self):
        with self.router() as r1, self.router() as r2, self.network() as net,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(network=net, cidr='12.0.0.0/24') as s2,\
                self.subnet(network=net, cidr='13.0.0.0/24') as s3:
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(2, len(routers_2))
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s3['subnet']['id'],
                                          None)
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(2, len(routers_2))
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s3['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s3['subnet']['id'],
                                          None)
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(1, len(routers_2))
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s3['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)

    def test_routers_set_same_gateway_on_same_edge(self):
        with self.router() as r1, self.router() as r2,\
                self.network() as ext_net,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(cidr='12.0.0.0/24') as s2,\
                self.subnet(network=ext_net, cidr='13.0.0.0/24'):
            self._set_net_external(ext_net['network']['id'])
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._add_external_gateway_to_router(
                r1['router']['id'],
                ext_net['network']['id'])
            self._add_external_gateway_to_router(
                r2['router']['id'],
                ext_net['network']['id'])
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(2, len(routers_2))

            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._remove_external_gateway_from_router(
                r1['router']['id'],
                ext_net['network']['id'])
            self._remove_external_gateway_from_router(
                r2['router']['id'],
                ext_net['network']['id'])

    def test_routers_set_different_gateway_on_different_edge(self):
        with self.router() as r1, self.router() as r2,\
                self.network() as ext1, self.network() as ext2,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(cidr='12.0.0.0/24') as s2,\
                self.subnet(network=ext1, cidr='13.0.0.0/24'),\
                self.subnet(network=ext2, cidr='14.0.0.0/24'):
            self._set_net_external(ext1['network']['id'])
            self._set_net_external(ext2['network']['id'])
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._add_external_gateway_to_router(
                r1['router']['id'],
                ext1['network']['id'])
            self._add_external_gateway_to_router(
                r2['router']['id'],
                ext1['network']['id'])
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(2, len(routers_2))
            self._add_external_gateway_to_router(
                r2['router']['id'],
                ext2['network']['id'])
            routers_2 = (self.plugin_instance.edge_manager.
                         get_routers_on_same_edge(
                             context.get_admin_context(),
                             r2['router']['id']))
            self.assertEqual(1, len(routers_2))

            self._router_interface_action('remove',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('remove',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._remove_external_gateway_from_router(
                r1['router']['id'],
                ext1['network']['id'])
            self._remove_external_gateway_from_router(
                r2['router']['id'],
                ext2['network']['id'])

    def test_get_available_and_conflicting_ids_with_no_conflict(self):
        with self.router() as r1, self.router() as r2,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(cidr='12.0.0.0/24') as s2:
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            router_driver = (self.plugin_instance._router_managers.
                             get_tenant_router_driver(context, 'shared'))
            available_router_ids, conflict_router_ids = (
                router_driver._get_available_and_conflicting_ids(
                    context.get_admin_context(), r1['router']['id']))
            self.assertIn(r2['router']['id'], available_router_ids)
            self.assertEqual(0, len(conflict_router_ids))

    def test_get_available_and_conflicting_ids_with_conflict(self):
        with self.router() as r1, self.router() as r2,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(cidr='11.0.0.0/24') as s2:
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            router_driver = (self.plugin_instance._router_managers.
                             get_tenant_router_driver(context, 'shared'))
            available_router_ids, conflict_router_ids = (
                router_driver._get_available_and_conflicting_ids(
                    context.get_admin_context(), r1['router']['id']))
            self.assertIn(r2['router']['id'], conflict_router_ids)
            self.assertEqual(0, len(available_router_ids))

    def test_get_available_and_conflicting_ids_with_diff_gw(self):
        with self.router() as r1, self.router() as r2,\
                self.network() as ext1, self.network() as ext2,\
                self.subnet(cidr='11.0.0.0/24') as s1,\
                self.subnet(cidr='12.0.0.0/24') as s2,\
                self.subnet(network=ext1, cidr='13.0.0.0/24'),\
                self.subnet(network=ext2, cidr='14.0.0.0/24'):
            self._set_net_external(ext1['network']['id'])
            self._set_net_external(ext2['network']['id'])
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)
            self._router_interface_action('add',
                                          r2['router']['id'],
                                          s2['subnet']['id'],
                                          None)
            self._add_external_gateway_to_router(
                r1['router']['id'],
                ext1['network']['id'])
            self._add_external_gateway_to_router(
                r2['router']['id'],
                ext2['network']['id'])
            router_driver = (self.plugin_instance._router_managers.
                             get_tenant_router_driver(context, 'shared'))
            available_router_ids, conflict_router_ids = (
                router_driver._get_available_and_conflicting_ids(
                    context.get_admin_context(), r1['router']['id']))
            self.assertIn(r2['router']['id'], conflict_router_ids)
            self.assertEqual(0, len(available_router_ids))

    def test_migrate_shared_router_to_exclusive(self):
        with self.router(name='r7') as r1, \
                self.subnet(cidr='11.0.0.0/24') as s1:
            self._router_interface_action('add',
                                          r1['router']['id'],
                                          s1['subnet']['id'],
                                          None)

            # update the router type:
            router_id = r1['router']['id']
            self._update('routers', router_id,
                         {'router': {'router_type': 'exclusive'}})

            # get the updated router and check it's type
            body = self._show('routers', router_id)
            self.assertEqual('exclusive', body['router']['router_type'])

    def _test_create_router_with_az_hint(self, with_hint):
        # init the availability zones in the plugin
        az_name = 'az7'
        set_az_in_config(az_name)
        p = directory.get_plugin()
        p._availability_zones_data = nsx_az.NsxVAvailabilityZones()

        # create a router with/without hints
        router = {'router': {'admin_state_up': True,
                  'name': 'e161be1d-0d0d-4046-9823-5a593d94f72c',
                  'tenant_id': 'FAKE_TENANT',
                  'router_type': 'shared'}}
        if with_hint:
            router['router']['availability_zone_hints'] = [az_name]
        returned_router = p.create_router(context.get_admin_context(),
                                          router)
        # availability zones is still empty because the router is not attached
        if with_hint:
            self.assertEqual([az_name],
                             returned_router['availability_zone_hints'])
        else:
            self.assertEqual([],
                             returned_router['availability_zone_hints'])
        self.assertEqual([],
                         returned_router['availability_zones'])

        # Add interface so the router will be attached to an edge
        with self.subnet() as s1:
            router_id = returned_router['id']
            self._router_interface_action('add',
                                          router_id,
                                          s1['subnet']['id'],
                                          None)
            edge_id = edge_utils.get_router_edge_id(
                context.get_admin_context(), router_id)
            res_az = nsxv_db.get_edge_availability_zone(
                context.get_admin_context().session, edge_id)
            expected_az = az_name if with_hint else 'default'
            self.assertEqual(expected_az, res_az)

    def test_create_router_with_az_hint(self):
        self._test_create_router_with_az_hint(True)

    def test_create_router_without_az_hint(self):
        self._test_create_router_with_az_hint(False)


class TestRouterFlavorTestCase(extension.ExtensionTestCase,
                               test_l3_plugin.L3NatTestCaseMixin,
                               L3NatTest
                               ):

    FLAVOR_PLUGIN = 'neutron.services.flavors.flavors_plugin.FlavorsPlugin'

    def _mock_add_flavor_id(dummy, router_res, router_db):
        # this function is a registered callback so we can't mock it
        # in a regular way.
        # need to change behavior for this test suite only, since
        # there is no "unregister_dict_extend_funcs"
        if router_res['name'] == 'router_with_flavor':
            router_res['flavor_id'] = 'raspberry'

    def setUp(self, plugin=PLUGIN_NAME):
        # init the core plugin and flavors plugin
        service_plugins = {plugin_const.FLAVORS: self.FLAVOR_PLUGIN}
        super(TestRouterFlavorTestCase, self).setUp(
            plugin=plugin, service_plugins=service_plugins)
        self.plugin = directory.get_plugin()
        self.plugin._flv_plugin = directory.get_plugin(plugin_const.FLAVORS)
        self.plugin._process_router_flavor_create = mock.Mock()

        self.plugin.register_dict_extend_funcs(
                l3.ROUTERS, [self._mock_add_flavor_id])

        # init the availability zones
        self.az_name = 'az7'
        set_az_in_config(self.az_name)
        self.plugin._availability_zones_data = (
            nsx_az.NsxVAvailabilityZones())
        self._iteration = 1

    def assertSyslogConfig(self, expected):
        """Verify syslog was updated in fake driver

        Test assumes edge ids are created sequentally starting from edge-1
        """
        edge_id = ('edge-%s' % self._iteration)
        actual = self.plugin.nsx_v.vcns.get_edge_syslog(edge_id)[1]
        if not expected:
            # test expects no syslog to be configured
            self.assertNotIn('serverAddresses', actual)
            return

        self.assertEqual(expected['protocol'], actual['protocol'])
        self.assertEqual(expected['server_ip'],
                actual['serverAddresses']['ipAddress'][0])
        if 'server2_ip' in expected:
            self.assertEqual(expected['server2_ip'],
                    actual['serverAddresses']['ipAddress'][1])

    def _test_router_create_with_flavor(
        self, metainfo, expected_data,
        create_type=None,
        create_size=None,
        create_az=None):

        router_data = {'flavor_id': 'dummy',
                       'tenant_id': 'whatever',
                       'name': 'router_with_flavor',
                       'admin_state_up': True}

        if create_type is not None:
            router_data['router_type'] = create_type
        if create_size is not None:
            router_data['router_size'] = create_size
        if create_az is not None:
            router_data['availability_zone_hints'] = [create_az]

        flavor_data = {'service_type': plugin_const.L3,
                       'enabled': True,
                       'service_profiles': ['profile_id']}

        # Mock the flavors plugin
        with mock.patch(self.FLAVOR_PLUGIN + '.get_flavor',
            return_value=flavor_data):
            with mock.patch(self.FLAVOR_PLUGIN + '.get_service_profile',
                return_value={'metainfo': metainfo}):
                router = self.plugin.create_router(
                    context.get_admin_context(),
                    {'router': router_data})
                # syslog data is not part of router config
                # and needs to be validated separately
                if 'syslog' in expected_data.keys():
                    self.assertSyslogConfig(expected_data['syslog'])

                for key, expected_val in expected_data.items():
                    if key != 'syslog':
                        self.assertEqual(expected_val, router[key])

    def test_router_create_with_flavor_different_sizes(self):
        """Create exclusive router with size in flavor
        """
        for size in ['compact', 'large', 'xlarge', 'quadlarge']:
            metainfo = "{'router_size':'%s'}" % size
            expected_router = {'router_type': 'exclusive',
                               'router_size': size}
            self._test_router_create_with_flavor(
                metainfo, expected_router,
                create_type='exclusive')

    def test_router_create_with_flavor_ex_different_sizes(self):
        """Create exclusive router with size and type in flavor
        """
        for size in ['compact', 'large', 'xlarge', 'quadlarge']:
            metainfo = "{'router_size':'%s','router_type':'exclusive'}" % size
            expected_router = {'router_type': 'exclusive',
                               'router_size': size}
            self._test_router_create_with_flavor(
                metainfo, expected_router)

    def test_router_create_with_flavor_az(self):
        """Create exclusive router with availability zone in flavor
        """
        metainfo = "{'availability_zone_hints':'%s'}" % self.az_name
        expected_router = {'router_type': 'exclusive',
                           'availability_zone_hints': [self.az_name],
                           'distributed': False}
        self._test_router_create_with_flavor(
            metainfo, expected_router,
            create_type='exclusive')

    def test_router_create_with_flavor_shared(self):
        """Create shared router with availability zone and type in flavor
        """
        metainfo = ("{'availability_zone_hints':'%s',"
                    "'router_type':'shared'}" % self.az_name)
        expected_router = {'router_type': 'shared',
                           'availability_zone_hints': [self.az_name],
                           'distributed': False}
        self._test_router_create_with_flavor(
            metainfo, expected_router)

    def test_router_create_with_flavor_distributed(self):
        """Create distributed router with availability zone and type in flavor
        """
        metainfo = ("{'availability_zone_hints':'%s',"
                    "'distributed':true}" % self.az_name)
        expected_router = {'distributed': True,
                           'availability_zone_hints': [self.az_name]}
        self._test_router_create_with_flavor(
            metainfo, expected_router)

    def test_router_flavor_error_parsing(self):
        """Use the wrong format for the flavor metainfo

        It should be ignored, and default values are used
        """
        metainfo = "xxx"
        expected_router = {'distributed': False,
                           'router_type': 'shared'}
        self._test_router_create_with_flavor(
            metainfo, expected_router)

    def test_router_create_with_syslog_flavor(self):
        """Create exclusive router with syslog config in flavor"""
        # Basic config - server IP only
        ip = '1.1.1.10'
        expected_router = {'router_type': 'exclusive',
                    'syslog': {'protocol': 'tcp',
                    'server_ip': ip}}

        metainfo = ("{'router_type':'exclusive',"
                    "'syslog':{'server_ip':'%s'}}" % ip)

        self._iteration = 1
        self._test_router_create_with_flavor(
            metainfo, expected_router)

        # Advanced config - secondary server IP, protocol and loglevel
        ip2 = '1.1.1.11'
        for protocol in ['tcp', 'udp']:
            for loglevel in ['none', 'debug', 'info', 'warning', 'error']:
                expected_router = {'router_type': 'exclusive',
                               'syslog': {'protocol': protocol,
                                   'server_ip': ip, 'server2_ip': ip2}}

                metainfo = ("{'router_type':'exclusive',"
                        "'syslog':{'server_ip':'%s', 'server2_ip':'%s',"
                        "'protocol':'%s', 'log_level':'%s'}}" %
                        (ip, ip2, protocol, loglevel))

                self._iteration += 1
                self._test_router_create_with_flavor(
                    metainfo, expected_router)

    def test_router_create_with_syslog_flavor_error(self):
        """Create router based on flavor with badly formed syslog metadata

        Syslog metadata should be ignored
        """
        expected_router = {'router_type': 'exclusive',
                           'syslog': None}

        self._iteration = 0
        bad_defs = ("'server_ip':'1.1.1.1', 'protocol':'http2'",
                "'server2_ip':'2.2.2.2'",
                "'protocol':'tcp'",
                "'server_ip':'1.1.1.1', 'protocol':'udp','log_level':'pro'",
                "'log_level':'error'")
        for meta in bad_defs:
            metainfo = "{'router_type':'exclusive', 'syslog': {%s}}" % meta

            self._iteration += 1
            self._test_router_create_with_flavor(
                metainfo, expected_router)

    def _test_router_create_with_flavor_error(
        self, metainfo, error_code,
        create_type=None,
        create_size=None,
        create_az=None):

        router_data = {'flavor_id': 'dummy',
                       'tenant_id': 'whatever',
                       'name': 'test_router',
                       'admin_state_up': True}

        if create_type is not None:
            router_data['router_type'] = create_type
        if create_size is not None:
            router_data['router_size'] = create_size
        if create_az is not None:
            router_data['availability_zone_hints'] = [create_az]

        flavor_data = {'service_type': plugin_const.L3,
                       'enabled': True,
                       'service_profiles': ['profile_id']}

        # Mock the flavors plugin
        with mock.patch(self.FLAVOR_PLUGIN + '.get_flavor',
            return_value=flavor_data):
            with mock.patch(self.FLAVOR_PLUGIN + '.get_service_profile',
                return_value={'metainfo': metainfo}):
                self.assertRaises(error_code,
                    self.plugin.create_router,
                    context.get_admin_context(),
                    {'router': router_data})

    def test_router_flavor_size_conflict(self):
        metainfo = "{'router_size':'large','router_type':'exclusive'}"
        self._test_router_create_with_flavor_error(
            metainfo, n_exc.BadRequest,
            create_size='compact')

    def test_router_flavor_type_conflict(self):
        metainfo = "{'router_size':'large','router_type':'exclusive'}"
        self._test_router_create_with_flavor_error(
            metainfo, n_exc.BadRequest,
            create_type='shared')

    def test_router_flavor_az_conflict(self):
        metainfo = ("{'availability_zone_hints':'%s',"
                    "'distributed':true}" % self.az_name)
        self._test_router_create_with_flavor_error(
            metainfo, n_exc.BadRequest,
            create_az=['az2'])


class DHCPOptsTestCase(test_dhcpopts.TestExtraDhcpOpt,
                       NsxVPluginV2TestCase):

    def setUp(self, plugin=None):
        super(test_dhcpopts.ExtraDhcpOptDBTestCase, self).setUp(
            plugin=PLUGIN_NAME)

    def test_create_port_with_extradhcpopts(self):
        opt_list = [{'opt_name': 'bootfile-name',
                     'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server-address',
                     'opt_value': '123.123.123.123'}]

        params = {edo_ext.EXTRADHCPOPTS: opt_list,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            self._check_opts(opt_list,
                             port['port'][edo_ext.EXTRADHCPOPTS])

    def test_create_port_with_extradhcpopts_ipv6_opt_version(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_create_port_with_extradhcpopts_ipv4_opt_version(self):
        opt_list = [{'opt_name': 'bootfile-name',
                     'opt_value': 'pxelinux.0',
                     'ip_version': 4},
                    {'opt_name': 'tftp-server-address',
                     'opt_value': '123.123.123.123',
                     'ip_version': 4}]

        params = {edo_ext.EXTRADHCPOPTS: opt_list,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            self._check_opts(opt_list,
                             port['port'][edo_ext.EXTRADHCPOPTS])

    def test_update_port_with_extradhcpopts_with_same(self):
        opt_list = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server-address',
                     'opt_value': '123.123.123.123'}]
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': 'changeme.0'}]
        expected_opts = opt_list[:]
        for i in expected_opts:
            if i['opt_name'] == upd_opts[0]['opt_name']:
                i['opt_value'] = upd_opts[0]['opt_value']
                break
        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)

    def test_update_port_with_additional_extradhcpopt(self):
        opt_list = [{'opt_name': 'tftp-server-address',
                     'opt_value': '123.123.123.123'}]
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': 'changeme.0'}]
        expected_opts = copy.deepcopy(opt_list)
        expected_opts.append(upd_opts[0])
        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)

    def test_update_port_with_extradhcpopts(self):
        opt_list = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server-address',
                     'opt_value': '123.123.123.123'}]
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': 'changeme.0'}]
        expected_opts = copy.deepcopy(opt_list)
        for i in expected_opts:
            if i['opt_name'] == upd_opts[0]['opt_name']:
                i['opt_value'] = upd_opts[0]['opt_value']
                break
        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)

    def test_update_port_with_extradhcpopt_delete(self):
        opt_list = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server-address',
                     'opt_value': '123.123.123.123'}]
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': None}]
        expected_opts = []

        expected_opts = [opt for opt in opt_list
                         if opt['opt_name'] != 'bootfile-name']
        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)

    def test_update_port_adding_extradhcpopts(self):
        opt_list = []
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server-address',
                     'opt_value': '123.123.123.123'}]
        expected_opts = copy.deepcopy(upd_opts)
        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)

    def test_update_port_with_blank_name_extradhcpopt(self):
        opt_list = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server-address',
                     'opt_value': '123.123.123.123'}]
        upd_opts = [{'opt_name': '     ', 'opt_value': 'pxelinux.0'}]

        params = {edo_ext.EXTRADHCPOPTS: opt_list,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            update_port = {'port': {edo_ext.EXTRADHCPOPTS: upd_opts}}

            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            res = req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_port_with_empty_router_extradhcpopts(self):
        self.skipTest('No DHCP support option for router')

    def test_update_port_with_blank_router_extradhcpopt(self):
        self.skipTest('No DHCP support option for router')

    def test_update_port_with_extradhcpopts_ipv6_change_value(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_port_with_extradhcpopts_add_another_ver_opt(self):
        self.skipTest('No DHCP v6 Support yet')

    def test_update_port_with_blank_string_extradhcpopt(self):
        opt_list = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'}]
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': '    '}]

        params = {edo_ext.EXTRADHCPOPTS: opt_list,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            update_port = {'port': {edo_ext.EXTRADHCPOPTS: upd_opts}}

            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            res = req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_port_with_none_extradhcpopts(self):
        opt_list = [{'opt_name': 'bootfile-name',
                     'opt_value': None},
                    {'opt_name': 'tftp-server-address',
                     'opt_value': '123.123.123.123'}]
        expected = [{'opt_name': 'tftp-server-address',
                     'opt_value': '123.123.123.123'}]

        params = {edo_ext.EXTRADHCPOPTS: opt_list,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            self._check_opts(expected,
                             port['port'][edo_ext.EXTRADHCPOPTS])

    def test_create_port_with_extradhcpopts_codes(self):
        opt_list = [{'opt_name': '85',
                     'opt_value': 'cafecafe'}]

        params = {edo_ext.EXTRADHCPOPTS: opt_list,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            self._check_opts(opt_list,
                             port['port'][edo_ext.EXTRADHCPOPTS])

    def test_update_port_with_extradhcpopts_codes(self):
        opt_list = [{'opt_name': '85',
                     'opt_value': 'cafecafe'}]
        upd_opts = [{'opt_name': '85',
                     'opt_value': '01010101'}]
        expected_opts = copy.deepcopy(opt_list)
        for i in expected_opts:
            if i['opt_name'] == upd_opts[0]['opt_name']:
                i['opt_value'] = upd_opts[0]['opt_value']
                break
        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)
