# Copyright (c) 2014 VMware.
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
from neutron_lib import context
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.tests import base
import neutron.tests.unit.db.test_db_base_plugin_v2 as test_plugin
from neutron_lib.api.definitions import portbindings
from neutron_lib import exceptions as exp
from neutron_lib.plugins import directory
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db as nsx_db
from vmware_nsx.dvs import dvs
from vmware_nsx.dvs import dvs_utils

PLUGIN_NAME = 'vmware_nsx.plugin.NsxDvsPlugin'


class fake_session(object):
    def __init__(self, *ret):
        self._vim = mock.Mock()

    def invoke_api(self, *args, **kwargs):
        pass

    def wait_for_task(self, task):
        pass

    def vim(self):
        return self._vim


class DvsTestCase(base.BaseTestCase):

    @mock.patch.object(dvs_utils, 'dvs_create_session',
                       return_value=fake_session())
    @mock.patch.object(dvs.SingleDvsManager, '_get_dvs_moref_by_name',
                       return_value=mock.MagicMock())
    def setUp(self, mock_moref, mock_session):
        super(DvsTestCase, self).setUp()
        cfg.CONF.set_override('dvs_name', 'fake_dvs', group='dvs')
        self._dvs = dvs.SingleDvsManager()
        self.assertEqual(mock_moref.return_value, self._dvs._dvs_moref)
        mock_moref.assert_called_once_with(mock_session.return_value,
                                           'fake_dvs')

    @mock.patch.object(dvs_utils, 'dvs_create_session',
                       return_value=fake_session())
    def test_dvs_not_found(self, mock_session):
        self.assertRaises(nsx_exc.DvsNotFound,
                          dvs.SingleDvsManager)

    @mock.patch.object(dvs.DvsManager, '_get_port_group_spec',
                       return_value='fake-spec')
    def test_add_port_group(self, fake_get_spec):
        self._dvs.add_port_group('fake-uuid', vlan_tag=7)
        fake_get_spec.assert_called_once_with('fake-uuid', 7, trunk_mode=False)

    @mock.patch.object(dvs.DvsManager, '_get_port_group_spec',
                       return_value='fake-spec')
    def test_add_port_group_with_exception(self, fake_get_spec):
        with (
            mock.patch.object(self._dvs._dvs._session, 'wait_for_task',
                              side_effect=exp.NeutronException())
        ):
            self.assertRaises(exp.NeutronException,
                              self._dvs.add_port_group,
                              'fake-uuid', 7,
                              trunk_mode=False)
            fake_get_spec.assert_called_once_with('fake-uuid', 7,
                                                  trunk_mode=False)

    @mock.patch.object(dvs.DvsManager, '_net_id_to_moref',
                       return_value='fake-moref')
    def test_delete_port_group(self, fake_get_moref):
        self._dvs.delete_port_group('fake-uuid')
        fake_get_moref.assert_called_once_with(mock.ANY, 'fake-uuid')

    @mock.patch.object(dvs.DvsManager, '_net_id_to_moref',
                       return_value='fake-moref')
    def test_delete_port_group_with_exception(self, fake_get_moref):
        with (
            mock.patch.object(self._dvs._dvs._session, 'wait_for_task',
                              side_effect=exp.NeutronException())
        ):
            self.assertRaises(exp.NeutronException,
                              self._dvs.delete_port_group,
                              'fake-uuid')
            fake_get_moref.assert_called_once_with(mock.ANY, 'fake-uuid')

    @mock.patch.object(dvs.DvsManager, '_update_vxlan_port_groups_config')
    @mock.patch.object(dvs.DvsManager, '_get_port_group_spec',
                       return_value='fake-spec')
    @mock.patch.object(dvs.DvsManager, '_net_id_to_moref',
                       return_value='fake-moref')
    def test_update_vxlan_net_group_conf(self, fake_get_moref,
                                         fake_get_spec, fake_update_vxlan):
        net_id = 'vxlan-uuid'
        vlan = 7
        self._dvs.add_port_group(net_id, vlan)
        self._dvs.net_id_to_moref(net_id)
        fake_get_moref.assert_called_once_with(mock.ANY, net_id)
        fake_get_spec.assert_called_once_with(net_id, vlan, trunk_mode=False)

    @mock.patch.object(dvs.DvsManager, '_update_net_port_groups_config')
    @mock.patch.object(dvs.DvsManager, '_get_port_group_spec',
                       return_value='fake-spec')
    @mock.patch.object(dvs.DvsManager, '_net_id_to_moref',
                       return_value='dvportgroup-fake-moref')
    def test_update_flat_net_conf(self, fake_get_moref,
                                  fake_get_spec, fake_update_net):
        net_id = 'flat-uuid'
        vlan = 7
        self._dvs.add_port_group(net_id, vlan)
        self._dvs.net_id_to_moref(net_id)
        fake_get_moref.assert_called_once_with(mock.ANY, net_id)
        fake_get_spec.assert_called_once_with(net_id, vlan, trunk_mode=False)


class NeutronSimpleDvsTest(test_plugin.NeutronDbPluginV2TestCase):

    @mock.patch.object(dvs_utils, 'dvs_create_session',
                       return_value=fake_session())
    @mock.patch.object(dvs.SingleDvsManager, '_get_dvs_moref_by_name',
                       return_value=mock.MagicMock())
    def setUp(self, mock_moref, mock_session,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        # Ensure that DVS is enabled
        cfg.CONF.set_override('host_ip', 'fake_ip', group='dvs')
        cfg.CONF.set_override('host_username', 'fake_user', group='dvs')
        cfg.CONF.set_override('host_password', 'fake_password', group='dvs')
        cfg.CONF.set_override('dvs_name', 'fake_dvs', group='dvs')
        super(NeutronSimpleDvsTest, self).setUp(plugin=PLUGIN_NAME)
        self._plugin = directory.get_plugin()

    def _create_and_delete_dvs_network(self, network_type='flat', vlan_tag=0,
                                       trunk_mode=False):
        params = {'provider:network_type': network_type,
                  'provider:physical_network': 'fake-moid',
                  'name': 'fake-name'}
        if network_type == 'vlan':
            params['provider:segmentation_id'] = vlan_tag
        if trunk_mode:
            params['vlan_transparent'] = True
        params['arg_list'] = tuple(params.keys())
        with mock.patch.object(self._plugin._dvs,
                               'add_port_group') as mock_add,\
                mock.patch.object(self._plugin._dvs,
                    'delete_port_group') as mock_delete,\
                mock.patch.object(dvs.DvsManager,
                    '_get_trunk_vlan_spec') as mock_trunk_vlan:
            with self.network(**params) as network:
                ctx = context.get_admin_context()
                id = network['network']['id']
                dvs_id = '%s-%s' % (network['network']['name'], id)
                binding = nsx_db.get_network_bindings(ctx.session, id)
                self.assertIsNotNone(binding)
                if network_type == 'flat':
                    self.assertEqual('flat', binding[0].binding_type)
                    self.assertEqual(0, binding[0].vlan_id)
                    self.assertEqual('dvs', binding[0].phy_uuid)
                elif network_type == 'vlan':
                    self.assertEqual('vlan', binding[0].binding_type)
                    self.assertEqual(vlan_tag, binding[0].vlan_id)
                    self.assertEqual('dvs', binding[0].phy_uuid)
                elif network_type == 'portgroup':
                    self.assertEqual('portgroup', binding[0].binding_type)
                    self.assertEqual(0, binding[0].vlan_id)
                    self.assertEqual('fake-moid', binding[0].phy_uuid)
                else:
                    self.fail()
            if network_type != 'portgroup':
                mock_add.assert_called_once_with(dvs_id, vlan_tag,
                                                 trunk_mode=trunk_mode)
            else:
                mock_add.call_count = 0
                mock_delete.call_count = 0
            if trunk_mode:
                mock_trunk_vlan.called_once_with(start=0, end=4094)
            else:
                mock_trunk_vlan.call_count = 0

    def test_create_and_delete_dvs_network_tag(self):
        self._create_and_delete_dvs_network(network_type='vlan', vlan_tag=7)

    def test_create_and_delete_dvs_network_flat(self):
        self._create_and_delete_dvs_network()

    def test_create_and_delete_dvs_network_flat_vlan_transparent(self):
        self._create_and_delete_dvs_network(trunk_mode=True)

    @mock.patch.object(dvs.DvsManager, 'get_port_group_info')
    @mock.patch.object(dvs.DvsManager, '_net_id_to_moref')
    def test_create_and_delete_dvs_network_portgroup(self, fake_get_moref,
                                                     fake_pg_info):
        fake_pg_info.return_value = {'name': 'fake-name'}
        self._create_and_delete_dvs_network(network_type='portgroup')
        self.assertTrue(fake_get_moref.call_count)
        self.assertTrue(fake_pg_info.call_count)

    @mock.patch.object(dvs.DvsManager, 'get_port_group_info')
    @mock.patch.object(dvs.DvsManager, '_net_id_to_moref')
    def test_create_and_delete_dvs_network_portgroup_vlan(self,
                                                          fake_get_moref,
                                                          fake_pg_info):
        fake_pg_info.return_value = {'name': 'fake-name'}
        self._create_and_delete_dvs_network(network_type='portgroup',
                                            vlan_tag=7)
        self.assertTrue(fake_get_moref.call_count)
        self.assertTrue(fake_pg_info.call_count)

    def test_create_and_delete_dvs_port(self):
        params = {'provider:network_type': 'vlan',
                  'provider:physical_network': 'dvs',
                  'provider:segmentation_id': 7}
        params['arg_list'] = tuple(params.keys())
        with mock.patch.object(self._plugin._dvs, 'add_port_group'),\
                mock.patch.object(self._plugin._dvs, 'delete_port_group'):
            with self.network(**params) as network,\
                    self.subnet(network) as subnet,\
                    self.port(subnet) as port:
                self.assertEqual('dvs',
                                 port['port'][portbindings.VIF_TYPE])
                port_status = port['port']['status']
                self.assertEqual(port_status, 'ACTIVE')

    def test_create_router_only_dvs_backend(self):
        data = {'router': {'tenant_id': 'whatever'}}
        data['router']['name'] = 'router1'
        data['router']['external_gateway_info'] = {'network_id': 'whatever'}
        self.assertRaises(exp.BadRequest,
                          self._plugin.create_router,
                          context.get_admin_context(),
                          data)

    def test_dvs_get_id(self):
        id = uuidutils.generate_uuid()
        net = {'name': '',
               'id': id}
        expected = id
        self.assertEqual(expected, self._plugin._dvs_get_id(net))
        net = {'name': 'pele',
               'id': id}
        expected = '%s-%s' % ('pele', id)
        self.assertEqual(expected, self._plugin._dvs_get_id(net))
        name = 'X' * 500
        net = {'name': name,
               'id': id}
        expected = '%s-%s' % (name[:43], id)
        self.assertEqual(expected, self._plugin._dvs_get_id(net))

    def test_update_dvs_network(self):
        """Test update of a DVS network
        """
        params = {'provider:network_type': 'flat',
                  'admin_state_up': True,
                  'name': 'test_net',
                  'tenant_id': 'fake_tenant',
                  'shared': False,
                  'port_security_enabled': False}

        with mock.patch.object(self._plugin._dvs, 'add_port_group'):
            ctx = context.get_admin_context()
            # create the initial network
            network = self._plugin.create_network(ctx, {'network': params})
            id = network['id']

            # update the different attributes of the DVS network

            # cannot update the provider type
            self.assertRaises(
                exp.InvalidInput,
                self._plugin.update_network,
                ctx, id,
                {'network': {'provider:network_type': 'vlan'}})

            # update the Shared attribute
            self.assertEqual(False, network['shared'])
            updated_net = self._plugin.update_network(
                ctx, id,
                {'network': {'shared': True}})
            self.assertEqual(True, updated_net['shared'])

            # Update the description attribute
            self.assertIsNone(network['description'])
            updated_net = self._plugin.update_network(
                ctx, id,
                {'network': {'description': 'test'}})
            self.assertEqual('test', updated_net['description'])

            # update the port security attribute
            self.assertEqual(False, network['port_security_enabled'])
            updated_net = self._plugin.update_network(
                ctx, id,
                {'network': {'port_security_enabled': True}})
            self.assertEqual(True, updated_net['port_security_enabled'])

    @mock.patch.object(dvs.DvsManager, 'get_port_group_info')
    @mock.patch.object(dvs.DvsManager, '_net_id_to_moref')
    def test_create_and_delete_portgroup_network_invalid_name(self,
                                                          fake_get_moref,
                                                          fake_pg_info):
        fake_pg_info.return_value = {'name': 'fake-different-name'}
        data = {'network': {'provider:network_type': 'portgroup',
                            'name': 'fake-name',
                            'admin_state_up': True}}
        self.assertRaises(exp.BadRequest, self._plugin.create_network,
                          context.get_admin_context(), data)
