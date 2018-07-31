# Copyright (c) 2017 OpenStack Foundation.
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

from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory

from vmware_nsx.tests.unit.dvs import test_plugin as dvs_tests
from vmware_nsx.tests.unit.nsx_v import test_plugin as v_tests
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as t_tests

PLUGIN_NAME = 'vmware_nsx.plugin.NsxTVDPlugin'
_uuid = uuidutils.generate_uuid


class NsxTVDPluginTestCase(v_tests.NsxVPluginV2TestCase,
                           t_tests.NsxV3PluginTestCaseMixin,
                           dvs_tests.NeutronSimpleDvsTestCase):

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):

        # set the default plugin
        if self.plugin_type:
            cfg.CONF.set_override('default_plugin', self.plugin_type,
                                  group="nsx_tvd")

        # set the default availability zones
        cfg.CONF.set_override('nsx_v_default_availability_zones',
                              ['default'],
                              group="nsx_tvd")
        cfg.CONF.set_override('nsx_v3_default_availability_zones',
                              ['defaultv3'],
                              group="nsx_tvd")

        super(NsxTVDPluginTestCase, self).setUp(
            plugin=plugin,
            ext_mgr=ext_mgr,
            with_md_proxy=False)
        self._project_id = _uuid()
        self.core_plugin = directory.get_plugin()

        # create a context with this tenant
        self.context = context.get_admin_context()
        self.context.tenant_id = self.project_id

        # create a default user for this plugin
        self.core_plugin.create_project_plugin_map(self.context,
                {'project_plugin_map': {'plugin': self.plugin_type,
                                        'project': self.project_id}})
        self.sub_plugin = self.core_plugin.get_plugin_by_type(self.plugin_type)

    @property
    def project_id(self):
        return self._project_id

    @property
    def plugin_type(self):
        pass

    def _test_plugin_initialized(self):
        self.assertTrue(self.core_plugin.is_tvd_plugin())
        self.assertIsNotNone(self.sub_plugin)

    def _test_call_create(self, obj_name, calls_count=1, project_id=None,
                          is_bulk=False):
        method_name = single_name = 'create_%s' % obj_name
        if is_bulk:
            method_name = method_name + '_bulk'
        func_to_call = getattr(self.core_plugin, method_name)
        if not project_id:
            project_id = self.project_id
        with mock.patch.object(self.sub_plugin, method_name) as sub_func,\
            mock.patch.object(self.sub_plugin, single_name) as single_func:
            if is_bulk:
                func_to_call(self.context,
                             {obj_name + 's': [{obj_name:
                                                {'tenant_id': project_id}}]})
            else:
                func_to_call(self.context,
                             {obj_name: {'tenant_id': project_id}})
            self.assertEqual(calls_count,
                             sub_func.call_count or single_func.call_count)

    def _test_call_create_with_net_id(self, obj_name, field_name='network_id',
                                      calls_count=1, is_bulk=False):
        method_name = 'create_%s' % obj_name
        if is_bulk:
            method_name = method_name + '_bulk'
        func_to_call = getattr(self.core_plugin, method_name)
        net_id = _uuid()

        with mock.patch.object(self.sub_plugin, method_name) as sub_func,\
            mock.patch.object(self.core_plugin, '_get_network',
                              return_value={'tenant_id': self.project_id}):
            if is_bulk:
                func_to_call(self.context,
                             {obj_name + 's': [{obj_name:
                                                {'tenant_id': self.project_id,
                                                 field_name: net_id}}]})
            else:
                func_to_call(self.context,
                             {obj_name: {'tenant_id': self.project_id,
                                         field_name: net_id}})
            self.assertEqual(calls_count, sub_func.call_count)

    def _test_call_delete(self, obj_name):
        method_name = 'delete_%s' % obj_name
        func_to_call = getattr(self.core_plugin, method_name)
        obj_id = _uuid()
        with mock.patch.object(self.sub_plugin, method_name) as sub_func,\
            mock.patch.object(self.core_plugin, '_get_%s' % obj_name,
                              return_value={'tenant_id': self.project_id}):
            func_to_call(self.context, obj_id)
            sub_func.assert_called_once()

    def _test_call_delete_with_net(self, obj_name, field_name='network_id'):
        method_name = 'delete_%s' % obj_name
        func_to_call = getattr(self.core_plugin, method_name)
        obj_id = _uuid()
        net_id = _uuid()
        with mock.patch.object(self.sub_plugin, method_name) as sub_func,\
            mock.patch.object(self.core_plugin, '_get_%s' % obj_name,
                              return_value={field_name: net_id}),\
            mock.patch.object(self.core_plugin, '_get_network',
                              return_value={'tenant_id': self.project_id}):
            func_to_call(self.context, obj_id)
            sub_func.assert_called_once()

    def _test_call_update(self, obj_name):
        method_name = 'update_%s' % obj_name
        func_to_call = getattr(self.core_plugin, method_name)
        obj_id = _uuid()
        with mock.patch.object(self.sub_plugin, method_name) as sub_func,\
            mock.patch.object(self.core_plugin, '_get_%s' % obj_name,
                              return_value={'tenant_id': self.project_id}):
            func_to_call(self.context, obj_id, {obj_name: {}})
            sub_func.assert_called_once()

    def _test_call_update_with_net(self, obj_name, field_name='network_id'):
        method_name = 'update_%s' % obj_name
        func_to_call = getattr(self.core_plugin, method_name)
        obj_id = _uuid()
        net_id = _uuid()
        with mock.patch.object(self.sub_plugin, method_name) as sub_func,\
            mock.patch.object(self.core_plugin, '_get_%s' % obj_name,
                              return_value={field_name: net_id}),\
            mock.patch.object(self.core_plugin, '_get_network',
                              return_value={'tenant_id': self.project_id}):
            func_to_call(self.context, obj_id, {obj_name: {}})
            sub_func.assert_called_once()

    def _test_call_get(self, obj_name):
        method_name = 'get_%s' % obj_name
        func_to_call = getattr(self.core_plugin, method_name)
        obj_id = _uuid()
        with mock.patch.object(self.sub_plugin, method_name) as sub_func,\
            mock.patch.object(self.core_plugin, '_get_%s' % obj_name,
                              return_value={'tenant_id': self.project_id}):
            func_to_call(self.context, obj_id)
            sub_func.assert_called_once()

    def _test_call_get_with_net(self, obj_name, field_name='network_id'):
        method_name = 'get_%s' % obj_name
        func_to_call = getattr(self.core_plugin, method_name)
        obj_id = _uuid()
        net_id = _uuid()
        with mock.patch.object(self.sub_plugin, method_name) as sub_func,\
            mock.patch.object(self.core_plugin, '_get_%s' % obj_name,
                              return_value={field_name: net_id}),\
            mock.patch.object(self.core_plugin, '_get_network',
                              return_value={'tenant_id': self.project_id}):
            func_to_call(self.context, obj_id)
            sub_func.assert_called_once()


class TestPluginWithDefaultPlugin(NsxTVDPluginTestCase):
    """Test TVD plugin with the NSX-T (default) sub plugin"""

    @property
    def plugin_type(self):
        return 'nsx-t'

    def test_plugin_initialized(self):
        self._test_plugin_initialized()

        # no unsupported extensions for the nsx_t plugin
        self.assertItemsEqual(
            ['router_type', 'router_size'],
            self.core_plugin._unsupported_fields[self.plugin_type]['router'])
        self.assertEqual(
            [],
            self.core_plugin._unsupported_fields[self.plugin_type]['port'])

    def test_create_network(self):
        self._test_call_create('network')

    def test_create_subnet(self):
        self._test_call_create_with_net_id('subnet')

    def test_create_port(self):
        self._test_call_create_with_net_id('port')

    def test_create_router(self):
        self._test_call_create('router')

    def test_create_floatingip(self):
        self._test_call_create_with_net_id(
            'floatingip', field_name='floating_network_id')

    def test_create_security_group(self):
        # plugin will be called twice because of the default sg
        self._test_call_create('security_group', calls_count=2)

    def test_create_security_group_rule(self):
        self._test_call_create('security_group_rule')

    def test_create_network_bulk(self):
        self._test_call_create('network', is_bulk=True)

    def test_create_subnet_bulk(self):
        self._test_call_create_with_net_id('subnet', is_bulk=True)

    def test_create_security_group_rule_bulk(self):
        self._test_call_create('security_group_rule', is_bulk=True)

    def test_delete_network(self):
        self._test_call_delete('network')

    def test_delete_subnet(self):
        self._test_call_delete_with_net('subnet')

    def test_delete_port(self):
        self._test_call_delete_with_net('port')

    def test_delete_router(self):
        self._test_call_delete('router')

    def test_delete_floatingip(self):
        self._test_call_delete_with_net(
            'floatingip', field_name='floating_network_id')

    def test_delete_security_group(self):
        self._test_call_delete('security_group')

    def test_update_network(self):
        self._test_call_update('network')

    def test_update_subnet(self):
        self._test_call_update_with_net('subnet')

    def test_update_port(self):
        self._test_call_update_with_net('port')

    def test_update_router(self):
        self._test_call_update('router')

    def test_update_floatingip(self):
        self._test_call_update_with_net(
            'floatingip', field_name='floating_network_id')

    def test_update_security_group(self):
        self._test_call_update('security_group')

    def test_unsupported_extensions(self):
        self.assertRaises(n_exc.InvalidInput,
            self.core_plugin.create_router,
            self.context,
            {'router': {'tenant_id': self.project_id,
                        'router_type': 'exclusive'}})

    def test_get_network(self):
        self._test_call_get('network')

    def test_get_subnet(self):
        self._test_call_get_with_net('subnet')

    def test_get_port(self):
        self._test_call_get_with_net('port')

    def test_get_router(self):
        self._test_call_get('router')

    def test_get_floatingip(self):
        self._test_call_get_with_net(
            'floatingip', field_name='floating_network_id')

    def test_get_security_group(self):
        self._test_call_get('security_group')

    def test_add_router_interface(self):
        rtr_id = _uuid()
        port_id = _uuid()
        net_id = _uuid()
        with mock.patch.object(self.sub_plugin,
                               'add_router_interface') as sub_func,\
            mock.patch.object(self.core_plugin, '_get_router',
                              return_value={'tenant_id': self.project_id}),\
            mock.patch.object(self.core_plugin, '_get_port',
                              return_value={'network_id': net_id}),\
            mock.patch.object(self.core_plugin, '_get_network',
                              return_value={'tenant_id': self.project_id}),\
            mock.patch.object(self.core_plugin, '_validate_interface_info',
                              return_value=(True, False)):
            self.core_plugin.add_router_interface(self.context, rtr_id,
                                                  {'port_id': port_id})
            sub_func.assert_called_once()

    def test_add_invalid_router_interface(self):
        # Test that the plugin prevents adding interface from one plugin
        # to a router of another plugin
        rtr_id = _uuid()
        port_id = _uuid()
        net_id = _uuid()
        another_tenant_id = _uuid()
        another_plugin = 'nsx-v' if self.plugin_type == 'nsx-t' else 'nsx-t'
        self.core_plugin.create_project_plugin_map(self.context,
                {'project_plugin_map': {'plugin': another_plugin,
                                        'project': another_tenant_id}})

        with mock.patch.object(self.core_plugin, '_get_router',
                               return_value={'tenant_id': self.project_id}),\
            mock.patch.object(self.core_plugin, '_get_port',
                              return_value={'network_id': net_id}),\
            mock.patch.object(self.core_plugin, '_get_network',
                              return_value={'tenant_id': another_tenant_id}),\
            mock.patch.object(self.core_plugin, '_validate_interface_info',
                              return_value=(True, False)):
            self.assertRaises(n_exc.InvalidInput,
                              self.core_plugin.add_router_interface,
                              self.context, rtr_id, {'port_id': port_id})

    def test_remove_router_interface(self):
        rtr_id = _uuid()
        with mock.patch.object(self.sub_plugin,
                               'remove_router_interface') as sub_func,\
            mock.patch.object(self.core_plugin, '_get_router',
                              return_value={'tenant_id': self.project_id}):
            self.core_plugin.remove_router_interface(self.context, rtr_id, {})
            sub_func.assert_called_once()

    def test_disassociate_floatingips(self):
        port_id = _uuid()
        net_id = _uuid()
        with mock.patch.object(self.sub_plugin,
                               'disassociate_floatingips') as sub_func,\
            mock.patch.object(self.core_plugin, '_get_port',
                              return_value={'network_id': net_id}),\
            mock.patch.object(self.core_plugin, '_get_network',
                              return_value={'tenant_id': self.project_id}):
            self.core_plugin.disassociate_floatingips(self.context, port_id)
            sub_func.assert_called_once()

    def test_new_user(self):
        project_id = _uuid()
        self._test_call_create('network', project_id=project_id)


class TestPluginWithNsxv(TestPluginWithDefaultPlugin):
    """Test TVD plugin with the NSX-V sub plugin"""

    @property
    def plugin_type(self):
        return 'nsx-v'

    def test_plugin_initialized(self):
        self._test_plugin_initialized()

        # no unsupported extensions for the nsx_v plugin
        self.assertEqual(
            [],
            self.core_plugin._unsupported_fields[self.plugin_type]['router'])
        self.assertEqual(
            [],
            self.core_plugin._unsupported_fields[self.plugin_type]['port'])

    def test_unsupported_extensions(self):
        self.skipTest('No unsupported extensions in this plugin')


class TestPluginWithDvs(TestPluginWithDefaultPlugin):
    """Test TVD plugin with the DVS sub plugin"""

    @property
    def plugin_type(self):
        return 'dvs'

    def test_plugin_initialized(self):
        self._test_plugin_initialized()

        # no unsupported extensions for the dvs plugin
        self.assertItemsEqual(
            ['mac_learning_enabled', 'provider_security_groups'],
            self.core_plugin._unsupported_fields[self.plugin_type]['port'])

    def test_unsupported_extensions(self):
        net_id = _uuid()
        with mock.patch.object(self.core_plugin, '_get_network',
                               return_value={'tenant_id': self.project_id}):
            self.assertRaises(n_exc.InvalidInput,
                self.core_plugin.create_port,
                self.context,
                {'port': {'tenant_id': self.project_id,
                          'network_id': net_id,
                          'mac_learning_enabled': True}})
