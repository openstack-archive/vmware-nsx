# Copyright 2014 VMware, Inc.
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

from oslo_config import cfg
from oslo_db import exception as d_exc
from oslo_utils import uuidutils

from neutron.db import db_base_plugin_v2
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_db_plugin
from neutron_lib.api import validators
from neutron_lib import context as neutron_context
from neutron_lib.db import api as db_api
from neutron_lib.plugins import directory

from vmware_nsx.db import vnic_index_db
from vmware_nsx.extensions import vnicindex as vnicidx
from vmware_nsx.tests import unit as vmware


DB_PLUGIN_KLASS = ('vmware_nsx.tests.unit.extensions.'
                   'test_vnic_index.VnicIndexTestPlugin')

_uuid = uuidutils.generate_uuid


class VnicIndexTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                          vnic_index_db.VnicIndexDbMixin):

    supported_extension_aliases = [vnicidx.ALIAS]

    def update_port(self, context, id, port):
        p = port['port']
        current_port = super(VnicIndexTestPlugin, self).get_port(context, id)
        vnic_idx = p.get(vnicidx.VNIC_INDEX)
        device_id = current_port['device_id']
        if validators.is_attr_set(vnic_idx) and device_id != '':
            self._set_port_vnic_index_mapping(
                context, id, device_id, vnic_idx)

        with db_api.CONTEXT_WRITER.using(context):
            p = port['port']
            ret_port = super(VnicIndexTestPlugin, self).update_port(
                context, id, port)
            vnic_idx = current_port.get(vnicidx.VNIC_INDEX)
            if (validators.is_attr_set(vnic_idx) and
                device_id != ret_port['device_id']):
                self._delete_port_vnic_index_mapping(
                    context, id)
        return ret_port

    def delete_port(self, context, id):
        port_db = self.get_port(context, id)
        vnic_idx = port_db.get(vnicidx.VNIC_INDEX)
        if validators.is_attr_set(vnic_idx):
            self._delete_port_vnic_index_mapping(context, id)
        with db_api.CONTEXT_WRITER.using(context):
            super(VnicIndexTestPlugin, self).delete_port(context, id)


class VnicIndexDbTestCase(test_db_plugin.NeutronDbPluginV2TestCase):
    def setUp(self, plugin=None, ext_mgr=None):
        plugin = plugin or DB_PLUGIN_KLASS
        cfg.CONF.set_override('api_extensions_path', vmware.NSXEXT_PATH)
        super(VnicIndexDbTestCase, self).setUp(plugin=plugin, ext_mgr=ext_mgr)

    def _port_index_update(self, port_id, index):
        data = {'port': {'vnic_index': index}}
        req = self.new_update_request('ports', data, port_id)
        res = self.deserialize('json', req.get_response(self.api))
        return res

    def test_vnic_index_db(self):
        plugin = directory.get_plugin()
        vnic_index = 2
        device_id = _uuid()
        context = neutron_context.get_admin_context()
        with self.port(device_id=device_id,
                       device_owner='compute:None') as port:
            port_id = port['port']['id']
            res = self._port_index_update(port_id, vnic_index)
            self.assertEqual(res['port'][vnicidx.VNIC_INDEX], vnic_index)
            # Port should be associated with at most one vnic index
            self.assertRaises(d_exc.DBDuplicateEntry,
                              plugin._set_port_vnic_index_mapping,
                              context, port_id, device_id, 1)

            # Check that the call for _delete_port_vnic_index_mapping remove
            # the row from the table
            plugin._delete_port_vnic_index_mapping(context, port_id)
            self.assertIsNone(plugin._get_port_vnic_index(context, port_id))

    def test_vnic_index_db_duplicate(self):
        plugin = directory.get_plugin()
        vnic_index = 2
        device_id = _uuid()
        context = neutron_context.get_admin_context()
        with self.port(device_id=device_id,
                       device_owner='compute:None') as port:
            port_id = port['port']['id']
            res = self._port_index_update(port_id, vnic_index)
            self.assertEqual(res['port'][vnicidx.VNIC_INDEX], vnic_index)
            plugin._set_port_vnic_index_mapping(context, port_id, device_id,
                                                vnic_index)

    def test_vnic_index_db_duplicate_new_port(self):
        plugin = directory.get_plugin()
        vnic_index = 2
        device_id = _uuid()
        context = neutron_context.get_admin_context()
        with self.port(device_id=device_id,
                       device_owner='compute:None') as port:
            with self.port(device_id=device_id,
                           device_owner='compute:None') as port1:
                port_id = port['port']['id']
                res = self._port_index_update(port_id, vnic_index)
                self.assertEqual(res['port'][vnicidx.VNIC_INDEX], vnic_index)
                port_id1 = port1['port']['id']
                plugin._set_port_vnic_index_mapping(context, port_id1,
                                                    device_id, 2)
                self.assertIsNone(plugin._get_port_vnic_index(context,
                                                              port_id))
                self.assertEqual(vnic_index,
                                 plugin._get_port_vnic_index(context,
                                                             port_id1))


class TestVnicIndex(VnicIndexDbTestCase):
    pass
