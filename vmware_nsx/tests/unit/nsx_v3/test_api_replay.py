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

from vmware_nsx.tests.unit.nsx_v3 import test_plugin

from neutron.api.v2 import attributes
from neutron_lib.plugins import directory
from oslo_config import cfg


class TestApiReplay(test_plugin.NsxV3PluginTestCaseMixin):

    def setUp(self, plugin=None, ext_mgr=None, service_plugins=None):
        # enables api_replay_mode for these tests
        cfg.CONF.set_override('api_replay_mode', True)

        super(TestApiReplay, self).setUp()

    def tearDown(self):
        # disables api_replay_mode for these tests
        cfg.CONF.set_override('api_replay_mode', False)

        # remove the extension from the plugin
        directory.get_plugin().supported_extension_aliases.remove(
            'api-replay')

        # Revert the attributes map back to normal
        for attr_name in ('ports', 'networks', 'security_groups',
                          'security_group_rules', 'routers', 'policies'):
            attr_info = attributes.RESOURCE_ATTRIBUTE_MAP[attr_name]
            attr_info['id']['allow_post'] = False

        super(TestApiReplay, self).tearDown()

    def test_create_port_specify_id(self):
        specified_network_id = '555e762b-d7a1-4b44-b09b-2a34ada56c9f'
        specified_port_id = 'e55e762b-d7a1-4b44-b09b-2a34ada56c9f'
        network_res = self._create_network(self.fmt,
                                           'test-network',
                                           True,
                                           arg_list=('id',),
                                           id=specified_network_id)
        network = self.deserialize(self.fmt, network_res)
        self.assertEqual(specified_network_id, network['network']['id'])
        port_res = self._create_port(self.fmt,
                                     network['network']['id'],
                                     arg_list=('id',),
                                     id=specified_port_id)
        port = self.deserialize(self.fmt, port_res)
        self.assertEqual(specified_port_id, port['port']['id'])
