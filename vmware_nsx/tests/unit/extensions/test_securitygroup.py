# Copyright (c) 2015 VMware, Inc.
# All Rights Reserved.
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

from neutron.tests.unit.extensions import test_securitygroup as ext_sg

from vmware_nsx.plugins.nsx_v3 import plugin as nsx_plugin
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_nsxv3


class TestSecurityGroups(test_nsxv3.NsxV3PluginTestCaseMixin,
                         ext_sg.TestSecurityGroups):

    @mock.patch.object(nsx_plugin.security.firewall, 'remove_nsgroup_member')
    @mock.patch.object(nsx_plugin.security.firewall, 'add_nsgroup_member')
    @mock.patch.object(nsx_plugin.security.firewall, 'create_nsgroup')
    def test_create_port_with_multiple_security_groups(self,
                                                       create_nsgroup_mock,
                                                       add_member_mock,
                                                       remove_member_mock):
        NSG_IDS = ['11111111-1111-1111-1111-111111111111',
                   '22222222-2222-2222-2222-222222222222',
                   '33333333-3333-3333-3333-333333333333']
        count = [-1]

        def _create_nsgroup_mock(x, y, z):
            count[0] += 1
            return {'id': NSG_IDS[count[0]]}

        create_nsgroup_mock.side_effect = _create_nsgroup_mock

        super(TestSecurityGroups,
              self).test_create_port_with_multiple_security_groups()

        # The first nsgroup is associated with the default secgroup, which is
        # not added to this port.
        calls = [mock.call(NSG_IDS[1], mock.ANY, mock.ANY),
                 mock.call(NSG_IDS[2], mock.ANY, mock.ANY)]
        add_member_mock.assert_has_calls(calls, any_order=True)

    @mock.patch.object(nsx_plugin.security.firewall, 'remove_nsgroup_member')
    @mock.patch.object(nsx_plugin.security.firewall, 'add_nsgroup_member')
    @mock.patch.object(nsx_plugin.security.firewall, 'create_nsgroup')
    def test_update_port_with_multiple_security_groups(self,
                                                       create_nsgroup_mock,
                                                       add_member_mock,
                                                       remove_member_mock):
        NSG_IDS = ['11111111-1111-1111-1111-111111111111',
                   '22222222-2222-2222-2222-222222222222',
                   '33333333-3333-3333-3333-333333333333']
        count = [-1]

        def _create_nsgroup_mock(x, y, z):
            count[0] += 1
            return {'id': NSG_IDS[count[0]]}

        create_nsgroup_mock.side_effect = _create_nsgroup_mock

        super(TestSecurityGroups,
              self).test_update_port_with_multiple_security_groups()

        calls = [mock.call(NSG_IDS[0], mock.ANY, mock.ANY),
                 mock.call(NSG_IDS[1], mock.ANY, mock.ANY),
                 mock.call(NSG_IDS[2], mock.ANY, mock.ANY)]
        add_member_mock.assert_has_calls(calls, any_order=True)

        remove_member_mock.assert_called_with(NSG_IDS[0], mock.ANY)

    @mock.patch.object(nsx_plugin.security.firewall, 'remove_nsgroup_member')
    @mock.patch.object(nsx_plugin.security.firewall, 'add_nsgroup_member')
    @mock.patch.object(nsx_plugin.security.firewall, 'create_nsgroup')
    def test_update_port_remove_security_group_empty_list(self,
                                                          create_nsgroup_mock,
                                                          add_member_mock,
                                                          remove_member_mock):
        NSG_ID = '11111111-1111-1111-1111-111111111111'
        create_nsgroup_mock.side_effect = lambda x, y, z: {'id': NSG_ID}

        super(TestSecurityGroups,
              self).test_update_port_remove_security_group_empty_list()

        add_member_mock.assert_called_with(NSG_ID, mock.ANY, mock.ANY)
        remove_member_mock.assert_called_with(NSG_ID, mock.ANY)
