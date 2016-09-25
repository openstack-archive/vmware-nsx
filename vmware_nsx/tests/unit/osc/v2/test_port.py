# Copyright 2016 VMware, Inc.
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
import re

from openstackclient.tests.unit.network.v2 import test_port
from openstackclient.tests.unit import utils as tests_utils

from vmware_nsx.osc.v2 import port


supported_extensions = ('vnic-index', 'provider-security-group')


class TestCreatePort(test_port.TestCreatePort):

    def setUp(self):
        super(TestCreatePort, self).setUp()
        # Get the command object to test
        self.cmd = port.NsxCreatePort(self.app, self.namespace)
        # mock the relevant extensions
        get_ext = mock.patch('vmware_nsx.osc.v2.utils.get_extensions').start()
        get_ext.return_value = supported_extensions

    def _test_create_with_arg_and_val(self, arg_name, arg_val, is_valid=True):
        self.network.create_port.reset_mock()
        # add '--' to the arg name and change '_' to '-'
        conv_name = '--' + re.sub('_', '-', arg_name)
        arglist = [
            self._port.name,
            '--network', self._port.network_id,
            conv_name, str(arg_val)
        ]
        verifylist = [
            ('name', self._port.name),
            ('network', self._port.network_id,),
            (arg_name, arg_val),
            ('enable', True),
        ]
        if not is_valid:
            self.assertRaises(tests_utils.ParserException, self.check_parser,
                              self.cmd, arglist, verifylist)
            return

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        columns, data = (self.cmd.take_action(parsed_args))
        self.network.create_port.assert_called_once_with(**{
            'admin_state_up': True,
            'network_id': self._port.network_id,
            'name': self._port.name,
            arg_name: arg_val,
        })

        ref_columns, ref_data = self._get_common_cols_data(self._port)
        self.assertEqual(ref_columns, columns)
        self.assertEqual(ref_data, data)

    def _test_create_with_vnix_index(self, val, is_valid=True):
        self._test_create_with_arg_and_val('vnic_index', val, is_valid)

    def test_create_with_vnic_index(self):
        self._test_create_with_vnix_index(1)

    def test_create_with_illegal_vnic_index(self):
        self._test_create_with_vnix_index('illegal', is_valid=False)


class TestSetPort(test_port.TestSetPort):

    def setUp(self):
        super(TestSetPort, self).setUp()
        # Get the command object to test
        self.cmd = port.NsxSetPort(self.app, self.namespace)
        # mock the relevant extensions
        get_ext = mock.patch('vmware_nsx.osc.v2.utils.get_extensions').start()
        get_ext.return_value = supported_extensions

    def _test_set_with_arg_and_val(self, arg_name, arg_val, is_valid=True):
        self.network.update_port.reset_mock()
        # add '--' to the arg name and change '_' to '-'
        conv_name = '--' + re.sub('_', '-', arg_name)
        arglist = [
            self._port.name,
            conv_name, str(arg_val)
        ]
        verifylist = [
            ('port', self._port.name),
            (arg_name, arg_val)
        ]
        if not is_valid:
            self.assertRaises(tests_utils.ParserException, self.check_parser,
                              self.cmd, arglist, verifylist)
            return

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        result = self.cmd.take_action(parsed_args)

        attrs = {arg_name: arg_val}
        self.network.update_port.assert_called_once_with(
            self._port, **attrs)
        self.assertIsNone(result)

    def _test_set_Vnic_index(self, val, is_valid=True):
        self._test_set_with_arg_and_val('vnic_index', val, is_valid)

    def test_set_vnic_index(self):
        self._test_set_Vnic_index(1)

    def test_set_illegal_vnic_index(self):
        # check illegal index
        self._test_set_Vnic_index('illegal', is_valid=False)

# TODO(asarfaty): add tests for provider-security-groups
