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

import re

import mock
from openstackclient.tests.unit.network.v2 import fakes as network_fakes
from openstackclient.tests.unit.network.v2 import test_port
from openstackclient.tests.unit import utils as tests_utils

from vmware_nsx.extensions import maclearning
from vmware_nsx.extensions import providersecuritygroup
from vmware_nsx.extensions import vnicindex
from vmware_nsx.osc.v2 import port


supported_extensions = (vnicindex.ALIAS,
                        providersecuritygroup.ALIAS,
                        maclearning.ALIAS)


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

    def test_create_with_provider_security_group(self):
        # create a port with 1 provider security group
        secgroup = network_fakes.FakeSecurityGroup.create_one_security_group()
        self.network.find_security_group = mock.Mock(return_value=secgroup)
        arglist = [
            '--network', self._port.network_id,
            '--provider-security-group', secgroup.id,
            'test-port',
        ]
        verifylist = [
            ('network', self._port.network_id,),
            ('enable', True),
            ('provider_security_groups', [secgroup.id]),
            ('name', 'test-port'),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        columns, data = (self.cmd.take_action(parsed_args))

        self.network.create_port.assert_called_once_with(**{
            'admin_state_up': True,
            'network_id': self._port.network_id,
            'provider_security_groups': [secgroup.id],
            'name': 'test-port',
        })

        ref_columns, ref_data = self._get_common_cols_data(self._port)
        self.assertEqual(ref_columns, columns)
        self.assertEqual(ref_data, data)

    def test_create_with_provider_security_groups(self):
        # create a port with few provider security groups
        sg_1 = network_fakes.FakeSecurityGroup.create_one_security_group()
        sg_2 = network_fakes.FakeSecurityGroup.create_one_security_group()
        self.network.find_security_group = mock.Mock(side_effect=[sg_1, sg_2])
        arglist = [
            '--network', self._port.network_id,
            '--provider-security-group', sg_1.id,
            '--provider-security-group', sg_2.id,
            'test-port',
        ]
        verifylist = [
            ('network', self._port.network_id,),
            ('enable', True),
            ('provider_security_groups', [sg_1.id, sg_2.id]),
            ('name', 'test-port'),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        columns, data = (self.cmd.take_action(parsed_args))

        self.network.create_port.assert_called_once_with(**{
            'admin_state_up': True,
            'network_id': self._port.network_id,
            'provider_security_groups': [sg_1.id, sg_2.id],
            'name': 'test-port',
        })

        ref_columns, ref_data = self._get_common_cols_data(self._port)
        self.assertEqual(ref_columns, columns)
        self.assertEqual(ref_data, data)

    def test_create_with_provider_security_group_by_name(self):
        # create a port with 1 provider security group
        secgroup = network_fakes.FakeSecurityGroup.create_one_security_group()
        self.network.find_security_group = mock.Mock(return_value=secgroup)
        arglist = [
            '--network', self._port.network_id,
            '--provider-security-group', secgroup.name,
            'test-port',
        ]
        verifylist = [
            ('network', self._port.network_id,),
            ('enable', True),
            ('provider_security_groups', [secgroup.name]),
            ('name', 'test-port'),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        columns, data = (self.cmd.take_action(parsed_args))

        self.network.create_port.assert_called_once_with(**{
            'admin_state_up': True,
            'network_id': self._port.network_id,
            'provider_security_groups': [secgroup.id],
            'name': 'test-port',
        })

        ref_columns, ref_data = self._get_common_cols_data(self._port)
        self.assertEqual(ref_columns, columns)
        self.assertEqual(ref_data, data)

    def _test_create_with_flag_arg(
        self, arg_name, validate_name, validate_val):
        self.network.create_port.reset_mock()
        # add '--' to the arg name and change '_' to '-'
        conv_name = '--' + re.sub('_', '-', arg_name)
        arglist = [
            self._port.name,
            '--network', self._port.network_id,
            conv_name
        ]
        verifylist = [
            ('name', self._port.name),
            ('network', self._port.network_id,),
            (arg_name, True),
            ('enable', True),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        columns, data = (self.cmd.take_action(parsed_args))
        self.network.create_port.assert_called_once_with(**{
            'admin_state_up': True,
            'network_id': self._port.network_id,
            'name': self._port.name,
            validate_name: validate_val,
        })

        ref_columns, ref_data = self._get_common_cols_data(self._port)
        self.assertEqual(ref_columns, columns)
        self.assertEqual(ref_data, data)

    def test_create_with_mac_learning(self):
        self._test_create_with_flag_arg(
            'enable_mac_learning', 'mac_learning_enabled', True)

    def test_create_with_no_mac_learning(self):
        self._test_create_with_flag_arg(
            'disable_mac_learning', 'mac_learning_enabled', False)


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

    def test_set_provider_security_group(self):
        # It is not allowed to change the provider security groups
        sg = network_fakes.FakeSecurityGroup.create_one_security_group()
        self.network.find_security_group = mock.Mock(return_value=sg)
        arglist = [
            '--provider-security-group', sg.id,
            self._port.name,
        ]
        verifylist = [
            ('provider_security_groups', [sg.id]),
            ('port', self._port.name),
        ]

        self.assertRaises(tests_utils.ParserException, self.check_parser,
                          self.cmd, arglist, verifylist)

    def _test_set_with_flag_arg(self, arg_name, validate_name,
                                validate_val, is_valid=True):
        self.network.update_port.reset_mock()
        # add '--' to the arg name and change '_' to '-'
        conv_name = '--' + re.sub('_', '-', arg_name)
        arglist = [
            self._port.name,
            conv_name
        ]
        verifylist = [
            ('port', self._port.name),
            (arg_name, True)
        ]
        if not is_valid:
            self.assertRaises(tests_utils.ParserException, self.check_parser,
                              self.cmd, arglist, verifylist)
            return

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        result = self.cmd.take_action(parsed_args)

        attrs = {validate_name: validate_val}
        self.network.update_port.assert_called_once_with(
            self._port, **attrs)
        self.assertIsNone(result)

    def test_set_with_mac_learning(self):
        self._test_set_with_flag_arg(
            'enable_mac_learning', 'mac_learning_enabled', True)

    def test_set_with_no_mac_learning(self):
        self._test_set_with_flag_arg(
            'disable_mac_learning', 'mac_learning_enabled', False)
