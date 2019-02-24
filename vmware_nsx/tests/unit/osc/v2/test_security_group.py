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
from openstackclient.tests.unit.network.v2 import (
    test_security_group_network as test_security_group)
from openstackclient.tests.unit import utils as tests_utils


from vmware_nsx.extensions import providersecuritygroup
from vmware_nsx.extensions import securitygrouplogging
from vmware_nsx.extensions import securitygrouppolicy
from vmware_nsx.osc.v2 import security_group


supported_extensions = (securitygrouplogging.ALIAS,
                        providersecuritygroup.ALIAS,
                        securitygrouppolicy.ALIAS)


class TestCreateSecurityGroup(
    test_security_group.TestCreateSecurityGroupNetwork):

    def setUp(self):
        super(TestCreateSecurityGroup, self).setUp()
        # Get the command object to test
        self.cmd = security_group.NsxCreateSecurityGroup(
            self.app, self.namespace)
        # mock the relevant extensions
        get_ext = mock.patch('vmware_nsx.osc.v2.utils.get_extensions').start()
        get_ext.return_value = supported_extensions

    def _test_create_with_flag_arg(
        self, arg_name, validate_name, validate_val):
        self.network.create_security_group = mock.Mock(
            return_value=self._security_group)
        # add '--' to the arg name and change '_' to '-'
        conv_name = '--' + re.sub('_', '-', arg_name)
        arglist = [
            '--description', self._security_group.description,
            conv_name,
            self._security_group.name
        ]
        verifylist = [
            ('description', self._security_group.description),
            ('name', self._security_group.name),
            (arg_name, True),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        columns, data = self.cmd.take_action(parsed_args)

        self.network.create_security_group.assert_called_once_with(**{
            'description': self._security_group.description,
            'name': self._security_group.name,
            validate_name: validate_val,
        })
        self.assertEqual(self.columns, columns)
        self.assertEqual(self.data, data)

    def test_create_with_logging(self):
        self._test_create_with_flag_arg('logging', 'logging', True)

    def test_create_with_no_logging(self):
        self._test_create_with_flag_arg('no_logging', 'logging', False)

    def test_create_with_provider(self):
        self._test_create_with_flag_arg('provider', 'provider', True)

    def _test_create_with_arg_val(self, arg_name, arg_val):
        self.network.create_security_group = mock.Mock(
            return_value=self._security_group)
        # add '--' to the arg name and change '_' to '-'
        conv_name = '--' + re.sub('_', '-', arg_name)
        arglist = [
            '--description', self._security_group.description,
            conv_name, str(arg_val),
            self._security_group.name
        ]
        verifylist = [
            ('description', self._security_group.description),
            ('name', self._security_group.name),
            (arg_name, arg_val),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        columns, data = self.cmd.take_action(parsed_args)

        self.network.create_security_group.assert_called_once_with(**{
            'description': self._security_group.description,
            'name': self._security_group.name,
            arg_name: arg_val,
        })
        self.assertEqual(self.columns, columns)
        self.assertEqual(self.data, data)

    def test_create_with_policy(self):
        self._test_create_with_arg_val('policy', 'policy-1')


class TestSetSecurityGroup(
    test_security_group.TestSetSecurityGroupNetwork):

    def setUp(self):
        super(TestSetSecurityGroup, self).setUp()
        # Get the command object to test
        self.cmd = security_group.NsxSetSecurityGroup(
            self.app, self.namespace)
        # mock the relevant extensions
        get_ext = mock.patch('vmware_nsx.osc.v2.utils.get_extensions').start()
        get_ext.return_value = supported_extensions

    def _test_set_with_flag_arg(self, arg_name, validate_name,
                                validate_val, is_valid=True):
        self.network.create_security_group = mock.Mock(
            return_value=self._security_group)
        # add '--' to the arg name and change '_' to '-'
        conv_name = '--' + re.sub('_', '-', arg_name)
        arglist = [
            conv_name,
            self._security_group.name
        ]
        verifylist = [
            (arg_name, True),
            ('group', self._security_group.name),
        ]

        if not is_valid:
            self.assertRaises(tests_utils.ParserException, self.check_parser,
                              self.cmd, arglist, verifylist)
            return

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        result = self.cmd.take_action(parsed_args)

        self.network.update_security_group.assert_called_once_with(
            self._security_group,
            **{validate_name: validate_val})
        self.assertIsNone(result)

    def test_set_with_logging(self):
        self._test_set_with_flag_arg('logging', 'logging', True)

    def test_set_with_no_logging(self):
        self._test_set_with_flag_arg('no_logging', 'logging', False)

    def test_set_with_provider(self):
        # modifying the provider flag should fail
        self._test_set_with_flag_arg('provider', 'provider',
                                     True, is_valid=False)

    def _test_set_with_arg_val(self, arg_name, arg_val):
        self.network.create_security_group = mock.Mock(
            return_value=self._security_group)
        # add '--' to the arg name and change '_' to '-'
        conv_name = '--' + re.sub('_', '-', arg_name)
        arglist = [
            conv_name, str(arg_val),
            self._security_group.name
        ]
        verifylist = [
            (arg_name, arg_val),
            ('group', self._security_group.name),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        result = self.cmd.take_action(parsed_args)

        self.network.update_security_group.assert_called_once_with(
            self._security_group,
            **{arg_name: arg_val})
        self.assertIsNone(result)

    def test_set_with_policyr(self):
        self._test_set_with_arg_val('policy', 'policy-1')
