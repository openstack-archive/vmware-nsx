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
from openstackclient.tests.unit.network.v2 import test_subnet
from openstackclient.tests.unit import utils as tests_utils

from vmware_nsx.extensions import dhcp_mtu
from vmware_nsx.extensions import dns_search_domain
from vmware_nsx.osc.v2 import subnet


supported_extensions = (dhcp_mtu.ALIAS, dns_search_domain.ALIAS)


class TestCreateSubnet(test_subnet.TestCreateSubnet):

    def setUp(self):
        super(TestCreateSubnet, self).setUp()
        # Get the command object to test
        self.cmd = subnet.NsxCreateSubnet(self.app, self.namespace)
        # mock the relevant extensions
        get_ext = mock.patch('vmware_nsx.osc.v2.utils.get_extensions').start()
        get_ext.return_value = supported_extensions

    def _test_create_with_arg_and_val(self, arg_name, arg_val, is_valid=True):
        self.network.create_subnet = mock.Mock(return_value=self._subnet)
        # add '--' to the arg name and change '_' to '-'
        conv_name = '--' + re.sub('_', '-', arg_name)
        arglist = [
            "--subnet-range", self._subnet.cidr,
            "--network", self._subnet.network_id,
            conv_name, str(arg_val),
            self._subnet.name
        ]
        verifylist = [
            ('name', self._subnet.name),
            ('subnet_range', self._subnet.cidr),
            ('network', self._subnet.network_id),
            ('ip_version', self._subnet.ip_version),
            ('gateway', 'auto'),
            (arg_name, arg_val),
        ]
        if not is_valid:
            self.assertRaises(tests_utils.ParserException, self.check_parser,
                              self.cmd, arglist, verifylist)
            return

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        columns, data = self.cmd.take_action(parsed_args)
        self.network.create_subnet.assert_called_once_with(**{
            'cidr': mock.ANY,
            'ip_version': mock.ANY,
            'network_id': mock.ANY,
            'name': self._subnet.name,
            arg_name: arg_val,
        })

        self.assertEqual(self.columns, columns)
        self.assertEqual(self.data, data)

    def _test_create_with_tag(self, add_tags=True):
        self.skipTest('Unblock gate')

    def _test_create_with_mtu(self, mtu, is_valid=True):
        self._test_create_with_arg_and_val('dhcp_mtu', mtu, is_valid)

    def test_create_with_mtu(self):
        # check a valid value
        self._test_create_with_mtu(1500)

    def test_create_with_illegal_mtu(self):
        self._test_create_with_mtu('illegal', is_valid=False)

    def _test_create_with_search_domain(self, val, is_valid=True):
        self._test_create_with_arg_and_val('dns_search_domain', val, is_valid)

    def test_create_with_search_domain(self):
        # check a valid value
        self._test_create_with_search_domain('www.aaa.com')

    # Cannot check illegal search domain - validation is on the server side


class TestSetSubnet(test_subnet.TestSetSubnet):

    def setUp(self):
        super(TestSetSubnet, self).setUp()
        # Get the command object to test
        self.cmd = subnet.NsxSetSubnet(self.app, self.namespace)
        # mock the relevant extensions
        get_ext = mock.patch('vmware_nsx.osc.v2.utils.get_extensions').start()
        get_ext.return_value = supported_extensions

    def _test_set_with_arg_and_val(self, arg_name, arg_val, is_valid=True):
        # add '--' to the arg name and change '_' to '-'
        conv_name = '--' + re.sub('_', '-', arg_name)
        arglist = [
            conv_name, str(arg_val),
            self._subnet.name,
        ]
        verifylist = [
            (arg_name, arg_val),
            ('subnet', self._subnet.name),
        ]

        if not is_valid:
            self.assertRaises(tests_utils.ParserException, self.check_parser,
                              self.cmd, arglist, verifylist)
            return

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)
        attrs = {
            arg_name: arg_val
        }
        self.network.update_subnet.assert_called_with(self._subnet, **attrs)
        self.assertIsNone(result)

    def _test_set_mtu(self, mtu, is_valid=True):
        self._test_set_with_arg_and_val('dhcp_mtu', mtu, is_valid)

    def test_set_mtu(self):
        # check a valid value
        self._test_set_mtu(1500)

    def test_set_illegal_mtu(self):
        self._test_set_mtu('illegal', is_valid=False)

    def _test_set_with_search_domain(self, val, is_valid=True):
        self._test_set_with_arg_and_val('dns_search_domain', val, is_valid)

    def test_set_with_search_domain(self):
        # check a valid value
        self._test_set_with_search_domain('www.aaa.com')
