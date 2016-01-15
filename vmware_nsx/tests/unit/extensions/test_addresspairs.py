# Copyright (c) 2014 OpenStack Foundation.
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

from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.tests.unit.db import test_allowedaddresspairs_db as ext_pairs

from vmware_nsx.tests.unit.nsx_mh import test_plugin as test_nsx_plugin
from vmware_nsx.tests.unit.nsx_v3 import test_constants as v3_constants
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_v3_plugin


class TestAllowedAddressPairsNSXv2(test_nsx_plugin.NsxPluginV2TestCase,
                                   ext_pairs.TestAllowedAddressPairs):

    # TODO(arosen): move to ext_pairs.TestAllowedAddressPairs once all
    # plugins do this correctly.
    def test_create_port_no_allowed_address_pairs(self):
        with self.network() as net:
            res = self._create_port(self.fmt, net['network']['id'])
            port = self.deserialize(self.fmt, res)
            self.assertEqual(port['port'][addr_pair.ADDRESS_PAIRS], [])
            self._delete('ports', port['port']['id'])

    def test_create_port_security_false_allowed_address_pairs(self):
        self.skipTest('TBD')


class TestAllowedAddressPairsNSXv3(test_v3_plugin.NsxV3PluginTestCaseMixin,
                                   ext_pairs.TestAllowedAddressPairs):

    def setUp(self, plugin=v3_constants.PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(TestAllowedAddressPairsNSXv3, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)

    def test_create_bad_address_pairs_with_cidr(self):
        address_pairs = [{'mac_address': '00:00:00:00:00:01',
                          'ip_address': '10.0.0.1/24'}]
        self._create_port_with_address_pairs(address_pairs, 400)

    def test_update_add_bad_address_pairs_with_cidr(self):
        with self.network() as net:
            res = self._create_port(self.fmt, net['network']['id'])
            port = self.deserialize(self.fmt, res)
            address_pairs = [{'mac_address': '00:00:00:00:00:01',
                              'ip_address': '10.0.0.1/24'}]
            update_port = {'port': {addr_pair.ADDRESS_PAIRS:
                                    address_pairs}}
            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            res = req.get_response(self.api)
            self.assertEqual(res.status_int, 400)
            self._delete('ports', port['port']['id'])

    def test_create_port_security_false_allowed_address_pairs(self):
        self.skipTest('TBD')
