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
from neutron.extensions import portbindings as pbin
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_nsx_v3_plugin


class TestParentTagPortBinding(test_nsx_v3_plugin.NsxV3PluginTestCaseMixin):

    # NOTE(arosen): commenting out this test for now for demo setup.
    # def test_create_port_with_invalid_parent(self):
    #    binding = {pbin.PROFILE: {"parent_name": 'invalid', 'tag': 1}}
    #    with self.network() as n:
    #        with self.subnet(n):
    #            # FIXME(arosen): we shouldn't be returning 404 in this case.
    #            self._create_port(
    #                self.fmt, n['network']['id'],
    #                expected_res_status=404,
    #                arg_list=(pbin.PROFILE,),
    #                **binding)

    def test_create_port_with_parent_and_tag(self):
        binding = {pbin.PROFILE: {"parent_name": '', 'tag': 1}}
        with self.network() as n:
            with self.subnet(n) as s:
                with self.port(s) as p:
                    binding[pbin.PROFILE]['parent_name'] = p['port']['id']
                    res = self._create_port(self.fmt, n['network']['id'],
                                            arg_list=(pbin.PROFILE,),
                                            **binding)
                    port = self.deserialize(self.fmt, res)
                    self.assertEqual(port['port'][pbin.PROFILE],
                                     binding[pbin.PROFILE])

    def test_create_port_with_invalid_tag(self):
        binding = {pbin.PROFILE: {"parent_name": '', 'tag': 10000000}}
        with self.network() as n:
            with self.subnet(n) as s:
                with self.port(s) as p:
                    binding[pbin.PROFILE]['parent_name'] = p['port']['id']
                    self._create_port(self.fmt, n['network']['id'],
                                      arg_list=(pbin.PROFILE,),
                                      expected_res_status=400,
                                      **binding)
