# Copyright (c) 2018 OpenStack Foundation.
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

from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_securitygroup

from vmware_nsxlib.v3 import nsx_constants


PLUGIN_NAME = 'vmware_nsx.plugin.NsxPolicyPlugin'


class NsxPPluginTestCaseMixin(
    test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self, plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None, **kwargs):

        self._mock_nsx_policy_backend_calls()
        self.setup_conf_overrides()
        super(NsxPPluginTestCaseMixin, self).setUp(plugin=plugin,
                                                   ext_mgr=ext_mgr)

    def _mock_nsx_policy_backend_calls(self):
        resource_list_result = {'results': [{'id': 'test',
                                             'display_name': 'test'}]}
        mock.patch(
            "vmware_nsxlib.v3.NsxPolicyLib.get_version",
            return_value=nsx_constants.NSX_VERSION_2_4_0).start()
        mock.patch(
            "vmware_nsxlib.v3.client.RESTClient.get").start()
        mock.patch(
            "vmware_nsxlib.v3.client.RESTClient.list",
            return_value=resource_list_result).start()
        mock.patch(
            "vmware_nsxlib.v3.client.RESTClient.patch").start()
        mock.patch(
            "vmware_nsxlib.v3.client.RESTClient.delete").start()
        mock.patch("vmware_nsxlib.v3.policy_resources."
                   "NsxPolicyCommunicationMapApi._get_last_seq_num",
                   return_value=-1).start()

    def setup_conf_overrides(self):
        #TODO(asarfaty): will be needed in the future
        #cfg.CONF.set_override('default_overlay_tz', NSX_TZ_NAME, 'nsx_p')
        #cfg.CONF.set_override('native_dhcp_metadata', False, 'nsx_p')
        #cfg.CONF.set_override('dhcp_profile',
        #                      NSX_DHCP_PROFILE_ID, 'nsx_p')
        #cfg.CONF.set_override('metadata_proxy',
        #                      NSX_METADATA_PROXY_ID, 'nsx_p')
        pass


class NsxPTestNetworks(test_db_base_plugin_v2.TestNetworksV2,
                       NsxPPluginTestCaseMixin):

    def setUp(self, plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(NsxPTestNetworks, self).setUp(plugin=plugin,
                                            ext_mgr=ext_mgr)

    def tearDown(self):
        super(NsxPTestNetworks, self).tearDown()


class NsxPTestPorts(test_db_base_plugin_v2.TestPortsV2,
                    NsxPPluginTestCaseMixin):
    def test_update_port_update_ip_address_only(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_update_port_with_new_ipv6_slaac_subnet_in_fixed_ips(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_update_port_mac_v6_slaac(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_requested_subnet_id_v4_and_v6(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_requested_invalid_fixed_ips(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_requested_subnet_id_v4_and_v6_slaac(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_range_allocation(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_create_port_anticipating_allocation(self):
        self.skipTest('Multiple fixed ips on a port are not supported')

    def test_update_port_add_additional_ip(self):
        self.skipTest('Multiple fixed ips on a port are not supported')


class NsxPTestSecurityGroup(NsxPPluginTestCaseMixin,
                            test_securitygroup.TestSecurityGroups,
                            test_securitygroup.SecurityGroupDBTestCase):

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None):
        super(NsxPTestSecurityGroup, self).setUp(plugin=plugin,
                                                 ext_mgr=ext_mgr)

    def test_create_security_group_rule_icmp_with_type_and_code(self):
        """No non-zero icmp codes are currently supported by the NSX"""
        self.skipTest('not supported')

    def test_create_security_group_rule_icmp_with_type(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            remote_ip_prefix = "10.0.0.0/24"
            protocol = "icmp"
            # port_range_min (ICMP type) is greater than port_range_max
            # (ICMP code) in order to confirm min <= max port check is
            # not called for ICMP.
            port_range_min = 14
            port_range_max = None
            keys = [('remote_ip_prefix', remote_ip_prefix),
                    ('security_group_id', security_group_id),
                    ('direction', direction),
                    ('protocol', protocol),
                    ('port_range_min', port_range_min),
                    ('port_range_max', port_range_max)]
            with self.security_group_rule(security_group_id, direction,
                                          protocol, port_range_min,
                                          port_range_max,
                                          remote_ip_prefix) as rule:
                for k, v, in keys:
                    self.assertEqual(rule['security_group_rule'][k], v)

    # Temporarily skip all port related tests until the plugin supports it
    def test_create_port_with_no_security_groups(self):
        self.skipTest('Temporarily not supported')

    def test_create_delete_security_group_port_in_use(self):
        self.skipTest('Temporarily not supported')

    def test_create_port_with_multiple_security_groups(self):
        self.skipTest('Temporarily not supported')

    def test_list_ports_security_group(self):
        self.skipTest('Temporarily not supported')

    def test_update_port_with_security_group(self):
        self.skipTest('Temporarily not supported')
