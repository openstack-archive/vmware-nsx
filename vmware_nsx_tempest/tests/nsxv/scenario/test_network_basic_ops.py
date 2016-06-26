# Copyright 2016 VMware Inc.
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

from tempest.scenario import test_network_basic_ops as network_ops


class TestNetworkBasicOps(network_ops.TestNetworkBasicOps):

    # NSX-v does not allow tenants to access dhcp service.
    # Overwirte parent class to skip dhcp service testing.
    def _check_network_internal_connectivity(self, network,
                                             should_connect=True):
        floating_ip, server = self.floating_ip_tuple
        # get internal ports' ips:
        # get all network ports in the new network
        # NSX-v: dhcp is not reachable
        internal_ips = (p['fixed_ips'][0]['ip_address'] for p in
                        self._list_ports(tenant_id=server['tenant_id'],
                                         network_id=network['id'])
                        if (p['device_owner'].startswith('network') and
                            not p['device_owner'].endswith('dhcp')))

        self._check_server_connectivity(floating_ip,
                                        internal_ips,
                                        should_connect)
