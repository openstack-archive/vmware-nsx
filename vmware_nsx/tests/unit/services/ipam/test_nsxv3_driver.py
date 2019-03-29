# Copyright 2016 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
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
import netaddr

from oslo_config import cfg
from oslo_utils import uuidutils

from vmware_nsx.tests.unit.nsx_v3 import test_plugin
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as error


class MockIPPools(object):

    def patch_nsxlib_ipam(self):
        self.nsx_pools = {}

        def _create_pool(*args, **kwargs):
            pool_id = uuidutils.generate_uuid()
            gateway_ip = None
            if kwargs.get('gateway_ip'):
                gateway_ip = str(kwargs['gateway_ip'])
            subnet = {"allocation_ranges": kwargs.get('allocation_ranges'),
                      "gateway_ip": gateway_ip,
                      "cidr": args[0]}
            pool = {'id': pool_id,
                    'subnets': [subnet]}
            self.nsx_pools[pool_id] = {'pool': pool, 'allocated': []}
            return {'id': pool_id}

        def _update_pool(pool_id, **kwargs):
            pool = self.nsx_pools[pool_id]['pool']
            subnet = pool['subnets'][0]
            if 'gateway_ip' in kwargs:
                if kwargs['gateway_ip']:
                    subnet["gateway_ip"] = str(kwargs['gateway_ip'])
                else:
                    del subnet["gateway_ip"]

            if 'allocation_ranges' in kwargs:
                if kwargs['allocation_ranges']:
                    subnet["allocation_ranges"] = kwargs['allocation_ranges']
                else:
                    del subnet["allocation_ranges"]

        def _delete_pool(pool_id):
            del self.nsx_pools[pool_id]

        def _get_pool(pool_id):
            return self.nsx_pools[pool_id]['pool']

        def _allocate_ip(*args, **kwargs):
            nsx_pool = self.nsx_pools[args[0]]
            if kwargs.get('ip_addr'):
                ip_addr = netaddr.IPAddress(kwargs['ip_addr'])
                # verify that this ip was not yet allocated
                if ip_addr in nsx_pool['allocated']:
                    raise nsx_lib_exc.ManagerError(
                        manager='dummy', operation='allocate',
                        details='IP already allocated',
                        error_code=error.ERR_CODE_IPAM_IP_ALLOCATED)
                # skip ip validation for this mock.
                nsx_pool['allocated'].append(ip_addr)
                return {'allocation_id': str(ip_addr)}
            # get an unused ip from the pool
            ranges = nsx_pool['pool']['subnets'][0]['allocation_ranges']
            for ip_range in ranges:
                r = netaddr.IPRange(ip_range['start'], ip_range['end'])
                for ip_addr in r:
                    if ip_addr not in nsx_pool['allocated']:
                        nsx_pool['allocated'].append(ip_addr)
                        return {'allocation_id': str(ip_addr)}
            # no IP was found
            raise nsx_lib_exc.ManagerError(
                manager='dummy', operation='allocate',
                details='All IPs in the pool are allocated',
                error_code=error.ERR_CODE_IPAM_POOL_EXHAUSTED)

        def _release_ip(*args, **kwargs):
            nsx_pool = self.nsx_pools[args[0]]
            ip_addr = netaddr.IPAddress(args[1])
            nsx_pool['allocated'].remove(ip_addr)

        mock.patch(
            "vmware_nsxlib.v3.resources.IpPool.get",
            side_effect=_get_pool).start()
        mock.patch(
            "vmware_nsxlib.v3.resources.IpPool.create",
            side_effect=_create_pool).start()
        mock.patch(
            "vmware_nsxlib.v3.resources.IpPool.update",
            side_effect=_update_pool).start()
        mock.patch(
            "vmware_nsxlib.v3.resources.IpPool.delete",
            side_effect=_delete_pool).start()
        mock.patch(
            "vmware_nsxlib.v3.resources.IpPool.allocate",
            side_effect=_allocate_ip).start()
        mock.patch(
            "vmware_nsxlib.v3.resources.IpPool.release",
            side_effect=_release_ip).start()


class TestNsxv3IpamSubnets(test_plugin.TestSubnetsV2, MockIPPools):
    """Run the nsxv3 plugin subnets tests with the ipam driver."""
    def setUp(self):
        cfg.CONF.set_override(
            "ipam_driver",
            "vmware_nsx.services.ipam.nsx_v3.driver.Nsxv3IpamDriver")
        super(TestNsxv3IpamSubnets, self).setUp()
        self.patch_nsxlib_ipam()

    def test_subnet_update_ipv4_and_ipv6_pd_slaac_subnets(self):
        self.skipTest('Update ipam subnet is not supported')

    def test_subnet_update_ipv4_and_ipv6_pd_v6stateless_subnets(self):
        self.skipTest('Update ipam subnet is not supported')


class TestNsxv3IpamPorts(test_plugin.TestPortsV2, MockIPPools):
    """Run the nsxv3 plugin ports tests with the ipam driver."""
    def setUp(self):
        cfg.CONF.set_override(
            "ipam_driver",
            "vmware_nsx.services.ipam.nsx_v3.driver.Nsxv3IpamDriver")
        super(TestNsxv3IpamPorts, self).setUp()
        self.patch_nsxlib_ipam()

    def test_create_port_invalid_fixed_ip_address_v6_pd_slaac(self):
        self.skipTest('Update ipam subnet is not supported')

    def test_update_port_invalid_subnet_v6_pd_slaac(self):
        self.skipTest('Update ipam subnet is not supported')

    def test_update_port_update_ip_address_only(self):
        self.skipTest('Update ipam subnet is not supported')

    def test_update_port_invalid_fixed_ip_address_v6_pd_slaac(self):
        self.skipTest('Update ipam subnet is not supported')

    def test_ip_allocation_for_ipv6_2_subnet_slaac_mode(self):
        self.skipTest('Only one ipv6 subnet per network is supported')

    def test_create_port_with_multiple_ipv4_and_ipv6_subnets(self):
        self.skipTest('Only one ipv6 subnet per network is supported')
