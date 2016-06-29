# Copyright 2016 VMware Inc
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

import time

from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import test_utils
from tempest import test

from vmware_nsx_tempest.tests.nsxv.scenario import (
    manager_topo_deployment as dmgr)

CONF = config.CONF


class TestXnetMultiSubnetsOps(dmgr.TopoDeployScenarioManager):
    """Test NSX external network can support multiple subnets/cidrs.

    With multiple subnets, VMs get its floatingip from all subnets
    attached to the external network.

    This test validates that VM can get its floatingip from all subnets,
    and are reachable. However due to the physical network routing issue,
    we can only validate at devstack environment:

        1. VM's floatingip is pingable
        2. can ssh to VM's floatingip.
        3. from VM can ping other VMs' private address.

    If this test fail and were not able to revert to its original subnet
    ip ranges, other tempest tests require floatingip's might FAIL.

    The test will shrink the primary subnet range to 3 ip addresses.
    Note: the 1st one is already used by the router1@devstack.

    The 2nd subnet is set with CONF.scenario.xnet_multiple_subnets_dict,
    and no-gateway is required. Make sure the 2nd CIRD is reachable by
    your devstack.

    LIMITATION:
        This test can only be done at devstack environment, other environment,
        for example VIO can not be executed unless you can modify the physical
        network to route the 2nd subnet cidr to the OS environment.

        This test validates data-path from the devstack host itself:
            1. Ping to floating-ips
            2. ssh to VM
            3. from VM ping other VMs' private ip address

    ATTENTION:
        Because, this test consumes floatingip's so both subnets ip-ranges
        will be used.  NO OTHER TESTS should run when executing this test.

        Run this test module sequencially :

             ./run_tempest.sh -t <tests>
    """

    @classmethod
    def skip_checks(cls):
        super(TestXnetMultiSubnetsOps, cls).skip_checks()
        if not CONF.scenario.xnet_multiple_subnets_dict:
            msg = 'scenario.xnet_multiple_subnets_dict must be set.'
            raise cls.skipException(msg)
        if not CONF.network.public_network_id:
            msg = ('network.public_network_id must be defined.')
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TestXnetMultiSubnetsOps, cls).resource_setup()
        cls.xnet_subnets = [None, None]
        cls.public_network_id = CONF.network.public_network_id
        # primary user
        cls.primary_tenant_id = cls.manager.networks_client.tenant_id
        cls.floating_ips_client = cls.manager.floating_ips_client
        cls.servers_client = cls.manager.servers_client

    @classmethod
    def resource_cleanup(cls):
        cls.remove_this_test_resources()
        super(TestXnetMultiSubnetsOps, cls).resource_cleanup()

    @classmethod
    def remove_this_test_resources(cls):
        dmgr.delete_all_servers(cls.manager.servers_client)
        subnets_client = cls.admin_manager.subnets_client
        subnet_1 = cls.xnet_subnets[0]
        subnet_2 = cls.xnet_subnets[1]
        if subnet_2:
            subnets_client.delete_subnet(subnet_2['id'])
            cls.xnet_subnets[1] = None
        if subnet_1:
            subnets_client.update_subnet(
                subnet_1['id'],
                allocation_pools=subnet_1['allocation_pools'])
            cls.xnet_subnets[0] = None

    @classmethod
    def create_no_gateway_subnet(cls, network_id, cidr, allocation_pool,
                                 ip_version=4, dns_nameservers=None,
                                 name=None, client_mgr=None, **kwargs):
        """Subnets, except the 1st one, no-gateway should be applied."""

        client_mgr = client_mgr or cls.admin_manager
        subnets_client = client_mgr.subnets_client
        post_body = {'network_id': network_id,
                     'cidr': cidr,
                     'allocation_pools': [allocation_pool],
                     'ip_version': ip_version,
                     'gateway_ip': None,
                     'enable_dhcp': False}
        if name:
            post_body['name'] = name
        if dns_nameservers:
            post_body['dns_nameservers'] = dns_nameservers
        body = subnets_client.create_subnet(**post_body)
        subnet_2 = subnets_client.show_subnet(body['subnet']['id'])
        # no addCleanup, it is to be done at tearDown
        return subnet_2['subnet']

    def setUp(self):
        """Create the 2nd subnet attached to public network.

        Idealy this is at class method. However we need to validate that
        the public network and its subnets are correctly configured.

        External network/subnet configured here, so assert* can be called.
        """
        super(TestXnetMultiSubnetsOps, self).setUp()
        # only admin user can manage external network/subnets
        networks_client = self.admin_manager.networks_client
        subnets_client = self.admin_manager.subnets_client
        self.sub2_dict = CONF.scenario.xnet_multiple_subnets_dict
        # limited to only one subnet available when test started.
        subnet_id_list = networks_client.show_network(
            self.public_network_id)["network"]["subnets"]
        self.assertEqual(1, len(subnet_id_list))
        subnet_1 = subnets_client.show_subnet(
            subnet_id_list[0])["subnet"]
        self.assertEqual(1, len(subnet_1["allocation_pools"]))
        pool_start = subnet_1["allocation_pools"][0]["start"]
        iprange = pool_start.split(".")
        iprange[3] = str(int(iprange[3]) + 3)
        pool_end = ".".join(iprange)
        sub1_allocation = {'start': pool_start, 'end': pool_end}
        self.xnet_subnets[0] = subnet_1
        # update the 1st subnet so it only has 3 ip addresses
        subnet1 = subnets_client.update_subnet(
            subnet_1['id'],
            allocation_pools=[sub1_allocation])['subnet']
        alloc_pool1 = subnet1['allocation_pools']
        self.assertEqual(1, len(alloc_pool1))
        alloc_pool1 = alloc_pool1[0]
        self.assertEqual(pool_start, alloc_pool1['start'])
        self.assertEqual(pool_end, alloc_pool1['end'])
        # create the 2nd subnet under external network
        alloc_pool2 = {'start': self.sub2_dict['start'],
                       'end': self.sub2_dict['end']}
        dns_nameservers = subnet_1['dns_nameservers']
        subnet_2 = self.create_no_gateway_subnet(
            subnet_1['network_id'], cidr=self.sub2_dict['cidr'],
            allocation_pool=alloc_pool2, dns_nameservers=dns_nameservers,
            name='public-xnet-subnet2')
        self.xnet_subnets[1] = subnet_2
        self.my_network = None
        self.user_sg = self._create_security_group(
            security_groups_client=self.manager.security_groups_client,
            namestart='xnet-subnets')

    def tearDown(self):
        super(TestXnetMultiSubnetsOps, self).tearDown()

    def create_user_servers(self, num_servers=5):
        network = self.my_network['network']
        user_sg = [{'name': self.user_sg['id']}]
        self.my_network['servers'] = []
        server_id_list = []
        for num in range(0, num_servers):
            vm_name = 'xnet-subnet-%d' % (num + 1)
            sv = self.create_server_on_network(
                network,
                security_groups=user_sg,
                name=vm_name, wait_on_boot=False)
            self.my_network['servers'].append(sv)
            server_id_list.append(sv['id'])
        self.wait_for_servers_become_active(server_id_list,
                                            self.servers_client)

    def wait_for_servers_become_active(self, server_id_list,
                                       servers_client):
        for server_id in server_id_list:
            waiters.wait_for_server_status(
                servers_client, server_id, 'ACTIVE')

    def create_floatingips_and_assign_to_servers(self):
        self.my_network['floatingips'] = []
        self.fixed_ip_addresses = []
        for sv in self.my_network['servers']:
            floatingip, sshc = self.create_floatingip_for_server(sv)
            self.my_network['floatingips'].append(floatingip)
            self.fixed_ip_addresses.append(floatingip['fixed_ip_address'])
        # check inside this tenant network, all VMs are reachable.
        self.validate_all_servers_private_address_are_reachable(
            sshc, self.fixed_ip_addresses)

    def create_floatingip_for_server(self, server):
        # project/tenant create the server, not the ADMIN
        username, password = self.get_image_userpass()
        # Only admin can create resource with tenant_id attributes, so
        # always providing the admin_manager as client to create_floatingip
        # as scenario/manager.py always insert tenant_id attribe
        # while creating the serve..
        floatingip = super(TestXnetMultiSubnetsOps,
                           self).create_floatingip_for_server(
            server,
            external_network_id=self.public_network_id,
            client_mgr=self.admin_manager)
        msg = ("Associate floatingip[%s] to server[%s]"
               % (floatingip, server['name']))
        self._check_floatingip_connectivity(
            floatingip, server, should_connect=True, msg=msg)
        serv_fip = floatingip['floating_ip_address']
        dmgr.rm_sshkey(serv_fip)
        ssh_client = dmgr.get_remote_client_by_password(
            serv_fip, username, password)
        return (floatingip, ssh_client)

    def delete_floatingips_and_servers(self):
        for net_floatingip in self.my_network['floatingips']:
            test_utils.call_and_ignore_notfound_exc(
                self.floating_ips_client.delete_floatingip,
                net_floatingip['id'])
        fip_list = self.floating_ips_client.list_floatingips()['floatingips']
        if len(fip_list) > 0:
            time.sleep(dmgr.WAITTIME_AFTER_DISASSOC_FLOATINGIP)
        self.my_network['floatingips'] = []
        dmgr.delete_all_servers(self.servers_client)

    def validate_all_servers_private_address_are_reachable(self,
                                                           ssh_client,
                                                           ip_addresses):
        for ip_addr in ip_addresses:
            msg = "VM private address[%s] is not reachable." % ip_addr
            reachable = dmgr.is_reachable(ssh_client, ip_addr)
            self.assertTrue(reachable, msg)

    def _test_xnet_multiple_subnets_basic_ops(self, router_type='exclusive',
                                              namestart='xnet-subnets',
                                              distributed=None):
        network, subnet, router = self.setup_project_network(
            self.public_network_id,
            client_mgr=self.admin_manager,
            tenant_id=self.primary_tenant_id,
            namestart=namestart,
            router_type=router_type, distributed=distributed)
        self.my_network = {'router': router,
                           'subnet': subnet,
                           'network': network,
                           'servers': [],
                           'floatingips': []}
        self.create_user_servers()
        self.create_floatingips_and_assign_to_servers()
        self.delete_floatingips_and_servers()


class TestXnetMultiSubnetsOpsOnSharedRouter(TestXnetMultiSubnetsOps):

    @test.idempotent_id('e25d030f-7fdf-4500-bd55-4ed6f62c0a5c')
    def test_xnet_multiple_subnets_basic_ops_on_shared_router(self):
        return self._test_xnet_multiple_subnets_basic_ops(
            'shared', 'xnet-shared', False)


class TestXnetMultiSubnetsOpsOnExclusiveRouter(TestXnetMultiSubnetsOps):

    @test.idempotent_id('5b09351a-0560-4555-99f0-a1f80d54d435')
    def test_xnet_multiple_subnets_basic_ops_on_exclusive_router(self):
        return self._test_xnet_multiple_subnets_basic_ops(
            'exclusive', 'xnet-exclusive', False)


class TestXnetMultiSubnetsOpsOnDistributedRouter(TestXnetMultiSubnetsOps):

    @test.idempotent_id('9652d36b-8816-4212-a6e1-3a8b2580deee')
    def test_xnet_multiple_subnets_basic_ops_on_distributed_router(self):
        return self._test_xnet_multiple_subnets_basic_ops(
            '', 'xnet-distributed', True)
