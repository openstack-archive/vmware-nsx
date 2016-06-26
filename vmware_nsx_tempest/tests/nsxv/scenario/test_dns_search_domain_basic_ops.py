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

from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest import test

from vmware_nsx_tempest.tests.nsxv.scenario import (
    manager_topo_deployment as dmgr)
from vmware_nsx_tempest.tests.nsxv.scenario import (
    network_addon_methods as HELO)

CONF = config.CONF
DNS_SEARCH_DOMAIN = 'dns_search_domain'


class TestDnsSearchDomainBasicOps(dmgr.TopoDeployScenarioManager):
    """Test dns_search_domain working in subnets w/wo dns_search_domain.

    network's subnet with dns_search_domain configured:
        CONF.network.host_in_search_domain can be resolved,
        update dns_search_dmain='' then host can not be resolved.
    network's subnet without dns_search_domain configured:
        CONF.network.host_in_search_domain can not be resolved,
        update dns_search_dmain to CONF.network_dns_search_domain,
        then host can be resolved.

    Verify above 2 scenarios under shared/exclusive/distributed routers.
    """
    @classmethod
    def resource_setup(cls):
        super(TestDnsSearchDomainBasicOps, cls).resource_setup()
        cls.dns_search_domain = CONF.network.dns_search_domain
        cls.host_in_search_domain = CONF.network.host_in_search_domain

    @classmethod
    def resource_cleanup(cls):
        # lately, server up and down take long time. let's delete servers
        # before test's auto cleanup kickin.
        dmgr.delete_all_servers(cls.servers_client)
        super(TestDnsSearchDomainBasicOps, cls).resource_cleanup()

    def create_networks(self, dns_search_domain=None, cidr_offset=0):
        prefix_name = 'dns-search' if dns_search_domain else 'no-search'
        network_name = data_utils.rand_name(prefix_name)
        network = self.create_network(client=self.networks_client,
                                      name=network_name)
        network = network.get('network', network)
        subnet_kwargs = dict(name=network_name,
                             dns_nameservers=CONF.network.dns_servers,
                             cidr_offset=cidr_offset)
        if dns_search_domain:
            subnet_kwargs[DNS_SEARCH_DOMAIN] = dns_search_domain
        subnet = self.create_subnet(network,
                                    client=self.subnets_client,
                                    **subnet_kwargs)
        subnet = subnet.get('subnet', subnet)
        if dns_search_domain:
            self.assertEqual(dns_search_domain, subnet[DNS_SEARCH_DOMAIN])
        return (network, subnet, dns_search_domain)

    def create_router_by_type(self, router_type, client=None,
                              name=None, **kwargs):
        routers_client = client or self.admin_manager.routers_client
        create_kwargs = dict(namestart='dns-search', external_gateway_info={
            "network_id": CONF.network.public_network_id})
        if router_type in ('shared', 'exclusive'):
            create_kwargs['router_type'] = router_type
        elif router_type in ('distributed'):
            create_kwargs['distributed'] = True
        create_kwargs.update(**kwargs)
        router = HELO.router_create(self, client=routers_client,
                                    **create_kwargs)
        return router

    def create_router_and_add_interfaces(self, router_type, net_list,
                                         client_mgr=None):
        client_mgr = client_mgr or self.admin_manager
        routers_client = client_mgr.routers_client
        router = self.create_router_by_type(router_type,
                                            client=routers_client)
        for (network, subnet, dns_search_domain) in net_list:
            HELO.router_interface_add(self, router['id'], subnet['id'],
                                      client=routers_client)
        return router

    def setup_tenant_networks(self, router_type):
        self.networks_with_search_domain = self.create_networks(
            self.dns_search_domain, cidr_offset=1)
        self.networks_wo_search_domain = self.create_networks(
            None, cidr_offset=2)
        net_list = [self.networks_with_search_domain,
                    self.networks_wo_search_domain]
        router = self.create_router_and_add_interfaces(router_type, net_list)
        return (router, net_list)

    def create_security_group_with_loginable_rules(self):
        security_group = self._create_security_group(
            security_groups_client=self.security_groups_client,
            namestart='dns-search-')
        return security_group

    def wait_for_servers_become_active(self, server_id_list):
        servers_client = self.admin_manager.servers_client
        for server_id in server_id_list:
            waiters.wait_for_server_status(
                servers_client, server_id, 'ACTIVE')

    def create_servers_on_networks(self, networks_info, security_group):
        servers_client = self.servers_client
        (network, subnet, dns_search_domain) = networks_info
        security_groups = [{'name': security_group['id']}]
        svr = self.create_server_on_network(
            network, security_groups, name=network['name'],
            wait_on_boot=False,
            servers_client=self.servers_client)
        server_info = dict(
            server=svr, network=network, subnet=subnet,
            dns_search_domain=dns_search_domain,
            security_group=security_group,
            servers_client=servers_client)
        return server_info

    def create_floatingip_for_server(self, server):
        username, password = self.get_image_userpass()
        floatingip = super(TestDnsSearchDomainBasicOps,
                           self).create_floatingip_for_server(
            server, client_mgr=self.admin_manager)
        msg = ("Associate floatingip[%s] to server[%s]"
               % (floatingip, server['name']))
        self._check_floatingip_connectivity(
            floatingip, server, should_connect=True, msg=msg)
        serv_fip = floatingip['floating_ip_address']
        dmgr.rm_sshkey(serv_fip)
        ssh_client = dmgr.get_remote_client_by_password(
            serv_fip, username, password)
        return (floatingip, ssh_client)

    def _test_host_cannot_be_resolved(self):
        """"test CONF.network.host_in_dns_search_dmain can not be resolved.

        The network/subnet does not define dns_search_domain and
        its host_in_search_domain in dns_search_domain can not be resolved.

        Later, update dns_search_domain to CONF.network.dns_search_domain,
        then the host can be resovled.
        """
        floatingip, sshc = self.create_floatingip_for_server(
            self.net_wo_search['server'])
        ping_cmd = 'ping -c3 %s' % self.host_in_search_domain
        self.assertRaises(exceptions.SSHExecCommandFailed,
                          sshc.exec_command,
                          ping_cmd)
        subnet = self.net_wo_search['subnet']
        subnet = self.subnets_client.update_subnet(
            subnet['id'],
            dns_search_domain=self.dns_search_domain)
        subnet = subnet.get('subnet', subnet)
        self.assertEqual(subnet[DNS_SEARCH_DOMAIN],
                         self.dns_search_domain)
        # renew dhcp lease to force dns_search_domain update too
        sshc.renew_lease(floatingip['fixed_ip_address'])
        sshc.exec_command(ping_cmd)

    def _test_host_can_be_resolved(self):
        """"test CONF.network.host_in_dns_search_dmain can be resolved.

        The network/subnet has dns_search_domain defined and
        its host_in_search_domain is in dns_search_domain should be resolved.

        Later, update dns_search_domain to '', then the host is not resovled.
        """
        floatingip, sshc = self.create_floatingip_for_server(
            self.net_w_search['server'])
        ping_cmd = 'ping -c3 %s' % self.host_in_search_domain
        sshc.exec_command(ping_cmd)
        subnet = self.net_w_search['subnet']
        subnet = self.subnets_client.update_subnet(
            subnet['id'], dns_search_domain='')
        subnet = subnet.get('subnet', subnet)
        self.assertEqual(subnet[DNS_SEARCH_DOMAIN], '')
        # renew dhcp lease to force dns_search_domain update too
        sshc.renew_lease(floatingip['fixed_ip_address'])
        self.assertRaises(exceptions.SSHExecCommandFailed,
                          sshc.exec_command,
                          ping_cmd)

    # entry point for dns_search_domain test for different router-type
    def run_dns_search_domain_basic_ops(self, router_type):
        router, net_list = self.setup_tenant_networks(router_type)
        security_group = self.create_security_group_with_loginable_rules()
        self.net_w_search = self.create_servers_on_networks(
            self.networks_with_search_domain, security_group)
        self.net_wo_search = self.create_servers_on_networks(
            self.networks_wo_search_domain, security_group)
        server_id_list = [self.net_w_search['server']['id'],
                          self.net_wo_search['server']['id']]
        self.wait_for_servers_become_active(server_id_list)
        self._test_host_can_be_resolved()
        self._test_host_cannot_be_resolved()


class TestDnsSearchDomainOpsOverSharedRouter(TestDnsSearchDomainBasicOps):

    @test.idempotent_id('5556cdce-075c-437a-9d9d-f1e4583e9f4c')
    def test_dns_search_domain_ops_over_shared_router(self):
        return self.run_dns_search_domain_basic_ops('shared')


class TestDnsSearchDomainOpsOverExclusiveRouter(TestDnsSearchDomainBasicOps):

    @test.idempotent_id('6878c3cf-88d2-46ef-b366-b2a49bfa1e0a')
    def test_dns_search_domain_ops_over_exclusive_router(self):
        return self.run_dns_search_domain_basic_ops('exclusive')


class TestDnsSearchDomainOpsOverDistributedeRouter(
        TestDnsSearchDomainBasicOps):

    @test.idempotent_id('ad24cb58-532a-4675-9bbc-98ec4c296716')
    def test_dns_search_domain_ops_over_distributed_router(self):
        return self.run_dns_search_domain_basic_ops('distributed')
