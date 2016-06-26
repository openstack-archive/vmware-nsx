# Copyright 2015 OpenStack Foundation
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

from tempest import config
from tempest import test

import manager_topo_deployment as dmgr
from tempest.lib.common.utils import data_utils

CONF = config.CONF
LOG = dmgr.manager.log.getLogger(__name__)

FLAT_ALLOC_DICT = CONF.scenario.flat_alloc_pool_dict
Z_DEPLOY_TOPO = "tc[%s] deploying"
Z_DEPLOY_DELETE_SERVER = "tc[%s] deploy delete-server"
Z_DEPLOY_COMPLETED = "tc[%s] deploy test-completed."


class TestSimpleFlatNetwork(dmgr.TopoDeployScenarioManager):

    """TestSimpleFlatNetwork: with 1 flat network/subnet

       1. client:admin create FLAT network.
       2. client:primary boot a server (icmp/ssh security rules enabled)
          on the flat network.
       3. check the server is reachable.
    """

    @classmethod
    def skip_checks(cls):
        super(TestSimpleFlatNetwork, cls).skip_checks()
        if not FLAT_ALLOC_DICT:
            msg = "FLAT network allocation pool not defined."
            raise cls.skipException(msg)

    def setUp(self):
        super(TestSimpleFlatNetwork, self).setUp()
        self.info_flat1 = FLAT_ALLOC_DICT

    def tearDown(self):
        super(TestSimpleFlatNetwork, self).tearDown()

    def create_network(self, name=None, shared=True):
        name = name or data_utils.rand_name('FLAT-net')
        post_body = {'name': name,
                     'provider:network_type': 'flat',
                     'shared': shared}
        net_flat = self.create_provider_network(create_body=post_body)
        return net_flat

    def create_subnet(self, net_network, info_flat):
        alloc_pool = [{'start': info_flat['start'],
                       'end': info_flat['end']}]
        post_body = {'name': net_network['name'],
                     'network_id': net_network['id'],
                     'ip_version': 4,
                     'gateway_ip': info_flat['gateway'],
                     'cidr': info_flat['cidr'],
                     'allocation_pools': alloc_pool,
                     'dns_nameservers': CONF.network.dns_servers}
        net_subnet = self.create_provider_subnet(create_body=post_body)
        return net_subnet

    def check_server_connected(self, serv):
        serv_net = list(serv['addresses'].keys())[0]
        serv_addr = serv['addresses'][serv_net][0]
        host_ip = serv_addr['addr']
        # host_mac = serv_addr['OS-EXT-IPS-MAC:mac_addr']
        # host_ver = serv_addr['version']
        self.waitfor_host_connected(host_ip)

    @test.idempotent_id('bc081b8d-49eb-4710-9442-c6b225ef16f0')
    @test.services('compute', 'network')
    def test_simple_flat_network(self):
        # provider actions
        self.net_network = self.create_network()
        self.net_subnet = self.create_subnet(self.net_network, self.info_flat1)
        # tenant actions
        self.security_group = self._create_security_group(
            security_groups_client=self.security_groups_client,
            security_group_rules_client=self.security_group_rules_client,
            namestart='FLAT-tenant')
        security_groups = [{'name': self.security_group['id']}]
        self.serv1 = self.create_server_on_network(
            self.net_network, security_groups,
            image=self.get_server_image(),
            flavor=self.get_server_flavor(),
            name=self.net_network['name'])
        self.check_server_connected(self.serv1)
        LOG.debug(Z_DEPLOY_DELETE_SERVER, "flat-network")
        self.servers_client.delete_server(self.serv1['id'])
        LOG.debug(Z_DEPLOY_COMPLETED, "flat-network")


class TestTenantConnectivity(dmgr.TopoDeployScenarioManager):

    """TestTenantConnectivity: router attached with one network/subnet

       1. boot server #1 with icmp/ssh security rules enabled.
       2. create/associate floatingip associate to server #1
       3. disassociate floatingip from server #1
       4. check server #1 is not reachable.
       5. boot server #2, and associated with the last floatingip.
       6. check the 2nd and outside-world-server are reachable.
    """

    def setUp(self):
        super(TestTenantConnectivity, self).setUp()
        self.servers = []

    def tearDown(self):
        # do mini teardown if test failed already
        super(TestTenantConnectivity, self).tearDown()

    @test.idempotent_id('3c6cd4fe-de25-47ef-b638-a6bbb312da09')
    @test.services('compute', 'network')
    def test_tenant_connectivity(self):
        LOG.debug(Z_DEPLOY_TOPO, "tenant connectivity")
        client_mgr = self.manager
        username, password = self.get_image_userpass()
        # create security_group with loginable rules
        self.security_group = self._create_security_group(
            security_groups_client=client_mgr.security_groups_client,
            security_group_rules_client=client_mgr.security_group_rules_client,
            namestart='deploy-connect')
        self.network, self.subnet, self.router = self.setup_project_network(
            self.public_network_id, client_mgr=client_mgr,
            namestart='deploy-connect')
        self.check_networks(self.network, self.subnet, self.router)
        security_groups = [{'name': self.security_group['id']}]
        self.serv1 = self.create_server_on_network(
            self.network, security_groups,
            image=self.get_server_image(),
            flavor=self.get_server_flavor(),
            name=self.network['name'])
        self.fip1 = self.create_floatingip_for_server(
            self.serv1, client_mgr=client_mgr)
        msg = "Associate floatingip[%s] sever#1" % self.fip1
        self._check_floatingip_connectivity(
            self.fip1, self.serv1, should_connect=True, msg=msg)
        # VM is reachable from public; check VM can reach outside world
        node1 = dmgr.make_node_info(self.fip1, username, password, True)
        is_reachable = dmgr.check_host_is_reachable(
            node1, node1['dest'], ['outside'])
        self.assertTrue(
            is_reachable,
            "VM=%s CAN-NOT-REACH-OUTSIDE-WORLD" % (node1['ipaddr']))
        LOG.debug('tenant[%s] CAN-REACH-OUTSIDE-WORLD',
                  node1['ipaddr'])
        self.disassociate_floatingip(self.fip1,
                                     client=self.manager.floating_ips_client)
        time.sleep(dmgr.WAITTIME_AFTER_DISASSOC_FLOATINGIP)
        msg = "after disassociate floatingip[%s] from server#1" % self.fip1
        self._check_floatingip_connectivity(
            self.fip1, self.serv1, should_connect=False, msg=msg)
        self.serv2 = self.create_server_on_network(
            self.network, security_groups,
            image=self.get_server_image(),
            flavor=self.get_server_flavor(),
            name=self.network['name'])
        self.associate_floatingip(self.fip1, self.serv2,
                                  client=self.manager.floating_ips_client)
        server_pingable = self._waitfor_associated_floatingip(self.fip1)
        self.assertTrue(
            server_pingable,
            msg="Expect server#2 to be reachable after floatingip assigned.")
        self.disassociate_floatingip(self.fip1,
                                     client=self.manager.floating_ips_client,
                                     and_delete=True)
        LOG.debug(Z_DEPLOY_DELETE_SERVER, "tenant connectivity")
        self.servers_client.delete_server(self.serv1['id'])
        self.servers_client.delete_server(self.serv2['id'])
        # self._router_unset_gateway(self.router['id'])
        LOG.debug(Z_DEPLOY_COMPLETED, "tenant connectivity")


class TestMultiTenantsNetwork(dmgr.TopoDeployScenarioManager):

    """TestMultiTenantsNetwork: with router, attached with 1 network/subnet

       1. boot 2 servers (icmp/ssh rules enabled) on primary(green) network.
       2. create/associate floatingip to each server.
       3. check VM-A can reach VM-B's fixed IP
       4. chekc VM-B can reach VM-A's fixed IP
       5. repeat 1-4 with alt-tenant (red), however its cidr is different
          from the primary network for negative test. We don't want to ping
          fixed-ip that being assigned to both tenents.
       6. check VM@primary can not access VM@alt with fixed-ip
       7. check VM@primary can access floatingip of VM@alt
    """

    def tearDown(self):
        # do mini teardown if test failed already
        try:
            self.remove_project_network(False)
        except Exception:
            pass

        super(TestMultiTenantsNetwork, self).tearDown()

    def remove_project_network(self, from_test=True):
        for tn in ['green', 'red']:
            tenant = getattr(self, tn, None)
            if tenant and 'fip1' in tenant:
                servers_client = tenant['client_mgr'].servers_client
                dmgr.delete_all_servers(servers_client)
                fip_client = tenant['client_mgr'].floating_ips_client
                self.disassociate_floatingip(tenant['fip1'],
                                             client=fip_client,
                                             and_delete=True)
                self.disassociate_floatingip(tenant['fip2'],
                                             client=fip_client,
                                             and_delete=True)
                tenant.pop('fip1')

    def create_project_network_env(self, client_mgr, t_id,
                                  check_outside_world=True,
                                  cidr_offset=1):
        username, password = self.get_image_userpass()
        t_security_group = self._create_security_group(
            security_groups_client=client_mgr.security_groups_client,
            security_group_rules_client=client_mgr.security_group_rules_client,
            namestart="deploy-multi-tenant")
        t_network, t_subnet, t_router = self.setup_project_network(
            self.public_network_id, client_mgr,
            namestart=("deploy-%s-tenant" % t_id),
            cidr_offset=cidr_offset)
        self.check_networks(t_network, t_subnet, t_router)
        name1 = t_network['name'] + "-A"
        name2 = t_network['name'] + "-B"
        security_groups = [{'name': t_security_group['name']}]
        servers_client = client_mgr.servers_client
        t_serv1 = self.create_server_on_network(
            t_network, security_groups,
            image=self.get_server_image(),
            flavor=self.get_server_flavor(),
            name=name1,
            servers_client=servers_client, wait_on_boot=False)
        t_serv2 = self.create_server_on_network(
            t_network, security_groups,
            image=self.get_server_image(),
            flavor=self.get_server_flavor(),
            servers_client=servers_client, name=name2)
        t_fip1 = self.create_floatingip_for_server(
            t_serv1, client_mgr=client_mgr)
        t_fip2 = self.create_floatingip_for_server(
            t_serv2, client_mgr=client_mgr)
        node1 = dmgr.make_node_info(t_fip1, username, password,
                                    check_outside_world)
        node2 = dmgr.make_node_info(t_fip2, username, password,
                                    check_outside_world)
        T = dict(security_group=t_security_group,
                 network=t_network, subnet=t_subnet,
                 router=t_router, client_mgr=client_mgr,
                 serv1=t_serv1, fip1=t_fip1, node1=node1,
                 serv2=t_serv2, fip2=t_fip2, node2=node2)
        is_reachable = dmgr.check_host_is_reachable(
            node1, node2['dest'], [dmgr.IPTYPE_FIXED])
        self.assertTrue(
            is_reachable,
            ("VM-A-%s=%s CANNOT-REACH VM-B-%s=%s" %
             (t_id, str(node1), t_id, str(node2))))
        is_reachable = dmgr.check_host_is_reachable(
            node2, node1['dest'], [dmgr.IPTYPE_FIXED])
        self.assertTrue(
            True,
            ("VM-B-%s=%s CANNOT-REACH VM-A-%s=%s" %
             (t_id, str(node2), t_id, str(node1))))
        return T

    @test.idempotent_id('19d19cd0-9686-49c9-acea-a9db28f7458c')
    @test.services('compute', 'network')
    def test_multi_tenants_network(self):
        LOG.debug(Z_DEPLOY_TOPO, "multi tenant network")
        self.green = self.create_project_network_env(
            self.manager, 'green', True)
        # in multiple tenant environment, ip overlay could happen
        # for the 2nd tenent give it a different ip-range to
        # make sure private-ip at tenat-1 is not the same being
        # assigned to tenant-2
        self.red = self.create_project_network_env(
            self.alt_manager, 'red', False, cidr_offset=3)
        # t1 can reach t2's public interface
        is_rechable = dmgr.check_host_is_reachable(
            self.green['node1'], self.red['node2']['dest'],
            [dmgr.IPTYPE_FLOATING])
        self.assertTrue(
            is_rechable,
            ("t1:VM-A=%s CANNOT-REACH t2:VM-A=[floating-ip %s]" %
             (str(self.green['node1']), str(self.red['node2']))))
        # Do the reachable first, then check other VM's fixed-ip
        # is not reachable - again tenants should not have overlay IPs.
        not_reachable = dmgr.check_host_not_reachable(
            self.green['node1'], self.red['node2']['dest'],
            [dmgr.IPTYPE_FIXED], 10, 20, 2)
        self.assertFalse(
            not_reachable,
            ("t1:VM-A=%s SHOULD-NOT-REACH t2:VM-B=[fixed-ip %s]" %
             (str(self.green['node1']), str(self.red['node2']))))
        self.remove_project_network()
        LOG.debug(Z_DEPLOY_COMPLETED, "multi tenant network")


class TestProviderRouterTenantNetwork(dmgr.TopoDeployScenarioManager):

    """TestProviderRouterTenantNetwork:

       1. admin client create a router, gw to external network
       2. primary client (yellow) create a network
       3. alt client (blue) create a network
       4. admin client add primary network and alt network to router
       5. primary client boot a server, icmp/ssh enabled, to its network
       6. alt client boot a server, icmp/ssh enabled, to its network
       7. primary client create floatingip to its server
       8. alt client create floatingip to its server
       9. check primary server can reach fixed-ip & floating-ip of alt server
       10. check alt server can reach fixed-ip & floating-ip of primary server
    """

    def setUp(self):
        super(TestProviderRouterTenantNetwork, self).setUp()

    def tearDown(self):
        # do mini teardown if test failed already
        try:
            self.remove_project_network(False)
        except Exception:
            pass
        super(TestProviderRouterTenantNetwork, self).tearDown()

    def remove_project_network(self, from_test=True):
        router_id = self.p_router['id']
        for tn in ['yellow', 'blue']:
            tenant = getattr(self, tn, None)
            if tenant and 'fip' in tenant:
                servers_client = tenant['client_mgr'].servers_client
                dmgr.delete_all_servers(servers_client)
                fip_client = tenant['client_mgr'].floating_ips_client
                self.disassociate_floatingip(tenant['fip'],
                                             client=fip_client,
                                             and_delete=True)
                tenant.pop('fip')
                self.router_interface_delete(
                    router_id, tenant['subnet']['id'],
                    self.admin_manager.routers_client)
                self.admin_manager.networks_client.delete_network(
                    tenant['network']['id'])
                tenant.pop('subnet')
                tenant.pop('network')
        self._router_clear_gateway(
            router_id, client=self.admin_manager.routers_client)

    def create_project_network_env(self, t_id, client_mgr=None,
                                   tenant_id=None, cidr_offset=0, **kwargs):
        tenant = self.create_tenant_network(t_id, client_mgr, tenant_id,
                                            cidr_offset, **kwargs)
        tenant = self.create_server_and_assign_floatingip(tenant)
        return tenant

    def create_tenant_network(self, t_id, client_mgr=None,
                              tenant_id=None, cidr_offset=0, **kwargs):
        namestart = "deploy-%s-tenant" % t_id
        name = data_utils.rand_name(namestart)
        client_mgr = client_mgr or self.manager
        security_groups_client = client_mgr.security_groups_client
        security_group_rules_client = client_mgr.security_group_rules_client
        t_network, t_subnet = self.create_network_subnet(
            client_mgr, name=name, tenant_id=tenant_id,
            cidr_offset=cidr_offset,)
        t_security_group = self._create_security_group(
            security_groups_client=security_groups_client,
            security_group_rules_client=security_group_rules_client,
            namestart=namestart, tenant_id=tenant_id)
        self._router_add_interface(
            self.p_router, t_subnet, self.admin_manager)
        return dict(id=t_id, network=t_network, subnet=t_subnet,
                    client_mgr=client_mgr, security_group=t_security_group)

    def create_server_and_assign_floatingip(self, tenant):
        t_network = tenant['network']
        t_security_group = tenant['security_group']
        client_mgr = tenant['client_mgr']
        servers_client = client_mgr.servers_client
        security_groups = [{'name': t_security_group['name']}]
        t_serv = self.create_server_on_network(
            t_network, security_groups,
            name=t_network['name'],
            image=self.get_server_image(),
            flavor=self.get_server_flavor(),
            servers_client=servers_client)
        t_fip = self.create_floatingip_for_server(
            t_serv, client_mgr=client_mgr)
        tenant.update(serv=t_serv, fip=t_fip)
        return tenant

    @test.idempotent_id('a31712de-33ad-4dc2-9755-1a0631a4f66a')
    @test.services('compute', 'network')
    def test_provider_router_project_network(self):
        # provider router owned by admin_manager
        self.p_router = self._create_router(
            client_mgr=self.admin_manager, namestart="deploy-provider-router",
            distributed=self.tenant_router_attrs.get('distributed'),
            router_type=self.tenant_router_attrs.get('router_type'))
        self._router_set_gateway(self.p_router['id'], self.public_network_id,
                                 client=self.admin_manager.routers_client)
        self.yellow = self.create_project_network_env(
            'yellow', self.manager, cidr_offset=1)
        self.blue = self.create_project_network_env(
            'blue', self.alt_manager, cidr_offset=2)
        username, password = self.get_image_userpass()
        yellow = dmgr.make_node_info(self.yellow['fip'], username, password)
        blue = dmgr.make_node_info(self.blue['fip'], username, password)
        is_reachable = dmgr.check_host_is_reachable(
            yellow, blue['dest'], [dmgr.IPTYPE_FLOATING])
        self.assertTrue(
            is_reachable,
            "VM-yello=%s CANNOT-REACH VM-blue=%s" % (str(yellow), str(blue)))
        is_reachable = dmgr.check_host_is_reachable(
            blue, yellow['dest'], [dmgr.IPTYPE_FLOATING])
        self.assertTrue(
            is_reachable,
            "VM-blue=%s CANNOT-REACH VM-yellow=%s" % (str(blue), str(yellow)))
        self.remove_project_network()


# exclusive router
class TestTenantConnectivityWithExclusiveRouter(
        TestTenantConnectivity):

    """TestTenantConnectivityWithExclusiveRouter:

       samet as TestTenantConnectivity, except router is exclusive.
    """

    # router attributes used to create the tenant's router
    tenant_router_attrs = {'router_type': 'exclusive'}

    @classmethod
    def skip_checks(cls):
        super(TestTenantConnectivityWithExclusiveRouter,
              cls).skip_checks()
        for ext in ['nsxv-router-type']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)


class TestMultiTenantsNetworkWithExclusiveRouter(
        TestMultiTenantsNetwork):

    """TestMultiTenantsNetworkWithExclusiveRouter:

       samet as TenantNetwork , except router is exclusive.
    """

    tenant_router_attrs = {'router_type': 'exclusive'}

    @classmethod
    def skip_checks(cls):
        super(TestMultiTenantsNetworkWithExclusiveRouter,
              cls).skip_checks()
        for ext in ['nsxv-router-type']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)


class TestProviderExclusiveRouterTenantNetwork(
        TestProviderRouterTenantNetwork):

    """TestProviderExclusiveRouterTenantNetwork:

       same as TestProviderRouterTenantNework, except router is exclusive.
    """

    tenant_router_attrs = {'router_type': 'exclusive'}

    @classmethod
    def skip_checks(cls):
        super(TestProviderExclusiveRouterTenantNetwork,
              cls).skip_checks()
        for ext in ['nsxv-router-type']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)


# distributed router
class TestTenantConnectivityWithDistributedRouter(
        TestTenantConnectivity):

    """TestTenantConnectivityWithDistributedRouter:

       same as TestTenantConnectivity, except router is distributed.
    """

    # router attributes used to create the tenant's router
    tenant_router_attrs = {'distributed': True}

    @classmethod
    def skip_checks(cls):
        super(TestTenantConnectivityWithDistributedRouter,
              cls).skip_checks()
        for ext in ['dvr', 'nsxv-router-type']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)


class TestMultiTenantsNetworkWithDistributedRouter(
        TestMultiTenantsNetwork):

    """TestMultiTenantsNetworkWithDistributedRouter:

       same as TestMultiTenantsNetwork, except router is distributed.
    """

    tenant_router_attrs = {'distributed': True}

    @classmethod
    def skip_checks(cls):
        super(TestMultiTenantsNetworkWithDistributedRouter,
              cls).skip_checks()
        for ext in ['dvr', 'nsxv-router-type']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)


class TestProviderDistributedRouterTenantNetwork(
        TestProviderRouterTenantNetwork):

    """TestProviderDistributedRouterTenantNetwork:

       same as TestProviderRouterTenantNework, except router is distributed.
    """

    tenant_router_attrs = {'distributed': True}

    @classmethod
    def skip_checks(cls):
        super(TestProviderDistributedRouterTenantNetwork,
              cls).skip_checks()
        for ext in ['dvr', 'nsxv-router-type']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)


def _g_service_client(req_mgr, client_name):
    s_client = getattr(req_mgr, client_name, None)
    if s_client:
        return s_client
    return req_mgr.networks_client


# self vs req: there are possible 3 client managers (admin, pri, 2nd)
# in each class, but the default is the primary, other clients need aslo
# to create resources, so you should call this to get proper client.
def _g_neutron_service_client(self_mgr, req_mgr, client_name):
    if req_mgr:
        return _g_service_client(req_mgr, client_name)
    return _g_service_client(self_mgr, client_name)
