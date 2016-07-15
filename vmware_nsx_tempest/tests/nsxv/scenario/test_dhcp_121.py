# Copyright 2016 OpenStack Foundation
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

import netaddr
import re
import socket
import struct
import sys
import time

from tempest.common.utils.linux import remote_client
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest import test

from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest.services import nsxv_client
from vmware_nsx_tempest.tests.nsxv.scenario import (
    manager_topo_deployment as dmgr)
from vmware_nsx_tempest.tests.nsxv.scenario import (
    network_addon_methods as HELO)

CONF = config.CONF
LOG = dmgr.manager.log.getLogger(__name__)

DHCP_121_DEPLOY_TOPO = "Testcase DHCP-121 option [%s] deploying"
DHCP_121_DEPLOY_COMPLETED = "Testcase [%s] deploy test-completed."
Metadataserver_ip = '169.254.169.254'


class TestDHCP121BasicOps(dmgr.TopoDeployScenarioManager):
    """Base class provides DHCP 121 options operations.

    1) Creates an instance
    2) Ssh to instance and then check below information:
       a) check metadata routes avialable or not
       b) check host routes avialble or not
       c) clear host-routes from subnet and check routes present on vm or not
       d) update subnet to disbale dhcp and check metadata routes not visible
          on instance
    3) Check at beckend(nsx-v) for host-routes and metadata route information
    4) Delete of host routes from subnet will make it deleted from beckend
    5) Negative test where try to make subnet dhcp disable but host-routes
       present and vice-versa
    6) Create large no of host-routes for subnet and check validation at
       beckend
    """

    @classmethod
    def skip_checks(cls):
        super(TestDHCP121BasicOps, cls).skip_checks()
        if not (CONF.network.project_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                               CONF.nsxv.manager_uri).group(0)
        cls.vsm = nsxv_client.VSMClient(
            manager_ip, CONF.nsxv.user, CONF.nsxv.password)
        nsxv_version = cls.vsm.get_vsm_version()
        # Raise skip testcase exception if nsx-v version is less than 6.2.3
        if (nsxv_version and nsxv_version < '6.2.3'):
            msg = ('NSX-v version should be greater than or equal to 6.2.3')
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TestDHCP121BasicOps, cls).resource_setup()

    @classmethod
    def resource_cleanup(cls):
        super(TestDHCP121BasicOps, cls).resource_cleanup()

    def tearDown(self):
        self.remove_project_network()
        super(TestDHCP121BasicOps, self).tearDown()

    def remove_project_network(self):
        project_name = 'green'
        tenant = getattr(self, project_name, None)
        if tenant:
            servers_client = tenant['client_mgr'].servers_client
            dmgr.delete_all_servers(servers_client)
            self.disassociate_floatingip(tenant['fip1'],
                                         and_delete=True)

    def check_server_connected(self, serv):
        # Fetch tenant-network from where vm deployed
        serv_net = list(serv['addresses'].keys())[0]
        serv_addr = serv['addresses'][serv_net][0]
        host_ip = serv_addr['addr']
        self.waitfor_host_connected(host_ip)

    def create_project_network_subnet(self,
                                      name_prefix='dhcp-project'):
        network_name = data_utils.rand_name(name_prefix)
        network, subnet = self.create_network_subnet(
            name=network_name)
        return (network['id'], network, subnet)

    def dhcp_121_metadata_hostroutes_check_on_vm_nsxv(self, vm_env):
        self.serv_fip = vm_env['fip1']['floating_ip_address']
        username, password = self.get_image_userpass()
        # Connect to instance launched using ssh lib
        client = remote_client.RemoteClient(self.serv_fip, username=username,
                                            password=password)
        # Executes route over launched instance
        cmd = ('/sbin/route -n')
        out_data = client.exec_command(cmd)
        self.assertIn(Metadataserver_ip, out_data)
        LOG.info(_LI("Metadata routes available on vm"))
        cmd = ('wget  http://169.254.169.254 -O sample.txt')
        client.exec_command(cmd)
        cmd = ('cat sample.txt')
        out_data = client.exec_command(cmd)
        # Check metadata server inforamtion available or not
        self.assertIn('latest', out_data)
        LOG.info(_LI("metadata server is acessible"))
        # Fetch dhcp edge infor from nsx-v
        exc_edge = self.vsm.get_dhcp_edge_info()
        self.assertIsNotNone(exc_edge)
        # Fetch host-route and metadata info from nsx-v
        dhcp_options_info = {}
        dhcp_options_info = \
            exc_edge['staticBindings']['staticBindings'][0]['dhcpOptions']
        # Check Host Route information avaialable at beckend
        self.assertIn(
            Metadataserver_ip,
            dhcp_options_info['option121'][
                'staticRoutes'][0]['destinationSubnet'])
        # Storing sec-group, network, subnet, router, server info in dict
        project_dict = dict(security_group=vm_env['security_group'],
                            network=vm_env['network'], subnet=vm_env['subnet'],
                            router=vm_env['router'],
                            client_mgr=vm_env['client_mgr'],
                            serv1=vm_env['serv1'], fip1=vm_env['fip1'])
        return project_dict

    def dhcp_121_hostroutes_clear(self, vm_env):
        # Fetch next hop information from tempest.conf
        next_hop = CONF.network.project_network_cidr
        self.nexthop_host_route = next_hop.rsplit('.', 1)[0]
        # Floating-ip of VM
        self.serv_fip = vm_env['fip1']['floating_ip_address']
        username, password = self.get_image_userpass()
        subnet_id = vm_env['subnet']['id']
        subnet_info = self.subnets_client.show_subnet(subnet_id)
        self.nexthop1 = subnet_info['subnet']['gateway_ip']
        # Update subnet with host routes
        _subnet_data = {'host_routes': [{'destination': '10.20.0.0/32',
                                         'nexthop': '10.100.1.1'}],
                        'new_host_routes': [{'destination': '10.20.0.0/32',
                                             'nexthop': self.nexthop1}]}
        new_host_routes = _subnet_data['new_host_routes']
        kwargs = {'host_routes': new_host_routes}
        new_name = "New_subnet"
        # Update subnet with host-route info
        self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        # Connect to instance launched using ssh lib
        client = remote_client.RemoteClient(self.serv_fip, username=username,
                                            password=password)
        # Executes route over instance launched
        fixed_ip = vm_env['fip1']['fixed_ip_address']
        client._renew_lease_udhcpc(fixed_ip)
        cmd = ('/sbin/route -n')
        out_data = client.exec_command(cmd)
        self.assertIn(
            _subnet_data['new_host_routes'][0]['nexthop'], out_data)
        self.assertIn(self.nexthop_host_route, out_data)
        LOG.info(_LI("Host routes available on vm"))
        # Check Host route info at beckend
        exc_edge = self.vsm.get_dhcp_edge_info()
        self.assertIsNotNone(exc_edge)
        # Fetch host-route and metadata info from nsx-v
        dhcp_options_info = {}
        dhcp_options_info = exc_edge['staticBindings']['staticBindings'][0][
            'dhcpOptions']['option121']['staticRoutes']
        # Check Host Route information avaialable at beckend
        for destination_net in dhcp_options_info:
            dest = _subnet_data['new_host_routes'][0]['destination']
            dest_subnet = destination_net['destinationSubnet']
            dest_router = destination_net['router']
            if (dest in dest_subnet and self.nexthop1 in dest_router):
                LOG.info(_LI("Host routes available on nsxv"))
        # Update subnet with no host-routes
        _subnet_data1 = {'new_host_routes': []}
        new_host_routes = _subnet_data1['new_host_routes']
        kwargs = {'host_routes': new_host_routes}
        new_name = "New_subnet"
        self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        # Executes route over instance launched
        fixed_ip = vm_env['fip1']['fixed_ip_address']
        client._renew_lease_udhcpc(fixed_ip)
        cmd = ('/sbin/route -n')
        out_data = client.exec_command(cmd)
        self.assertIsNotNone(out_data)
        # Check Host routes on VM shouldn't be avialable
        self.assertNotIn(
            _subnet_data['new_host_routes'][0]['destination'], out_data)
        # Check Host-routes at beckend after deletion
        exc_edge = self.vsm.get_dhcp_edge_info()
        self.assertIsNotNone(exc_edge)
        dhcp_options_info = []
        dhcp_options_info = exc_edge['staticBindings']['staticBindings'][0][
            'dhcpOptions']['option121']['staticRoutes']
        # Check Host Route information avaialable at beckend
        for destination_net in dhcp_options_info:
            if (_subnet_data['new_host_routes'][0]['destination']
                    not in destination_net['destinationSubnet']):
                LOG.info(_LI("Host routes not available on nsxv"))
        project_dict = dict(security_group=vm_env['security_group'],
                            network=vm_env['network'], subnet=vm_env['subnet'],
                            router=vm_env['router'],
                            client_mgr=vm_env['client_mgr'],
                            serv1=vm_env['serv1'], fip1=vm_env['fip1'])
        return project_dict

    def create_project_network_subnet_with_cidr(self,
                                                name_prefix='dhcp-project',
                                                cidr=None):
        network_name = data_utils.rand_name(name_prefix)
        network, subnet = self.create_network_subnet_with_cidr(
            name=network_name, cidr=cidr)
        return (network, subnet)

    def create_port(self, network_id):
        port_client = self.manager.ports_client
        return HELO.create_port(self, network_id=network_id,
                                client=port_client)

    def create_network_subnet_with_cidr(self, client_mgr=None,
                                        tenant_id=None, name=None, cidr=None):
        client_mgr = client_mgr or self.manager
        tenant_id = tenant_id
        name = name or data_utils.rand_name('topo-deploy-network')
        net_network = self.create_network(
            client=client_mgr.networks_client,
            tenant_id=tenant_id, name=name)
        net_subnet = self.create_subnet(
            client=client_mgr.subnets_client,
            network=net_network,
            cidr=cidr, name=net_network['name'])
        return net_network, net_subnet

    def setup_vm_enviornment(self, client_mgr, t_id,
                             check_outside_world=True,
                             cidr_offset=0):
        t_network, t_subnet, t_router = self.setup_project_network(
            self.public_network_id, namestart=("deploy-%s-dhcp" % t_id),
            cidr_offset=1)
        t_security_group = self._create_security_group(
            security_groups_client=self.security_groups_client,
            security_group_rules_client=self.security_group_rules_client,
            namestart='adm')
        username, password = self.get_image_userpass()
        security_groups = [{'name': t_security_group['id']}]
        t_serv1 = self.create_server_on_network(
            t_network, security_groups,
            image=self.get_server_image(),
            flavor=self.get_server_flavor(),
            name=t_network['name'])
        self.check_server_connected(t_serv1)
        t_floatingip = self.create_floatingip_for_server(
            t_serv1, client_mgr=self.admin_manager)
        msg = ("Associate t_floatingip[%s] to server[%s]"
               % (t_floatingip, t_serv1['name']))
        self._check_floatingip_connectivity(
            t_floatingip, t_serv1, should_connect=True, msg=msg)
        vm_enviornment = dict(security_group=t_security_group,
                              network=t_network, subnet=t_subnet,
                              router=t_router, client_mgr=client_mgr,
                              serv1=t_serv1, fip1=t_floatingip)
        return vm_enviornment


class TestDhcpMetadata(TestDHCP121BasicOps):
    @test.attr(type='nsxv')
    @test.idempotent_id('95d06aba-895f-47f8-b47d-ae48c6853a85')
    def test_dhcp_121_metadata_check_on_vm_nsxv(self):
        LOG.info(_LI("Testcase DHCP-121 option metadata check on vm and \
            on nsx deploying"))
        self.vm_env = self.setup_vm_enviornment(self.manager, 'green', True)
        self.green = self.dhcp_121_metadata_hostroutes_check_on_vm_nsxv(
            self.vm_env)
        LOG.info(_LI("Testcase DHCP-121 option metadata check on vm and on \
            nsx completed"))


class TestDhcpHostroutesClear(TestDHCP121BasicOps):
    @test.attr(type='nsxv')
    @test.idempotent_id('6bec6eb4-8632-493d-a895-a3ee87cb3002')
    def test_dhcp_121_hostroutes_clear(self):
        LOG.info(_LI("Testcase DHCP-121 option host routes clear deploying"))
        self.vm_env = self.setup_vm_enviornment(self.manager, 'green', True)
        self.green = self.dhcp_121_hostroutes_clear(self.vm_env)
        LOG.info(_LI("Testcase DHCP-121 option host routes clear completed"))


class TestDhcpNegative(TestDHCP121BasicOps):
    @test.attr(type='nsxv')
    @test.idempotent_id('a58dc6c5-9f28-4184-baf7-37ded52593c4')
    def test_dhcp121_negative_test(self):
        LOG.info(_LI("Testcase DHCP-121 option negative test deploying"))
        t_net_id, t_network, t_subnet =\
            self.create_project_network_subnet('admin')
        subnet_id = t_subnet['id']
        kwargs = {'enable_dhcp': 'false'}
        new_name = "New_subnet"
        # Update subnet with disable dhcp subnet
        self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        # Fetch next hop information from tempest.conf
        next_hop = CONF.network.project_network_cidr
        self.nexthop_host_route = next_hop.rsplit('.', 1)[0]
        self.nexthop1 = self.nexthop_host_route + ".2"
        username, password = self.get_image_userpass()
        # Update subnet with host routes
        _subnet_data = {'host_routes': [{'destination': '10.20.0.0/32',
                                         'nexthop': '10.100.1.1'}],
                        'new_host_routes': [{'destination': '10.20.0.0/32',
                                             'nexthop': self.nexthop1}]}
        new_host_routes = _subnet_data['new_host_routes']
        kwargs = {'host_routes': new_host_routes}
        new_name = "New_subnet"
        # Update subnet with host-route info
        try:
            self.subnets_client.update_subnet(
                subnet_id, name=new_name, **kwargs)
        except exceptions.BadRequest:
            e = sys.exc_info()[0].__dict__['message']
            if (e == "Bad request"):
                LOG.info(_LI("Invalid input for operation:\
                              Host routes can only be supported when\
                              DHCP is enabled"))
            pass
        subnet_id = t_subnet['id']
        kwargs = {'enable_dhcp': 'true'}
        new_name = "New_subnet"
        # Update subnet with disable dhcp subnet
        self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        # Update subnet with host routes
        _subnet_data = {'host_routes': [{'destination': '10.20.0.0/32',
                                         'nexthop': '10.100.1.1'}],
                        'new_host_routes': [{'destination': '10.20.0.0/32',
                                             'nexthop': self.nexthop1}]}
        new_host_routes = _subnet_data['new_host_routes']
        kwargs = {'host_routes': new_host_routes}
        new_name = "Subnet_host_routes"
        # Update subnet with host-route info
        self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        # Disable dhcp subnet
        kwargs = {'enable_dhcp': 'false'}
        # Update subnet with disable dhcp subnet
        try:
            self.subnets_client.update_subnet(
                subnet_id, name=new_name, **kwargs)
        except exceptions.BadRequest:
            e = sys.exc_info()[0].__dict__['message']
            if (e == "Bad request"):
                LOG.info(_LI("Can't disable DHCP while using host routes"))
            pass
        LOG.info(_LI("Testcase DHCP-121 option negative test completed"))


class TestDhcpMultiHostRoute(TestDHCP121BasicOps):
    @test.attr(type='nsxv')
    @test.idempotent_id('c3ca96d7-b704-4d94-b42d-e7bae94b82cd')
    def test_dhcp121_multi_host_route(self):
        LOG.info(_LI("Testcase DHCP-121 option multi host routes deploying"))
        t_net_id, t_network, t_subnet =\
            self.create_project_network_subnet('admin')
        # Fetch next hop information from tempest.conf
        next_hop = CONF.network.project_network_cidr
        self.nexthop_host_route = next_hop.rsplit('.', 1)[0]
        self.nexthop1 = self.nexthop_host_route + ".2"
        # Update subnet with host routes
        _subnet_data = {'host_routes': [{'destination': '10.20.0.0/32',
                                         'nexthop': '10.100.1.1'}],
                        'new_host_routes': [{'destination': '10.20.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.21.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.22.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.23.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.24.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.25.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.26.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.27.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.28.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.29.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.30.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.31.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.32.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.33.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.34.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.35.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.36.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.37.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.38.0.0/32',
                                             'nexthop': self.nexthop1}]}
        new_host_routes = _subnet_data['new_host_routes']
        kwargs = {'host_routes': new_host_routes}
        new_name = "New_subnet"
        subnet_id = t_subnet['id']
        # Update subnet with host-route info
        subnet = self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        '''
        Above No of host-routes added are 19 so checking len of
        subnet host_routes equal to 19 or not
        '''
        if (len(subnet['subnet']['host_routes']) == 19):
            LOG.info(_LI("Multiple entries for host routes available"))
        LOG.info(_LI("Testcase DHCP-121 option multi host routes completed"))


class TestDhcpHostRoutesBetweenVms(TestDHCP121BasicOps):
    @test.attr(type='nsxv')
    @test.idempotent_id('34e6d23f-db00-446e-8299-57ff2c0911b2')
    def test_host_routes_between_vms(self):
        client_mgr = self.manager
        next_hop = CONF.network.project_network_cidr
        ip = next_hop.rsplit('/', 1)[0]
        ip2int = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
        ss = (ip2int(ip))
        int2ip = lambda n: socket.inet_ntoa(struct.pack('!I', n))
        new_network_cidr = (int2ip(ss + 256))
        net_mask = str(CONF.network.project_network_mask_bits)
        new_network_cidr = new_network_cidr + '/' + net_mask
        cidr = netaddr.IPNetwork(new_network_cidr)
        self.green = self.setup_vm_enviornment(self.manager, 'green', True)
        network, subnet =\
            self.create_project_network_subnet_with_cidr('dhcp121-tenant',
                                                         cidr=cidr)
        net_id = network['id']
        # Create Port
        port = self.create_port(net_id)
        HELO.router_add_port_interface(self, net_router=self.green['router'],
                                       net_port=port, client_mgr=client_mgr)
        t_security_group = self._create_security_group(
            security_groups_client=self.security_groups_client,
            security_group_rules_client=self.security_group_rules_client,
            namestart='adm')
        username, password = self.get_image_userpass()
        security_groups = [{'name': t_security_group['name']}]
        _subnet_data = {'host_routes': [{'destination': '10.20.0.0/32',
                                         'nexthop': '10.100.1.1'}],
                        'new_host_routes': [{
                            'destination': CONF.network.project_network_cidr,
                            'nexthop': port['fixed_ips'][0]['ip_address']}]}
        subnet_client = client_mgr.subnets_client
        subnet_id = subnet['id']
        new_name = "New_subnet"
        new_host_routes = _subnet_data['new_host_routes']
        kwargs = {'host_routes': new_host_routes}
        # Update subnet with host-route info
        subnet_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        # launched dest vm
        t_serv2 = self.create_server_on_network(
            network, security_groups,
            image=self.get_server_image(),
            flavor=self.get_server_flavor(),
            name=network['name'])
        self.check_server_connected(t_serv2)
        time.sleep(dmgr.WAITTIME_FOR_CONNECTIVITY)
        # Connect to instance launched using ssh lib
        self.serv_fip = self.green['fip1']['floating_ip_address']
        username, password = self.get_image_userpass()
        client = remote_client.RemoteClient(self.serv_fip, username=username,
                                            password=password)
        network_name = network['name']
        dest_ip = t_serv2['addresses'][network_name][0]['addr']
        # Ping dest vm from source vm
        cmd = ('ping %s -c 3' % dest_ip)
        out_data = client.exec_command(cmd)
        desired_output = "64 bytes from %s" % dest_ip
        self.assertIn(desired_output, out_data)
