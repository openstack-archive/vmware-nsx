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

import collections

from oslo_log import log as logging

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.scenario import manager
from tempest import test

from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF

LOG = logging.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class TestProviderSecurityGroup(manager.NetworkScenarioTest):

    """Test Provider security Group Scenario

    Test the following Provider security Group scenarios
        - Create default and PSG based servers and check connectivity
        - Create mulitple default and PSG based servers and check
          connectivity
        - Create mulitple default and PSG based servers and check
          connectivity on differect cidr
    """

    @classmethod
    def skip_checks(cls):
        super(TestProviderSecurityGroup, cls).skip_checks()
        if not test.is_extension_enabled('provider-security-group', 'network'):
            msg = "Extension provider-security-group is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(TestProviderSecurityGroup, cls).setup_credentials()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)

    def setUp(self):
        super(TestProviderSecurityGroup, self).setUp()
        self.cmgr_pri = self.get_client_manager('primary')
        self.cmgr_alt = self.get_client_manager('alt')
        self.cmgr_adm = self.get_client_manager('admin')
        self.keypairs = {}
        self.servers = []

    def create_security_provider_group(self, cmgr=None,
                                       project_id=None, provider=False):
        sg_client_admin = self.cmgr_adm.security_groups_client
        sg_dict = dict(name=data_utils.rand_name('provider-sec-group'))
        if project_id:
            sg_dict['tenant_id'] = project_id
        if provider:
            sg_dict['provider'] = True
        sg = sg_client_admin.create_security_group(**sg_dict)
        sg = sg.get('security_group', sg)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_security_group,
                        sg_client_admin, sg.get('id'))
        return sg

    def delete_security_group(self, sg_client, sg_id):
        sg_client.delete_security_group(sg_id)

    def _delete_router(self, router):
        body = self.ports_client.list_ports(device_id=router['id'])
        interfaces = body['ports']
        for i in interfaces:
            test_utils.call_and_ignore_notfound_exc(
                self.routers_client.remove_router_interface, router['id'],
                subnet_id=i['fixed_ips'][0]['subnet_id'])
        self.routers_client.delete_router(router['id'])

    def _create_router(self, router_name=None, admin_state_up=True,
                       external_network_id=None, enable_snat=None,
                       **kwargs):
        ext_gw_info = {}
        if external_network_id:
            ext_gw_info['network_id'] = external_network_id
        if enable_snat is not None:
            ext_gw_info['enable_snat'] = enable_snat
        body = self.routers_client.create_router(
            name=router_name, external_gateway_info=ext_gw_info,
            admin_state_up=admin_state_up, **kwargs)
        router = body.get('router', body)
        self.addCleanup(self._delete_router, router)
        return router

    def _create_subnet(self, network, cidr, subnets_client=None, **kwargs):
        client = subnets_client or self.subnets_client
        body = client.create_subnet(
            name=data_utils.rand_name('subnet-psg'),
            network_id=network['id'], tenant_id=network['tenant_id'],
            cidr=cidr, ip_version=4, **kwargs)
        subnet = body.get('subnet', body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        client.delete_subnet, subnet['id'])
        return subnet

    def get_port_id(self, network_id, subnet_id, instance):
        _, instance_addr = instance["addresses"].items()[0]
        instance_fixed_ip = instance_addr[0]["addr"]
        for port in self._list_ports():
            port_fixed_ip = port["fixed_ips"][0]["ip_address"]
            if port["network_id"] == network_id and port["fixed_ips"][0][
                    "subnet_id"] == subnet_id and instance["id"] == port[
                    "device_id"] and port_fixed_ip == instance_fixed_ip:
                port_id = port["id"]
        self.assertIsNotNone(port_id, "Failed to find Instance's port id!!!")
        return port_id

    def _create_server(self, name, network, image_id=None):
        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        security_groups = [{'name': self.security_group['name']}]
        network = {'uuid': network['id']}
        server = self.create_server(name=name, networks=[network],
                                    key_name=keypair['name'],
                                    security_groups=security_groups,
                                    image_id=image_id,
                                    wait_until='ACTIVE')
        self.servers.append(server)
        return server

    def _get_server_key(self, server):
        return self.keypairs[server['key_name']]['private_key']

    def _get_server_ip(self, server):
        addresses = server['addresses'][self.network['name']]
        for address in addresses:
            if address['version'] == CONF.validation.ip_version_for_ssh:
                return address['addr']

    def create_security_group_rule(self, security_group_id,
                                   cmgr=None, project_id=None,
                                   protocol=None):
        cmgr = cmgr or self.cmgr_adm
        sgr_client = cmgr.security_group_rules_client
        sgr_dict = dict(security_group_id=security_group_id,
                        direction='ingress', protocol=protocol)
        if project_id:
            sgr_dict['tenant_id'] = project_id
        sgr = sgr_client.create_security_group_rule(**sgr_dict)
        return sgr.get('security_group_rule', sgr)

    def create_network_topo(self):
        self.security_group = self._create_security_group()
        self.network = self._create_network()
        self.subnet = self._create_subnet(self.network,
                                          cidr='10.168.1.0/24')
        self.router = self._create_router(
            router_name=data_utils.rand_name('router-psg'),
            external_network_id=CONF.network.public_network_id)
        self.routers_client.add_router_interface(
            self.router['id'], subnet_id=self.subnet['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        self.router['id'], subnet_id=self.subnet['id'])
        networks = dict(security_group=self.security_group,
                        network=self.network,
                        subnet=self.subnet, router=self.router)
        return networks

    def create_multi_network_topo(self):
        self.security_group = self._create_security_group()
        self.network = self._create_network(namestart="net-psg")
        self.subnet = self._create_subnet(self.network,
                                          cidr='10.168.1.0/24')
        self.router = self._create_router(
            router_name=data_utils.rand_name('router-psg'),
            external_network_id=CONF.network.public_network_id)
        self.routers_client.add_router_interface(
            self.router['id'], subnet_id=self.subnet['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        self.router['id'], subnet_id=self.subnet['id'])
        self.network_2 = self._create_network()
        self.subnet_2 = self._create_subnet(self.network_2,
                                            cidr='10.168.2.0/24')
        self.routers_client.add_router_interface(
            self.router['id'], subnet_id=self.subnet_2['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        self.router['id'], subnet_id=self.subnet_2['id'])
        networks_topo = dict(security_group=self.security_group,
                             network=self.network,
                             subnet=self.subnet, router=self.router,
                             network2=self.network_2, subnet2=self.subnet_2)
        return networks_topo

    def _check_server_connectivity(self, floating_ip,
                                   remote_ip, private_key,
                                   should_connect=True):
            ssh_source = self.get_remote_client(floating_ip,
                                                private_key=private_key)
            msg = "ip address %s is reachable" % remote_ip
            try:
                self.assertTrue(self._check_remote_connectivity
                                (ssh_source, remote_ip, should_connect),
                                msg)
            except Exception:
                LOG.exception("Unable to access {dest} via ssh to "
                              "floating-ip {src}".format(dest=remote_ip,
                                                         src=floating_ip))
                raise

    def _create_vms_without_psg(self, network_topo):
        server_name_default = data_utils.rand_name('server-default-sec-group')
        network = network_topo['network']
        server_default = self._create_server(server_name_default, network)
        server_name_psg = data_utils.rand_name('server-psg-sec-group')
        server_psg = self._create_server(server_name_psg, network)
        servers = dict(server_default=server_default, server_psg=server_psg)
        return servers

    def _test_connectivity_between_vms_after_port_update(self, network_topo,
                                                         servers):
        floating_ip_default = self.create_floating_ip(
            servers['server_default'])
        floating_ip_psg = self.create_floating_ip(servers['server_psg'])
        private_ip_address_psg_vm = floating_ip_psg['fixed_ip_address']
        public_ip_address_psg_vm = \
            floating_ip_psg['floating_ip_address']
        private_ip_address_default_vm = floating_ip_default['fixed_ip_address']
        public_ip_address_default_vm = \
            floating_ip_default['floating_ip_address']
        private_key_default_vm = \
            self._get_server_key(servers['server_default'])
        private_key_psg_vm = \
            self._get_server_key(servers['server_psg'])
        self._check_server_connectivity(public_ip_address_default_vm,
                                        private_ip_address_psg_vm,
                                        private_key_default_vm)
        self._check_server_connectivity(public_ip_address_psg_vm,
                                        private_ip_address_default_vm,
                                        private_key_psg_vm)
        project_id = network_topo['network']['tenant_id']
        sg = self.create_security_provider_group(provider=True,
                                                 project_id=project_id)
        sg_id = sg.get('id')
        self.create_security_group_rule(sg_id, cmgr=self.cmgr_adm,
                                        protocol='icmp')
        p_client = self.ports_client
        kwargs = {"provider_security_groups": ["%s" % sg_id]}
        port_id_psg = self.get_port_id(network_topo['network']['id'],
                                       network_topo['subnet']['id'],
                                       servers['server_psg'])
        port_id_default = self.get_port_id(network_topo['network']['id'],
                                           network_topo['subnet']['id'],
                                           servers['server_default'])
        p_client.update_port(port_id_psg, **kwargs)
        p_client.update_port(port_id_default, **kwargs)
        self._check_server_connectivity(public_ip_address_default_vm,
                                        private_ip_address_psg_vm,
                                        private_key_default_vm,
                                        should_connect=False)
        self._check_server_connectivity(public_ip_address_psg_vm,
                                        private_ip_address_default_vm,
                                        private_key_psg_vm,
                                        should_connect=False)
        kwargs = {"provider_security_groups": ''}
        p_client.update_port(port_id_psg, **kwargs)
        p_client.update_port(port_id_default, **kwargs)

    def _test_connectivity_between_default_psg_server(self, network_topo):
        server_name_default = \
            data_utils.rand_name('server-default-sec-group')
        network = network_topo['network']
        server_default = self._create_server(server_name_default, network)
        project_id = network['tenant_id']
        sg = self.create_security_provider_group(provider=True,
                                                 project_id=project_id)
        sg_id = sg.get('id')
        server_name_psg = data_utils.rand_name('server-psg-sec-group')
        server_psg = self._create_server(server_name_psg, network)
        floating_ip_default = self.create_floating_ip(server_default)
        floating_ip_psg = self.create_floating_ip(server_psg)
        private_ip_address_psg_vm = floating_ip_psg['fixed_ip_address']
        ip_address_default_vm = floating_ip_default['floating_ip_address']
        private_key_default_vm = self._get_server_key(server_default)
        self._check_server_connectivity(ip_address_default_vm,
                                        private_ip_address_psg_vm,
                                        private_key_default_vm)
        self.create_security_group_rule(sg_id, cmgr=self.cmgr_adm,
                                        protocol='icmp')
        self._check_server_connectivity(ip_address_default_vm,
                                        private_ip_address_psg_vm,
                                        private_key_default_vm,
                                        should_connect=False)

    def _test_ping_when_psg_enabled_disbaled_on_port(self, network_topo):
        server_name_default = data_utils.rand_name('server-default-sec-group')
        network = network_topo['network']
        server_default = self._create_server(server_name_default, network)
        project_id = network['tenant_id']
        sg = self.create_security_provider_group(provider=True,
                                                 project_id=project_id)
        sg_id = sg.get('id')
        server_name_psg = data_utils.rand_name('server-psg-sec-group')
        server_psg = self._create_server(server_name_psg, network)
        floating_ip_default = self.create_floating_ip(server_default)
        floating_ip_psg = self.create_floating_ip(server_psg)
        private_ip_address_psg_vm = floating_ip_psg['fixed_ip_address']
        ip_address_default_vm = floating_ip_default['floating_ip_address']
        private_key_default_vm = self._get_server_key(server_default)
        self._check_server_connectivity(ip_address_default_vm,
                                        private_ip_address_psg_vm,
                                        private_key_default_vm)
        self.create_security_group_rule(sg_id, cmgr=self.cmgr_adm,
                                        protocol='icmp')
        self._check_server_connectivity(ip_address_default_vm,
                                        private_ip_address_psg_vm,
                                        private_key_default_vm,
                                        should_connect=False)
        p_client = self.ports_client
        kwargs = {"provider_security_groups": ''}
        port_id = self.get_port_id(network['id'],
                                   network_topo['subnet']['id'], server_psg)
        p_client.update_port(port_id, **kwargs)
        self._check_server_connectivity(ip_address_default_vm,
                                        private_ip_address_psg_vm,
                                        private_key_default_vm)

    def _test_build_up_topology_and_check_connectivity(self, network_topo):
        server_name_default_1 =\
            data_utils.rand_name('server-default-sec-group-1')
        server_name_default_2 =\
            data_utils.rand_name('server-default-sec-group-2')
        network = network_topo['network']
        if 'network2' in network_topo:
            network2 = network_topo['network2']
        else:
            network2 = network
        server_default_1 = self._create_server(server_name_default_1, network)
        server_default_2 = self._create_server(server_name_default_2,
                                               network2)
        project_id = network['tenant_id']
        sg = self.create_security_provider_group(provider=True,
                                                 project_id=project_id)
        sg_id = sg.get('id')
        server_name_psg_1 = data_utils.rand_name('server-psg-sec-group1')
        server_psg_1 = self._create_server(server_name_psg_1, network)
        server_name_psg_2 = data_utils.rand_name('server-psg-sec-group2')
        server_psg_2 = self._create_server(server_name_psg_2, network2)
        floating_ip_default_1 = self.create_floating_ip(server_default_1)
        floating_ip_psg_1 = self.create_floating_ip(server_psg_1)
        ip_address_default_vm_1 = floating_ip_default_1['floating_ip_address']
        private_ip_address_psg_vm_1 = floating_ip_psg_1['fixed_ip_address']
        private_key_default_vm_1 = self._get_server_key(server_default_1)
        floating_ip_default_2 = self.create_floating_ip(server_default_2)
        floating_ip_psg_2 = self.create_floating_ip(server_psg_2)
        private_ip_address_psg_vm_2 =\
            floating_ip_psg_2['fixed_ip_address']
        private_ip_address_default_vm_2 =\
            floating_ip_default_2['fixed_ip_address']
        self._check_server_connectivity(ip_address_default_vm_1,
                                        private_ip_address_psg_vm_1,
                                        private_key_default_vm_1)
        self._check_server_connectivity(ip_address_default_vm_1,
                                        private_ip_address_psg_vm_2,
                                        private_key_default_vm_1)
        self._check_server_connectivity(ip_address_default_vm_1,
                                        private_ip_address_default_vm_2,
                                        private_key_default_vm_1)
        self.create_security_group_rule(sg_id, cmgr=self.cmgr_adm,
                                        protocol='icmp')
        self._check_server_connectivity(ip_address_default_vm_1,
                                        private_ip_address_psg_vm_1,
                                        private_key_default_vm_1,
                                        should_connect=False)
        self._check_server_connectivity(ip_address_default_vm_1,
                                        private_ip_address_psg_vm_2,
                                        private_key_default_vm_1,
                                        should_connect=False)
        self._check_server_connectivity(ip_address_default_vm_1,
                                        private_ip_address_default_vm_2,
                                        private_key_default_vm_1)

    @test.attr(type='nsxv3')
    @test.idempotent_id('9d4192e9-b1b7-48c9-af04-67a82637c715')
    def test_connectivity_between_default_psg_server(self):
        self.network_topo = self.create_network_topo()
        self._test_connectivity_between_default_psg_server(self.network_topo)

    @test.attr(type='nsxv3')
    @test.idempotent_id('a14b5c25-39ce-4641-bd51-f28c25e69440')
    def test_vm_connectivity_port_update_with_psg(self):
        self.network_topo = self.create_network_topo()
        self.servers = self._create_vms_without_psg(self.network_topo)
        self._test_connectivity_between_vms_after_port_update(
            self.network_topo, self.servers)

    @test.attr(type='nsxv3')
    @test.idempotent_id('4a8eac6a-68ff-4392-bab9-70ea08132acb')
    def test_connectivity_between_default_psg_servers(self):
        self.network_topo = self.create_network_topo()
        self._test_build_up_topology_and_check_connectivity(self.network_topo)

    @test.attr(type='nsxv3')
    @test.idempotent_id('8bae2101-4f74-4d61-a7a5-42420611cf86')
    def test_connectivity_between_default_psg_server_with_multi_networks(self):
        self.network_topo = self.create_multi_network_topo()
        self._test_build_up_topology_and_check_connectivity(self.network_topo)

    @test.attr(type='nsxv3')
    @test.idempotent_id('998789ce-8db7-4295-bce0-390fbbf0e489')
    def test_ping_when_psg_enabled_disbaled_on_port(self):
        self.network_topo = self.create_multi_network_topo()
        self._test_ping_when_psg_enabled_disbaled_on_port(self.network_topo)
