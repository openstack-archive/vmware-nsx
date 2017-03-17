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
import time

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.scenario import manager
from tempest import test

from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF

LOG = logging.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class TestAllowedAddressPair(manager.NetworkScenarioTest):
    """Test Allowed Address Pair Scenario

    Test the following Allowed Address Pair scenarios
        - Create 2 vms and update with allowed address pair ip, mac and check
          vm's pingable via allowed address pair ip's
        - Create 2 vms and update with allowed address pair muliple ips and
          check vm's pingable via allowed address pair multiple ip's
        - Create vm and normal port + fip assigned, now update compute vm port
          with allowed address pair ip which is of port created .Now check vm
          connectivity using fip assigned to port.
    """

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(TestAllowedAddressPair, cls).setup_credentials()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)

    def setUp(self):
        super(TestAllowedAddressPair, self).setUp()
        self.cmgr_pri = self.get_client_manager('primary')
        self.cmgr_alt = self.get_client_manager('alt')
        self.cmgr_adm = self.get_client_manager('admin')
        self.keypairs = {}
        self.servers = []

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
            name=data_utils.rand_name('subnet-default1'),
            network_id=network['id'], tenant_id=network['tenant_id'],
            cidr=cidr, ip_version=4, **kwargs)
        subnet = body.get('subnet', body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        client.delete_subnet, subnet['id'])
        return subnet

    def _list_ports(self, *args, **kwargs):
        """List ports using admin creds """
        ports_list = self.admin_manager.ports_client.list_ports(
            *args, **kwargs)
        return ports_list['ports']

    def get_port_id(self, network_id, subnet_id, instance):
        _, instance_addr = instance["addresses"].items()[0]
        instance_fixed_ip = instance_addr[0]["addr"]
        for port in self._list_ports(device_id=instance['id']):
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

    def _create_port(self, **body):
        port_client = self.ports_client
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        return port_id

    def _get_server_key(self, server):
        return self.keypairs[server['key_name']]['private_key']

    def _get_server_ip(self, server):
        addresses = server['addresses'][self.network['name']]
        for address in addresses:
            if address['version'] == CONF.validation.ip_version_for_ssh:
                return address['addr']

    def create_network_topo(self):
        self.security_group = self._create_security_group()
        self.network = self._create_network()
        self.subnet = self._create_subnet(self.network,
                                          cidr='13.168.1.0/24')
        self.router = self._create_router(
            router_name=data_utils.rand_name('router-default1'),
            external_network_id=CONF.network.public_network_id)
        self.routers_client.add_router_interface(
            self.router['id'], subnet_id=self.subnet['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        self.router['id'], subnet_id=self.subnet['id'])
        networks = dict(security_group=self.security_group,
                        network=self.network,
                        subnet=self.subnet, router=self.router)
        return networks

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

    def _assign_ip_address(self, ssh_source, interface_name, ip_address):
        ssh_source.exec_command("sudo ifconfig %s %s/24 up" % (interface_name,
                                                               ip_address))

    def _assign_mac_address(self, ssh_source, interface_name, mac_address):
        ssh_source.exec_command("sudo ifconfig %s down" % interface_name)
        ssh_source.exec_command("sudo ip link set %s address %s" % (
            interface_name, mac_address))
        ssh_source.exec_command("sudo ifconfig %s up" % interface_name)

    def _test_connectivity_between_allowed_adddress_pair_ports(self,
                                                               network_topo):
        server_name_default = data_utils.rand_name('server-default')
        network = network_topo['network']
        server_default = self._create_server(server_name_default, network)
        server_name_default1 = \
            data_utils.rand_name('server-default1-sec-group')
        server_default1 = self._create_server(server_name_default1, network)
        floating_ip_default = self.create_floating_ip(server_default)
        floating_ip_default1 = self.create_floating_ip(server_default1)
        ip_address_default_vm = floating_ip_default['floating_ip_address']
        ip_address_default1_vm = floating_ip_default1['floating_ip_address']
        private_key_default_vm = self._get_server_key(server_default)
        private_key_default1_vm = self._get_server_key(server_default1)
        port_client = self.ports_client
        # Allowed Address pair
        ip_address_vm1 = '87.0.0.3'
        ip_address_vm2 = '87.0.0.4'
        port_id = self.get_port_id(network['id'],
                                   network_topo['subnet']['id'],
                                   server_default)
        # Update allowed address pair attribute of port
        allowed_address_pairs = [{'ip_address': ip_address_vm1}]
        port_client.update_port(
            port_id, allowed_address_pairs=allowed_address_pairs)
        port1_id = self.get_port_id(network['id'],
                                    network_topo['subnet']['id'],
                                    server_default1)
        # Update allowed address pair attribute of port
        allowed_address_pairs = [{'ip_address': ip_address_vm2}]
        port_client.update_port(
            port1_id, allowed_address_pairs=allowed_address_pairs)
        ssh_source = self.get_remote_client(
            ip_address_default_vm,
            private_key=private_key_default_vm)
        ssh_source1 = self.get_remote_client(
            ip_address_default1_vm,
            private_key=private_key_default1_vm)
        # Assign Allowed pair ip to vm's
        self._assign_ip_address(ssh_source, 'eth0:1', ip_address_vm1)
        self._assign_ip_address(ssh_source1, 'eth0:1', ip_address_vm2)
        self.assertTrue(self._check_remote_connectivity
                        (ssh_source1, ip_address_vm1, 'True'),
                        'Destination is reachable')
        self.assertTrue(self._check_remote_connectivity
                        (ssh_source, ip_address_vm2, 'True'),
                        'Destination is reachable')

    def _test_allowed_adddress_pair_ports_attach_as_interface_on_vms(
            self, network_topo):
        server_name_default = data_utils.rand_name('server-default')
        network = network_topo['network']
        server_default = self._create_server(server_name_default, network)
        server_name_default1 = \
            data_utils.rand_name('server-default1-sec-group')
        server_default1 = self._create_server(server_name_default1, network)
        floating_ip_default = self.create_floating_ip(server_default)
        floating_ip_default1 = self.create_floating_ip(server_default1)
        ip_address_default_vm = floating_ip_default['floating_ip_address']
        ip_address_default1_vm = floating_ip_default1['floating_ip_address']
        private_key_default_vm = self._get_server_key(server_default)
        private_key_default1_vm = self._get_server_key(server_default1)
        port_client = self.ports_client
        # Allowed Address pair
        ip_address_vm1 = '77.0.0.3'
        ip_address_vm2 = '77.0.0.4'
        body = {"network_id": network['id'],
                "admin_state_up": 'true'}
        port_id = self._create_port(**body)
        # Update allowed address pair attribute of port
        allowed_address_pairs = [{'ip_address': ip_address_vm1}]
        body = port_client.update_port(
            port_id['port']['id'], allowed_address_pairs=allowed_address_pairs)
        # Update allowed address pair attribute of port
        body = {"network_id": network['id'],
                "admin_state_up": 'true'}
        port1_id = self._create_port(**body)
        allowed_address_pairs = [{'ip_address': ip_address_vm2}]
        body = port_client.update_port(
            port1_id['port']['id'],
            allowed_address_pairs=allowed_address_pairs)
        kwargs = {'port_id': port_id['port']['id']}
        # Attach interface to vm
        self.interface_client.create_interface(server_default['id'], **kwargs)
        time.sleep(10)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.interface_client.delete_interface,
                        server_default['id'], port_id['port']['id'])
        kwargs = {'port_id': port1_id['port']['id']}
        # Attach interface to vm
        self.interface_client.create_interface(server_default1['id'], **kwargs)
        time.sleep(10)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.interface_client.delete_interface,
                        server_default1['id'], port1_id['port']['id'])
        # Allowed Address pair
        ssh_source = self.get_remote_client(ip_address_default_vm,
                                            private_key=private_key_default_vm)
        ssh_source1 = self.get_remote_client(
            ip_address_default1_vm,
            private_key=private_key_default1_vm)
        # Assign Allowed pair ip to vm's
        self._assign_ip_address(ssh_source, 'eth1', ip_address_vm1)
        self._assign_ip_address(ssh_source1, 'eth1', ip_address_vm2)
        self.assertTrue(self._check_remote_connectivity
                        (ssh_source1, ip_address_vm1, 'True'),
                        'Destination is reachable')
        self.assertTrue(self._check_remote_connectivity
                        (ssh_source, ip_address_vm2, 'True'),
                        'Destination is reachable')

    def _test_allowed_adddress_with_ip_mac_attach_as_interface_on_vms(
            self, network_topo):
        server_name_default = data_utils.rand_name('server-default')
        network = network_topo['network']
        server_default = self._create_server(server_name_default, network)
        server_name_default1 = \
            data_utils.rand_name('server-default1-sec-group')
        server_default1 = self._create_server(server_name_default1, network)
        floating_ip_default = self.create_floating_ip(server_default)
        floating_ip_default1 = self.create_floating_ip(server_default1)
        ip_address_default_vm = floating_ip_default['floating_ip_address']
        ip_address_default1_vm = floating_ip_default1['floating_ip_address']
        private_key_default_vm = self._get_server_key(server_default)
        private_key_default1_vm = self._get_server_key(server_default1)
        port_client = self.ports_client
        # Allowed Address pair
        ip_address_vm1 = '77.0.0.3'
        vm1_mac_address = 'aa:11:0a:e4:f1:aa'
        ip_address_vm2 = '77.0.0.4'
        vm2_mac_address = 'aa:11:0a:e4:f1:bb'
        body = {"network_id": network['id'],
                "admin_state_up": 'true'}
        port_id = self._create_port(**body)
        # Update allowed address pair attribute of port
        allowed_address_pairs = [{'ip_address': ip_address_vm1,
                                  'mac_address': vm1_mac_address}]
        body = port_client.update_port(
            port_id['port']['id'], allowed_address_pairs=allowed_address_pairs)
        # Update allowed address pair attribute of port
        body = {"network_id": network['id'],
                "admin_state_up": 'true'}
        port1_id = self._create_port(**body)
        allowed_address_pairs = [{'ip_address': ip_address_vm2,
                                  'mac_address': vm2_mac_address}]
        body = port_client.update_port(
            port1_id['port']['id'],
            allowed_address_pairs=allowed_address_pairs)
        kwargs = {'port_id': port_id['port']['id']}
        # Attach interface to vm
        self.interface_client.create_interface(server_default['id'], **kwargs)
        time.sleep(10)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.interface_client.delete_interface,
                        server_default['id'], port_id['port']['id'])
        kwargs = {'port_id': port1_id['port']['id']}
        # Attach interface to vm
        self.interface_client.create_interface(server_default1['id'], **kwargs)
        time.sleep(10)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.interface_client.delete_interface,
                        server_default1['id'], port1_id['port']['id'])
        ssh_source = self.get_remote_client(ip_address_default_vm,
                                            private_key=private_key_default_vm)
        ssh_source1 = self.get_remote_client(
            ip_address_default1_vm,
            private_key=private_key_default1_vm)
        # Attach allowed pair ip's to vm's
        self._assign_ip_address(ssh_source, 'eth1', ip_address_vm1)
        self._assign_ip_address(ssh_source1, 'eth1', ip_address_vm2)
        self._assign_mac_address(ssh_source, 'eth1', vm1_mac_address)
        self._assign_mac_address(ssh_source1, 'eth1', vm2_mac_address)
        self.assertTrue(self._check_remote_connectivity
                        (ssh_source1, ip_address_vm1, 'True'),
                        'Destination is reachable')
        self.assertTrue(self._check_remote_connectivity
                        (ssh_source, ip_address_vm2, 'True'),
                        'Destination is reachable')

    def _test_allowed_address_pair_on_vms_with_multiple_ips(
            self, network_topo):
        server_name_default = data_utils.rand_name('server-default')
        network = network_topo['network']
        server_default = self._create_server(server_name_default, network)
        server_name_default1 = \
            data_utils.rand_name('server-default1-sec-group')
        server_default1 = self._create_server(server_name_default1, network)
        floating_ip_default = self.create_floating_ip(server_default)
        floating_ip_default1 = self.create_floating_ip(server_default1)
        ip_address_default_vm = floating_ip_default['floating_ip_address']
        ip_address_default1_vm = floating_ip_default1['floating_ip_address']
        private_key_default_vm = self._get_server_key(server_default)
        private_key_default1_vm = self._get_server_key(server_default1)
        port_client = self.ports_client
        # Allowed Address pair
        ip_address_vm1_1 = '77.0.0.3'
        ip_address_vm1_2 = '78.0.0.3'
        ip_address_vm2_1 = '77.0.0.4'
        ip_address_vm2_2 = '78.0.0.4'
        port_id = self.get_port_id(network['id'],
                                   network_topo['subnet']['id'],
                                   server_default)
        # Update allowed address pair attribute of port
        allowed_address_pairs = [{'ip_address': ip_address_vm1_1},
                                 {'ip_address': ip_address_vm1_2}]
        port_client.update_port(
            port_id, allowed_address_pairs=allowed_address_pairs)
        port1_id = self.get_port_id(network['id'],
                                    network_topo['subnet']['id'],
                                    server_default1)
        # Update allowed address pair attribute of port
        allowed_address_pairs = [{'ip_address': ip_address_vm2_1},
                                 {'ip_address': ip_address_vm2_2}]
        port_client.update_port(
            port1_id, allowed_address_pairs=allowed_address_pairs)
        ssh_source = self.get_remote_client(ip_address_default_vm,
                                            private_key=private_key_default_vm)
        ssh_source1 = self.get_remote_client(
            ip_address_default1_vm,
            private_key=private_key_default1_vm)
        # Attach allowed pair ip's to vm's
        self._assign_ip_address(ssh_source, 'eth0:1', ip_address_vm1_1)
        self._assign_ip_address(ssh_source, 'eth0:2', ip_address_vm1_2)
        self._assign_ip_address(ssh_source1, 'eth0:1', ip_address_vm2_1)
        self._assign_ip_address(ssh_source1, 'eth0:2', ip_address_vm2_2)
        self.assertTrue(self._check_remote_connectivity
                        (ssh_source, ip_address_vm2_1, 'True'),
                        'Destination is reachable')
        self.assertTrue(self._check_remote_connectivity
                        (ssh_source, ip_address_vm2_2, 'True'),
                        'Destination is reachable')
        self.assertTrue(self._check_remote_connectivity
                        (ssh_source1, ip_address_vm1_1, 'True'),
                        'Destination is reachable')
        self.assertTrue(self._check_remote_connectivity
                        (ssh_source1, ip_address_vm1_2, 'True'),
                        'Destination is reachable')

    def _test_vm_accessible_using_allowed_adddress_pair_port_fip(
            self, network_topo):
        server_name_default = data_utils.rand_name('server-default')
        network = network_topo['network']
        server_default = self._create_server(server_name_default, network)
        project_id = network['tenant_id']
        floating_ip_default = self.create_floating_ip(server_default)
        ip_address_default_vm = floating_ip_default['floating_ip_address']
        private_key_default_vm = self._get_server_key(server_default)
        port_client = self.ports_client
        body = {"network_id": network['id'],
                "admin_state_up": 'true'}
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        external_network_id = CONF.network.public_network_id
        client = self.floating_ips_client
        result = client.create_floatingip(
            floating_network_id=external_network_id,
            port_id=port_id['port']['id'],
            tenant_id=project_id
        )
        ip_address_vm1 = result['floatingip']['fixed_ip_address']
        # Allowed Address pair
        port_id = self.get_port_id(network['id'],
                                   network_topo['subnet']['id'],
                                   server_default)
        # Update allowed address pair attribute of port
        allowed_address_pairs = [{'ip_address': ip_address_vm1}]
        body = port_client.update_port(
            port_id, allowed_address_pairs=allowed_address_pairs)
        ssh_source = self.get_remote_client(ip_address_default_vm,
                                            private_key=private_key_default_vm)
        # Attach allowed pair ip's to vm's
        self._assign_ip_address(ssh_source, 'eth0:1', ip_address_vm1)
        self.compute_floating_ips_client.disassociate_floating_ip_from_server(
            ip_address_default_vm, server_default['id'])
        # Check connectivity to vm from external world using fip assigned to
        # port which is added as Allowed address pair to vm compute port
        ssh_source = self.get_remote_client(result['floatingip']
                                            ['floating_ip_address'],
                                            private_key=private_key_default_vm)
        cmd_out = ssh_source.exec_command("sudo ifconfig eth0:1")
        self.assertIn(ip_address_vm1, cmd_out)

    @test.attr(type='nsxv3')
    @decorators.idempotent_id('c0f0f446-65f5-40fa-8b05-b5798e8dd676')
    def test_allowed_adddress_pair_on_vms_with_single_ip(self):
        self.network_topo = self.create_network_topo()
        self._test_connectivity_between_allowed_adddress_pair_ports(
            self.network_topo)

    @test.attr(type='nsxv3')
    @decorators.idempotent_id('92bba9d2-c7d1-42f8-a8a2-63b1c842112d')
    def test_allowed_adddress_pair_ports_attach_as_interface_on_vms(self):
        self.network_topo = self.create_network_topo()
        self._test_allowed_adddress_pair_ports_attach_as_interface_on_vms(
            self.network_topo)

    @test.attr(type='nsxv3')
    @decorators.idempotent_id('ceb8a0db-8b5a-46de-a328-bf6093ea2102')
    def test_allowed_adddress_with_ip_mac_attach_as_interface_on_vms(self):
        self.network_topo = self.create_network_topo()
        self._test_allowed_adddress_with_ip_mac_attach_as_interface_on_vms(
            self.network_topo)

    @test.attr(type='nsxv3')
    @decorators.idempotent_id('735b9afb-2cb8-4e37-9603-2b918906a4df')
    def test_allowed_address_pair_on_vms_with_multiple_ips(self):
        self.network_topo = self.create_network_topo()
        self._test_allowed_address_pair_on_vms_with_multiple_ips(
            self.network_topo)

    @test.attr(type='nsxv3')
    @decorators.idempotent_id('4a0fb0e0-c801-4aed-94fe-6c57ff41c6f6')
    def test_vm_accessible_using_allowed_adddress_pair_port_fip(self):
        self.network_topo = self.create_network_topo()
        self._test_vm_accessible_using_allowed_adddress_pair_port_fip(
            self.network_topo)
