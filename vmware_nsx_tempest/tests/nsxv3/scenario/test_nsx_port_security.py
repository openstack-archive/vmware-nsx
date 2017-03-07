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

from oslo_log import log as logging

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.services import nsxv3_client
from vmware_nsx_tempest.tests.scenario import manager

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestNSXv3PortSecurityScenario(manager.NetworkScenarioTest):

    """Test Port Security Scenario

    Test the following Port security scenarios
        - Create server with enable/disable port security and check at
          backend under NSGroup
        - Create servers on same network and check connectivity between
          then after enable/disable port security
        - Create server and update port with port security check xonnectivity
          and at backend under NSGroup
        - Create servers under different network connected via router and
          check connectivity after enable/disable port security
        - Check vm with port security disbaled can not ping which is having
          port security enabled
        - Check vm with port security enabled can ping any either dest vm
          has port security enabled or disabled.
    """

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(TestNSXv3PortSecurityScenario, cls).setup_credentials()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)

    def setUp(self):
        super(TestNSXv3PortSecurityScenario, self).setUp()
        self.cmgr_pri = self.get_client_manager('primary')
        self.cmgr_alt = self.get_client_manager('alt')
        self.cmgr_adm = self.get_client_manager('admin')
        self.keypairs = {}
        self.servers = []
        self.config_drive = CONF.compute_feature_enabled.config_drive

    def _delete_router(self, router):
        body = self.ports_client.list_ports(device_id=router['id'])
        interfaces = body['ports']
        for i in interfaces:
            test_utils.call_and_ignore_notfound_exc(
                self.routers_client.remove_router_interface, router['id'],
                subnet_id=i['fixed_ips'][0]['subnet_id'])
        self.routers_client.delete_router(router['id'])

    def create_security_group(self, sg_client, sg_name=None, desc=None,
                              tenant_id=None):
        name = sg_name or data_utils.rand_name('security-group')
        desc = desc or "OS security-group %s" % name
        sg_dict = dict(name=name, description=desc)
        if tenant_id:
            sg_dict['tenant_id'] = tenant_id
        sg = sg_client.create_security_group(**sg_dict)
        sg = sg.get('security_group', sg)
        return sg

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
            name=data_utils.rand_name('subnet-port-sec'),
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
        for port in self._list_ports():
            port_fixed_ip = port["fixed_ips"][0]["ip_address"]
            if port["network_id"] == network_id and port["fixed_ips"][0][
                    "subnet_id"] == subnet_id and instance["id"] == port[
                    "device_id"] and port_fixed_ip == instance_fixed_ip:
                port_id = port["id"]
        self.assertIsNotNone(port_id, "Failed to find Instance's port id!!!")
        return port_id

    def _create_server(self, name, network, port_id=None, image_id=None):
        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        security_groups = [{'name': self.security_group['name']}]
        network = {'uuid': network['id']}
        if port_id is not None:
            network['port'] = port_id
        server = self.create_server(name=name, networks=[network],
                                    key_name=keypair['name'],
                                    config_drive=self.config_drive,
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

    def setup_sec_group(self, tenant_id):
        self.security_group = \
            self.create_security_group(self.cmgr_adm.security_groups_client,
                                       tenant_id=tenant_id)
        rulesets = [
            dict(
                direction='ingress',
                protocol='tcp',
                port_range_min=22,
                port_range_max=22,
                remote_ip_prefix=CONF.network.public_network_cidr
            ),
            dict(
                direction='ingress',
                protocol='icmp',
                remote_ip_prefix=CONF.network.public_network_cidr
            ),
            dict(
                direction='ingress',
                protocol='icmp',
                remote_group_id=self.security_group['id']
            )
        ]
        for ruleset in rulesets:
            self._create_security_group_rule(secgroup=self.security_group,
                                             tenant_id=tenant_id, **ruleset)

    def create_network_topo(self):
        self.network = self._create_network()
        tenant_id = self.network['tenant_id']
        self.setup_sec_group(tenant_id)
        self.subnet = self._create_subnet(self.network,
                                          cidr='10.168.1.0/24')
        self.router = self._create_router(
            router_name=data_utils.rand_name('router-port-sec'),
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
        self.network = self._create_network(namestart="net-port-sec")
        tenant_id = self.network['tenant_id']
        self.setup_sec_group(tenant_id)
        self.subnet = self._create_subnet(self.network,
                                          cidr='10.168.1.0/24')
        self.router = self._create_router(
            router_name=data_utils.rand_name('router-port-sec'),
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

    def _test_create_server_with_port_security_and_check_backend(self,
                                                                 network_topo):
        status = []
        server_name_1 = data_utils.rand_name('server-default-sec-group')
        network = network_topo['network']
        body = {"network_id": network_topo['network']['id'],
                "admin_state_up": "true",
                "port_security_enabled": "false", "security_groups": []}
        port_client = self.ports_client
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        self._create_server(server_name_1,
                            network,
                            port_id['port']['id'])
        kwargs = {"port_security_enabled": "false", "security_groups": []}
        port_client.update_port(port_id['port']['id'], **kwargs)
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        nsgroup_id = self.nsx.get_neutron_ns_group_id()
        nsxgroup_data = self.nsx.get_ns_group_port_members(nsgroup_id)
        instance = "instance-port_%s" % port_id['port']['id'][0:4]
        for nsxgroup in nsxgroup_data['results']:
            if instance in nsxgroup['target_display_name']:
                break
        status.append('True')
        kwargs = {"port_security_enabled": "true"}
        port_client.update_port(port_id['port']['id'], **kwargs)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        nsgroup_id = self.nsx.get_neutron_ns_group_id()
        nsxgroup_data = self.nsx.get_ns_group_port_members(nsgroup_id)
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        for nsxgroup in nsxgroup_data['results']:
            if instance in nsxgroup['target_display_name']:
                status.append('True')
                return status
            else:
                continue
        status.append('False')
        return status

    def _test_create_servers_with_port_security_and_check_traffic(
            self, network_topo):
        server_name_1 = data_utils.rand_name('server-default-sec-group')
        network = network_topo['network']
        body = {"network_id": network_topo['network']['id'],
                "admin_state_up": "true",
                "port_security_enabled": "false", "security_groups": []}
        port_client = self.ports_client
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        server_default_1 = self._create_server(server_name_1,
                                               network)
        server_default_2 = self._create_server(server_name_1,
                                               network,
                                               port_id['port']['id'])
        floating_ip_server_1 = self.create_floating_ip(server_default_1)
        floating_ip_server_2 = self.create_floating_ip(server_default_2)
        private_ip_address_server_2 = floating_ip_server_2['fixed_ip_address']
        public_ip_address_server_1 = \
            floating_ip_server_1['floating_ip_address']
        private_key_server_1 = \
            self._get_server_key(server_default_1)
        self._check_server_connectivity(public_ip_address_server_1,
                                        private_ip_address_server_2,
                                        private_key_server_1)
        port_id_server_1 = self.get_port_id(network_topo['network']['id'],
                                            network_topo['subnet']['id'],
                                            server_default_1)
        port_id_server_2 = port_id['port']['id']
        sec_grp_port = port_client.show_port(port_id_server_1)
        sec_group = sec_grp_port['port']['security_groups'][0]
        body = {"port_security_enabled": "true",
                "security_groups": [sec_group]}
        port_client.update_port(port_id_server_2, **body)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        self._check_server_connectivity(public_ip_address_server_1,
                                        private_ip_address_server_2,
                                        private_key_server_1)
        body = {"port_security_enabled": "false", "security_groups": []}
        private_ip_address_server_1 = floating_ip_server_1['fixed_ip_address']
        public_ip_address_server_2 = \
            floating_ip_server_2['floating_ip_address']
        private_key_server_2 = \
            self._get_server_key(server_default_2)
        port_client.update_port(port_id_server_2, **body)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        self._check_server_connectivity(public_ip_address_server_2,
                                        private_ip_address_server_1,
                                        private_key_server_2,
                                        should_connect=False)
        body = {"port_security_enabled": "true",
                "security_groups": [sec_group]}
        port_client.update_port(port_id_server_2, **body)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        self._check_server_connectivity(public_ip_address_server_2,
                                        private_ip_address_server_1,
                                        private_key_server_2)

    def _test_server_at_beckend_with_port_security(self, network_topo):
        status = []
        server_name_1 = \
            data_utils.rand_name('server-port-sec-1')
        network = network_topo['network']
        server_1 = self._create_server(server_name_1, network)
        port_id = self.get_port_id(network['id'],
                                   network_topo['subnet']['id'], server_1)
        kwargs = {"port_security_enabled": "false", "security_groups": []}
        port_client = self.cmgr_adm.ports_client
        sec_grp_port = port_client.show_port(port_id)
        sec_group = sec_grp_port['port']['security_groups'][0]
        port_client.update_port(port_id, **kwargs)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        nsgroup_id = self.nsx.get_neutron_ns_group_id()
        nsxgroup_data = self.nsx.get_ns_group_port_members(nsgroup_id)
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        instance = "instance-port_%s" % port_id[0:4]
        for nsxgroup in nsxgroup_data['results']:
            if instance in nsxgroup['target_display_name']:
                break
        status.append('True')
        kwargs = {"port_security_enabled": "true",
                  "security_groups": [sec_group]}
        port_client.update_port(port_id, **kwargs)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        nsgroup_id = self.nsx.get_neutron_ns_group_id()
        nsxgroup_data = self.nsx.get_ns_group_port_members(nsgroup_id)
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        for nsxgroup in nsxgroup_data['results']:
            if instance in nsxgroup['target_display_name']:
                status.append('True')
                return status
            else:
                continue
        status.append('False')
        return status

    def _test_connectivity_bw_port_sec_enable_port_sec_disable_server(
            self, network_topo):
        server_name_1 = \
            data_utils.rand_name('server-port-sec-1')
        network = network_topo['network']
        server_1 = self._create_server(server_name_1, network)
        server_name_2 = data_utils.rand_name('server-port-sec-2')
        server_2 = self._create_server(server_name_2, network)
        floating_ip_server_1 = self.create_floating_ip(server_1)
        floating_ip_server_2 = self.create_floating_ip(server_2)
        private_ip_address_server_1 = floating_ip_server_1['fixed_ip_address']
        public_ip_address_server_2 = \
            floating_ip_server_2['floating_ip_address']
        private_key_server_2 = self._get_server_key(server_2)
        port_client = self.cmgr_adm.ports_client
        self._check_server_connectivity(public_ip_address_server_2,
                                        private_ip_address_server_1,
                                        private_key_server_2)
        port_id1 = self.get_port_id(network['id'],
                                    network_topo['subnet']['id'], server_2)
        kwargs = {"port_security_enabled": "false", "security_groups": []}
        port_client = self.cmgr_adm.ports_client
        sec_grp_port = port_client.show_port(port_id1)
        sec_group = sec_grp_port['port']['security_groups'][0]
        port_client.update_port(port_id1, **kwargs)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        self._check_server_connectivity(public_ip_address_server_2,
                                        private_ip_address_server_1,
                                        private_key_server_2,
                                        should_connect=False)
        kwargs = {"port_security_enabled": "true",
                  "security_groups": [sec_group]}
        port_client.update_port(port_id1, **kwargs)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        self._check_server_connectivity(public_ip_address_server_2,
                                        private_ip_address_server_1,
                                        private_key_server_2)

    def _test_connectivity_between_servers_with_router(self, network_topo):
        server_name_default_1 =\
            data_utils.rand_name('server-port-sec-1')
        server_name_default_2 =\
            data_utils.rand_name('server-port-sec-1')
        network = network_topo['network']
        if 'network2' in network_topo:
            network2 = network_topo['network2']
        else:
            network2 = network
        if 'subnet2' in network_topo:
            subnet2 = network_topo['subnet2']
        else:
            subnet2 = network_topo['subnet']
        server_1 = self._create_server(server_name_default_1, network)
        server_2 = self._create_server(server_name_default_2,
                                       network2)
        floating_ip_1 = self.create_floating_ip(server_1)
        floating_ip_2 = self.create_floating_ip(server_2)
        public_address_server_2 = floating_ip_2['floating_ip_address']
        private_address_server_1 = floating_ip_1['fixed_ip_address']
        private_key_server_2 = self._get_server_key(server_2)
        self._check_server_connectivity(public_address_server_2,
                                        private_address_server_1,
                                        private_key_server_2)
        port_client = self.cmgr_adm.ports_client
        kwargs = {"port_security_enabled": "false",
                  "security_groups": []}
        port_id = self.get_port_id(network2['id'],
                                   subnet2['id'], server_2)
        sec_grp_port = port_client.show_port(port_id)
        sec_group = sec_grp_port['port']['security_groups'][0]
        port_client.update_port(port_id, **kwargs)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        self._check_server_connectivity(public_address_server_2,
                                        private_address_server_1,
                                        private_key_server_2,
                                        should_connect=False)
        kwargs = {"port_security_enabled": "true",
                  "security_groups": [sec_group]}
        port_client.update_port(port_id, **kwargs)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        self._check_server_connectivity(public_address_server_2,
                                        private_address_server_1,
                                        private_key_server_2)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('f1c1d9b8-2fbd-4e7c-9ba7-a1d85d8d77d3')
    def test_create_server_with_port_security_and_check_backend(self):
        self.network_topo = self.create_network_topo()
        status = self._test_create_server_with_port_security_and_check_backend(
            self.network_topo)
        self.assertEqual('True', status[0])
        self.assertEqual('False', status[1])

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('6853b492-8acd-4e2b-b3a0-75112cef7066')
    def test_create_servers_with_port_security_and_check_traffic(self):
        self.network_topo = self.create_network_topo()
        self._test_create_servers_with_port_security_and_check_traffic(
            self.network_topo)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('f5be118c-d9cd-4401-b559-de9ee6d0fdad')
    def test_server_at_beckend_with_port_security(self):
        self.network_topo = self.create_network_topo()
        status = \
            self._test_server_at_beckend_with_port_security(self.network_topo)
        self.assertEqual('True', status[0])
        self.assertEqual('False', status[1])

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('a64da313-e5d7-4f57-98b6-9906c35332e7')
    def test_connectivity_bw_port_sec_enable_port_sec_disable_server(self):
        self.network_topo = self.create_network_topo()
        self._test_connectivity_bw_port_sec_enable_port_sec_disable_server(
            self.network_topo)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('520e7847-8103-41d0-90c8-6ba52306921d')
    def test_connectivity_between_servers_with_router_on_same_network(self):
        self.network_topo = self.create_multi_network_topo()
        self._test_connectivity_between_servers_with_router(self.network_topo)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('f621bbd9-c889-4c78-9ca1-7217e0df4e95')
    def test_connectivity_between_servers_with_router_on_diff_networks(self):
        self.network_topo = self.create_network_topo()
        self._test_connectivity_between_servers_with_router(self.network_topo)
