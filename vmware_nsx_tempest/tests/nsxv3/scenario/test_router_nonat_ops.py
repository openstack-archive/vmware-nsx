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

from vmware_nsx_tempest._i18n import _LE
from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF

LOG = logging.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class TestRouterNoNATOps(manager.NetworkScenarioTest):

    """Test l3 router NoNAT scenario

    Test the following two NoNAT scenarios
        - Create a NoNAT topology and check end to end traffic.
        - Create a NATed topology and check end to end traffic.
          Update the router to NoNAT and check end to end traffic.

    Note: For NoNAT use case, we need to add the static route on external
    VM in order for NSX connected network to be reachable from external.
        $ route add -net 192.168.1.0 netmask 255.255.255.0 gw 172.20.1.60 eth1
    """

    @classmethod
    def skip_checks(cls):
        super(TestRouterNoNATOps, cls).skip_checks()
        if not (CONF.network.project_networks_reachable or
                CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        for ext in ['router', 'security-group']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(TestRouterNoNATOps, cls).setup_credentials()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)

    def setUp(self):
        super(TestRouterNoNATOps, self).setUp()
        self.keypairs = {}
        self.servers = []

    def _setup_network_topo(self, enable_snat=None):
        self.security_group = self._create_security_group(
            tenant_id=self.tenant_id)
        self.network = self._create_network()
        self.subnet = self._create_subnet(self.network)
        self.router = self._create_router(
            router_name=data_utils.rand_name('router-smoke'),
            external_network_id=CONF.network.public_network_id,
            enable_snat=enable_snat)
        self.routers_client.add_router_interface(
            self.router['id'], subnet_id=self.subnet['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        self.router['id'], subnet_id=self.subnet['id'])
        server_name = data_utils.rand_name('server-smoke')
        self.server = self._create_server(server_name, self.network)
        floating_ip = self.create_floating_ip(self.server)
        self.floating_ip_tuple = Floating_IP_tuple(floating_ip,
                                                   self.server)

    def _cleanup_router(self, router):
        self._delete_router(router)

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
        router = body['router']
        self.addCleanup(self._cleanup_router, router)
        return router

    def _create_subnet(self, network, subnets_client=None, **kwargs):
        client = subnets_client or self.subnets_client
        body = client.create_subnet(
            name=data_utils.rand_name('subnet-smoke'),
            network_id=network['id'], tenant_id=network['tenant_id'],
            cidr='192.168.1.0/24', ip_version=4, **kwargs)
        subnet = body['subnet']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        client.delete_subnet, subnet['id'])
        return subnet

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

    def _check_network_internal_connectivity(self, network,
                                             should_connect=True):
        floating_ip, server = self.floating_ip_tuple
        # test internal connectivity to the network ports on the network
        network_ips = (p['fixed_ips'][0]['ip_address'] for p in
                       self._list_ports(tenant_id=server['tenant_id'],
                                        network_id=network['id'])
                       if p['device_owner'].startswith('network'))
        self._check_server_connectivity(floating_ip,
                                        network_ips,
                                        should_connect)

    def _check_network_vm_connectivity(self, network,
                                       should_connect=True):
        floating_ip, server = self.floating_ip_tuple
        # test internal connectivity to the other VM on the same network
        compute_ips = (p['fixed_ips'][0]['ip_address'] for p in
                       self._list_ports(tenant_id=server['tenant_id'],
                                        network_id=network['id'])
                       if p['device_owner'].startswith('compute'))
        self._check_server_connectivity(floating_ip,
                                        compute_ips,
                                        should_connect)

    def _check_nonat_network_connectivity(self):
        server_ip = self._get_server_ip(self.server)
        # test internal connectivity to the network ports on the network
        network_ips = (p['fixed_ips'][0]['ip_address'] for p in
                       self._list_ports(tenant_id=self.server['tenant_id'],
                                        network_id=self.network['id'])
                       if p['device_owner'].startswith('network'))
        self._check_server_connectivity(server_ip,
                                        network_ips,
                                        should_connect=True,
                                        enable_snat=False)

    def _check_server_connectivity(self, floating_ip, address_list,
                                   should_connect=True, enable_snat=True):
        ip_address = floating_ip['floating_ip_address'] if enable_snat \
            else floating_ip
        private_key = self._get_server_key(self.server)
        ssh_source = self.get_remote_client(ip_address,
                                            private_key=private_key)
        for remote_ip in address_list:
            if should_connect:
                msg = ("Timed out waiting for %s to become "
                       "reachable") % remote_ip
            else:
                msg = "ip address %s is reachable" % remote_ip
            try:
                self.assertTrue(self._check_remote_connectivity
                                (ssh_source, remote_ip, should_connect),
                                msg)
            except Exception:
                LOG.exception(_LE("Unable to access %{dest}s via ssh to "
                                  "floating-ip %{src}s"),
                              {'dest': remote_ip, 'src': floating_ip})
                raise

    def _test_router_nat_update(self, snat=True):
        """Test update router from NATed to NoNAT scenario"""
        self._setup_network_topo(enable_snat=snat)
        nsx_router = self.nsx.get_logical_router(
            self.router['name'], self.router['id'])
        self.assertNotEqual(nsx_router, None)
        self.assertEqual(nsx_router['router_type'], 'TIER1')
        # Check nat rules created correctly
        nat_rules = self.nsx.get_logical_router_nat_rules(nsx_router)
        self.assertTrue((len(nat_rules) == 3) == snat)
        # Check router advertisement is correctly set
        router_adv = self.nsx.get_logical_router_advertisement(nsx_router)
        adv_msg = "Tier1 router's advertise_nsx_connected_routes is not %s"
        nat_msg = "Tier1 router's advertise_nat_routes is not %s"
        self.assertTrue(router_adv['advertise_nat_routes'], adv_msg % True)
        self.assertFalse(router_adv['advertise_nsx_connected_routes'],
                         adv_msg % (not snat))
        self._check_network_internal_connectivity(network=self.network)
        self._check_network_vm_connectivity(network=self.network)

        # Update router to disable snat
        self.routers_client.update_router(
            self.router['id'],
            external_gateway_info={
                'network_id': CONF.network.public_network_id,
                'enable_snat': (not snat)})
        nsx_router = self.nsx.get_logical_router(
            self.router['name'], self.router['id'])
        self.assertNotEqual(nsx_router, None)
        self.assertEqual(nsx_router['router_type'], 'TIER1')
        # Check nat rules created correctly
        nat_rules = self.nsx.get_logical_router_nat_rules(nsx_router)
        self.assertTrue((len(nat_rules) == 2) == snat)
        # Check router advertisement is correctly set
        router_adv = self.nsx.get_logical_router_advertisement(nsx_router)
        self.assertTrue(router_adv['advertise_nat_routes'],
                        nat_msg % True)
        self.assertTrue(router_adv['advertise_nsx_connected_routes'],
                        adv_msg % snat)
        self._check_nonat_network_connectivity()

    @test.attr(type='nsxv3')
    @test.idempotent_id('5e5bfdd4-0962-47d3-a89b-7ce64322b53e')
    def test_router_nat_to_nonat_ops(self):
        """Test update router from NATed to NoNAT scenario"""
        self._test_router_nat_update(snat=True)

    @test.attr(type='nsxv3')
    @test.idempotent_id('a0274738-d3e7-49db-bf10-a5563610940d')
    def test_router_nonat_to_nat_ops(self):
        """Test update router from NoNAT to NATed scenario"""
        self._test_router_nat_update(snat=False)
