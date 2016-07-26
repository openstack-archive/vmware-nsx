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

from oslo_log import log as logging

from tempest import config
from tempest import exceptions
from tempest.lib.common.utils import data_utils
from tempest.scenario import manager
from tempest import test

CONF = config.CONF
LOG = logging.getLogger(__name__)


class TestDvsNetworkBasicOps(manager.NetworkScenarioTest):

    """
    This smoke test suite assumes that Nova has been configured to
    boot VM's with Neutron-managed VDS networking, and attempts to
    verify network connectivity as follows:

    """
    def setUp(self):
        super(TestDvsNetworkBasicOps, self).setUp()
        self._ip_version = 4
        self.keypairs = {}
        self.servers = []
        self.admin_net_client = self.admin_manager.networks_client
        self.admin_subnet_client = self.admin_manager.subnets_client

    def _setup_network(self):
        self.network = self._create_network()
        self.subnet = self._create_subnet(self.network)

    def _create_network(self, network_name=None):
        """Wrapper utility that returns a test admin provider network."""
        network_name = network_name or data_utils.rand_name('test-adm-net-')
        if test.is_extension_enabled('provider', 'network'):
            body = {'name': network_name}
            body.update({'provider:network_type': 'flat',
                         'provider:physical_network': 'dvs',
                         'shared': True})
            body = self.admin_net_client.create_network(**body)
        self.addCleanup(self.delete_wrapper,
                        self.admin_net_client.delete_network,
                        body['network']['id'])
        return body['network']

    def _create_subnet(self, network):
        # The cidr and mask_bits depend on the ip version.
        if self._ip_version == 4:
            cidr = netaddr.IPNetwork(CONF.network.tenant_network_cidr
                                     or "192.168.101.0/24")
            mask_bits = CONF.network.tenant_network_mask_bits or 24
        elif self._ip_version == 6:
            cidr = netaddr.IPNetwork(CONF.network.tenant_network_v6_cidr)
            mask_bits = CONF.network.tenant_network_v6_mask_bits
        # Find a cidr that is not in use yet and create a subnet with it
        for subnet_cidr in cidr.subnet(mask_bits):
            try:
                body = self.admin_subnet_client.create_subnet(
                                            network_id=network['id'],
                                            cidr=str(subnet_cidr),
                                            ip_version=self._ip_version)
                break
            except exceptions.BadRequest as e:
                is_overlapping_cidr = 'overlaps with another subnet' in str(e)
                if not is_overlapping_cidr:
                    raise
                else:
                    message = ('Available CIDR for subnet creation '
                               'could not be found')
                    raise exceptions.BuildErrorException(message)
        return body['subnet']

    def _check_networks(self):
        """
        Checks that we see the newly created network/subnet via
        checking the result of list_[networks,subnets]
        """

        seen_nets = self._list_networks()
        seen_names = [n['name'] for n in seen_nets]
        seen_ids = [n['id'] for n in seen_nets]
        self.assertIn(self.network['name'], seen_names)
        self.assertIn(self.network['id'], seen_ids)

        seen_subnets = self._list_subnets()
        seen_net_ids = [n['network_id'] for n in seen_subnets]
        seen_subnet_ids = [n['id'] for n in seen_subnets]
        self.assertIn(self.network['id'], seen_net_ids)
        self.assertIn(self.subnet['id'], seen_subnet_ids)

    def _create_server(self):
        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        networks = [{'uuid': self.network['id']}]

        name = data_utils.rand_name('server-smoke')
        server = self.create_server(name=name,
                                    networks=networks,
                                    key_name=keypair['name'],
                                    wait_until='ACTIVE')
        self.servers.append(server)
        return server

    def _get_server_key(self, server):
        return self.keypairs[server['key_name']]['private_key']

    def _check_tenant_network_connectivity(self):
        ssh_login = CONF.compute.image_ssh_user
        for server in self.servers:
            # call the common method in the parent class
            (super(TestDvsNetworkBasicOps, self).
                _check_tenant_network_connectivity(
                    server, ssh_login, self._get_server_key(server),
                    servers_for_debug=self.servers))

    def _check_server_connectivity(self, address_list,
                                   should_connect=True):
        private_key = self._get_server_key(self.servers[0])
        ip_address = address_list[0]
        ssh_source = self._ssh_to_server(ip_address, private_key)
        for remote_ip in address_list:
            if should_connect:
                msg = "Timed out waiting for "
                "%s to become reachable" % remote_ip
            else:
                msg = "ip address %s is reachable" % remote_ip
            try:
                self.assertTrue(self._check_remote_connectivity
                                (ssh_source, remote_ip, should_connect),
                                msg)
            except Exception:
                LOG.exception("Unable to access {dest} via ssh to "
                              "fix-ip {src}".format(dest=remote_ip,
                                                    src=ip_address))
                raise

    def _check_network_internal_connectivity(self, network,
                                             should_connect=True):
        """
        via ssh check VM internal connectivity:
        - ping internal gateway and DHCP port, implying in-tenant connectivity
        pinging both, because L3 and DHCP agents might be on different nodes
        """
        server = self.servers[0]
        self._create_server()
        # get internal ports' ips:
        # get all network ports in the new network
        internal_ips = ([p['fixed_ips'][0]['ip_address'] for p in
                        self._list_ports(tenant_id=server['tenant_id'],
                                         network_id=network['id'])
                        if p['device_owner'].startswith('compute')])

        self._check_server_connectivity(internal_ips,
                                        should_connect)

    @test.attr(type='smoke')
    @test.idempotent_id('b977dce6-6527-4676-9b66-862b22058f0f')
    @test.services('compute', 'network')
    def test_network_basic_ops(self):
        """
        For a freshly-booted VM with an IP address ("port") on a given
            network:

        - the Tempest host can ping the IP address.  This implies, but
         does not guarantee (see the ssh check that follows), that the
         VM has been assigned the correct IP address and has
         connectivity to the Tempest host.

        - the Tempest host can perform key-based authentication to an
         ssh server hosted at the IP address.  This check guarantees
         that the IP address is associated with the target VM.

        - the Tempest host can ssh into the VM via the IP address and
         successfully execute the following:

        - ping an internal IP address, implying connectivity to another
           VM on the same network.

        """
        self._setup_network()
        self._check_networks()
        self._create_server()
        self._check_network_internal_connectivity(self.network)
