# Copyright 2012 OpenStack Foundation
# Copyright 2015 VMware Inc
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
import re
import time

from oslo_log import log as logging
import testtools

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.scenario import manager
from tempest import test

from vmware_nsx_tempest.tests.nsxv.scenario import (
    network_addon_methods as HELO)

CONF = config.CONF
FIP_OPS_TIMEOUT = 10
LOG = logging.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class TestDvrBasicOps(manager.NetworkScenarioTest):

    """
    This smoke test suite assumes that Nova has been configured to
    boot VM's with Neutron-managed networking, and attempts to
    verify network connectivity as follows:

     There are presumed to be two types of networks: tenant and
     public.  A tenant network may or may not be reachable from the
     Tempest host.  A public network is assumed to be reachable from
     the Tempest host, and it should be possible to associate a public
     ('floating') IP address with a tenant ('fixed') IP address to
     facilitate external connectivity to a potentially unroutable
     tenant IP address.

     This test suite can be configured to test network connectivity to
     a VM via a tenant network, a public network, or both.  If both
     networking types are to be evaluated, tests that need to be
     executed remotely on the VM (via ssh) will only be run against
     one of the networks (to minimize test execution time).

     Determine which types of networks to test as follows:

     * Configure tenant network checks (via the
       'project_networks_reachable' key) if the Tempest host should
       have direct connectivity to tenant networks.  This is likely to
       be the case if Tempest is running on the same host as a
       single-node devstack installation with IP namespaces disabled.

     * Configure checks for a public network if a public network has
       been configured prior to the test suite being run and if the
       Tempest host should have connectivity to that public network.
       Checking connectivity for a public network requires that a
       value be provided for 'public_network_id'.  A value can
       optionally be provided for 'public_router_id' if tenants will
       use a shared router to access a public network (as is likely to
       be the case when IP namespaces are not enabled).  If a value is
       not provided for 'public_router_id', a router will be created
       for each tenant and use the network identified by
       'public_network_id' as its gateway.

    """

    @classmethod
    def skip_checks(cls):
        super(TestDvrBasicOps, cls).skip_checks()
        if not (CONF.network.project_networks_reachable or
                CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        for ext in ['router', 'security-group', 'dvr']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        # Ask framework to not create network resources for these tests.
        cls.set_network_resources()
        super(TestDvrBasicOps, cls).setup_credentials()

    def setUp(self):
        super(TestDvrBasicOps, self).setUp()
        self.keypairs = {}
        self.servers = []

    def _setup_network_and_servers(self, **kwargs):
        boot_with_port = kwargs.pop('boot_with_port', False)
        self.security_group = \
            self._create_security_group(tenant_id=self.tenant_id)
        self.network, self.subnet, self.router = self.create_networks(**kwargs)
        self.check_networks()

        self.port_id = None
        if boot_with_port:
            # create a port on the network and boot with that
            self.port_id = self._create_port(self.network['id'])['id']

        name = data_utils.rand_name('server-smoke')
        server = self._create_server(name, self.network, self.port_id)
        self._check_project_network_connectivity()

        floating_ip = self.create_floating_ip(server)
        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)

    # overwrite super class who does not accept router attributes
    def create_networks(self, dns_nameservers=None, **kwargs):
        namestart = 'dvr-ops'
        routers_client = self.routers_client
        networks_client = self.networks_client
        subnets_client = self.subnets_client
        network = self._create_network(
            networks_client=networks_client,
            routers_client=routers_client,
            namestart=namestart,
            tenant_id=self.tenant_id)

        router_kwargs = dict(client=routers_client, namestart=namestart)
        for k in kwargs.keys():
            if k in ('distributed', 'router_type', 'router_size'):
                router_kwargs[k] = kwargs.pop(k)
        router = self._create_router(**router_kwargs)
        HELO.router_gateway_set(self, router['id'],
                                CONF.network.public_network_id,
                                routers_client)

        subnet_kwargs = dict(network=network,
                             namestart=namestart,
                             subnets_client=subnets_client)
        # use explicit check because empty list is a valid option
        if dns_nameservers is not None:
            subnet_kwargs['dns_nameservers'] = dns_nameservers
        subnet = self._create_subnet(**subnet_kwargs)
        HELO.router_interface_add(self, router['id'], subnet['id'],
                                  routers_client)
        return network, subnet, router

    # overwrite super class
    def _create_router(self, client=None, tenant_id=None,
                       namestart='dvr-ops', **kwargs):
        return HELO.router_create(self, client,
                                  tenant_id=tenant_id,
                                  namestart=namestart,
                                  admin_state_up=True,
                                  **kwargs)

    def check_networks(self):
        HELO.check_networks(self, self.network, self.subnet, self.router)

    def _create_server(self, name, network, port_id=None):
        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        security_groups = [{'name': self.security_group['name']}]
        create_kwargs = {
            'networks': [
                {'uuid': network['id']},
            ],
            'key_name': keypair['name'],
            'security_groups': security_groups,
            'wait_until': 'ACTIVE',
        }
        if port_id is not None:
            create_kwargs['networks'][0]['port'] = port_id
        server = self.create_server(name=name, **create_kwargs)
        self.servers.append(server)
        return server

    def _get_server_key(self, server):
        return self.keypairs[server['key_name']]['private_key']

    def _check_project_network_connectivity(self):
        ssh_login = CONF.validation.image_ssh_user
        for server in self.servers:
            # call the common method in the parent class
            super(TestDvrBasicOps, self).\
                _check_tenant_network_connectivity(
                    server, ssh_login, self._get_server_key(server),
                    servers_for_debug=self.servers)

    def check_public_network_connectivity(
            self, should_connect=True, msg=None,
            should_check_floating_ip_status=True):
        """Verifies connectivty to a VM via public network and floating IP,
        and verifies floating IP has resource status is correct.

        :param should_connect: bool. determines if connectivity check is
        negative or positive.
        :param msg: Failure message to add to Error message. Should describe
        the place in the test scenario where the method was called,
        to indicate the context of the failure
        :param should_check_floating_ip_status: bool. should status of
        floating_ip be checked or not
        """
        ssh_login = CONF.validation.image_ssh_user
        floating_ip, server = self.floating_ip_tuple
        ip_address = floating_ip['floating_ip_address']
        private_key = None
        floatingip_status = 'DOWN'
        if should_connect:
            private_key = self._get_server_key(server)
            floatingip_status = 'ACTIVE'
        # Check FloatingIP Status before initiating a connection
        if should_check_floating_ip_status:
            self.check_floating_ip_status(floating_ip, floatingip_status)
        # call the common method in the parent class
        super(TestDvrBasicOps, self).check_public_network_connectivity(
            ip_address, ssh_login, private_key, should_connect, msg,
            self.servers)

    def _disassociate_floating_ips(self):
        floating_ip, server = self.floating_ip_tuple
        self._disassociate_floating_ip(floating_ip)
        self.floating_ip_tuple = Floating_IP_tuple(
            floating_ip, None)

    def _reassociate_floating_ips(self):
        floating_ip, server = self.floating_ip_tuple
        name = data_utils.rand_name('new_server-smoke')
        # create a new server for the floating ip
        server = self._create_server(name, self.network)
        self._associate_floating_ip(floating_ip, server)
        self.floating_ip_tuple = Floating_IP_tuple(
            floating_ip, server)

    def _create_new_network(self, create_gateway=False):
        self.new_net = self._create_network(tenant_id=self.tenant_id)
        if create_gateway:
            self.new_subnet = self._create_subnet(
                network=self.new_net)
        else:
            self.new_subnet = self._create_subnet(
                network=self.new_net,
                gateway_ip=None)

    def _get_server_nics(self, ssh_client):
        reg = re.compile(r'(?P<num>\d+): (?P<nic_name>\w+):')
        ipatxt = ssh_client.get_ip_list()
        return reg.findall(ipatxt)

    def _check_network_internal_connectivity(self, network,
                                             should_connect=True):
        """
        via ssh check VM internal connectivity:
        - ping internal gateway and DHCP port, implying in-tenant connectivity
        pinging both, because L3 and DHCP agents might be on different nodes
        """
        floating_ip, server = self.floating_ip_tuple
        # get internal ports' ips:
        # get all network ports in the new network
        internal_ips = (p['fixed_ips'][0]['ip_address'] for p in
                        self._list_ports(tenant_id=server['tenant_id'],
                                         network_id=network['id'])
                        if (p['device_owner'].startswith('network') and
                            not p['device_owner'].endswith('dhcp')))

        self._check_server_connectivity(floating_ip,
                                        internal_ips,
                                        should_connect)

    def _check_network_external_connectivity(self):
        """
        ping public network default gateway to imply external connectivity

        """
        if not CONF.network.public_network_id:
            msg = 'public network not defined.'
            LOG.debug(msg)
            return

        # We ping the external IP from the instance using its floating IP
        # which is always IPv4, so we must only test connectivity to
        # external IPv4 IPs if the external network is dualstack.
        v4_subnets = [s for s in self._list_subnets(
            network_id=CONF.network.public_network_id) if s['ip_version'] == 4]
        self.assertEqual(1, len(v4_subnets),
                         "Found %d IPv4 subnets" % len(v4_subnets))

        external_ips = [v4_subnets[0]['gateway_ip']]
        self._check_server_connectivity(self.floating_ip_tuple.floating_ip,
                                        external_ips)

    def _check_server_connectivity(self, floating_ip, address_list,
                                   should_connect=True):
        ip_address = floating_ip['floating_ip_address']
        private_key = self._get_server_key(self.floating_ip_tuple.server)
        # ssh_source = self._ssh_to_server(ip_address, private_key)
        ssh_source = self.get_remote_client(ip_address,
                                            private_key=private_key)

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
                LOG.debug("Unable to access {dest} via ssh to "
                          "floating-ip {src}".format(dest=remote_ip,
                                                     src=floating_ip))
                raise

    @test.idempotent_id('62eb50a8-45f3-4eec-acc4-f01cee10a011')
    @test.services('compute', 'network')
    def test_dvr_network_basic_ops(self):
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

         - ping an external IP address, implying external connectivity.

         - ping an external hostname, implying that dns is correctly
           configured.

         - ping an internal IP address, implying connectivity to another
           VM on the same network.

        - detach the floating-ip from the VM and verify that it becomes
        unreachable

        - associate detached floating ip to a new VM and verify connectivity.
        VMs are created with unique keypair so connectivity also asserts that
        floating IP is associated with the new VM instead of the old one

        Verifies that floating IP status is updated correctly after each change


        """
        self._setup_network_and_servers(distributed=True)
        LOG.debug("Sleeping %ss after associate floating ip %s" %
                  (FIP_OPS_TIMEOUT, self.floating_ip_tuple))
        self.check_public_network_connectivity(should_connect=True)
        self._check_network_internal_connectivity(network=self.network)
        self._check_network_external_connectivity()
        self._disassociate_floating_ips()
        LOG.debug("Sleeping %ss after disassociate floating ip %s" %
                  (FIP_OPS_TIMEOUT, self.floating_ip_tuple))
        self.check_public_network_connectivity(should_connect=False,
                                               msg="after disassociate "
                                                   "floating ip")
        self._reassociate_floating_ips()
        LOG.debug("Sleeping %ss after reassociate floating ip %s" %
                  (FIP_OPS_TIMEOUT, self.floating_ip_tuple))
        self.check_public_network_connectivity(should_connect=True,
                                               msg="after re-associate "
                                                   "floating ip")

    @test.idempotent_id('d99b62ec-28ce-44db-a195-edb74037a354')
    @testtools.skipIf(CONF.baremetal.driver_enabled,
                      'Baremetal relies on a shared physical network.')
    @test.services('compute', 'network')
    def test_dvr_connectivity_between_vms_on_different_networks(self):
        """
        For a freshly-booted VM with an IP address ("port") on a given
            network:

        - the Tempest host can ping the IP address.

        - the Tempest host can ssh into the VM via the IP address and
         successfully execute the following:

         - ping an external IP address, implying external connectivity.

         - ping an external hostname, implying that dns is correctly
           configured.

         - ping an internal IP address, implying connectivity to another
           VM on the same network.

        - Create another network on the same tenant with subnet, create
        an VM on the new network.

         - Ping the new VM from previous VM failed since the new network
         was not attached to router yet.

         - Attach the new network to the router, Ping the new VM from
         previous VM succeed.

        """
        self._setup_network_and_servers(distributed=True)
        LOG.debug("Sleeping %ss after associate floating ip %s" %
                  (FIP_OPS_TIMEOUT, self.floating_ip_tuple))
        time.sleep(FIP_OPS_TIMEOUT)
        self.check_public_network_connectivity(should_connect=True)
        self._check_network_internal_connectivity(network=self.network)
        self._check_network_external_connectivity()
        self._create_new_network(create_gateway=True)
        name = data_utils.rand_name('server-smoke')
        self._create_server(name, self.new_net)
        self._check_network_internal_connectivity(network=self.new_net,
                                                  should_connect=False)
        HELO.router_interface_add(self, self.router['id'],
                                  self.new_subnet['id'])
        self._check_network_internal_connectivity(network=self.new_net,
                                                  should_connect=True)

    @test.idempotent_id('a73fd605-d55e-4151-b25e-41e7a7ff2258')
    @testtools.skipIf(CONF.baremetal.driver_enabled,
                      'Router state cannot be altered on a shared baremetal '
                      'network')
    @test.services('compute', 'network')
    def test_dvr_update_router_admin_state(self):
        """
        1. Check public connectivity before updating
                admin_state_up attribute of router to False
        2. Check public connectivity after updating
                admin_state_up attribute of router to False
        3. Check public connectivity after updating
                admin_state_up attribute of router to True
        """
        self._setup_network_and_servers(distributed=True)
        LOG.debug("Sleeping %ss after associate floating ip %s" %
                  (FIP_OPS_TIMEOUT, self.floating_ip_tuple))
        time.sleep(FIP_OPS_TIMEOUT)
        self.check_public_network_connectivity(
            should_connect=True, msg="before updating "
            "admin_state_up of router to False")
        self._update_router_admin_state(self.router, False)
        # TODO(alokmaurya): Remove should_check_floating_ip_status=False check
        # once bug 1396310 is fixed

        self.check_public_network_connectivity(
            should_connect=False, msg="after updating "
            "admin_state_up of router to False",
            should_check_floating_ip_status=False)
        self._update_router_admin_state(self.router, True)
        self.check_public_network_connectivity(
            should_connect=True, msg="after updating "
            "admin_state_up of router to True")
