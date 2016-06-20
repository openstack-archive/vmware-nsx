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
from tempest.scenario import manager
from tempest import test

from vmware_nsx_tempest._i18n import _LE

CONF = config.CONF

LOG = logging.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class TestMultiHVNetworkOps(manager.NetworkScenarioTest):

    """Test suite for multi-hypervisor network operations

    Assume the NSX backend already configured both ESX and KVM hypervisors.
    Also, in tempest conf there should be two image configured, one for
    ESX hypervisor and the other one is for KVM hypervisor.

    These test cases test the following steps
      - Create a class level network topology which contains router, network
        and external network. Router sets gateway on external network and add
        interface of the network.
      - Create floating ip and loginable security group.
      - Boot two VMs on this network. One uses ESX image and the other one uses
        KVM image type.
      - Test external and internal connectivity of the VMs.

    """

    @classmethod
    def skip_checks(cls):
        super(TestMultiHVNetworkOps, cls).skip_checks()
        if not (CONF.network.project_networks_reachable
                or CONF.network.public_network_id):
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
        super(TestMultiHVNetworkOps, cls).setup_credentials()

    def setUp(self):
        super(TestMultiHVNetworkOps, self).setUp()
        self.keypairs = {}
        self.servers = []
        self.esx_image = CONF.compute.image_ref
        self.kvm_image = CONF.compute.image_ref_alt

    def _setup_l2_topo(self, **kwargs):
        self.security_group = self._create_security_group(
            tenant_id=self.tenant_id)
        self.network, self.subnet, self.router = self.create_networks(**kwargs)
        esx_server_name = data_utils.rand_name('server-esx')
        kvm_server_name = data_utils.rand_name('server-kvm')
        # Create a VM on ESX hypervisor
        esx_server = self._create_server(esx_server_name, self.network,
                                         image_id=self.esx_image)
        # Create a VM on KVM hypervisor
        self._create_server(kvm_server_name, self.network,
                            image_id=self.kvm_image)
        floating_ip = self.create_floating_ip(esx_server)
        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, esx_server)

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

    def _check_server_connectivity(self, floating_ip, address_list,
                                   should_connect=True):
        ip_address = floating_ip['floating_ip_address']
        private_key = self._get_server_key(self.floating_ip_tuple.server)
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

    @test.attr(type='nsxv3')
    @test.idempotent_id('42373fef-cb05-47c9-bb67-32b7a3b48168')
    def test_multi_hv_network_l2_ops(self):
        """Test connectivity between ESX VM and KVM VM on same network

        Boot VM on the same network with both ESX and KVM images and test
        L2 network connectivity if they are on the same L2 network.

        """
        self._setup_l2_topo()
        self._check_network_internal_connectivity(network=self.network)
        self._check_network_vm_connectivity(network=self.network)
