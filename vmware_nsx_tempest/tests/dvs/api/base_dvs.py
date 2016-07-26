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

from tempest.api.network import base
from tempest import config
from tempest import exceptions
from tempest.lib.common.utils import data_utils
import tempest.test

CONF = config.CONF


class BaseDvsAdminNetworkTest(base.BaseAdminNetworkTest):

    @classmethod
    def resource_cleanup(cls):
        for port in cls.ports:
            cls.admin_ports_client.delete_port(port['id'])
        for subnet in cls.subnets:
            cls.admin_subnets_client.delete_subnet(subnet['id'])
        for network in cls.networks:
            cls.admin_networks_client.delete_network(network['id'])
        # clean up ports, subnets and networks
        cls.ports = []
        cls.subnets = []
        cls.networks = []

    @classmethod
    def create_network(cls, **kwargs):
        """Wrapper utility that returns a test admin provider network."""
        network_name = (kwargs.get('net_name')
                        or data_utils.rand_name('test-adm-net-'))
        net_type = kwargs.get('net_type', "flat")
        if tempest.test.is_extension_enabled('provider', 'network'):
            body = {'name': network_name}
            body.update({'provider:network_type': net_type,
                         'provider:physical_network': 'dvs'})
            if net_type == 'vlan':
                _vlanid = kwargs.get('seg_id')
                body.update({'provider:segmentation_id': _vlanid})

            body = cls.admin_networks_client.create_network(**body)
        network = body['network']
        cls.networks.append(network)
        return network

    @classmethod
    def create_subnet(cls, network):
        """Wrapper utility that returns a test subnet."""
        # The cidr and mask_bits depend on the ip version.
        if cls._ip_version == 4:
            cidr = netaddr.IPNetwork(CONF.network.tenant_network_cidr
                                     or "192.168.101.0/24")
            mask_bits = CONF.network.tenant_network_mask_bits or 24
        elif cls._ip_version == 6:
            cidr = netaddr.IPNetwork(CONF.network.tenant_network_v6_cidr)
            mask_bits = CONF.network.tenant_network_v6_mask_bits
        # Find a cidr that is not in use yet and create a subnet with it
        for subnet_cidr in cidr.subnet(mask_bits):
            try:
                body = cls.admin_subnets_client.create_subnet(
                    network_id=network['id'],
                    cidr=str(subnet_cidr),
                    ip_version=cls._ip_version)
                break
            except exceptions.BadRequest as e:
                is_overlapping_cidr = 'overlaps with another subnet' in str(e)
                if not is_overlapping_cidr:
                    raise
        else:
            message = 'Available CIDR for subnet creation could not be found'
            raise exceptions.BuildErrorException(message)
        subnet = body['subnet']
        cls.subnets.append(subnet)
        return subnet

    @classmethod
    def create_port(cls, network_id, **kwargs):
        """Wrapper utility that returns a test port."""
        body = cls.admin_ports_client.create_port(network_id=network_id,
                                                  **kwargs)
        port = body['port']
        cls.ports.append(port)
        return port

    @classmethod
    def update_network(cls, network_id, client=None, **kwargs):
        net_client = client if client else cls.admin_networks_client
        return net_client.update_network(network_id, **kwargs)

    @classmethod
    def delete_network(cls, network_id, client=None):
        net_client = client if client else cls.admin_networks_client
        return net_client.delete_network(network_id)

    @classmethod
    def show_network(cls, network_id, client=None, **kwargs):
        net_client = client if client else cls.admin_networks_client
        return net_client.show_network(network_id, **kwargs)

    @classmethod
    def list_networks(cls, client=None, **kwargs):
        net_client = client if client else cls.admin_networks_client
        return net_client.list_networks(**kwargs)

    @classmethod
    def update_subnet(cls, subnet_id, client=None, **kwargs):
        net_client = client if client else cls.admin_subnets_client
        return net_client.update_subnet(subnet_id, **kwargs)

    @classmethod
    def delete_subnet(cls, subnet_id, client=None):
        net_client = client if client else cls.admin_subnets_client
        return net_client.delete_subnet(subnet_id)

    @classmethod
    def show_subnet(cls, subnet_id, client=None, **kwargs):
        net_client = client if client else cls.admin_subnets_client
        return net_client.show_subnet(subnet_id, **kwargs)

    @classmethod
    def list_subnets(cls, client=None, **kwargs):
        net_client = client if client else cls.admin_subnets_client
        return net_client.list_subnets(**kwargs)

    @classmethod
    def delete_port(cls, port_id, client=None):
        net_client = client if client else cls.admin_ports_client
        return net_client.delete_port(port_id)

    @classmethod
    def show_port(cls, port_id, client=None, **kwargs):
        net_client = client if client else cls.admin_ports_client
        return net_client.show_port(port_id, **kwargs)

    @classmethod
    def list_ports(cls, client=None, **kwargs):
        net_client = client if client else cls.admin_ports_client
        return net_client.list_ports(**kwargs)

    @classmethod
    def update_port(cls, port_id, client=None, **kwargs):
        net_client = client if client else cls.admin_ports_client
        return net_client.update_port(port_id, **kwargs)
