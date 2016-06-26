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

import netaddr

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions
from tempest import test

CONF = config.CONF


class BaseAdminNetworkTest(base.BaseAdminNetworkTest):
    # NOTE(akang): This class inherits from BaseAdminNetworkTest.
    # By default client is cls.client, but for provider network,
    # the client is admin_client. The test class should pass
    # client=self.admin_client, if it wants to create provider
    # network/subnet.

    @classmethod
    def skip_checks(cls):
        super(BaseAdminNetworkTest, cls).skip_checks()
        if not test.is_extension_enabled('provider', 'network'):
            msg = "Network Provider Extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(BaseAdminNetworkTest, cls).resource_setup()
        cls.admin_netwk_info = []

    @classmethod
    def resource_cleanup(cls):
        if CONF.service_available.neutron:
            for netwk_info in cls.admin_netwk_info:
                net_client, network = netwk_info
                try:
                    test_utils.call_and_ignore_notfound_exc(
                        net_client.delete_network, network['id'])
                except Exception:
                    pass
        super(BaseAdminNetworkTest, cls).resource_cleanup()

    @classmethod
    def create_network(cls, network_name=None, client=None,
                       **kwargs):
        net_client = client if client else cls.admin_networks_client
        network_name = network_name or data_utils.rand_name('ADM-network-')
        post_body = {'name': network_name}
        post_body.update(kwargs)
        body = net_client.create_network(**post_body)
        network = body['network']
        cls.admin_netwk_info.append([net_client, network])
        return body

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
    def create_subnet(cls, network, client=None,
                      gateway='', cidr=None, mask_bits=None,
                      ip_version=None, cidr_offset=0, **kwargs):
        ip_version = (ip_version if ip_version is not None
                      else cls._ip_version)
        net_client = client if client else cls.admin_subnets_client
        post_body = get_subnet_create_options(
            network['id'], ip_version,
            gateway=gateway, cidr=cidr, cidr_offset=cidr_offset,
            mask_bits=mask_bits, **kwargs)
        return net_client.create_subnet(**post_body)

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

    # add other create methods, i.e. security-group, port, floatingip
    # if needed.


def get_subnet_create_options(network_id, ip_version=4,
                              gateway='', cidr=None, mask_bits=None,
                              num_subnet=1, gateway_offset=1, cidr_offset=0,
                              **kwargs):

    """When cidr_offset>0 it request only one subnet-options:

        subnet = get_subnet_create_options('abcdefg', 4, num_subnet=4)[3]
        subnet = get_subnet_create_options('abcdefg', 4, cidr_offset=3)
    """

    gateway_not_set = (gateway == '')
    if ip_version == 4:
        cidr = cidr or netaddr.IPNetwork(CONF.network.project_network_cidr)
        mask_bits = mask_bits or CONF.network.project_network_mask_bits
    elif ip_version == 6:
        cidr = (
            cidr or netaddr.IPNetwork(CONF.network.project_network_v6_cidr))
        mask_bits = mask_bits or CONF.network.project_network_v6_mask_bits
    # Find a cidr that is not in use yet and create a subnet with it
    subnet_list = []
    if cidr_offset > 0:
        num_subnet = cidr_offset + 1
    for subnet_cidr in cidr.subnet(mask_bits):
        if gateway_not_set:
            gateway_ip = gateway or (
                str(netaddr.IPAddress(subnet_cidr) + gateway_offset))
        else:
            gateway_ip = gateway
        try:
            subnet_body = dict(
                network_id=network_id,
                cidr=str(subnet_cidr),
                ip_version=ip_version,
                gateway_ip=gateway_ip,
                **kwargs)
            if num_subnet <= 1:
                return subnet_body
            subnet_list.append(subnet_body)
            if len(subnet_list) >= num_subnet:
                if cidr_offset > 0:
                    # user request the 'cidr_offset'th of cidr
                    return subnet_list[cidr_offset]
                # user request list of cidr
                return subnet_list
        except exceptions.BadRequest as e:
            is_overlapping_cidr = 'overlaps with another subnet' in str(e)
            if not is_overlapping_cidr:
                raise
    else:
        message = 'Available CIDR for subnet creation could not be found'
        raise exceptions.BuildErrorException(message)
    return {}
