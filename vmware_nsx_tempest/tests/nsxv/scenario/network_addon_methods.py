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
#
# This module contains the methods added to test class that to be shared by
# scenario tests that are inherent from tempest/scneario/manager.py or
# manager_topo_deployment.py

import netaddr
from oslo_log import log

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions

CONF = config.CONF
LOG = log.getLogger(__name__)
NO_ROUTER_TYPE = CONF.nsxv.no_router_type


# following router methods are not support by upstream tempest,
def router_create(SELF, client=None, tenant_id=None,
                  namestart='nsxv-router',
                  admin_state_up=True, **kwargs):
    routers_client = client or SELF.routers_client
    no_router_type = kwargs.pop('no_router_type', False)
    if tenant_id:
        if routers_client.tenant_id != tenant_id:
            kwargs['tenant_id'] = tenant_id
    distributed = kwargs.pop('distributed', None)
    router_type = kwargs.pop('router_type', None)
    if distributed:
        kwargs['distributed'] = True
    elif router_type in ('shared', 'exclusive'):
        kwargs['router_type'] = router_type
    name = kwargs.pop('name', None) or data_utils.rand_name(namestart)
    kwargs['name'] = name
    kwargs['admin_state_up'] = admin_state_up
    if NO_ROUTER_TYPE or no_router_type:
        # router_type is NSX-v extension.
        # caller can set no_router_type=True to remove it
        kwargs.pop('router_type', None)
    result = routers_client.create_router(**kwargs)
    router = result['router']
    SELF.addCleanup(test_utils.call_and_ignore_notfound_exc,
                    routers_client.delete_router, router['id'])
    SELF.assertEqual(router['name'], name)
    return router


def router_delete(SELF, router_id):
    routers_client = SELF.routers_client
    routers_client.delete_router(router_id)


def router_gateway_set(SELF, router_id, network_id, client=None):
    routers_client = client or SELF.routers_client
    routers_client.update_router(
        router_id,
        external_gateway_info=dict(network_id=network_id))
    SELF.addCleanup(test_utils.call_and_ignore_notfound_exc,
                    router_gateway_clear, SELF,
                    router_id, client=routers_client)
    router = routers_client.show_router(router_id)
    return router.get('router', router)


def router_gateway_clear(SELF, router_id, client=None):
    routers_client = client or SELF.routers_client
    routers_client.update_router(
        router_id,
        external_gateway_info=dict())
    router = routers_client.show_router(router_id)
    return router.get('router', router)


def router_update_extra_routes(SELF, router_id, routes, client=None):
    routers_client = client or SELF.routers_client
    router = routers_client.update_route(router_id, routes=routes)
    return router.get('router', router)


def router_delete_extra_routes(SELF, router_id, client=None):
    routers_client = client or SELF.routers_client
    router = routers_client.update_route(router_id, routes=None)
    return router.get('router', router)


def router_interface_add(SELF, router_id, subnet_id, client=None):
    routers_client = client or SELF.routers_client
    routers_client.add_router_interface(router_id,
                                        subnet_id=subnet_id)
    SELF.addCleanup(test_utils.call_and_ignore_notfound_exc,
                    routers_client.remove_router_interface,
                    router_id, subnet_id=subnet_id)


def router_interface_delete(SELF, router_id, subnet_id, client=None):
    routers_client = client or SELF.routers_client
    routers_client.remove_router_interface(router_id, subnet_id=subnet_id)


def router_add_interface(SELF, net_router, net_subnet, client_mgr):
    routers_client = client_mgr.routers_client
    return router_interface_add(SELF, net_router['id'], net_subnet['id'],
                                routers_client)


def router_port_interface_add(SELF, router_id, port_id, client=None):
    routers_client = client or SELF.routers_client
    routers_client.add_router_interface(router_id,
                                        port_id=port_id)
    SELF.addCleanup(test_utils.call_and_ignore_notfound_exc,
                    routers_client.remove_router_interface,
                    router_id, port_id=port_id)


def router_add_port_interface(SELF, net_router, net_port, client_mgr):
    routers_client = client_mgr.routers_client
    return router_port_interface_add(SELF, net_router['id'], net_port['id'],
                                     routers_client)


def check_networks(SELF, t_network, t_subnet=None, t_router=None):
    """Checks that we see the newly created network/subnet/router.

    checking the result of list_[networks,routers,subnets]
    """

    seen_nets = SELF._list_networks()
    seen_names = [n['name'] for n in seen_nets]
    seen_ids = [n['id'] for n in seen_nets]
    SELF.assertIn(t_network['name'], seen_names)
    SELF.assertIn(t_network['id'], seen_ids)

    if t_subnet:
        seen_subnets = SELF._list_subnets()
        seen_net_ids = [n['network_id'] for n in seen_subnets]
        seen_subnet_ids = [n['id'] for n in seen_subnets]
        SELF.assertIn(t_network['id'], seen_net_ids)
        SELF.assertIn(t_subnet['id'], seen_subnet_ids)

    if t_router:
        seen_routers = SELF._list_routers()
        seen_router_ids = [n['id'] for n in seen_routers]
        seen_router_names = [n['name'] for n in seen_routers]
        SELF.assertIn(t_router['name'],
                      seen_router_names)
        SELF.assertIn(t_router['id'],
                      seen_router_ids)


def create_network_subnet(SELF, client_mgr=None, name=None,
                          tenant_id=None, cidr_offset=0):
    client_mgr = client_mgr or SELF.manager
    networks_client = client_mgr.networks_client
    subnets_client = client_mgr.subnets_client
    tenant_id = tenant_id or networks_client.tenant_id
    name = name or data_utils.rand_name('network')
    net_network = create_network(SELF, client=networks_client,
                                 tenant_id=tenant_id, name=name)
    net_subnet = create_subnet(SELF, client=subnets_client,
                               network=net_network,
                               name=net_network['name'],
                               cidr_offset=cidr_offset)
    return net_network, net_subnet


# cloned from _create_network@manager.py. Allow name parameter
def create_network(SELF, client=None, tenant_id=None, name=None, **kwargs):
    networks_client = client or SELF.networks_client
    tenant_id = tenant_id or networks_client.tenant_id
    name = name or data_utils.rand_name('network')
    body = networks_client.create_network(name=name,
                                          tenant_id=tenant_id,
                                          **kwargs)
    net_network = body['network']
    SELF.addCleanup(test_utils.call_and_ignore_notfound_exc,
                    networks_client.delete_network,
                    net_network['id'])
    SELF.assertEqual(net_network['name'], name)
    return net_network


def create_port(SELF, client=None, **kwargs):
        if not client:
            client = SELF.port_client
        result = client.create_port(**kwargs)
        net_port = result['port']
        SELF.assertIsNotNone(result, 'Unable to allocate port')
        SELF.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        client.delete_port,
                        net_port['id'])

        return net_port


# gateway=None means don't set gateway_ip in subnet
def create_subnet(SELF, network, client=None,
                  gateway='', cidr=None, mask_bits=None,
                  ip_version=None, cidr_offset=0,
                  allocation_pools=None, dns_nameservers=None,
                  **kwargs):
    subnets_client = client or SELF.subnets_client
    network_id = network['id']
    ip_version = ip_version or 4
    post_body = get_subnet_create_options(
        network_id, ip_version,
        gateway=gateway, cidr=cidr, cidr_offset=cidr_offset,
        mask_bits=mask_bits, **kwargs)
    if allocation_pools:
        post_body['allocation_pools'] = allocation_pools
    if dns_nameservers:
        post_body['dns_nameservers'] = dns_nameservers
    LOG.debug("create_subnet args: %s", post_body)
    body = subnets_client.create_subnet(**post_body)
    net_subnet = body['subnet']
    SELF.addCleanup(test_utils.call_and_ignore_notfound_exc,
                    subnets_client.delete_subnet,
                    net_subnet['id'])
    return net_subnet


# utilities
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
            subnet_body = dict(network_id=network_id,
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
