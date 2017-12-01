# Copyright 2017 VMware, Inc.
# All Rights Reserved
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

from neutron.db import l3_db
from neutron.services.flavors import flavors_plugin
from neutron_lib import exceptions as n_exc

from vmware_nsx._i18n import _
from vmware_nsx.services.lbaas import lb_const
from vmware_nsxlib.v3 import utils


def get_tags(plugin, resource_id, resource_type, project_id, project_name):
    resource = {'project_id': project_id,
                'id': resource_id}
    tags = plugin.nsxlib.build_v3_tags_payload(
        resource, resource_type=resource_type,
        project_name=project_name)
    return tags


def get_network_from_subnet(context, plugin, subnet_id):
    subnet = plugin.get_subnet(context, subnet_id)
    if subnet:
        return plugin.get_network(context, subnet['network_id'])


def get_router_from_network(context, plugin, subnet_id):
    subnet = plugin.get_subnet(context, subnet_id)
    network_id = subnet['network_id']
    port_filters = {'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                    'network_id': [network_id]}
    ports = plugin.get_ports(context, filters=port_filters)
    if ports:
        router = plugin.get_router(context, ports[0]['device_id'])
        if router.get('external_gateway_info'):
            return router['id']


def get_lb_router_id(context, plugin, lb):
    router_client = plugin.nsxlib.logical_router
    name = utils.get_name_and_uuid(lb.name or 'router', lb.id)
    tags = get_tags(plugin, lb.id, lb_const.LB_LB_TYPE, lb.tenant_id,
                    context.project_name)
    edge_cluster_uuid = plugin._get_edge_cluster(plugin._default_tier0_router)
    lb_router = router_client.create(name, tags, edge_cluster_uuid)
    return lb_router


def get_lb_flavor_size(flavor_plugin, context, flavor_id):
    if not flavor_id:
        return lb_const.DEFAULT_LB_SIZE
    else:
        flavor = flavors_plugin.FlavorsPlugin.get_flavor(
            flavor_plugin, context, flavor_id)
        flavor_size = flavor['name']
        if flavor_size in lb_const.LB_FLAVOR_SIZES:
            return flavor_size.upper()
        else:
            err_msg = (_("Invalid flavor size %(flavor)s, only 'small', "
                         "'medium', or 'large' are supported") %
                       {'flavor': flavor_size})
            raise n_exc.InvalidInput(error_message=err_msg)


def validate_lb_subnet(context, plugin, subnet_id):
    '''Validate LB subnet before creating loadbalancer on it.

    To create a loadbalancer, the network has to be either an external
    network or private network that connects to a tenant router. The
    tenant router needs to connect to gateway. It will throw
    exception if the network doesn't meet this requirement.

    :param context: context
    :param plugin: core plugin
    :param subnet_id: loadbalancer's subnet id
    :return: True if subnet meet requirement, otherwise return False
    '''
    network = get_network_from_subnet(context, plugin, subnet_id)
    valid_router = get_router_from_network(
        context, plugin, subnet_id)
    if network.get('router:external') or valid_router:
        return True
    else:
        return False
