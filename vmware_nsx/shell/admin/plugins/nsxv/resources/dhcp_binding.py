# Copyright 2015 VMware, Inc.  All rights reserved.
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


import pprint
import sys

from neutron_lib import context as n_context
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.shell.admin.plugins.common import constants
import vmware_nsx.shell.admin.plugins.common.utils as admin_utils
import vmware_nsx.shell.admin.plugins.nsxv.resources.utils as utils
import vmware_nsx.shell.resources as shell

from neutron_lib.callbacks import registry
from neutron_lib import exceptions as nl_exc

from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import (
    constants as nsxv_constants)
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.plugins.nsx_v.vshield import vcns_driver


LOG = logging.getLogger(__name__)
nsxv = utils.get_nsxv_client()
neutron_db = utils.NeutronDbClient()


def nsx_get_static_bindings_by_edge(edge_id):
    nsx_dhcp_static_bindings = set()

    try:
        nsx_dhcp_bindings = nsxv.query_dhcp_configuration(edge_id)
    except exceptions.ResourceNotFound:
        LOG.error("Edge %s was not found", edge_id)
        return

    # nsx_dhcp_bindings[0] contains response headers;
    # nsx_dhcp_bindings[1] contains response payload
    sbindings = nsx_dhcp_bindings[1].get('staticBindings').get(
        'staticBindings')

    for binding in sbindings:
        nsx_dhcp_static_bindings.add(
            (edge_id, binding.get('macAddress').lower(),
             binding.get('bindingId').lower()))

    return nsx_dhcp_static_bindings


def neutron_get_static_bindings_by_edge(edge_id):
    neutron_db_dhcp_bindings = set()
    for binding in nsxv_db.get_dhcp_static_bindings_by_edge(
            neutron_db.context.session, edge_id):
        neutron_db_dhcp_bindings.add(
            (binding.edge_id, binding.mac_address.lower(),
             binding.binding_id.lower()))
    return neutron_db_dhcp_bindings


@admin_utils.output_header
def list_missing_dhcp_bindings(resource, event, trigger, **kwargs):
    """List missing DHCP bindings from NSXv backend.

    Missing DHCP bindings are those that exist in Neutron DB;
    but are not present on corresponding NSXv Edge.
    """
    for (edge_id, count) in nsxv_db.get_nsxv_dhcp_bindings_count_per_edge(
            neutron_db.context.session):
        LOG.info("%s", "=" * 60)
        LOG.info("For edge: %s", edge_id)
        nsx_dhcp_static_bindings = nsx_get_static_bindings_by_edge(edge_id)
        if nsx_dhcp_static_bindings is None:
            continue
        neutron_dhcp_static_bindings = \
            neutron_get_static_bindings_by_edge(edge_id)
        LOG.info("# of DHCP bindings in Neutron DB: %s",
                 len(neutron_dhcp_static_bindings))
        LOG.info("# of DHCP bindings on NSXv backend: %s",
                 len(nsx_dhcp_static_bindings))
        missing = neutron_dhcp_static_bindings - nsx_dhcp_static_bindings
        if not missing:
            LOG.info("No missing DHCP bindings found.")
            LOG.info("Neutron DB and NSXv backend are in sync")
        else:
            LOG.info("Missing DHCP bindings:")
            LOG.info("%s", pprint.pformat(missing))


@admin_utils.output_header
def nsx_update_dhcp_edge_binding(resource, event, trigger, **kwargs):
    """Resync DHCP bindings on NSXv Edge"""
    if not kwargs.get('property'):
        LOG.error("Need to specify edge-id parameter")
        return
    else:
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        edge_id = properties.get('edge-id')
        if not edge_id:
            LOG.error("Need to specify edge-id parameter")
            return
        LOG.info("Updating NSXv Edge: %s", edge_id)
        # Need to create a plugin object; so that we are able to
        # do neutron list-ports.
        with utils.NsxVPluginWrapper() as plugin:
            nsxv_manager = vcns_driver.VcnsDriver(
                               edge_utils.NsxVCallbacks(plugin))
            edge_manager = edge_utils.EdgeManager(nsxv_manager, plugin)
            try:
                edge_manager.update_dhcp_service_config(
                    neutron_db.context, edge_id)
            except exceptions.ResourceNotFound:
                LOG.error("Edge %s not found", edge_id)


def delete_old_dhcp_edge(context, old_edge_id, bindings):
    LOG.info("Deleting the old DHCP edge: %s", old_edge_id)
    with locking.LockManager.get_lock(old_edge_id):
        # Delete from NSXv backend
        # Note - If we will not delete the router, but free it - it will be
        # immediately used as the new one, So it is better to delete it.
        try:
            nsxv.delete_edge(old_edge_id)
        except Exception as e:
            LOG.warning("Failed to delete the old edge %(id)s: %(e)s",
                        {'id': old_edge_id, 'e': e})
            # Continue the process anyway
            # The edge may have been already deleted at the backend

        try:
            # Remove bindings from Neutron DB
            nsxv_db.clean_edge_router_binding(context.session, old_edge_id)
            nsxv_db.clean_edge_vnic_binding(context.session, old_edge_id)
        except Exception as e:
            LOG.warning("Failed to delete the old edge %(id)s from the "
                        "DB : %(e)s", {'id': old_edge_id, 'e': e})


def recreate_network_dhcp(context, plugin, edge_manager, old_edge_id, net_id):
    """Handle the DHCP edge recreation of a network
    """
    LOG.info("Moving network %s to a new edge", net_id)
    # delete the old binding
    resource_id = (nsxv_constants.DHCP_EDGE_PREFIX + net_id)[:36]
    nsxv_db.delete_nsxv_router_binding(context.session, resource_id)

    # Delete the old static binding of the networks` compute ports
    port_filters = {'network_id': [net_id],
                    'device_owner': ['compute:None']}
    compute_ports = plugin.get_ports(context, filters=port_filters)
    if old_edge_id:
        for port in compute_ports:
            # Delete old binding from the DB
            nsxv_db.delete_edge_dhcp_static_binding(context.session,
                old_edge_id, port['mac_address'])

    # Go over all the subnets with DHCP
    net_filters = {'network_id': [net_id], 'enable_dhcp': [True]}
    subnets = plugin.get_subnets(context, filters=net_filters)
    for subnet in subnets:
        LOG.info("Moving subnet %s to a new edge", subnet['id'])
        # allocate / reuse the new dhcp edge
        new_resource_id = edge_manager.create_dhcp_edge_service(
            context, net_id, subnet)
        if new_resource_id:
            # also add fw rules and metadata, once for the new edge
            plugin._update_dhcp_service_new_edge(context, resource_id)

    # Update the ip of the dhcp port
    LOG.info("Creating network %s DHCP address group", net_id)
    address_groups = plugin._create_network_dhcp_address_group(
        context, net_id)
    plugin.edge_manager.update_dhcp_edge_service(
        context, net_id, address_groups=address_groups)

    # find out the id of the new edge:
    new_binding = nsxv_db.get_nsxv_router_binding(
        context.session, resource_id)
    if new_binding:
        LOG.info("Network %(net_id)s was moved to edge %(edge_id)s",
                 {'net_id': net_id, 'edge_id': new_binding['edge_id']})
    else:
        LOG.error("Network %(net_id)s was not moved to a new edge",
                 {'net_id': net_id})


@admin_utils.output_header
def nsx_recreate_dhcp_edge(resource, event, trigger, **kwargs):
    """Recreate a dhcp edge with all the networks on a new NSXv edge"""
    usage_msg = ("Need to specify edge-id or net-id parameter")
    if not kwargs.get('property'):
        LOG.error(usage_msg)
        return

    # input validation
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    old_edge_id = properties.get('edge-id')
    if not old_edge_id:
        # if the net-id property exist - recreate the edge for this network
        net_id = properties.get('net-id')
        if net_id:
            nsx_recreate_dhcp_edge_by_net_id(net_id)
            return
        LOG.error(usage_msg)
        return
    LOG.info("ReCreating NSXv Edge: %s", old_edge_id)

    context = n_context.get_admin_context()

    # verify that this is a DHCP edge
    bindings = nsxv_db.get_nsxv_router_bindings_by_edge(
        context.session, old_edge_id)
    if (not bindings or
        not bindings[0]['router_id'].startswith(
            nsxv_constants.DHCP_EDGE_PREFIX)):
        LOG.error("Edge %(edge_id)s is not a DHCP edge",
                 {'edge_id': old_edge_id})
        return

    # init the plugin and edge manager
    cfg.CONF.set_override('core_plugin',
                          'vmware_nsx.shell.admin.plugins.nsxv.resources'
                          '.utils.NsxVPluginWrapper')
    with utils.NsxVPluginWrapper() as plugin:
        nsxv_manager = vcns_driver.VcnsDriver(
            edge_utils.NsxVCallbacks(plugin))
        edge_manager = edge_utils.EdgeManager(nsxv_manager, plugin)

        # find the networks bound to this DHCP edge
        networks_binding = nsxv_db.get_edge_vnic_bindings_by_edge(
            context.session, old_edge_id)
        network_ids = [binding['network_id'] for binding in networks_binding]

        # Delete the old edge
        delete_old_dhcp_edge(context, old_edge_id, bindings)

        # Move all the networks to other (new or existing) edge
        for net_id in network_ids:
            recreate_network_dhcp(context, plugin, edge_manager,
                                  old_edge_id, net_id)


def nsx_recreate_dhcp_edge_by_net_id(net_id):
    """Recreate a dhcp edge for a specific network without an edge"""
    LOG.info("ReCreating NSXv Edge for network: %s", net_id)

    context = n_context.get_admin_context()

    # init the plugin and edge manager
    cfg.CONF.set_override('core_plugin',
                          'vmware_nsx.shell.admin.plugins.nsxv.resources'
                          '.utils.NsxVPluginWrapper')
    with utils.NsxVPluginWrapper() as plugin:
        nsxv_manager = vcns_driver.VcnsDriver(edge_utils.NsxVCallbacks(plugin))
        edge_manager = edge_utils.EdgeManager(nsxv_manager, plugin)

        # verify that there is no DHCP edge for this network at the moment
        resource_id = (nsxv_constants.DHCP_EDGE_PREFIX + net_id)[:36]
        router_binding = nsxv_db.get_nsxv_router_binding(
            context.session, resource_id)
        if router_binding:
            # make sure there is no real edge
            if router_binding['edge_id']:
                edge_id = router_binding['edge_id']
                try:
                    nsxv_manager.vcns.get_edge(edge_id)
                except exceptions.ResourceNotFound:
                    # No edge on backend
                    # prevent logger from logging this exception
                    sys.exc_clear()
                    LOG.info("Edge %s does not exist on the NSX", edge_id)
                else:
                    LOG.warning("Network %(net_id)s already has a dhcp edge: "
                                "%(edge_id)s",
                                {'edge_id': edge_id,
                                 'net_id': net_id})
                    return
            # delete this old entry
            nsxv_db.delete_nsxv_router_binding(context.session, resource_id)

        # Verify that the network exists on neutron
        try:
            plugin.get_network(context, net_id)
        except nl_exc.NetworkNotFound:
            LOG.error("Network %s does not exist", net_id)
            return
        recreate_network_dhcp(context, plugin, edge_manager,
                              None, net_id)


@admin_utils.output_header
def nsx_redistribute_dhcp_edges(resource, event, trigger, **kwargs):
    """If any of the DHCP networks are on a conflicting edge move them"""
    context = n_context.get_admin_context()
    with utils.NsxVPluginWrapper() as plugin:
        nsxv_manager = vcns_driver.VcnsDriver(
                           edge_utils.NsxVCallbacks(plugin))
        edge_manager = edge_utils.EdgeManager(nsxv_manager, plugin)
        # go over all DHCP subnets
        networks = plugin.get_networks(context)
        for network in networks:
            network_id = network['id']
            # Check if the network has a related DHCP edge
            resource_id = (nsxv_constants.DHCP_EDGE_PREFIX + network_id)[:36]
            dhcp_edge_binding = nsxv_db.get_nsxv_router_binding(
                context.session, resource_id)
            if not dhcp_edge_binding:
                continue
            LOG.info("Checking network %s", network_id)
            edge_id = dhcp_edge_binding['edge_id']
            availability_zone = plugin.get_network_az_by_net_id(
                context, network['id'])
            filters = {'network_id': [network_id], 'enable_dhcp': [True]}
            subnets = plugin.get_subnets(context, filters=filters)
            for subnet in subnets:
                (conflict_edge_ids,
                 available_edge_ids) = edge_manager._get_used_edges(
                    context, subnet, availability_zone)
                if edge_id in conflict_edge_ids:
                    # move the DHCP to another edge
                    LOG.info("Network %(net)s on DHCP edge %(edge)s is "
                             "conflicting with another network and will be "
                             "moved",
                             {'net': network_id, 'edge': edge_id})
                    edge_manager.remove_network_from_dhcp_edge(
                        context, network_id, edge_id)
                    edge_manager.create_dhcp_edge_service(
                        context, network_id, subnet)
                    break


registry.subscribe(list_missing_dhcp_bindings,
                   constants.DHCP_BINDING,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_update_dhcp_edge_binding,
                   constants.DHCP_BINDING,
                   shell.Operations.NSX_UPDATE.value)
registry.subscribe(nsx_recreate_dhcp_edge,
                   constants.DHCP_BINDING,
                   shell.Operations.NSX_RECREATE.value)
registry.subscribe(nsx_redistribute_dhcp_edges,
                   constants.DHCP_BINDING,
                   shell.Operations.NSX_REDISTRIBURE.value)
