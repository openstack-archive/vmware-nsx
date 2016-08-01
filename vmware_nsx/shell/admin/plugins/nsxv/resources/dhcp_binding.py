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


import logging
import pprint

from oslo_config import cfg

from vmware_nsx.shell.admin.plugins.common import constants
import vmware_nsx.shell.admin.plugins.common.utils as admin_utils
import vmware_nsx.shell.admin.plugins.nsxv.resources.utils as utils
import vmware_nsx.shell.resources as shell

from neutron.callbacks import registry
from neutron import context as n_context
from neutron.db import l3_db

from vmware_nsx._i18n import _LE, _LI, _LW
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

    nsx_dhcp_bindings = nsxv.query_dhcp_configuration(edge_id)
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

    for (edge_id, __) in nsxv_db.get_nsxv_dhcp_bindings_count_per_edge(
            neutron_db.context.session):
        LOG.info(_LI("%s"), "=" * 60)
        LOG.info(_LI("For edge: %s"), edge_id)
        nsx_dhcp_static_bindings = nsx_get_static_bindings_by_edge(edge_id)
        neutron_dhcp_static_bindings = \
            neutron_get_static_bindings_by_edge(edge_id)
        LOG.info(_LI("# of DHCP bindings in Neutron DB: %s"),
                 len(neutron_dhcp_static_bindings))
        LOG.info(_LI("# of DHCP bindings on NSXv backend: %s"),
                 len(nsx_dhcp_static_bindings))
        missing = neutron_dhcp_static_bindings - nsx_dhcp_static_bindings
        if not missing:
            LOG.info(_LI("No missing DHCP bindings found."))
            LOG.info(_LI("Neutron DB and NSXv backend are in sync"))
        else:
            LOG.info(_LI("Missing DHCP bindings:"))
            LOG.info(_LI("%s"), pprint.pformat(missing))


@admin_utils.output_header
def nsx_update_dhcp_edge_binding(resource, event, trigger, **kwargs):
    """Resync DHCP bindings on NSXv Edge"""
    if not kwargs.get('property'):
        LOG.error(_LE("Need to specify edge-id parameter"))
        return
    else:
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        edge_id = properties.get('edge-id')
        if not edge_id:
            LOG.error(_LE("Need to specify edge-id parameter"))
            return
        LOG.info(_LI("Updating NSXv Edge: %s"), edge_id)
        # Need to create a plugin object; so that we are able to
        # do neutron list-ports.
        plugin = utils.NsxVPluginWrapper()
        nsxv_manager = vcns_driver.VcnsDriver(
                           edge_utils.NsxVCallbacks(plugin))
        edge_manager = edge_utils.EdgeManager(nsxv_manager, plugin)
        try:
            edge_manager.update_dhcp_service_config(
                neutron_db.context, edge_id)
        except exceptions.ResourceNotFound:
            LOG.error(_LE("Edge %s not found"), edge_id)


def delete_old_dhcp_edge(context, old_edge_id, bindings):
    LOG.info(_LI("Deleting the old DHCP edge: %s"), old_edge_id)
    # using one of the router-ids in the bindings for the deleting
    dhcp_names = [binding['router_id'] for binding in bindings]
    dhcp_name = dhcp_names[0]
    with locking.LockManager.get_lock(old_edge_id):
        # Delete from NSXv backend
        # (using the first dhcp name as the "router name")
        # Note - If we will not delete the router, but free it - it will be
        # immediately used as the new one, So it is better to delete it.
        try:
            nsxv.delete_edge(old_edge_id)
        except Exception as e:
            LOG.warning(_LW("Failed to delete the old edge %(id)s: %(e)s"),
                        {'id': old_edge_id, 'e': e})
            # Continue the process anyway
            # The edge may have been already deleted at the backend

        try:
            # Remove bindings from Neutron DB
            nsxv_db.delete_nsxv_router_binding(context.session, dhcp_name)
            nsxv_db.clean_edge_vnic_binding(context.session, old_edge_id)
        except Exception as e:
            LOG.warning(_LW("Failed to delete the old edge %(id)s from the "
                            "DB : %(e)s"), {'id': old_edge_id, 'e': e})


def recreate_vdr_dhcp_edge(context, plugin, edge_manager,
                           old_edge_id, vdr_router_id):
    """Handle the edge recreation of a VDR router DHCP.
    """
    # delete the old bindings
    nsxv_db.delete_vdr_dhcp_binding(context.session, vdr_router_id)

    # Add each interface port of this router to a new edge:
    intf_ports = plugin._get_port_by_device_id(
        context, vdr_router_id, l3_db.DEVICE_OWNER_ROUTER_INTF)
    for port in intf_ports:
        fixed_ips = port.get("fixed_ips", [])
        if len(fixed_ips) > 0:
            fixed_ip = fixed_ips[0]
            subnet_id = fixed_ip['subnet_id']
            subnet = plugin.get_subnet(context, subnet_id)
        do_metadata = False
        for fixed_ip in fixed_ips:
            if fixed_ip['ip_address'] == subnet['gateway_ip']:
                do_metadata = True

        if do_metadata:
            edge_manager.configure_dhcp_for_vdr_network(
                context, subnet['network_id'], vdr_router_id)

    new_binding = nsxv_db.get_vdr_dhcp_binding_by_vdr(
        context.session, vdr_router_id)
    if new_binding:
        LOG.info(_LI("VDR router %(vdr_id)s was moved to edge %(edge_id)s"),
                 {'vdr_id': vdr_router_id,
                  'edge_id': new_binding['dhcp_edge_id']})
    else:
        LOG.error(_LE("VDR router %(vdr_id)s was not moved to a new edge"),
                 {'vdr_id': vdr_router_id})


def recreate_network_dhcp(context, plugin, edge_manager, old_edge_id, net_id):
    """Handle the DHCP edge recreation of a network
    """
    LOG.info(_LI("Moving network %s to a new edge"), net_id)
    # delete the old binding
    resource_id = (nsxv_constants.DHCP_EDGE_PREFIX + net_id)[:36]
    nsxv_db.delete_nsxv_router_binding(context.session, resource_id)

    # Delete the old static binding of the networks` compute ports
    port_filters = {'network_id': [net_id],
                    'device_owner': ['compute:None']}
    compute_ports = plugin.get_ports(context, filters=port_filters)
    for port in compute_ports:
        # Delete old binding from the DB
        nsxv_db.delete_edge_dhcp_static_binding(context.session,
            old_edge_id, port['mac_address'])

    # Go over all the subnets with DHCP
    net_filters = {'network_id': [net_id], 'enable_dhcp': [True]}
    subnets = plugin.get_subnets(context, filters=net_filters)
    for subnet in subnets:
        LOG.info(_LI("Moving subnet %s to a new edge"), subnet['id'])
        # allocate / reuse the new dhcp edge
        new_resource_id = edge_manager.create_dhcp_edge_service(
            context, net_id, subnet)
        if new_resource_id:
            # also add fw rules and metadata, once for the new edge
            plugin._update_dhcp_service_new_edge(context, resource_id)

    # Update the ip of the dhcp port
    LOG.info(_LI("Creating network %s DHCP address group"), net_id)
    address_groups = plugin._create_network_dhcp_address_group(
        context, net_id)
    plugin._update_dhcp_edge_service(context, net_id, address_groups)

    # find out the id of the new edge:
    new_binding = nsxv_db.get_nsxv_router_binding(
        context.session, resource_id)
    if new_binding:
        LOG.info(_LI("Network %(net_id)s was moved to edge %(edge_id)s"),
                 {'net_id': net_id, 'edge_id': new_binding['edge_id']})
    else:
        LOG.error(_LE("Network %(net_id)s was not moved to a new edge"),
                 {'net_id': net_id})


@admin_utils.output_header
def nsx_recreate_dhcp_edge(resource, event, trigger, **kwargs):
    """Recreate a dhcp edge with all the networks n a new NSXv edge"""
    if not kwargs.get('property'):
        LOG.error(_LE("Need to specify edge-id parameter"))
        return

    # input validation
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    old_edge_id = properties.get('edge-id')
    if not old_edge_id:
        LOG.error(_LE("Need to specify edge-id parameter"))
        return
    LOG.info(_LI("ReCreating NSXv Edge: %s"), old_edge_id)

    # init the plugin and edge manager
    cfg.CONF.set_override('core_plugin',
                          'vmware_nsx.shell.admin.plugins.nsxv.resources'
                          '.utils.NsxVPluginWrapper')
    plugin = utils.NsxVPluginWrapper()
    nsxv_manager = vcns_driver.VcnsDriver(edge_utils.NsxVCallbacks(plugin))
    edge_manager = edge_utils.EdgeManager(nsxv_manager, plugin)
    context = n_context.get_admin_context()

    # verify that this is a DHCP edge
    bindings = nsxv_db.get_nsxv_router_bindings_by_edge(
        context.session, old_edge_id)
    if (not bindings or
        not bindings[0]['router_id'].startswith(
            nsxv_constants.DHCP_EDGE_PREFIX)):
        LOG.error(_LE("Edge %(edge_id)s is not a DHCP edge"),
                 {'edge_id': old_edge_id})
        return

    # find the networks bound to this DHCP edge
    networks_binding = nsxv_db.get_edge_vnic_bindings_by_edge(
        context.session, old_edge_id)
    network_ids = [binding['network_id'] for binding in networks_binding]

    # Find out the vdr router, if this is a vdr DHCP edge
    vdr_binding = nsxv_db.get_vdr_dhcp_binding_by_edge(
        context.session, old_edge_id)
    vdr_router_id = vdr_binding['vdr_router_id'] if vdr_binding else None

    # Delete the old edge
    delete_old_dhcp_edge(context, old_edge_id, bindings)

    if vdr_router_id:
        # recreate the edge as a VDR DHCP edge
        recreate_vdr_dhcp_edge(context, plugin, edge_manager,
                               old_edge_id, vdr_router_id)
    else:
        # This is a regular DHCP edge:
        # Move all the networks to other (new or existing) edge
        for net_id in network_ids:
            recreate_network_dhcp(context, plugin, edge_manager,
                                  old_edge_id, net_id)


registry.subscribe(list_missing_dhcp_bindings,
                   constants.DHCP_BINDING,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_update_dhcp_edge_binding,
                   constants.DHCP_BINDING,
                   shell.Operations.NSX_UPDATE.value)
registry.subscribe(nsx_recreate_dhcp_edge,
                   constants.DHCP_BINDING,
                   shell.Operations.NSX_RECREATE.value)
