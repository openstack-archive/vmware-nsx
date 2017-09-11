# Copyright 2016 VMware, Inc.  All rights reserved.
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


from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
import vmware_nsx.shell.admin.plugins.common.utils as admin_utils
import vmware_nsx.shell.admin.plugins.nsxv.resources.utils as utils
import vmware_nsx.shell.resources as shell

from neutron_lib.callbacks import registry
from neutron_lib import context as n_context
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.extensions import routersize
from vmware_nsx.plugins.nsx_v import availability_zones as nsx_az
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.plugins.nsx_v.vshield import vcns_driver

LOG = logging.getLogger(__name__)


def delete_old_edge(context, old_edge_id):
    LOG.info("Deleting the old edge: %s", old_edge_id)

    # clean it up from the DB
    nsxv_db.clean_edge_router_binding(context.session, old_edge_id)
    nsxv_db.clean_edge_vnic_binding(context.session, old_edge_id)
    nsxv_db.cleanup_nsxv_edge_firewallrule_binding(context.session,
                                                   old_edge_id)

    with locking.LockManager.get_lock(old_edge_id):
        # Delete from NSXv backend
        # Note - If we will not delete the edge, but free it - it will be
        # immediately used as the new one, So it is better to delete it.
        try:
            nsxv = utils.get_nsxv_client()
            nsxv.delete_edge(old_edge_id)
        except Exception as e:
            LOG.warning("Failed to delete the old edge %(id)s: %(e)s",
                        {'id': old_edge_id, 'e': e})
            # Continue the process anyway
            # The edge may have been already deleted at the backend


def _get_router_az_from_plugin_router(router):
    # If the router edge was already deployed the availability_zones will
    # return the az
    az_name = router.get('availability_zones', [''])[0]
    if not az_name:
        # If it was not deployed - it may be in the creation hints
        az_name = router.get('availability_zones_hints', [''])[0]
    if not az_name:
        # If not - the default az was used.
        az_name = nsx_az.DEFAULT_NAME
    return az_name


def nsx_recreate_router_edge(old_edge_id):
    # init the plugin and edge manager
    cfg.CONF.set_override('core_plugin',
                          'vmware_nsx.shell.admin.plugins.nsxv.resources'
                          '.utils.NsxVPluginWrapper')
    with utils.NsxVPluginWrapper() as plugin:
        nsxv_manager = vcns_driver.VcnsDriver(
            edge_utils.NsxVCallbacks(plugin))
        edge_manager = edge_utils.EdgeManager(nsxv_manager, plugin)
        context = n_context.get_admin_context()

        # verify that this is a Router edge
        router_ids = edge_manager.get_routers_on_edge(context, old_edge_id)
        if not router_ids:
            LOG.error("Edge %(edge_id)s is not a router edge",
                     {'edge_id': old_edge_id})
            return

        # all the routers on the same edge have the same type, so it
        # is ok to check the type once
        example_router = plugin.get_router(context, router_ids[0])
        if example_router.get('distributed'):
            LOG.error("Recreating a distributed router edge is not "
                      "supported")
            return
        router_driver = plugin._router_managers.get_tenant_router_driver(
            context, example_router['router_type'])

        # load all the routers before deleting their binding
        routers = []
        for router_id in router_ids:
            routers.append(plugin.get_router(context, router_id))

        # delete the backend edge and all the relevant DB entries
        delete_old_edge(context, old_edge_id)

        # Go over all the relevant routers
        for router in routers:
            router_id = router['id']
            az_name = _get_router_az_from_plugin_router(router)
            # clean up other objects related to this router
            if plugin.metadata_proxy_handler:
                md_proxy = plugin.get_metadata_proxy_handler(az_name)
                md_proxy.cleanup_router_edge(context, router_id)

            # attach the router to a new edge
            appliance_size = router.get(routersize.ROUTER_SIZE)
            router_driver.attach_router(context, router_id,
                                        {'router': router},
                                        appliance_size=appliance_size)
            # find out who is the new edge to print it
            new_edge_id = router_driver._get_edge_id_or_raise(
                context, router_id)
            LOG.info("Router %(router)s was attached to edge %(edge)s",
                     {'router': router_id, 'edge': new_edge_id})


def nsx_recreate_router(router_id):
    # init the plugin and edge manager
    cfg.CONF.set_override('core_plugin',
                          'vmware_nsx.shell.admin.plugins.nsxv.resources'
                          '.utils.NsxVPluginWrapper')
    with utils.NsxVPluginWrapper() as plugin:
        context = n_context.get_admin_context()

        router = plugin.get_router(context, router_id)
        if router.get('distributed'):
            LOG.error("Recreating a distributed router is not supported")
            return
        router_driver = plugin._router_managers.get_tenant_router_driver(
            context, router['router_type'])

        # Check if it is already attached to an edge
        binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                  router_id)
        if binding:
            old_edge_id = binding['edge_id']
            # detach the router from this edge
            LOG.info("Detaching the router from edge %s", old_edge_id)
            router_driver.detach_router(context, router_id,
                                        {'router': router})

        # attach the router to a new edge
        appliance_size = router.get(routersize.ROUTER_SIZE)
        router_driver.attach_router(context, router_id,
                                    {'router': router},
                                    appliance_size=appliance_size)
        # find out who is the new edge to print it
        new_edge_id = router_driver._get_edge_id_or_raise(
            context, router_id)
        LOG.info("Router %(router)s was attached to edge %(edge)s",
                 {'router': router_id, 'edge': new_edge_id})


@admin_utils.output_header
def nsx_recreate_router_or_edge(resource, event, trigger, **kwargs):
    """Recreate a router edge with all the data on a new NSXv edge"""
    if not kwargs.get('property'):
        LOG.error("Need to specify edge-id or router-id parameter")
        return

    # input validation
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    old_edge_id = properties.get('edge-id')
    router_id = properties.get('router-id')
    if (not old_edge_id and not router_id) or (old_edge_id and router_id):
        LOG.error("Need to specify edge-id or router-id parameter")
        return

    if old_edge_id:
        LOG.info("ReCreating NSXv Router Edge: %s", old_edge_id)
        return nsx_recreate_router_edge(old_edge_id)
    else:
        LOG.info("ReCreating NSXv Router: %s", router_id)
        return nsx_recreate_router(router_id)


@admin_utils.output_header
def migrate_distributed_routers_dhcp(resource, event, trigger, **kwargs):
    context = n_context.get_admin_context()
    nsxv = utils.get_nsxv_client()
    with utils.NsxVPluginWrapper() as plugin:
        routers = plugin.get_routers(context)
        for router in routers:
            if router.get('distributed', False):
                binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                          router['id'])
                if binding:
                    edge_id = binding['edge_id']
                    with locking.LockManager.get_lock(edge_id):
                        route_obj = nsxv.get_routes(edge_id)[1]
                        routes = route_obj.get('staticRoutes', {}
                                               ).get('staticRoutes', [])
                        new_routes = [route for route in routes if route.get(
                            'network') != '169.254.169.254/32']
                        route_obj['staticRoutes']['staticRoutes'] = new_routes

                        nsxv.update_routes(edge_id, route_obj)


@admin_utils.output_header
def list_orphaned_vnics(resource, event, trigger, **kwargs):
    """List router orphaned router vnics where the port was deleted"""
    orphaned_vnics = get_orphaned_vnics()
    if not orphaned_vnics:
        LOG.info("No orphaned router vnics found")
        return
    headers = ['edge_id', 'vnic_index', 'tunnel_index', 'network_id']
    LOG.info(formatters.output_formatter(constants.ORPHANED_VNICS,
                                         orphaned_vnics, headers))


def get_orphaned_vnics():
    orphaned_vnics = []
    context = n_context.get_admin_context()
    vnic_binds = nsxv_db.get_edge_vnic_bindings_with_networks(
        context.session)
    with utils.NsxVPluginWrapper() as plugin:
        for vnic_bind in vnic_binds:
            edge_id = vnic_bind['edge_id']
            # check if this is a router edge by the router bindings table
            router_bindings = nsxv_db.get_nsxv_router_bindings_by_edge(
                context.session, edge_id)
            if not router_bindings:
                # Only log it. this is a different type of orphaned
                LOG.warning("Router bindings for vnic %s not found", vnic_bind)
                continue

            router_ids = [b['router_id'] for b in router_bindings]
            routers = plugin.get_routers(context,
                                         filters={'id': router_ids})
            if routers:
                interface_found = False
                # check if any of those routers is attached to this network
                for router in routers:
                    if plugin._get_router_interface_ports_by_network(
                        context, router['id'], vnic_bind['network_id']):
                        interface_found = True
                        break
                if not interface_found:
                    # for later deleting the interface we need to know if this
                    # is a distributed router.
                    # All the routers on the same edge are of the same type,
                    # so we can check the first one.
                    vnic_bind['distributed'] = routers[0].get('distributed')
                    orphaned_vnics.append(vnic_bind)

    return orphaned_vnics


@admin_utils.output_header
def clean_orphaned_vnics(resource, event, trigger, **kwargs):
    """List router orphaned router vnics where the port was deleted"""
    orphaned_vnics = get_orphaned_vnics()
    if not orphaned_vnics:
        LOG.info("No orphaned router vnics found")
        return
    headers = ['edge_id', 'vnic_index', 'tunnel_index', 'network_id']
    LOG.info(formatters.output_formatter(constants.ORPHANED_VNICS,
                                         orphaned_vnics, headers))
    user_confirm = admin_utils.query_yes_no("Do you want to delete "
                                            "orphaned vnics",
                                            default="no")
    if not user_confirm:
        LOG.info("NSXv vnics deletion aborted by user")
        return

    context = n_context.get_admin_context()
    with utils.NsxVPluginWrapper() as plugin:
        nsxv_manager = vcns_driver.VcnsDriver(
            edge_utils.NsxVCallbacks(plugin))
        for vnic in orphaned_vnics:
            if not vnic['distributed']:
                try:
                    nsxv_manager.vcns.delete_interface(
                        vnic['edge_id'], vnic['vnic_index'])
                except Exception as e:
                    LOG.error("Failed to delete vnic from NSX: %s", e)
                nsxv_db.free_edge_vnic_by_network(
                    context.session, vnic['edge_id'], vnic['network_id'])
            else:
                try:
                    nsxv_manager.vcns.delete_vdr_internal_interface(
                        vnic['edge_id'], vnic['vnic_index'])
                except Exception as e:
                    LOG.error("Failed to delete vnic from NSX: %s", e)
                nsxv_db.delete_edge_vnic_binding_by_network(
                    context.session, vnic['edge_id'], vnic['network_id'])


registry.subscribe(nsx_recreate_router_or_edge,
                   constants.ROUTERS,
                   shell.Operations.NSX_RECREATE.value)

registry.subscribe(migrate_distributed_routers_dhcp,
                   constants.ROUTERS,
                   shell.Operations.MIGRATE_VDR_DHCP.value)

registry.subscribe(list_orphaned_vnics,
                   constants.ORPHANED_VNICS,
                   shell.Operations.NSX_LIST.value)

registry.subscribe(clean_orphaned_vnics,
                   constants.ORPHANED_VNICS,
                   shell.Operations.NSX_CLEAN.value)
