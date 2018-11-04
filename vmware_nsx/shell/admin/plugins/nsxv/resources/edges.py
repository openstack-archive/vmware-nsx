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
import textwrap

from vmware_nsx.common import config
from vmware_nsx.dvs import dvs
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.plugins.nsx_v.vshield import vcns_driver
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters

import vmware_nsx.shell.admin.plugins.common.utils as admin_utils
import vmware_nsx.shell.admin.plugins.nsxv.resources.utils as utils
import vmware_nsx.shell.resources as shell

from neutron_lib.callbacks import registry
from neutron_lib import context as n_context
from neutron_lib import exceptions
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v import availability_zones as nsx_az
from vmware_nsx.plugins.nsx_v.vshield.common import (
    constants as vcns_const)
import vmware_nsx.plugins.nsx_v.vshield.common.exceptions as nsxv_exceptions


LOG = logging.getLogger(__name__)
nsxv = utils.get_nsxv_client()


@admin_utils.output_header
def nsx_list_edges(resource, event, trigger, **kwargs):
    """List edges from NSXv backend"""

    headers = ['id', 'name', 'type', 'size', 'ha']
    edges = utils.get_nsxv_backend_edges()
    if (kwargs.get('verbose')):
        headers += ['syslog']
        extend_edge_info(edges)

    LOG.info(formatters.output_formatter(constants.EDGES, edges, headers))


def extend_edge_info(edges):
    """Add syslog info to each edge in list"""

    for edge in edges:
        # for the table to remain human readable, we need to
        # wrap long edge names
        edge['name'] = textwrap.fill(edge['name'], 25)
        edge['syslog'] = utils.get_edge_syslog_info(edge['id'])


def get_router_edge_bindings():
    edgeapi = utils.NeutronDbClient()
    return nsxv_db.get_nsxv_router_bindings(edgeapi.context)


@admin_utils.output_header
def neutron_list_router_edge_bindings(resource, event, trigger, **kwargs):
    """List NSXv edges from Neutron DB"""
    edges = get_router_edge_bindings()
    LOG.info(formatters.output_formatter(
        constants.EDGES, edges,
        ['edge_id', 'router_id', 'availability_zone', 'status']))


@admin_utils.output_header
def clean_orphaned_router_bindings(resource, event, trigger, **kwargs):
    """Delete nsx router bindings entries without real objects behind them"""
    orphaned_list = get_orphaned_router_bindings()
    if not len(orphaned_list):
        LOG.info("No orphaned Router bindings found.")
        return

    LOG.info("Before delete; Orphaned Bindings:")
    LOG.info(formatters.output_formatter(
        constants.ORPHANED_BINDINGS, orphaned_list,
        ['edge_id', 'router_id', 'availability_zone', 'status']))

    if not kwargs.get('force'):
        if len(orphaned_list):
            user_confirm = admin_utils.query_yes_no("Do you want to delete "
                                                    "orphaned bindings",
                                                    default="no")
            if not user_confirm:
                LOG.info("NSXv Router bindings deletion aborted by user")
                return

    edgeapi = utils.NeutronDbClient()
    for binding in orphaned_list:
        nsxv_db.delete_nsxv_router_binding(
            edgeapi.context.session, binding.router_id)

    LOG.info("Deleted %s orphaned router bindings. You may need to check for "
             "orphaned edges now.", len(orphaned_list))


@admin_utils.output_header
def list_orphaned_router_bindings(resource, event, trigger, **kwargs):
    """List nsx router bindings entries without real objects behind them"""
    orphaned_list = get_orphaned_router_bindings()
    LOG.info(formatters.output_formatter(
        constants.ORPHANED_BINDINGS, orphaned_list,
        ['edge_id', 'router_id', 'availability_zone', 'status']))


def get_orphaned_router_bindings():
    context = n_context.get_admin_context()
    orphaned_list = []

    with utils.NsxVPluginWrapper() as plugin:
        networks = plugin.get_networks(context, fields=['id'])
        net_ids = [x['id'] for x in networks]
        routers = plugin.get_routers(context, fields=['id'])
        rtr_ids = [x['id'] for x in routers]

        nsxv_manager = vcns_driver.VcnsDriver(
            edge_utils.NsxVCallbacks(plugin))
        edge_manager = edge_utils.EdgeManager(nsxv_manager, plugin)
        plr_tlr_ids = {}
        for tlr_id in rtr_ids:
            plr_id = edge_manager.get_plr_by_tlr_id(context, tlr_id)
            if plr_id:
                plr_tlr_ids[plr_id] = tlr_id

        for binding in get_router_edge_bindings():
            if not router_binding_obj_exist(context, binding,
                                            net_ids, rtr_ids, plr_tlr_ids):
                orphaned_list.append(binding)
    return orphaned_list


def _get_obj_id_from_binding(router_id, prefix):
    """Return the id part of the router-binding router-id field"""
    return router_id[len(prefix):]


def _is_id_prefix_in_list(id_prefix, ids):
    """Return True if the id_prefix is the prefix of one of the ids"""
    for x in ids:
        if x.startswith(id_prefix):
            return True
    return False


def router_binding_obj_exist(context, binding, net_ids, rtr_ids, plr_tlr_ids):
    """Check if the object responsible for the router binding entry exists

    Check if the relevant router/network/loadbalancer exists in the neutron DB
    """
    router_id = binding.router_id

    if router_id.startswith(vcns_const.BACKUP_ROUTER_PREFIX):
        # no neutron object that should match backup edges
        return True

    if router_id.startswith(vcns_const.DHCP_EDGE_PREFIX):
        # should have a network starting with this id
        # get the id. and look for a network with this id
        net_id_prefix = _get_obj_id_from_binding(
            router_id, vcns_const.DHCP_EDGE_PREFIX)
        if _is_id_prefix_in_list(net_id_prefix, net_ids):
            return True
        else:
            LOG.warning("Network for binding entry %s not found", router_id)
            return False

    if router_id.startswith(vcns_const.PLR_EDGE_PREFIX):
        # Look for the TLR that matches this PLR
        # and check if it exists in the neutron DB
        if router_id in plr_tlr_ids:
            tlr_id = plr_tlr_ids[router_id]
            if _is_id_prefix_in_list(tlr_id, rtr_ids):
                return True
            else:
                LOG.warning("TLR Router %s for PLR binding entry %s not found",
                            tlr_id, router_id)
                return False
        else:
            LOG.warning("TLR Router binding for PLR binding entry %s not "
                        "found", router_id)
            return False

    if router_id.startswith(lb_common.RESOURCE_ID_PFX):
        # should have a load balancer starting with this id on the same edge
        if nsxv_db.get_nsxv_lbaas_loadbalancer_binding_by_edge(
            context.session, binding.edge_id):
            return True
        else:
            LOG.warning("Loadbalancer for binding entry %s not found",
                        router_id)
            return False

    # regular router
    # get the id. and look for a router with this id
    if _is_id_prefix_in_list(router_id, rtr_ids):
        return True
    else:
        LOG.warning("Router for binding entry %s not found", router_id)
        return False


def get_orphaned_edges():
    nsxv_edge_ids = set()
    for edge in utils.get_nsxv_backend_edges():
        nsxv_edge_ids.add(edge.get('id'))

    neutron_edge_bindings = set()
    for binding in get_router_edge_bindings():
        neutron_edge_bindings.add(binding.edge_id)

    return nsxv_edge_ids - neutron_edge_bindings


@admin_utils.output_header
def nsx_list_orphaned_edges(resource, event, trigger, **kwargs):
    """List orphaned Edges on NSXv.

    Orphaned edges are NSXv edges that exist on NSXv backend but
    don't have a corresponding binding in Neutron DB
    """
    LOG.info("NSXv edges present on NSXv backend but not present "
             "in Neutron DB\n")
    orphaned_edges = get_orphaned_edges()
    if not orphaned_edges:
        LOG.info("\nNo orphaned edges found."
                 "\nNeutron DB and NSXv backend are in sync\n")
    else:
        LOG.info(constants.ORPHANED_EDGES)
        data = [('edge_id',)]
        for edge in orphaned_edges:
            data.append((edge,))
        LOG.info(formatters.tabulate_results(data))


@admin_utils.output_header
def nsx_delete_orphaned_edges(resource, event, trigger, **kwargs):
    """Delete orphaned edges from NSXv backend"""
    orphaned_edges = get_orphaned_edges()
    LOG.info("Before delete; Orphaned Edges: %s", orphaned_edges)

    if not kwargs.get('force'):
        if len(orphaned_edges):
            user_confirm = admin_utils.query_yes_no("Do you want to delete "
                                                    "orphaned edges",
                                                    default="no")
            if not user_confirm:
                LOG.info("NSXv Edge deletion aborted by user")
                return

    nsxv = utils.get_nsxv_client()
    for edge in orphaned_edges:
        LOG.info("Deleting edge: %s", edge)
        nsxv.delete_edge(edge)

    LOG.info("After delete; Orphaned Edges: \n%s",
        pprint.pformat(get_orphaned_edges()))


def get_missing_edges():
    nsxv_edge_ids = set()
    for edge in utils.get_nsxv_backend_edges():
        nsxv_edge_ids.add(edge.get('id'))

    neutron_edge_bindings = set()
    for binding in get_router_edge_bindings():
        neutron_edge_bindings.add(binding.edge_id)

    return neutron_edge_bindings - nsxv_edge_ids


def get_router_edge_vnic_bindings(edge_id):
    edgeapi = utils.NeutronDbClient()
    return nsxv_db.get_edge_vnic_bindings_by_edge(
        edgeapi.context.session, edge_id)


@admin_utils.output_header
def nsx_list_missing_edges(resource, event, trigger, **kwargs):
    """List missing edges and networks serviced by those edges.

    Missing edges are NSXv edges that have a binding in Neutron DB
    but are currently missing from the NSXv backend.
    """
    LOG.info("NSXv edges present in Neutron DB but not present "
             "on the NSXv backend\n")
    missing_edges = get_missing_edges()
    if not missing_edges:
        LOG.info("\nNo edges are missing."
                 "\nNeutron DB and NSXv backend are in sync\n")
    else:
        data = [('edge_id', 'network_id')]
        for edge in missing_edges:
            # Retrieve all networks which are serviced by this edge.
            edge_serviced_networks = get_router_edge_vnic_bindings(edge)
            if not edge_serviced_networks:
                # If the edge is missing on the backend but no network
                # is serviced by this edge, output N/A.
                data.append((edge, 'N/A'))
            for bindings in edge_serviced_networks:
                data.append((edge, bindings.network_id))
        LOG.info(formatters.tabulate_results(data))


def change_edge_ha(ha, edge_id):
    request = {
        'featureType': 'highavailability_4.0',
        'enabled': ha}
    try:
        nsxv.enable_ha(edge_id, request)
    except nsxv_exceptions.ResourceNotFound as e:
        LOG.error("Edge %s not found", edge_id)
    except exceptions.NeutronException as e:
        LOG.error("%s", str(e))


def change_edge_syslog(properties):
    request = {
        'featureType': 'syslog',
        'serverAddresses': {'ipAddress': [], 'type': 'IpAddressesDto'}}

    request['protocol'] = properties.get('syslog-proto', 'tcp')
    if request['protocol'] not in ['tcp', 'udp']:
        LOG.error("Property value error: syslog-proto must be tcp/udp")
        return

    if properties.get('syslog-server'):
        request['serverAddresses']['ipAddress'].append(
                properties.get('syslog-server'))
    if properties.get('syslog-server2'):
        request['serverAddresses']['ipAddress'].append(
                properties.get('syslog-server2'))

    edge_id = properties.get('edge-id')
    try:
        nsxv.update_edge_syslog(edge_id, request)
    except nsxv_exceptions.ResourceNotFound as e:
        LOG.error("Edge %s not found", edge_id)
    except exceptions.NeutronException as e:
        LOG.error("%s", str(e))


def delete_edge_syslog(edge_id):
    try:
        nsxv.delete_edge_syslog(edge_id)
    except nsxv_exceptions.ResourceNotFound as e:
        LOG.error("Edge %s not found", edge_id)
    except exceptions.NeutronException as e:
        LOG.error("%s", str(e))


def change_edge_loglevel(properties):
    """Update log level on edge

    Update log level either for specific module or for all modules.
    'none' disables logging, any other level enables logging
    Returns True if found any log level properties (regardless if action
    succeeded)
    """

    modules = {}
    if properties.get('log-level'):
        level = properties.get('log-level')
        # change log level for all modules
        modules = {k: level for k in edge_utils.SUPPORTED_EDGE_LOG_MODULES}
    else:
        # check for log level settings for specific modules
        for k, v in properties.items():
            if k.endswith('-log-level'):
                module = k[:-10]   # module is in parameter prefix
                modules[module] = v

    if not modules:
        # no log level properties
        return False

    edge_id = properties.get('edge-id')

    for module, level in modules.items():
        if level == 'none':
            LOG.info("Disabling logging for %s", module)
        else:
            LOG.info("Enabling logging for %(m)s with level %(l)s",
                    {'m': module, 'l': level})
        try:
            edge_utils.update_edge_loglevel(nsxv, edge_id, module, level)

        except nsxv_exceptions.ResourceNotFound as e:
            LOG.error("Edge %s not found", edge_id)
        except exceptions.NeutronException as e:
            LOG.error("%s", str(e))

    # take ownership for properties
    return True


def change_edge_appliance_size(properties):
    size = properties.get('size')
    if size not in vcns_const.ALLOWED_EDGE_SIZES:
        LOG.error("Edge appliance size not in %(size)s",
                  {'size': vcns_const.ALLOWED_EDGE_SIZES})
        return
    try:
        nsxv.change_edge_appliance_size(
            properties.get('edge-id'), size)
    except nsxv_exceptions.ResourceNotFound as e:
        LOG.error("Edge %s not found", properties.get('edge-id'))
    except exceptions.NeutronException as e:
        LOG.error("%s", str(e))


def _get_edge_az_and_size(edge_id):
    edgeapi = utils.NeutronDbClient()
    binding = nsxv_db.get_nsxv_router_binding_by_edge(
        edgeapi.context.session, edge_id)
    if binding:
        return binding['availability_zone'], binding['appliance_size']
    # default fallback
    return nsx_az.DEFAULT_NAME, nsxv_constants.LARGE


def change_edge_appliance(edge_id):
    """Update the appliances data of an edge

    Update the edge appliances data according to its current availability zone
    and the nsx.ini config, including the resource pool, edge_ha, datastore &
    ha_datastore.
    The availability zone of the edge will not be changed.
    This can be useful when the global resource pool/datastore/edge ha
    configuration is updated, or when the configuration of a specific
    availability zone was updated.
    """
    # find out what is the current resource pool & size, so we can keep them
    az_name, size = _get_edge_az_and_size(edge_id)
    config.register_nsxv_azs(cfg.CONF, cfg.CONF.nsxv.availability_zones)
    az = nsx_az.NsxVAvailabilityZones().get_availability_zone(az_name)
    appliances = [{'resourcePoolId': az.resource_pool,
                   'datastoreId': az.datastore_id}]

    if az.ha_datastore_id and az.edge_ha:
        appliances.append({'resourcePoolId': az.resource_pool,
                           'datastoreId': az.ha_datastore_id})
    request = {'appliances': appliances, 'applianceSize': size}
    try:
        nsxv.change_edge_appliance(edge_id, request)
    except nsxv_exceptions.ResourceNotFound as e:
        LOG.error("Edge %s not found", edge_id)
    except exceptions.NeutronException as e:
        LOG.error("%s", str(e))
    else:
        # also update the edge_ha of the edge
        change_edge_ha(az.edge_ha, edge_id)


def change_edge_appliance_reservations(properties):
    reservations = {}
    res = {}
    if properties.get('limit'):
        res['limit'] = properties.get('limit')
    if properties.get('reservation'):
        res['reservation'] = properties.get('reservation')
    if properties.get('shares'):
        res['shares'] = properties.get('shares')
    resource = properties.get('resource')
    if not res:
        LOG.error("Please configure reservations")
        return
    if resource == 'cpu':
        reservations['cpuReservation'] = res
    elif resource == 'memory':
        reservations['memoryReservation'] = res
    else:
        LOG.error("Please configure resource")
        return
    edge_id = properties.get('edge-id')
    try:
        h, edge = nsxv.get_edge(edge_id)
    except exceptions.NeutronException as e:
        LOG.error("%s", str(e))
        return
    appliances = edge['appliances']['appliances']
    for appliance in appliances:
        appliance.update(reservations)
    request = {'appliances': appliances}
    try:
        nsxv.change_edge_appliance(edge_id, request)
    except nsxv_exceptions.ResourceNotFound as e:
        LOG.error("Edge %s not found", edge_id)
    except exceptions.NeutronException as e:
        LOG.error("%s", str(e))


def _update_host_group_for_edge(nsxv, cluster_mng, edge_id, edge):
    if edge.get('type') == 'gatewayServices':
        try:
            az_name, size = _get_edge_az_and_size(edge_id)
            config.register_nsxv_azs(cfg.CONF,
                                     cfg.CONF.nsxv.availability_zones)
            zones = nsx_az.NsxVAvailabilityZones()
            az = zones.get_availability_zone(az_name)
            if az.edge_ha and az.edge_host_groups:
                edge_utils.update_edge_host_groups(nsxv, edge_id,
                                                   cluster_mng, az,
                                                   validate=True)
            else:
                LOG.error("Availability zone:%s does not have HA enabled or "
                          "no host groups defined. Skipping %s.",
                          az_name, edge_id)
        except Exception as e:
            LOG.error("Failed to update edge %(id)s - %(e)s",
                      {'id': edge['id'],
                       'e': e})
    else:
        LOG.error("%s is not a gateway services", edge_id)


def change_edge_hostgroup(properties):
    cluster_mng = dvs.ClusterManager()
    if properties.get('hostgroup').lower() == "update":
        edge_id = properties.get('edge-id')
        try:
            edge_result = nsxv.get_edge(edge_id)
        except exceptions.NeutronException as x:
            LOG.error("%s", str(x))
        else:
            # edge_result[0] is response status code
            # edge_result[1] is response body
            edge = edge_result[1]
            _update_host_group_for_edge(nsxv, cluster_mng,
                                        edge_id, edge)
    elif properties.get('hostgroup').lower() == "all":
        edges = utils.get_nsxv_backend_edges()
        for edge in edges:
            edge_id = edge['id']
            _update_host_group_for_edge(nsxv, cluster_mng,
                                        edge_id, edge)
    elif properties.get('hostgroup').lower() == "clean":
        config.register_nsxv_azs(cfg.CONF, cfg.CONF.nsxv.availability_zones)
        azs = nsx_az.NsxVAvailabilityZones()
        for az in azs.list_availability_zones_objects():
            try:
                edge_utils.clean_host_groups(cluster_mng, az)
            except Exception:
                LOG.error("Failed to clean AZ %s", az.name)
    else:
        LOG.error('Currently not supported')


@admin_utils.output_header
def nsx_update_edge(resource, event, trigger, **kwargs):
    """Update edge properties"""
    usage_msg = ("Need to specify edge-id parameter and "
                 "attribute to update. Add --property edge-id=<edge-id> "
                 "and --property highavailability=<True/False> or "
                 "--property size=<size> or --property appliances=True. "
                 "\nFor syslog, add --property syslog-server=<ip>|none and "
                 "(optional) --property syslog-server2=<ip> and/or "
                 "(optional) --property syslog-proto=[tcp/udp] "
                 "\nFor log levels, add --property [routing|dhcp|dns|"
                 "highavailability|loadbalancer]-log-level="
                 "[debug|info|warning|error]. To set log level for all "
                 "modules, add --property log-level=<level> "
                 "\nFor edge reservations, add "
                 "--property resource=cpu|memory and "
                 "(optional) --property limit=<limit> and/or "
                 "(optional) --property shares=<shares> and/or "
                 "(optional) --property reservation=<reservation> "
                 "\nFor hostgroup updates, add "
                 "--property hostgroup=update/all/clean")
    if not kwargs.get('property'):
        LOG.error(usage_msg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    if (not properties.get('edge-id') and
        not properties.get('hostgroup', '').lower() == "all" and
        not properties.get('hostgroup', '').lower() == "clean"):
        LOG.error("Need to specify edge-id. "
                  "Add --property edge-id=<edge-id>")
        return
    LOG.info("Updating NSXv edge: %(edge)s with properties\n%(prop)s",
             {'edge': properties.get('edge-id'), 'prop': properties})
    if properties.get('highavailability'):
        change_edge_ha(properties['highavailability'].lower() == "true",
                       properties['edge-id'])
    elif properties.get('size'):
        change_edge_appliance_size(properties)
    elif (properties.get('appliances') and
          properties.get('appliances').lower() == "true"):
        change_edge_appliance(properties['edge-id'])
    elif properties.get('syslog-server'):
        if (properties.get('syslog-server').lower() == "none"):
            delete_edge_syslog(properties['edge-id'])
        else:
            change_edge_syslog(properties)
    elif properties.get('resource'):
        change_edge_appliance_reservations(properties)
    elif properties.get('hostgroup'):
        change_edge_hostgroup(properties)
    elif change_edge_loglevel(properties):
        pass
    else:
        # no attribute was specified
        LOG.error(usage_msg)


@admin_utils.output_header
def nsx_update_edges(resource, event, trigger, **kwargs):
    """Update all edges with the given property"""
    if not kwargs.get('property'):
        usage_msg = ("Need to specify a property to update all edges. "
                     "Add --property appliances=<True/False>")
        LOG.error(usage_msg)
        return

    edges = utils.get_nsxv_backend_edges()
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    result = 0
    for edge in edges:
        if properties.get('appliances', 'false').lower() == "true":
            try:
                change_edge_appliance(edge.get('edge-id'))
            except Exception as e:
                result += 1
                LOG.error("Failed to update edge %(edge)s. Exception: "
                          "%(e)s", {'edge': edge.get('edge-id'),
                                    'e': str(e)})
    if result > 0:
        total = len(edges)
        LOG.error("%(result)s of %(total)s edges failed "
                  "to update.", {'result': result, 'total': total})


registry.subscribe(nsx_list_edges,
                   constants.EDGES,
                   shell.Operations.NSX_LIST.value)
registry.subscribe(neutron_list_router_edge_bindings,
                   constants.EDGES,
                   shell.Operations.NEUTRON_LIST.value)
registry.subscribe(nsx_list_orphaned_edges,
                   constants.ORPHANED_EDGES,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_delete_orphaned_edges,
                   constants.ORPHANED_EDGES,
                   shell.Operations.CLEAN.value)
registry.subscribe(nsx_list_missing_edges,
                   constants.MISSING_EDGES,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_update_edge,
                   constants.EDGES,
                   shell.Operations.NSX_UPDATE.value)
registry.subscribe(nsx_update_edges,
                   constants.EDGES,
                   shell.Operations.NSX_UPDATE_ALL.value)
registry.subscribe(list_orphaned_router_bindings,
                   constants.ORPHANED_BINDINGS,
                   shell.Operations.LIST.value)
registry.subscribe(clean_orphaned_router_bindings,
                   constants.ORPHANED_BINDINGS,
                   shell.Operations.CLEAN.value)
