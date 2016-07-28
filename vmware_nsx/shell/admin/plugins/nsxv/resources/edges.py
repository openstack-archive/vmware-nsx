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

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters

import vmware_nsx.shell.admin.plugins.common.utils as admin_utils
import vmware_nsx.shell.admin.plugins.nsxv.resources.utils as utils
import vmware_nsx.shell.resources as shell

from neutron.callbacks import registry
from neutron_lib import exceptions

from vmware_nsx._i18n import _LE, _LI
from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v import availability_zones as nsx_az
import vmware_nsx.plugins.nsx_v.vshield.common.exceptions as nsxv_exceptions

LOG = logging.getLogger(__name__)
nsxv = utils.get_nsxv_client()


@admin_utils.output_header
def nsx_list_edges(resource, event, trigger, **kwargs):
    """List edges from NSXv backend"""
    edges = utils.get_nsxv_backend_edges()
    LOG.info(formatters.output_formatter(constants.EDGES, edges,
                                         ['id', 'name', 'type', 'size']))


def get_router_edge_bindings():
    edgeapi = utils.NeutronDbClient()
    return nsxv_db.get_nsxv_router_bindings(edgeapi.context)


@admin_utils.output_header
def neutron_list_router_edge_bindings(resource, event, trigger, **kwargs):
    """List NSXv edges from Neutron DB"""
    edges = get_router_edge_bindings()
    LOG.info(formatters.output_formatter(constants.EDGES, edges,
                                         ['edge_id', 'router_id']))


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
    LOG.info(_LI("NSXv edges present on NSXv backend but not present "
                 "in Neutron DB\n"))
    orphaned_edges = get_orphaned_edges()
    if not orphaned_edges:
        LOG.info(_LI("\nNo orphaned edges found."
                     "\nNeutron DB and NSXv backend are in sync\n"))
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
    LOG.info(_LI("Before delete; Orphaned Edges: %s"), orphaned_edges)

    if not kwargs.get('force'):
        if len(orphaned_edges):
            user_confirm = admin_utils.query_yes_no("Do you want to delete "
                                                    "orphaned edges",
                                                    default="no")
            if not user_confirm:
                LOG.info(_LI("NSXv Edge deletion aborted by user"))
                return

    nsxv = utils.get_nsxv_client()
    for edge in orphaned_edges:
        LOG.info(_LI("Deleting edge: %s"), edge)
        nsxv.delete_edge(edge)

    LOG.info(_LI("After delete; Orphaned Edges: \n%s"),
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
    LOG.info(_LI("NSXv edges present in Neutron DB but not present "
                 "on the NSXv backend\n"))
    missing_edges = get_missing_edges()
    if not missing_edges:
        LOG.info(_LI("\nNo edges are missing."
                     "\nNeutron DB and NSXv backend are in sync\n"))
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
        LOG.error(_LE("Edge %s not found"), edge_id)
    except exceptions.NeutronException as e:
        LOG.error(_LE("%s"), str(e))


def change_edge_appliance_size(properties):
    size = properties.get('size')
    if size not in nsxv_constants.ALLOWED_EDGE_SIZES:
        LOG.error(_LE("Edge appliance size not in %(size)s"),
                  {'size': nsxv_constants.ALLOWED_EDGE_SIZES})
        return
    try:
        nsxv.change_edge_appliance_size(
            properties.get('edge-id'), size)
    except nsxv_exceptions.ResourceNotFound as e:
        LOG.error(_LE("Edge %s not found"), properties.get('edge-id'))
    except exceptions.NeutronException as e:
        LOG.error(_LE("%s"), str(e))


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
    az = nsx_az.ConfiguredAvailabilityZones().get_availability_zone(az_name)
    appliances = [{'resourcePoolId': az.resource_pool,
                   'datastoreId': az.datastore_id}]

    if az.ha_datastore_id and az.edge_ha:
        appliances.append({'resourcePoolId': az.resource_pool,
                           'datastoreId': az.ha_datastore_id})
    request = {'appliances': appliances, 'applianceSize': size}
    try:
        nsxv.change_edge_appliance(edge_id, request)
    except nsxv_exceptions.ResourceNotFound as e:
        LOG.error(_LE("Edge %s not found"), edge_id)
    except exceptions.NeutronException as e:
        LOG.error(_LE("%s"), str(e))
    else:
        # also update the edge_ha of the edge
        change_edge_ha(az.edge_ha, edge_id)


@admin_utils.output_header
def nsx_update_edge(resource, event, trigger, **kwargs):
    """Update edge properties"""
    usage_msg = _LE("Need to specify edge-id parameter and "
                    "attribute to update. Add --property edge-id=<edge-id> "
                    "and --property highavailability=<True/False> or "
                    "--property size=<size> or --property appliances=True")
    if not kwargs.get('property'):
        LOG.error(usage_msg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    if not properties.get('edge-id'):
        LOG.error(_LE("Need to specify edge-id. "
                      "Add --property edge-id=<edge-id>"))
        return
    LOG.info(_LI("Updating NSXv edge: %(edge)s with properties\n%(prop)s"),
             {'edge': properties.get('edge-id'), 'prop': properties})
    if properties.get('highavailability'):
        change_edge_ha(properties['highavailability'].lower() == "true",
                       properties['edge-id'])
    elif properties.get('size'):
        change_edge_appliance_size(properties)
    elif (properties.get('appliances') and
          properties.get('appliances').lower() == "true"):
        change_edge_appliance(properties['edge-id'])
    else:
        # no attribute was specified
        LOG.error(usage_msg)


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
