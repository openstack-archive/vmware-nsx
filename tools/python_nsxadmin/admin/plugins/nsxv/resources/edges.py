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

from tools.python_nsxadmin.admin.plugins.common import constants
from tools.python_nsxadmin.admin.plugins.common import formatters

import tools.python_nsxadmin.admin.plugins.common.utils as admin_utils
import tools.python_nsxadmin.admin.plugins.nsxv.resources.utils as utils
import tools.python_nsxadmin.admin.shell as shell

from neutron.callbacks import registry

from vmware_nsx._i18n import _LE, _LI
from vmware_nsx.db import nsxv_db

LOG = logging.getLogger(__name__)
nsxv = utils.get_nsxv_client()


def get_nsxv_edges():
    edges = nsxv.get_edges()[1]
    return edges['edgePage'].get('data', [])


@admin_utils.output_header
def nsx_list_edges(resource, event, trigger, **kwargs):
    """List edges from NSXv backend"""
    edges = get_nsxv_edges()
    LOG.info(formatters.output_formatter(constants.EDGES, edges,
                                         ['id']))


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
    for edge in get_nsxv_edges():
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
    orphaned_edges = get_orphaned_edges()
    LOG.info(orphaned_edges)


@admin_utils.output_header
def nsx_delete_orphaned_edges(resource, event, trigger, **kwargs):
    """Delete orphaned edges from NSXv backend"""
    orphaned_edges = get_orphaned_edges()
    LOG.info(_LI("Before delete; Orphaned Edges: %s"), orphaned_edges)

    if not kwargs['force']:
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

    LOG.info(_LI("After delete; Orphaned Edges: %s"), get_orphaned_edges())


@admin_utils.output_header
def nsx_update_edge(resource, event, trigger, **kwargs):
    """Update edge properties"""
    if not kwargs.get('property'):
        LOG.error(_LE("Need to specify edge-id parameter and "
                      "attribute to update. Add --property edge-id=<edge-id> "
                      "--property highavailability=True"))
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    if not properties.get('edge-id'):
        LOG.error(_LE("Need to specify edge-id. "
                      "Add --property edge-id=<edge-id>"))
        return
    LOG.info(_LI("Updating NSXv edge: %(edge)s with properties\n%(prop)s"),
             {'edge': properties.get('edge-id'), 'prop': properties})
    if properties.get('highavailability'):
        ha = bool(properties.get('highavailability').lower() == "true")
        ha_request = {
            'featureType': 'highavailability_4.0',
            'enabled': ha}
    return nsxv.enable_ha(properties.get('edge-id'), ha_request, async=False)


registry.subscribe(nsx_list_edges,
                   constants.EDGES,
                   shell.Operations.LIST.value)
registry.subscribe(neutron_list_router_edge_bindings,
                   constants.EDGES,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_list_orphaned_edges,
                   constants.EDGES,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_delete_orphaned_edges,
                   constants.EDGES,
                   shell.Operations.CLEAN.value)
registry.subscribe(nsx_update_edge,
                   constants.EDGES,
                   shell.Operations.NSX_UPDATE.value)
