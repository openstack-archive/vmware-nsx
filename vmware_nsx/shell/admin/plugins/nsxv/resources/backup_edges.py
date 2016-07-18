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

from neutron.callbacks import registry
from neutron.db import l3_db
from neutron_lib import exceptions
from oslo_utils import uuidutils

from vmware_nsx._i18n import _LE, _LI
from vmware_nsx.common import locking
from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import nsxv_db
from vmware_nsx.db import nsxv_models
from vmware_nsx.plugins.nsx_v.vshield.common import constants as vcns_const
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
import vmware_nsx.shell.admin.plugins.common.utils as admin_utils
import vmware_nsx.shell.admin.plugins.nsxv.resources.utils as utils
import vmware_nsx.shell.resources as shell


LOG = logging.getLogger(__name__)
nsxv = utils.get_nsxv_client()
_uuid = uuidutils.generate_uuid


def get_nsxv_backup_edges():
    edges = utils.get_nsxv_backend_edges()
    backup_edges = []
    edgeapi = utils.NeutronDbClient()
    for edge in edges:
        if edge['name'].startswith("backup-"):
            edge_vnic_binds = nsxv_db.get_edge_vnic_bindings_by_edge(
                edgeapi.context.session, edge['id'])
            if not edge_vnic_binds:
                backup_edges.append(edge)
    return backup_edges


@admin_utils.output_header
def nsx_list_backup_edges(resource, event, trigger, **kwargs):
    """List backup edges"""
    backup_edges = get_nsxv_backup_edges()
    LOG.info(formatters.output_formatter(constants.BACKUP_EDGES, backup_edges,
                                         ['id', 'name', 'size', 'type']))


def nsx_clean_backup_edge(resource, event, trigger, **kwargs):
    """Delete backup edge"""
    errmsg = ("Need to specify edge-id property. Add --property "
              "edge-id=<edge-id>")
    if not kwargs.get('property'):
        LOG.error(_LE("%s"), errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    edge_id = properties.get('edge-id')
    if not edge_id:
        LOG.error(_LE("%s"), errmsg)
        return
    try:
        edge = nsxv.get_edge(edge_id)
    except exceptions.NeutronException as x:
        LOG.error(_LE("%s"), str(x))
    else:
        # edge[0] is response status code
        # edge[1] is response body
        backup_edges = [e['id'] for e in get_nsxv_backup_edges()]
        if (not edge[1]['name'].startswith('backup-')
            or edge[1]['id'] not in backup_edges):
            LOG.error(
                _LE('Edge: %s is not a backup edge; aborting delete'), edge_id)
            return

        confirm = admin_utils.query_yes_no(
            "Do you want to delete edge: %s" % edge_id, default="no")
        if not confirm:
            LOG.info(_LI("Backup edge deletion aborted by user"))
            return
        try:
            with locking.LockManager.get_lock(edge_id):
                # Delete from NSXv backend
                nsxv.delete_edge(edge_id)
                # Remove bindings from Neutron DB
                edgeapi = utils.NeutronDbClient()
                nsxv_db.delete_nsxv_router_binding(
                    edgeapi.context.session, edge[1]['name'])
                nsxv_db.clean_edge_vnic_binding(edgeapi.context.session,
                                                edge_id)
        except Exception as expt:
            LOG.error(_LE("%s"), str(expt))


@admin_utils.output_header
def nsx_list_name_mismatches(resource, event, trigger, **kwargs):
    edges = utils.get_nsxv_backend_edges()
    plugin_nsx_mismatch = []
    backend_edge_ids = []
    edgeapi = utils.NeutronDbClient()
    # Look for edges with the wrong names:
    for edge in edges:
        backend_edge_ids.append(edge['id'])
        rtr_binding = nsxv_db.get_nsxv_router_binding_by_edge(
                edgeapi.context.session, edge['id'])

        if (rtr_binding and
            edge['name'].startswith('backup-')
            and rtr_binding['router_id'] != edge['name']):
            plugin_nsx_mismatch.append(
                    {'edge_id': edge['id'],
                     'edge_name': edge['name'],
                     'router_id': rtr_binding['router_id']})

    LOG.info(formatters.output_formatter(
            constants.BACKUP_EDGES + ' with name mismatch:',
            plugin_nsx_mismatch,
            ['edge_id', 'edge_name', 'router_id']))

    # Also look for missing edges
    like_filters = {'router_id': vcns_const.BACKUP_ROUTER_PREFIX + "%"}
    rtr_bindings = nsxv_db.get_nsxv_router_bindings(edgeapi.context.session,
        like_filters=like_filters)
    plugin_nsx_missing = []

    for rtr_binding in rtr_bindings:
        if rtr_binding['edge_id'] not in backend_edge_ids:
            plugin_nsx_missing.append(
                {'edge_id': rtr_binding['edge_id'],
                 'router_id': rtr_binding['router_id'],
                 'db_status': rtr_binding['status']})

    LOG.info(formatters.output_formatter(
            constants.BACKUP_EDGES + ' missing from backend:',
            plugin_nsx_missing,
            ['edge_id', 'router_id', 'db_status']))


def nsx_fix_name_mismatch(resource, event, trigger, **kwargs):
    errmsg = ("Need to specify edge-id property. Add --property "
              "edge-id=<edge-id>")
    if not kwargs.get('property'):
        LOG.error(_LE("%s"), errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    edgeapi = utils.NeutronDbClient()
    edge_id = properties.get('edge-id')
    if not edge_id:
        LOG.error(_LE("%s"), errmsg)
        return
    try:
        # edge[0] is response status code
        # edge[1] is response body
        edge = nsxv.get_edge(edge_id)[1]
    except exceptions.NeutronException as e:
        LOG.error(_LE("%s"), str(e))
    else:
        if edge['name'].startswith('backup-'):

            rtr_binding = nsxv_db.get_nsxv_router_binding_by_edge(
                    edgeapi.context.session, edge['id'])

            if rtr_binding['router_id'] == edge['name']:
                LOG.error(
                    _LE('Edge %s no mismatch with NSX'), edge_id)
                return

            try:
                with locking.LockManager.get_lock(edge_id):
                    # Update edge at NSXv backend
                    if rtr_binding['router_id'].startswith('dhcp-'):
                        # Edge is a DHCP edge - just use router_id as name
                        edge['name'] = rtr_binding['router_id']
                    else:
                        # This is a router - if shared, prefix with 'shared-'
                        nsx_attr = (edgeapi.context.session.query(
                            nsxv_models.NsxvRouterExtAttributes).filter_by(
                                router_id=rtr_binding['router_id']).first())
                        if nsx_attr and nsx_attr['router_type'] == 'shared':
                            edge['name'] = ('shared-' + _uuid())[
                                           :vcns_const.EDGE_NAME_LEN]
                        elif (nsx_attr
                              and nsx_attr['router_type'] == 'exclusive'):
                            rtr_db = (edgeapi.context.session.query(
                                l3_db.Router).filter_by(
                                    id=rtr_binding['router_id']).first())
                            if rtr_db:
                                edge['name'] = (
                                    rtr_db['name'][
                                        :nsxv_constants.ROUTER_NAME_LENGTH -
                                        len(rtr_db['id'])] +
                                    '-' + rtr_db['id'])
                            else:
                                LOG.error(
                                    _LE('No database entry for router id %s'),
                                    rtr_binding['router_id'])

                        else:
                            LOG.error(
                                _LE('Could not determine the name for '
                                    'Edge %s'), edge_id)
                            return

                    confirm = admin_utils.query_yes_no(
                        "Do you want to rename edge %s to %s" % (edge_id,
                                                                 edge['name']),
                        default="no")

                    if not confirm:
                        LOG.info(_LI("Edge rename aborted by user"))
                        return
                    LOG.info(_LI("Edge rename started"))
                    # remove some keys that will fail the NSX transaction
                    edge_utils.remove_irrelevant_keys_from_edge_request(edge)
                    try:
                        LOG.error(_LE("Update edge..."))
                        nsxv.update_edge(edge_id, edge)
                    except Exception as e:
                        LOG.error(_LE("Update failed - %s"), (e))
            except Exception as e:
                LOG.error(_LE("%s"), str(e))
        else:
            LOG.error(
                _LE('Edge %s has no backup prefix on NSX'), edge_id)
            return

registry.subscribe(nsx_list_backup_edges,
                   constants.BACKUP_EDGES,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_clean_backup_edge,
                   constants.BACKUP_EDGES,
                   shell.Operations.CLEAN.value)
registry.subscribe(nsx_list_name_mismatches,
                   constants.BACKUP_EDGES,
                   shell.Operations.LIST_MISMATCHES.value)
registry.subscribe(nsx_fix_name_mismatch,
                   constants.BACKUP_EDGES,
                   shell.Operations.FIX_MISMATCH.value)
