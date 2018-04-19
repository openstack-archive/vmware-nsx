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


from neutron.db import l3_db
from neutron_lib.callbacks import registry
from neutron_lib import exceptions
from oslo_log import log as logging
from oslo_utils import uuidutils

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


def get_nsxv_backup_edges(scope="all"):
    edges = utils.get_nsxv_backend_edges()
    backup_edges = []
    edgeapi = utils.NeutronDbClient()
    for edge in edges:
        if edge['name'].startswith("backup-"):
            # Make sure it is really a backup edge
            edge_vnic_binds = nsxv_db.get_edge_vnic_bindings_by_edge(
                edgeapi.context.session, edge['id'])
            if scope != "all":
                # Make sure the backup edge exists in neutron
                # Return backup edges existing in both neutron and backend
                # when scope != all
                edge_in_neutron = nsxv_db.get_nsxv_router_binding_by_edge(
                    edgeapi.context.session, edge['id'])
                if not edge_vnic_binds and edge_in_neutron:
                    extend_edge_info(edge)
                    backup_edges.append(edge)
            else:
                if not edge_vnic_binds:
                    extend_edge_info(edge)
                    backup_edges.append(edge)
    return backup_edges


def extend_edge_info(edge):
    """Add information from the nsxv-db, if available"""
    edgeapi = utils.NeutronDbClient()
    rtr_binding = nsxv_db.get_nsxv_router_binding_by_edge(
            edgeapi.context.session, edge['id'])
    if rtr_binding:
        edge['availability_zone'] = rtr_binding['availability_zone']
        edge['db_status'] = rtr_binding['status']


@admin_utils.output_header
def nsx_list_backup_edges(resource, event, trigger, **kwargs):
    """List backup edges"""
    backup_edges = get_nsxv_backup_edges()
    LOG.info(formatters.output_formatter(
        constants.BACKUP_EDGES, backup_edges,
        ['id', 'name', 'size', 'type', 'availability_zone', 'db_status']))


def _delete_backup_from_neutron_db(edge_id, router_id):
    # Remove bindings from Neutron DB
    edgeapi = utils.NeutronDbClient()
    nsxv_db.delete_nsxv_router_binding(
        edgeapi.context.session, router_id)
    if edge_id:
        nsxv_db.clean_edge_vnic_binding(edgeapi.context.session, edge_id)


def _delete_edge_from_nsx_and_neutron(edge_id, router_id):
    try:
        with locking.LockManager.get_lock(edge_id):
            # Delete from NSXv backend
            nsxv.delete_edge(edge_id)
            # Remove bindings from Neutron DB
            _delete_backup_from_neutron_db(edge_id, router_id)
            return True
    except Exception as expt:
        LOG.error("%s", str(expt))
        return False


def _nsx_delete_backup_edge(edge_id, all_backup_edges):
    """Delete a specific backup edge"""
    try:
        edge_result = nsxv.get_edge(edge_id)
    except exceptions.NeutronException as x:
        LOG.error("%s", str(x))
    else:
        # edge_result[0] is response status code
        # edge_result[1] is response body
        edge = edge_result[1]
        backup_edges = [e['id'] for e in all_backup_edges]
        if (not edge['name'].startswith('backup-') or
            edge['id'] not in backup_edges):
            LOG.error(
                'Edge: %s is not a backup edge; aborting delete',
                edge_id)
        else:
            return _delete_edge_from_nsx_and_neutron(edge_id, edge['name'])


def nsx_clean_backup_edge(resource, event, trigger, **kwargs):
    """Delete backup edge"""
    errmsg = ("Need to specify edge-id property. Add --property "
              "edge-id=<edge-id>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    edge_id = properties.get('edge-id')
    if not edge_id:
        LOG.error("%s", errmsg)
        return
    if not kwargs.get('force'):
        #ask for the user confirmation
        confirm = admin_utils.query_yes_no(
            "Do you want to delete edge: %s" % edge_id, default="no")
        if not confirm:
            LOG.info("Backup edge deletion aborted by user")
            return
    # delete the backup edge
    _nsx_delete_backup_edge(edge_id, get_nsxv_backup_edges())


def nsx_clean_all_backup_edges(resource, event, trigger, **kwargs):
    """Delete all backup edges"""
    scope = "all"
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        scope = properties.get("scope", "all")
        if scope not in ["neutron", "all"]:
            LOG.error("Need to specify the scope in ['neutron', 'all']")
            return

    backup_edges = get_nsxv_backup_edges(scope=scope)

    if not kwargs.get('force'):
        #ask for the user confirmation
        confirm = admin_utils.query_yes_no(
            "Do you want to delete %s backup edges?" % len(backup_edges),
            default="no")
        if not confirm:
            LOG.info("Backup edges deletion aborted by user")
            return

    deleted_cnt = 0
    for edge in backup_edges:
        # delete the backup edge
        if _nsx_delete_backup_edge(edge['id'], backup_edges):
            deleted_cnt = deleted_cnt + 1

    LOG.info('Done Deleting %s backup edges', deleted_cnt)


@admin_utils.output_header
def neutron_clean_backup_edge(resource, event, trigger, **kwargs):
    """Delete a backup edge from the neutron, and backend by it's name

    The name of the backup edge is the router-id column in the BD table
    nsxv_router_bindings, and it is also printed by list-mismatches
    """
    errmsg = ("Need to specify router-id property. Add --property "
              "router-id=<router-id>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    router_id = properties.get('router-id')
    if not router_id:
        LOG.error("%s", errmsg)
        return

    # look for the router-binding entry
    edgeapi = utils.NeutronDbClient()
    rtr_binding = nsxv_db.get_nsxv_router_binding(
            edgeapi.context.session, router_id)
    if not rtr_binding:
        LOG.error('Backup %s was not found in DB', router_id)
        return

    edge_id = rtr_binding['edge_id']
    if edge_id:
        # delete from backend too
        _delete_edge_from_nsx_and_neutron(edge_id, router_id)
    else:
        # delete only from DB
        _delete_backup_from_neutron_db(None, router_id)


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
            edge['name'].startswith('backup-') and
            rtr_binding['router_id'] != edge['name']):
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
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    edgeapi = utils.NeutronDbClient()
    edge_id = properties.get('edge-id')
    if not edge_id:
        LOG.error("%s", errmsg)
        return
    try:
        # edge[0] is response status code
        # edge[1] is response body
        edge = nsxv.get_edge(edge_id)[1]
    except exceptions.NeutronException as e:
        LOG.error("%s", str(e))
    else:
        if edge['name'].startswith('backup-'):

            rtr_binding = nsxv_db.get_nsxv_router_binding_by_edge(
                    edgeapi.context.session, edge['id'])

            if rtr_binding['router_id'] == edge['name']:
                LOG.error('Edge %s no mismatch with NSX', edge_id)
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
                        elif (nsx_attr and
                              nsx_attr['router_type'] == 'exclusive'):
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
                                    'No database entry for router id %s',
                                    rtr_binding['router_id'])

                        else:
                            LOG.error(
                                'Could not determine the name for '
                                'Edge %s', edge_id)
                            return

                    if not kwargs.get('force'):
                        confirm = admin_utils.query_yes_no(
                            "Do you want to rename edge %s to %s" %
                            (edge_id, edge['name']),
                            default="no")

                        if not confirm:
                            LOG.info("Edge rename aborted by user")
                            return
                    LOG.info("Edge rename started")
                    # remove some keys that will fail the NSX transaction
                    edge_utils.remove_irrelevant_keys_from_edge_request(edge)
                    try:
                        LOG.error("Update edge...")
                        nsxv.update_edge(edge_id, edge)
                    except Exception as e:
                        LOG.error("Update failed - %s", (e))
            except Exception as e:
                LOG.error("%s", str(e))
        else:
            LOG.error(
                'Edge %s has no backup prefix on NSX', edge_id)
            return

registry.subscribe(nsx_list_backup_edges,
                   constants.BACKUP_EDGES,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_clean_backup_edge,
                   constants.BACKUP_EDGES,
                   shell.Operations.CLEAN.value)
registry.subscribe(nsx_clean_all_backup_edges,
                   constants.BACKUP_EDGES,
                   shell.Operations.CLEAN_ALL.value)
registry.subscribe(nsx_list_name_mismatches,
                   constants.BACKUP_EDGES,
                   shell.Operations.LIST_MISMATCHES.value)
registry.subscribe(nsx_fix_name_mismatch,
                   constants.BACKUP_EDGES,
                   shell.Operations.FIX_MISMATCH.value)
registry.subscribe(neutron_clean_backup_edge,
                   constants.BACKUP_EDGES,
                   shell.Operations.NEUTRON_CLEAN.value)
