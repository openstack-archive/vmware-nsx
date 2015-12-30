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

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters

import vmware_nsx.shell.admin.plugins.common.utils as admin_utils
import vmware_nsx.shell.admin.plugins.nsxv.resources.utils as utils
import vmware_nsx.shell.nsxadmin as shell

from neutron.callbacks import registry
from neutron.common import exceptions

from vmware_nsx._i18n import _LE, _LI
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db


LOG = logging.getLogger(__name__)
nsxv = utils.get_nsxv_client()


def get_nsxv_backup_edges():
    edges = nsxv.get_edges()[1]
    edges = edges['edgePage'].get('data', [])
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
                                         ['id']))


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
    except exceptions.NeutronException as e:
        LOG.error(_LE("%s"), str(e))
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
            with locking.LockManager.get_lock(
                'nsx-edge-request', lock_file_prefix='get-'):
                # Delete from NSXv backend
                nsxv.delete_edge(edge_id)
                # Remove bindings from Neutron DB
                edgeapi = utils.NeutronDbClient()
                nsxv_db.delete_nsxv_router_binding(
                    edgeapi.context.session, edge[1]['name'])
        except Exception as e:
            LOG.error(_LE("%s"), str(e))


registry.subscribe(nsx_list_backup_edges,
                   constants.BACKUP_EDGES,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_clean_backup_edge,
                   constants.BACKUP_EDGES,
                   shell.Operations.CLEAN.value)
