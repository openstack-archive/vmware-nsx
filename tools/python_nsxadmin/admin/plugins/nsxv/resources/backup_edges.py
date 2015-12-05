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


LOG = logging.getLogger(__name__)
nsxv = utils.get_nsxv_client()


def get_nsxv_backup_edges():
    edges = nsxv.get_edges()[1]
    edges = edges['edgePage'].get('data', [])
    backup_edges = []
    for edge in edges:
        if edge['name'].startswith("backup-"):
            backup_edges.append(edge)
    return backup_edges


@admin_utils.output_header
def nsx_list_backup_edges(resource, event, trigger, **kwargs):
    """List backup edges"""
    backup_edges = get_nsxv_backup_edges()
    LOG.info(formatters.output_formatter(constants.BACKUP_EDGES, backup_edges,
                                         ['id']))


registry.subscribe(nsx_list_backup_edges,
                   constants.BACKUP_EDGES,
                   shell.Operations.LIST.value)
