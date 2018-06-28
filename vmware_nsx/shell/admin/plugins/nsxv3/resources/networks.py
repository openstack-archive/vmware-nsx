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

import sys

from vmware_nsx.db import db as nsx_db
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
from vmware_nsx.shell import resources as shell
from vmware_nsxlib.v3 import exceptions as nsx_exc

from neutron.db import db_base_plugin_v2
from neutron_lib.callbacks import registry
from neutron_lib import context as neutron_context
from oslo_log import log as logging

LOG = logging.getLogger(__name__)
neutron_client = utils.NeutronDbClient()


def get_network_nsx_id(context, neutron_id):
    # get the nsx switch id from the DB mapping
    mappings = nsx_db.get_nsx_switch_ids(context.session, neutron_id)
    if mappings and len(mappings) > 0:
        return mappings[0]


@admin_utils.output_header
def list_missing_networks(resource, event, trigger, **kwargs):
    """List neutron networks that are missing the NSX backend network
    """
    nsxlib = utils.get_connected_nsxlib()
    plugin = db_base_plugin_v2.NeutronDbPluginV2()
    admin_cxt = neutron_context.get_admin_context()
    filters = utils.get_plugin_filters(admin_cxt)
    neutron_networks = plugin.get_networks(admin_cxt, filters=filters)
    networks = []
    for net in neutron_networks:
        neutron_id = net['id']
        # get the network nsx id from the mapping table
        nsx_id = get_network_nsx_id(admin_cxt, neutron_id)
        if not nsx_id:
            # skip external networks
            pass
        else:
            try:
                nsxlib.logical_switch.get(nsx_id)
            except nsx_exc.ResourceNotFound:
                networks.append({'name': net['name'],
                                 'neutron_id': neutron_id,
                                 'nsx_id': nsx_id})
    if len(networks) > 0:
        title = ("Found %d internal networks missing from the NSX "
                 "manager:") % len(networks)
        LOG.info(formatters.output_formatter(
            title, networks,
            ['name', 'neutron_id', 'nsx_id']))
    else:
        LOG.info("All internal networks exist on the NSX manager")


@admin_utils.output_header
def list_orphaned_networks(resource, event, trigger, **kwargs):
    nsxlib = utils.get_connected_nsxlib()
    admin_cxt = neutron_context.get_admin_context()
    missing_networks = v3_utils.get_orphaned_networks(admin_cxt, nsxlib)
    LOG.info(formatters.output_formatter(constants.ORPHANED_NETWORKS,
                                         missing_networks,
                                         ['id', 'display_name']))


@admin_utils.output_header
def delete_backend_network(resource, event, trigger, **kwargs):
    errmsg = ("Need to specify nsx-id property. Add --property nsx-id=<id>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    nsx_id = properties.get('nsx-id')
    if not nsx_id:
        LOG.error("%s", errmsg)
        return

    nsxlib = utils.get_connected_nsxlib()
    # check if the network exists
    try:
        nsxlib.logical_switch.get(nsx_id, silent=True)
    except nsx_exc.ResourceNotFound:
        # prevent logger from logging this exception
        sys.exc_clear()
        LOG.warning("Backend network %s was not found.", nsx_id)
        return

    # try to delete it
    try:
        nsxlib.logical_switch.delete(nsx_id)
    except Exception as e:
        LOG.error("Failed to delete backend network %(id)s : %(e)s.", {
            'id': nsx_id, 'e': e})
        return

    # Verify that the network was deleted since the backend does not always
    # through errors
    try:
        nsxlib.logical_switch.get(nsx_id, silent=True)
    except nsx_exc.ResourceNotFound:
        # prevent logger from logging this exception
        sys.exc_clear()
        LOG.info("Backend network %s was deleted.", nsx_id)
    else:
        LOG.error("Failed to delete backend network %s.", nsx_id)


registry.subscribe(list_missing_networks,
                   constants.NETWORKS,
                   shell.Operations.LIST_MISMATCHES.value)

registry.subscribe(list_orphaned_networks,
                   constants.ORPHANED_NETWORKS,
                   shell.Operations.LIST.value)

registry.subscribe(delete_backend_network,
                   constants.ORPHANED_NETWORKS,
                   shell.Operations.NSX_CLEAN.value)
