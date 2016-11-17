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


import logging

from vmware_nsx._i18n import _LI
from vmware_nsx.db import db as nsx_db
from vmware_nsx.nsxlib.v3 import exceptions as nsx_exc
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
from vmware_nsx.shell import resources as shell

from neutron.callbacks import registry
from neutron import context as neutron_context
from neutron.db import db_base_plugin_v2

LOG = logging.getLogger(__name__)


def get_network_nsx_id(context, neutron_id):
    # get the nsx switch id from the DB mapping
    mappings = nsx_db.get_nsx_switch_ids(context.session, neutron_id)
    if mappings and len(mappings) > 0:
        return mappings[0]


@admin_utils.output_header
def list_missing_networks(resource, event, trigger, **kwargs):
    """List neutron networks that are missing the NSX backend network
    """
    plugin = db_base_plugin_v2.NeutronDbPluginV2()
    admin_cxt = neutron_context.get_admin_context()
    neutron_networks = plugin.get_networks(admin_cxt)
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
                utils.get_connected_nsxlib().get_logical_switch(nsx_id)
            except nsx_exc.ResourceNotFound:
                networks.append({'name': net['name'],
                                 'neutron_id': neutron_id,
                                 'nsx_id': nsx_id})
    if len(networks) > 0:
        title = _LI("Found %d internal networks missing from the NSX "
                    "manager:") % len(networks)
        LOG.info(formatters.output_formatter(
            title, networks,
            ['name', 'neutron_id', 'nsx_id']))
    else:
        LOG.info(_LI("All internal networks exist on the NSX manager"))


registry.subscribe(list_missing_networks,
                   constants.NETWORKS,
                   shell.Operations.LIST_MISMATCHES.value)
