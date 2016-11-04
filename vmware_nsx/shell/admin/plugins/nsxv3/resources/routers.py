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
from vmware_nsx.nsxlib.v3 import resources as nsx_resources
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
from vmware_nsx.shell import resources as shell

from neutron.callbacks import registry
from neutron import context as neutron_context
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db

LOG = logging.getLogger(__name__)


class RoutersPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                    l3_db.L3_NAT_db_mixin):
    pass


def get_router_client():
    _nsx_client = utils.get_nsxv3_client()
    return nsx_resources.LogicalRouter(_nsx_client)


@admin_utils.output_header
def list_missing_routers(resource, event, trigger, **kwargs):
    """List neutron routers that are missing the NSX backend router
    """
    plugin = RoutersPlugin()
    admin_cxt = neutron_context.get_admin_context()
    neutron_routers = plugin.get_routers(admin_cxt)
    router_client = get_router_client()
    routers = []
    for router in neutron_routers:
        neutron_id = router['id']
        # get the network nsx id from the mapping table
        nsx_id = nsx_db.get_nsx_router_id(admin_cxt.session,
                                          neutron_id)
        if not nsx_id:
            routers.append({'name': router['name'],
                            'neutron_id': neutron_id,
                            'nsx_id': None})
        else:
            try:
                router_client.get(nsx_id)
            except nsx_exc.ResourceNotFound:
                routers.append({'name': router['name'],
                              'neutron_id': neutron_id,
                              'nsx_id': nsx_id})
    if len(routers) > 0:
        title = _LI("Found %d routers missing from the NSX "
                    "manager:") % len(routers)
        LOG.info(formatters.output_formatter(
            title, routers,
            ['name', 'neutron_id', 'nsx_id']))
    else:
        LOG.info(_LI("All routers exist on the NSX manager"))


registry.subscribe(list_missing_routers,
                   constants.ROUTERS,
                   shell.Operations.LIST_MISMATCHES.value)
