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

from sqlalchemy.orm import exc

from vmware_nsx._i18n import _LI
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import nsx_models
from vmware_nsx.nsxlib.v3 import client as nsx_client
from vmware_nsx.nsxlib.v3 import cluster as nsx_cluster
from vmware_nsx.nsxlib.v3 import resources as nsx_resources
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell import nsxadmin as shell

from neutron.callbacks import registry
from neutron import context as neutron_context
from neutron.db import db_base_plugin_v2

LOG = logging.getLogger(__name__)


def get_port_nsx_id(session, neutron_id):
    # get the nsx port id from the DB mapping
    try:
        mapping = (session.query(nsx_models.NeutronNsxPortMapping).
                   filter_by(neutron_id=neutron_id).
                   one())
        return mapping['nsx_port_id']
    except exc.NoResultFound:
        pass


def get_port_client():
    _api_cluster = nsx_cluster.NSXClusteredAPI()
    _nsx_client = nsx_client.NSX3Client(_api_cluster)
    return nsx_resources.LogicalPort(_nsx_client)


@admin_utils.output_header
def list_missing_ports(resource, event, trigger, **kwargs):
    """List neutron ports that are missing the NSX backend port
    """
    plugin = db_base_plugin_v2.NeutronDbPluginV2()
    admin_cxt = neutron_context.get_admin_context()
    neutron_ports = plugin.get_ports(admin_cxt)
    port_client = get_port_client()
    ports = []
    for port in neutron_ports:
        neutron_id = port['id']
        # get the network nsx id from the mapping table
        nsx_id = get_port_nsx_id(admin_cxt.session, neutron_id)
        if not nsx_id:
            # skip external ports
            pass
        else:
            try:
                port_client.get(nsx_id)
            except nsx_exc.ResourceNotFound:
                ports.append({'name': port['name'],
                              'neutron_id': neutron_id,
                              'nsx_id': nsx_id})
    if len(ports) > 0:
        title = _LI("Found %d internal ports missing from the NSX "
                    "manager:") % len(ports)
        LOG.info(formatters.output_formatter(
            title, ports,
            ['name', 'neutron_id', 'nsx_id']))
    else:
        LOG.info(_LI("All internal ports exist on the NSX manager"))


registry.subscribe(list_missing_ports,
                   constants.PORTS,
                   shell.Operations.LIST_MISMATCHES.value)
