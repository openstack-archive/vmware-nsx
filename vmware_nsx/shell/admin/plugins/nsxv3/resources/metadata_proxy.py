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

from neutron.callbacks import registry
from oslo_config import cfg

from vmware_nsx._i18n import _LI, _LE
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.nsxlib.v3 import client
from vmware_nsx.nsxlib.v3 import cluster
from vmware_nsx.nsxlib.v3 import resources
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
import vmware_nsx.shell.nsxadmin as shell

LOG = logging.getLogger(__name__)
neutron_client = utils.NeutronDbClient()


@admin_utils.output_header
def nsx_update_metadata_proxy(resource, event, trigger, **kwargs):
    """Update Metadata proxy for NSXv3 CrossHairs."""

    cluster_api = cluster.NSXClusteredAPI()
    nsx_client = client.NSX3Client(cluster_api)
    client._set_default_api_cluster(cluster_api)
    port_resource = resources.LogicalPort(nsx_client)

    for network in neutron_client.get_networks():
        # For each Neutron network, create a logical switch port with
        # MD-Proxy attachment.
        lswitch_id = neutron_client.net_id_to_lswitch_id(network['id'])
        if lswitch_id:
            tags = nsx_utils.build_v3_tags_payload(
                network, resource_type='os-neutron-net-id',
                project_name='NSX Neutron plugin upgrade')
            port_resource.create(
                lswitch_id, cfg.CONF.nsx_v3.metadata_proxy_uuid, tags=tags,
                attachment_type=nsx_constants.ATTACHMENT_MDPROXY)
            LOG.info(_LI("Enabled native metadata proxy for network %s"),
                     network['id'])
        else:
            LOG.error(_LE("Unable to find logical switch for network %s"),
                      network['id'])

registry.subscribe(nsx_update_metadata_proxy,
                   constants.METADATA_PROXY,
                   shell.Operations.NSX_UPDATE.value)
