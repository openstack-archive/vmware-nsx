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

from neutron_lib.callbacks import registry
from neutron_lib import constants as const
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.dhcp_meta import rpc as nsx_rpc
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
import vmware_nsx.shell.resources as shell
from vmware_nsxlib.v3 import nsx_constants

LOG = logging.getLogger(__name__)
neutron_client = utils.NeutronDbClient()


def _is_metadata_network(network):
    # If a Neutron network has only one subnet with 169.254.169.252/30 CIDR,
    # then it is an internal metadata network.
    if len(network['subnets']) == 1:
        subnet = neutron_client.get_subnet(network['subnets'][0])
        if subnet['cidr'] == nsx_rpc.METADATA_SUBNET_CIDR:
            return True
    return False


@admin_utils.output_header
def list_metadata_networks(resource, event, trigger, **kwargs):
    """List Metadata networks in Neutron."""

    meta_networks = [network for network in neutron_client.get_networks()
                     if _is_metadata_network(network)]
    LOG.info(formatters.output_formatter(constants.METADATA_PROXY,
                                         meta_networks,
                                         ['id', 'name', 'subnets']))


@admin_utils.output_header
def nsx_update_metadata_proxy(resource, event, trigger, **kwargs):
    """Update Metadata proxy for NSXv3 CrossHairs."""

    nsxlib = utils.get_connected_nsxlib()
    nsx_version = nsxlib.get_version()
    if not nsx_utils.is_nsx_version_1_1_0(nsx_version):
        LOG.error("This utility is not available for NSX version %s",
                  nsx_version)
        return

    metadata_proxy_uuid = None
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        metadata_proxy_uuid = properties.get('metadata_proxy_uuid')
    if not metadata_proxy_uuid:
        LOG.error("metadata_proxy_uuid is not defined")
        return

    cfg.CONF.set_override('dhcp_agent_notification', False)
    cfg.CONF.set_override('native_dhcp_metadata', True, 'nsx_v3')
    cfg.CONF.set_override('metadata_proxy', metadata_proxy_uuid, 'nsx_v3')

    with utils.NsxV3PluginWrapper() as plugin:
        # For each Neutron network, check if it is an internal metadata
        # network.
        # If yes, delete the network and associated router interface.
        # Otherwise, create a logical switch port with MD-Proxy attachment.
        for network in neutron_client.get_networks():
            if _is_metadata_network(network):
                # It is a metadata network, find the attached router,
                # remove the router interface and the network.
                filters = {'device_owner': const.ROUTER_INTERFACE_OWNERS,
                           'fixed_ips': {
                               'subnet_id': [network['subnets'][0]],
                               'ip_address': [nsx_rpc.METADATA_GATEWAY_IP]}}
                ports = neutron_client.get_ports(filters=filters)
                if not ports:
                    continue
                router_id = ports[0]['device_id']
                interface = {'subnet_id': network['subnets'][0]}
                plugin.remove_router_interface(router_id, interface)
                LOG.info("Removed metadata interface on router %s", router_id)
                plugin.delete_network(network['id'])
                LOG.info("Removed metadata network %s", network['id'])
            else:
                lswitch_id = neutron_client.net_id_to_lswitch_id(
                    network['id'])
                if not lswitch_id:
                    continue
                tags = nsxlib.build_v3_tags_payload(
                    network, resource_type='os-neutron-net-id',
                    project_name='admin')
                name = nsx_utils.get_name_and_uuid('%s-%s' % (
                    'mdproxy', network['name'] or 'network'), network['id'])
                # check if this logical port already exists
                existing_ports = nsxlib.logical_port.find_by_display_name(
                    name)
                if not existing_ports:
                    # create a new port with the md-proxy
                    nsxlib.logical_port.create(
                        lswitch_id, metadata_proxy_uuid, tags=tags, name=name,
                        attachment_type=nsx_constants.ATTACHMENT_MDPROXY)
                    LOG.info("Enabled native metadata proxy for network %s",
                             network['id'])
                else:
                    # update the MDproxy of this port
                    port = existing_ports[0]
                    nsxlib.logical_port.update(
                        port['id'], metadata_proxy_uuid,
                        attachment_type=nsx_constants.ATTACHMENT_MDPROXY)
                    LOG.info("Updated native metadata proxy for network %s",
                             network['id'])


registry.subscribe(list_metadata_networks,
                   constants.METADATA_PROXY,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_update_metadata_proxy,
                   constants.METADATA_PROXY,
                   shell.Operations.NSX_UPDATE.value)
