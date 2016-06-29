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
from neutron_lib import constants as const
from oslo_config import cfg

from vmware_nsx._i18n import _LI
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils as comm_utils
from vmware_nsx.dhcp_meta import rpc as nsx_rpc
from vmware_nsx.nsxlib import v3 as nsxlib
from vmware_nsx.nsxlib.v3 import client
from vmware_nsx.nsxlib.v3 import cluster
from vmware_nsx.nsxlib.v3 import native_dhcp
from vmware_nsx.nsxlib.v3 import resources
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
import vmware_nsx.shell.resources as shell

LOG = logging.getLogger(__name__)
neutron_client = utils.NeutronDbClient()


@admin_utils.output_header
def list_dhcp_bindings(resource, event, trigger, **kwargs):
    """List DHCP bindings in Neutron."""

    ports = neutron_client.get_ports()
    comp_ports = [port for port in ports if port['device_owner'].startswith(
        const.DEVICE_OWNER_COMPUTE_PREFIX)]
    LOG.info(formatters.output_formatter(constants.DHCP_BINDING, comp_ports,
                                         ['id', 'mac_address', 'fixed_ips']))


@admin_utils.output_header
def nsx_update_dhcp_bindings(resource, event, trigger, **kwargs):
    """Resync DHCP bindings for NSXv3 CrossHairs."""

    nsx_version = nsxlib.get_version()
    if not comm_utils.is_nsx_version_1_1_0(nsx_version):
        LOG.info(_LI("This utility is not available for NSX version %s"),
                 nsx_version)
        return

    cluster_api = cluster.NSXClusteredAPI()
    nsx_client = client.NSX3Client(cluster_api)
    client._set_default_api_cluster(cluster_api)
    port_resource = resources.LogicalPort(nsx_client)
    dhcp_server_resource = resources.LogicalDhcpServer(nsx_client)

    port_bindings = {}    # lswitch_id: [(mac, ip, prefix_length), ...]
    server_bindings = {}  # lswitch_id: dhcp_server_id
    ports = neutron_client.get_ports()
    for port in ports:
        network_id = port['network_id']
        device_owner = port['device_owner']
        if device_owner == const.DEVICE_OWNER_DHCP:
            # For each DHCP-enabled network, create a logical DHCP server
            # and update the attachment type to DHCP on the corresponding
            # logical port of the Neutron DHCP port.
            subnet_id = port['fixed_ips'][0]['subnet_id']
            subnet = neutron_client.get_subnet(subnet_id)
            network = neutron_client.get_network(port['network_id'])
            if len(port['fixed_ips']) > 1:
                LOG.info(_LI("Network %(network)s has multiple subnets - "
                             "only enable native DHCP on subnet %(subnet)s"),
                         {'network': port['network_id'], 'subnet': subnet_id})
            server_data = native_dhcp.build_dhcp_server_config(
                network, subnet, port, 'NSX Neutron plugin upgrade')
            dhcp_server = dhcp_server_resource.create(**server_data)
            lswitch_id, lport_id = neutron_client.get_lswitch_and_lport_id(
                port['id'])
            port_resource.update(lport_id, dhcp_server['id'],
                                 attachment_type=nsx_constants.ATTACHMENT_DHCP)
            server_bindings[lswitch_id] = dhcp_server['id']
        elif device_owner.startswith(const.DEVICE_OWNER_COMPUTE_PREFIX):
            lswitch_id = neutron_client.net_id_to_lswitch_id(network_id)
            bindings = port_bindings.get(lswitch_id, [])
            bindings.append((port['mac_address'],
                             port['fixed_ips'][0]['ip_address']))
            port_bindings[lswitch_id] = bindings

    # Populate mac/IP bindings in each logical DHCP server.
    for lswitch_id, bindings in port_bindings.items():
        dhcp_server_id = server_bindings[lswitch_id]
        for (mac, ip) in bindings:
            hostname = 'host-%s' % ip.replace('.', '-')
            options = {'option121': {'static_routes': [
                {'network': '%s' % nsx_rpc.METADATA_DHCP_ROUTE,
                 'next_hop': ip}]}}
            dhcp_server_resource.create_binding(
                dhcp_server_id, mac, ip, hostname,
                cfg.CONF.nsx_v3.dhcp_lease_time, options)


registry.subscribe(list_dhcp_bindings,
                   constants.DHCP_BINDING,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_update_dhcp_bindings,
                   constants.DHCP_BINDING,
                   shell.Operations.NSX_UPDATE.value)
