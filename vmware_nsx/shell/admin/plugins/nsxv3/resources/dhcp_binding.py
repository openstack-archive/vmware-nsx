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

import netaddr

from neutron_lib.callbacks import registry
from neutron_lib import constants as const
from neutron_lib import context as neutron_context
from neutron_lib import exceptions
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
import vmware_nsx.shell.resources as shell
from vmware_nsxlib.v3 import nsx_constants

LOG = logging.getLogger(__name__)
neutron_client = utils.NeutronDbClient()


@admin_utils.output_header
def list_dhcp_bindings(resource, event, trigger, **kwargs):
    """List DHCP bindings in Neutron."""

    comp_ports = [port for port in neutron_client.get_ports()
                  if nsx_utils.is_port_dhcp_configurable(port)]
    LOG.info(formatters.output_formatter(constants.DHCP_BINDING, comp_ports,
                                         ['id', 'mac_address', 'fixed_ips']))


@admin_utils.output_header
def nsx_update_dhcp_bindings(resource, event, trigger, **kwargs):
    """Resync DHCP bindings for NSXv3 CrossHairs."""

    nsxlib = utils.get_connected_nsxlib()
    nsx_version = nsxlib.get_version()
    if not nsx_utils.is_nsx_version_1_1_0(nsx_version):
        LOG.error("This utility is not available for NSX version %s",
                  nsx_version)
        return

    dhcp_profile_uuid = None
    # TODO(asarfaty) Add availability zones support here
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        dhcp_profile_uuid = properties.get('dhcp_profile_uuid')
    if not dhcp_profile_uuid:
        LOG.error("dhcp_profile_uuid is not defined")
        return

    cfg.CONF.set_override('dhcp_agent_notification', False)
    cfg.CONF.set_override('native_dhcp_metadata', True, 'nsx_v3')
    cfg.CONF.set_override('dhcp_profile', dhcp_profile_uuid, 'nsx_v3')

    port_bindings = {}    # lswitch_id: [(port_id, mac, ip), ...]
    server_bindings = {}  # lswitch_id: dhcp_server_id
    ports = neutron_client.get_ports()
    for port in ports:
        device_owner = port['device_owner']
        if (device_owner != const.DEVICE_OWNER_DHCP and
            not nsx_utils.is_port_dhcp_configurable(port)):
            continue
        for fixed_ip in port['fixed_ips']:
            if netaddr.IPNetwork(fixed_ip['ip_address']).version == 6:
                continue
            network_id = port['network_id']
            subnet = neutron_client.get_subnet(None, fixed_ip['subnet_id'])
            if device_owner == const.DEVICE_OWNER_DHCP:
                # For each DHCP-enabled network, create a logical DHCP server
                # and update the attachment type to DHCP on the corresponding
                # logical port of the Neutron DHCP port.
                network = neutron_client.get_network(None, port['network_id'])
                net_tags = nsxlib.build_v3_tags_payload(
                    network, resource_type='os-neutron-net-id',
                    project_name='admin')
                # TODO(asarfaty): add default_dns_nameservers & dns_domain
                # from availability zone
                server_data = nsxlib.native_dhcp.build_server_config(
                    network, subnet, port, net_tags)
                server_data['dhcp_profile_id'] = dhcp_profile_uuid
                dhcp_server = nsxlib.dhcp_server.create(**server_data)
                LOG.info("Created logical DHCP server %(server)s for "
                         "network %(network)s",
                         {'server': dhcp_server['id'],
                          'network': port['network_id']})
                # Add DHCP service binding in neutron DB.
                neutron_client.add_dhcp_service_binding(
                    network['id'], port['id'], dhcp_server['id'])
                # Update logical port for DHCP purpose.
                lswitch_id, lport_id = (
                    neutron_client.get_lswitch_and_lport_id(port['id']))
                nsxlib.logical_port.update(
                    lport_id, dhcp_server['id'],
                    attachment_type=nsx_constants.ATTACHMENT_DHCP)
                server_bindings[lswitch_id] = dhcp_server['id']
                LOG.info("Updated DHCP logical port %(port)s for "
                         "network %(network)s",
                         {'port': lport_id, 'network': port['network_id']})
            elif subnet['enable_dhcp']:
                # Store (mac, ip) binding of each compute port in a
                # DHCP-enabled subnet.
                lswitch_id = neutron_client.net_id_to_lswitch_id(network_id)
                bindings = port_bindings.get(lswitch_id, [])
                bindings.append((port['id'], port['mac_address'],
                                 fixed_ip['ip_address'],
                                 fixed_ip['subnet_id']))
                port_bindings[lswitch_id] = bindings
            break  # process only the first IPv4 address

    # Populate mac/IP bindings in each logical DHCP server.
    for lswitch_id, bindings in port_bindings.items():
        dhcp_server_id = server_bindings.get(lswitch_id)
        if not dhcp_server_id:
            continue
        for (port_id, mac, ip, subnet_id) in bindings:
            hostname = 'host-%s' % ip.replace('.', '-')
            options = {'option121': {'static_routes': [
                {'network': '%s' % cfg.CONF.nsx_v3.native_metadata_route,
                 'next_hop': ip}]}}
            subnet = neutron_client.get_subnet(None, subnet_id)
            binding = nsxlib.dhcp_server.create_binding(
                dhcp_server_id, mac, ip, hostname,
                cfg.CONF.nsx_v3.dhcp_lease_time, options,
                subnet.get('gateway_ip'))
            # Add DHCP static binding in neutron DB.
            neutron_client.add_dhcp_static_binding(
                port_id, subnet_id, ip, dhcp_server_id, binding['id'])
            LOG.info("Added DHCP binding (mac: %(mac)s, ip: %(ip)s) "
                     "for neutron port %(port)s",
                     {'mac': mac, 'ip': ip, 'port': port_id})


@admin_utils.output_header
def nsx_recreate_dhcp_server(resource, event, trigger, **kwargs):
    """Recreate DHCP server & binding for a neutron network"""
    if not cfg.CONF.nsx_v3.native_dhcp_metadata:
        LOG.error("Native DHCP is disabled.")
        return

    errmsg = ("Need to specify net-id property. Add --property net-id=<id>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    net_id = properties.get('net-id')
    if not net_id:
        LOG.error("%s", errmsg)
        return

    context = neutron_context.get_admin_context()
    with utils.NsxV3PluginWrapper() as plugin:
        # verify that this is an existing network with dhcp enabled
        try:
            network = plugin._get_network(context, net_id)
        except exceptions.NetworkNotFound:
            LOG.error("Network %s was not found", net_id)
            return
        if plugin._has_no_dhcp_enabled_subnet(context, network):
            LOG.error("Network %s has no DHCP enabled subnet", net_id)
            return
        dhcp_relay = plugin.get_network_az_by_net_id(
            context, net_id).dhcp_relay_service
        if dhcp_relay:
            LOG.error("Native DHCP should not be enabled with dhcp relay")
            return

        # find the dhcp subnet of this network
        subnet_id = None
        for subnet in network.subnets:
            if subnet.enable_dhcp:
                subnet_id = subnet.id
                break
        if not subnet_id:
            LOG.error("Network %s has no DHCP enabled subnet", net_id)
            return
        dhcp_subnet = plugin.get_subnet(context, subnet_id)
        # disable and re-enable the dhcp
        plugin._enable_native_dhcp(context, network, dhcp_subnet)
    LOG.info("Done.")


registry.subscribe(list_dhcp_bindings,
                   constants.DHCP_BINDING,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_update_dhcp_bindings,
                   constants.DHCP_BINDING,
                   shell.Operations.NSX_UPDATE.value)
registry.subscribe(nsx_recreate_dhcp_server,
                   constants.DHCP_BINDING,
                   shell.Operations.NSX_RECREATE.value)
