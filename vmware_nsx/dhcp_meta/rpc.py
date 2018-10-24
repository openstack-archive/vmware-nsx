# Copyright 2013 VMware, Inc.
# All Rights Reserved
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
#

from neutron_lib import constants as const
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as ntn_exc
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.db import db_base_plugin_v2
from neutron.db import models_v2

from vmware_nsx.api_client import exception as api_exc
from vmware_nsx.common import config
from vmware_nsx.common import exceptions as nsx_exc

LOG = logging.getLogger(__name__)

METADATA_DEFAULT_PREFIX = 30
METADATA_SUBNET_CIDR = '169.254.169.252/%d' % METADATA_DEFAULT_PREFIX
METADATA_GATEWAY_IP = '169.254.169.253'
METADATA_DHCP_ROUTE = '169.254.169.254/32'


def handle_network_dhcp_access(plugin, context, network, action):
    pass


def handle_port_dhcp_access(plugin, context, port_data, action):
    pass


def handle_port_metadata_access(plugin, context, port, is_delete=False):
    # For instances supporting DHCP option 121 and created in a
    # DHCP-enabled but isolated network. This method is useful
    # only when no network namespace support.
    plugin_cfg = getattr(cfg.CONF, plugin.cfg_group)
    if (plugin_cfg.metadata_mode == config.MetadataModes.INDIRECT and
        port.get('device_owner') == const.DEVICE_OWNER_DHCP):
        if not port.get('fixed_ips'):
            # If port does not have an IP, the associated subnet is in
            # deleting state.
            LOG.info('Port %s has no IP due to subnet in deleting state',
                     port['id'])
            return
        fixed_ip = port['fixed_ips'][0]
        query = context.session.query(models_v2.Subnet)
        subnet = query.filter(
            models_v2.Subnet.id == fixed_ip['subnet_id']).one()
        # If subnet does not have a gateway, do not create metadata
        # route. This is done via the enable_isolated_metadata
        # option if desired.
        if not subnet.get('gateway_ip'):
            LOG.info('Subnet %s does not have a gateway, the '
                     'metadata route will not be created',
                     subnet['id'])
            return
        metadata_routes = [r for r in subnet.routes
                           if r['destination'] == METADATA_DHCP_ROUTE]
        if metadata_routes:
            # We should have only a single metadata route at any time
            # because the route logic forbids two routes with the same
            # destination. Update next hop with the provided IP address
            if not is_delete:
                metadata_routes[0].nexthop = fixed_ip['ip_address']
            else:
                context.session.delete(metadata_routes[0])
        else:
            # add the metadata route
            route = models_v2.SubnetRoute(
                subnet_id=subnet.id,
                destination=METADATA_DHCP_ROUTE,
                nexthop=fixed_ip['ip_address'])
            context.session.add(route)


def handle_router_metadata_access(plugin, context, router_id, interface=None):
    # For instances created in a DHCP-disabled network but connected to
    # a router.
    # The parameter "interface" is only used as a Boolean flag to indicate
    # whether to add (True) or delete (False) an internal metadata network.
    plugin_cfg = getattr(cfg.CONF, plugin.cfg_group)
    if plugin_cfg.metadata_mode != config.MetadataModes.DIRECT:
        LOG.debug("Metadata access network is disabled")
        return
    if not cfg.CONF.allow_overlapping_ips:
        LOG.warning("Overlapping IPs must be enabled in order to setup "
                    "the metadata access network")
        return
    ctx_elevated = context.elevated()
    on_demand = getattr(plugin_cfg, 'metadata_on_demand', False)
    try:
        if interface:
            # Add interface case
            filters = {'device_id': [router_id],
                       'device_owner': const.ROUTER_INTERFACE_OWNERS,
                       'fixed_ips': {'ip_address': [METADATA_GATEWAY_IP]}}
            # Retrieve metadata ports by calling database plugin
            ports = db_base_plugin_v2.NeutronDbPluginV2.get_ports(
                plugin, ctx_elevated, filters=filters)
            if not ports and (not on_demand or
                _find_dhcp_disabled_subnet_by_router(
                    plugin, ctx_elevated, router_id)):
                _create_metadata_access_network(
                    plugin, ctx_elevated, router_id)
        else:
            # Remove interface case
            filters = {'device_id': [router_id],
                       'device_owner': const.ROUTER_INTERFACE_OWNERS}
            # Retrieve router interface ports by calling database plugin
            ports = db_base_plugin_v2.NeutronDbPluginV2.get_ports(
                plugin, ctx_elevated, filters=filters)
            if len(ports) == 1 or (on_demand and not
                _find_dhcp_disabled_subnet_by_port(
                    plugin, ctx_elevated, ports)):
                # Delete the internal metadata network if the router port
                # is the last port left or no more DHCP-disabled subnet
                # attached to the router.
                _destroy_metadata_access_network(
                    plugin, ctx_elevated, router_id, ports)
    # TODO(salvatore-orlando): A better exception handling in the
    # NSX plugin would allow us to improve error handling here
    except (ntn_exc.NeutronException, nsx_exc.NsxPluginException,
            api_exc.NsxApiException):
        # Any exception here should be regarded as non-fatal
        LOG.exception("An error occurred while operating on the "
                      "metadata access network for router:'%s'",
                      router_id)


def _find_metadata_port(plugin, context, ports):
    for port in ports:
        for fixed_ip in port['fixed_ips']:
            if fixed_ip['ip_address'] == METADATA_GATEWAY_IP:
                return port


def _find_dhcp_disabled_subnet_by_port(plugin, context, ports):
    for port in ports:
        for fixed_ip in port['fixed_ips']:
            # NOTE(ihrachys) explicit use of reader.using guarantees we don't
            # fetch an old state of subnet with incorrect value for
            # enable_dhcp. A more correct fix would be switching all operations
            # of the vmware plugin (and base db neutron plugin) to engine
            # facade to avoid cross transaction session cache reuse but such
            # change wouldn't happen overnight.
            with db_api.CONTEXT_READER.using(context):
                subnet = plugin.get_subnet(context, fixed_ip['subnet_id'])
            if not subnet['enable_dhcp']:
                return subnet


def _find_dhcp_disabled_subnet_by_router(plugin, context, router_id):
    filters = {'device_id': [router_id],
               'device_owner': const.ROUTER_INTERFACE_OWNERS}
    ports = db_base_plugin_v2.NeutronDbPluginV2.get_ports(
        plugin, context, filters=filters)
    return _find_dhcp_disabled_subnet_by_port(plugin, context, ports)


def _create_metadata_access_network(plugin, context, router_id):
    # Add network
    # Network name is likely to be truncated on NSX
    net_data = {'name': 'meta-%s' % router_id,
                'tenant_id': '',  # intentionally not set
                'admin_state_up': True,
                'port_security_enabled': False,
                'shared': False,
                'status': const.NET_STATUS_ACTIVE}
    meta_net = plugin.create_network(context,
                                     {'network': net_data})
    plugin.schedule_network(context, meta_net)
    # From this point on there will be resources to garbage-collect
    # in case of failures
    meta_sub = None
    try:
        # Add subnet
        subnet_data = {'network_id': meta_net['id'],
                       'tenant_id': '',  # intentionally not set
                       'name': 'meta-%s' % router_id,
                       'ip_version': 4,
                       'shared': False,
                       'cidr': METADATA_SUBNET_CIDR,
                       'enable_dhcp': True,
                       # Ensure default allocation pool is generated
                       'allocation_pools': const.ATTR_NOT_SPECIFIED,
                       'gateway_ip': METADATA_GATEWAY_IP,
                       'dns_nameservers': [],
                       'host_routes': []}
        meta_sub = plugin.create_subnet(context,
                                        {'subnet': subnet_data})
        plugin.add_router_interface(context, router_id,
                                    {'subnet_id': meta_sub['id']})
        # Tell to start the metadata agent proxy, only if we had success
        _notify_rpc_agent(context, {'subnet': meta_sub}, 'subnet.create.end')
    except (ntn_exc.NeutronException,
            nsx_exc.NsxPluginException,
            api_exc.NsxApiException):
        # It is not necessary to explicitly delete the subnet
        # as it will be removed with the network
        plugin.delete_network(context, meta_net['id'])


def _destroy_metadata_access_network(plugin, context, router_id, ports):
    if not ports:
        return
    meta_port = _find_metadata_port(plugin, context, ports)
    if not meta_port:
        return
    meta_net_id = meta_port['network_id']
    meta_sub_id = meta_port['fixed_ips'][0]['subnet_id']
    plugin.remove_router_interface(
        context, router_id, {'port_id': meta_port['id']})
    context.session.expunge_all()
    try:
        # Remove network (this will remove the subnet too)
        plugin.delete_network(context, meta_net_id)
    except (ntn_exc.NeutronException, nsx_exc.NsxPluginException,
            api_exc.NsxApiException):
        # must re-add the router interface
        plugin.add_router_interface(context, router_id,
                                    {'subnet_id': meta_sub_id})
    except db_exc.DBReferenceError as e:
        LOG.debug("Unable to delete network %s. Reason: %s", meta_net_id, e)
    # Tell to stop the metadata agent proxy
    _notify_rpc_agent(
        context, {'network': {'id': meta_net_id}}, 'network.delete.end')


def _notify_rpc_agent(context, payload, event):
    if cfg.CONF.dhcp_agent_notification:
        dhcp_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        dhcp_notifier.notify(context, payload, event)
