# Copyright 2017 VMware, Inc.  All rights reserved.
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
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.common import config
from vmware_nsx.common import nsxv_constants
from vmware_nsx.plugins.nsx_v import availability_zones as nsx_az
from vmware_nsx.plugins.nsx_v.vshield.common import constants as vcns_const
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions
from vmware_nsx.plugins.nsx_v.vshield import vcns_driver
from vmware_nsx.services.dynamic_routing.nsx_v import driver as nsxv_bgp
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils as v_utils
from vmware_nsx.shell import resources as shell

LOG = logging.getLogger(__name__)
MIN_ASNUM = 1
MAX_ASNUM = 65535

nsxv = vcns_driver.VcnsDriver([])


def get_ip_prefix(name, ip_address):
    return {'ipPrefix': {'name': name, 'ipAddress': ip_address}}


def get_redistribution_rule(prefix_name, from_bgp, from_ospf,
                            from_static, from_connected, action):
    rule = {
        'action': action,
        'from': {
            'ospf': from_ospf,
            'bgp': from_bgp,
            'connected': from_connected,
            'static': from_static
        }
    }
    if prefix_name:
        rule['prefixName'] = prefix_name
    return {'rule': rule}


def _validate_asn(asn):
    if not MIN_ASNUM <= int(asn) <= MAX_ASNUM:
        msg = "Invalid AS number, expecting an integer value (1 - 65535)."
        LOG.error(msg)
        return False
    return True


def _extract_interface_info(info):
    info = info.split(':')
    try:
        network = netaddr.IPNetwork(info[-1])
    except Exception:
        LOG.error("Invalid IP address given: '%s'.", info)
        return None

    portgroup = info[0]
    subnet_mask = str(network.netmask)
    ip_address = str(network.ip)

    return portgroup, ip_address, subnet_mask


def _assemble_gw_edge(name, size, external_iface_info, internal_iface_info,
                      default_gateway, az):
    edge = nsxv._assemble_edge(
        name, datacenter_moid=az.datacenter_moid,
        deployment_container_id=az.datastore_id,
        appliance_size=size,
        remote_access=False, edge_ha=az.edge_ha)
    appliances = [nsxv._assemble_edge_appliance(
        az.resource_pool, az.datastore_id)]
    edge['appliances']['appliances'] = appliances

    portgroup, ip_address, subnet_mask = external_iface_info
    vnic_external = nsxv._assemble_edge_vnic(vcns_const.EXTERNAL_VNIC_NAME,
                                             vcns_const.EXTERNAL_VNIC_INDEX,
                                             portgroup,
                                             primary_address=ip_address,
                                             subnet_mask=subnet_mask,
                                             type="uplink")

    portgroup, gateway_ip, subnet_mask = internal_iface_info
    vnic_internal = nsxv._assemble_edge_vnic(vcns_const.INTERNAL_VNIC_NAME,
                                             vcns_const.INTERNAL_VNIC_INDEX,
                                             portgroup,
                                             primary_address=gateway_ip,
                                             subnet_mask=subnet_mask,
                                             type="internal")

    if (cfg.CONF.nsxv.edge_appliance_user and
        cfg.CONF.nsxv.edge_appliance_password):
        edge['cliSettings'].update({
            'userName': cfg.CONF.nsxv.edge_appliance_user,
            'password': cfg.CONF.nsxv.edge_appliance_password})

    edge['vnics']['vnics'].append(vnic_external)
    edge['vnics']['vnics'].append(vnic_internal)

    edge['featureConfigs']['features'] = [{'featureType': 'firewall_4.0',
                                           'enabled': False}]
    if default_gateway:
        routing = {'featureType': 'routing_4.0',
                   'enabled': True,
                   'staticRouting': {
                       'defaultRoute': {
                           'description': 'default-gateway',
                           'gatewayAddress': default_gateway
                       }
                   }}
        edge['featureConfigs']['features'].append(routing)

    header = nsxv.vcns.deploy_edge(edge)[0]
    edge_id = header.get('location', '/').split('/')[-1]
    return edge_id, gateway_ip


@admin_utils.output_header
def create_bgp_gw(resource, event, trigger, **kwargs):
    """Creates a new BGP GW edge"""
    usage = ("nsxadmin -r bgp-gw-edge -o create "
             "--property name=<GW_EDGE_NAME> "
             "--property local-as=<LOCAL_AS_NUMBER> "
             "--property external-iface=<PORTGROUP>:<IP_ADDRESS/PREFIX_LEN> "
             "--property internal-iface=<PORTGROUP>:<IP_ADDRESS/PREFIX_LEN> "
             "[--property default-gateway=<IP_ADDRESS>] "
             "[--property az-hint=<AZ_HINT>] "
             "[--property size=compact,large,xlarge,quadlarge]")
    required_params = ('name', 'local-as',
                       'internal-iface', 'external-iface')
    properties = admin_utils.parse_multi_keyval_opt(kwargs.get('property', []))
    if not properties or not set(required_params) <= set(properties.keys()):
        LOG.error(usage)
        return

    local_as = properties['local-as']
    if not _validate_asn(local_as):
        return

    size = properties.get('size', nsxv_constants.LARGE)
    if size not in vcns_const.ALLOWED_EDGE_SIZES:
        msg = ("Property 'size' takes one of the following values: %s."
               % ','.join(vcns_const.ALLOWED_EDGE_SIZES))
        LOG.error(msg)
        return

    external_iface_info = _extract_interface_info(properties['external-iface'])
    internal_iface_info = _extract_interface_info(properties['internal-iface'])
    if not (external_iface_info and internal_iface_info):
        return

    if 'default-gateway' in properties:
        default_gw = _extract_interface_info(properties['default-gateway'])
        if not default_gw:
            msg = ("Property 'default-gateway' doesn't contain a valid IP "
                   "address.")
            LOG.error(msg)
            return
        default_gw = default_gw[1]
    else:
        default_gw = None

    config.register_nsxv_azs(cfg.CONF, cfg.CONF.nsxv.availability_zones)
    az_hint = properties.get('az-hint', 'default')
    az = nsx_az.NsxVAvailabilityZones().get_availability_zone(az_hint)

    edge_id, gateway_ip = _assemble_gw_edge(properties['name'],
                                            size,
                                            external_iface_info,
                                            internal_iface_info,
                                            default_gw,
                                            az)
    nsxv.add_bgp_speaker_config(edge_id, gateway_ip, local_as,
                                True, [], [], [], default_originate=True)

    res = {'name': properties['name'],
           'edge_id': edge_id,
           'size': size,
           'availability_zone': az.name,
           'bgp_identifier': gateway_ip,
           'local_as': local_as}
    headers = ['name', 'edge_id', 'size', 'bgp_identifier',
               'availability_zone', 'local_as']
    LOG.info(formatters.output_formatter('BGP GW Edge', [res], headers))


def delete_bgp_gw(resource, event, trigger, **kwargs):
    usage = ("nsxadmin -r bgp-gw-edge -o delete "
             "--property gw-edge-id=<EDGE_ID>")
    required_params = ('gw-edge-id', )
    properties = admin_utils.parse_multi_keyval_opt(kwargs.get('property', []))
    if not properties or not set(required_params) <= set(properties.keys()):
        LOG.error(usage)
        return
    edge_id = properties['gw-edge-id']
    try:
        nsxv.vcns.delete_edge(edge_id)
    except Exception:
        LOG.error("Failed to delete edge %s", edge_id)
        return


def list_bgp_edges(resource, event, trigger, **kwargs):
    bgp_edges = []
    edges = v_utils.get_nsxv_backend_edges()
    for edge in edges:
        bgp_config = nsxv.get_routing_bgp_config(edge['id'])
        if bgp_config['bgp']['enabled']:
            bgp_edges.append({'name': edge['name'],
                              'edge_id': edge['id'],
                              'local_as': bgp_config['bgp']['localAS']})
    if not bgp_edges:
        LOG.info("No BGP GW edges found")
        return

    headers = ['name', 'edge_id', 'local_as']
    LOG.info(formatters.output_formatter(constants.EDGES, bgp_edges, headers))


@admin_utils.output_header
def create_redis_rule(resource, event, trigger, **kwargs):
    usage = ("nsxadmin -r routing-redistribution-rule -o create "
             "--property gw-edge-ids=<GW_EDGE_ID>[,...] "
             "[--property prefix=<NAME:CIDR>] "
             "--property learn-from=ospf,bgp,connected,static "
             "--property action=<permit/deny>")
    required_params = ('gw-edge-ids', 'learn-from', 'action')
    properties = admin_utils.parse_multi_keyval_opt(kwargs.get('property', []))
    if not properties or not set(required_params) <= set(properties.keys()):
        LOG.error(usage)
        return

    prefix = properties.get('prefix')
    if prefix:
        prefix_name, cidr = prefix.split(':')
        prefixes = [get_ip_prefix(prefix_name, cidr)] if cidr else []
    else:
        prefix_name = None
        prefixes = []

    learn_from = properties['learn-from'].split(',')

    rule = get_redistribution_rule(prefix_name,
                                   'bgp' in learn_from,
                                   'ospf' in learn_from,
                                   'static' in learn_from,
                                   'connected' in learn_from,
                                   properties['action'])

    edge_ids = properties['gw-edge-ids'].split(',')
    for edge_id in edge_ids:
        try:
            bgp_config = nsxv.get_routing_bgp_config(edge_id)
            if not bgp_config['bgp'].get('enabled'):
                LOG.error("BGP is not enabled on edge %s", edge_id)
                return
            if not bgp_config['bgp']['redistribution']['enabled']:
                LOG.error("BGP redistribution is not enabled on edge %s",
                          edge_id)
                return
            nsxv.add_bgp_redistribution_rules(edge_id, prefixes, [rule])
        except exceptions.ResourceNotFound:
            LOG.error("Edge %s was not found", edge_id)
            return

    res = [{'edge_id': edge_id,
           'prefix': prefix_name if prefix_name else 'ANY',
            'learner-protocol': 'bgp',
           'learn-from': ', '.join(set(learn_from)),
           'action': properties['action']} for edge_id in edge_ids]

    headers = ['edge_id', 'prefix', 'learner-protocol', 'learn-from', 'action']
    LOG.info(formatters.output_formatter(
        'Routing redistribution rule', res, headers))


def delete_redis_rule(resource, event, trigger, **kwargs):
    usage = ("nsxadmin -r routing-redistribution-rule -o delete "
             "--property gw-edge-ids=<GW_EDGE_ID>[,...]"
             "[--property prefix-name=<NAME>]")
    required_params = ('gw-edge-ids', )
    properties = admin_utils.parse_multi_keyval_opt(kwargs.get('property', []))
    if not properties or not set(required_params) <= set(properties.keys()):
        LOG.error(usage)
        return

    edge_ids = properties['gw-edge-ids'].split(',')
    # If no prefix-name is given then remove rules configured with default
    # prefix.
    prefixes = [properties.get('prefix-name')]
    for edge_id in edge_ids:
        try:
            nsxv.remove_bgp_redistribution_rules(edge_id, prefixes)
        except exceptions.ResourceNotFound:
            LOG.error("Edge %s was not found", edge_id)
            return


@admin_utils.output_header
def add_bgp_neighbour(resource, event, trigger, **kwargs):
    usage = ("nsxadmin -r bgp-neighbour -o create "
             "--property gw-edge-ids=<GW_EDGE_ID>[,...] "
             "--property ip-address=<IP_ADDRESS> "
             "--property remote-as=<AS_NUMBER> "
             "--property password=<PASSWORD>")
    required_params = ('gw-edge-ids', 'ip-address', 'remote-as', 'password')
    properties = admin_utils.parse_multi_keyval_opt(kwargs.get('property', []))
    if not properties or not set(required_params) <= set(properties.keys()):
        LOG.error(usage)
        return

    remote_as = properties['remote-as']
    if not _validate_asn(remote_as):
        return

    nbr = nsxv_bgp.gw_bgp_neighbour(properties['ip-address'],
                                    properties['remote-as'],
                                    properties['password'])

    edge_ids = properties['gw-edge-ids'].split(',')
    for edge_id in edge_ids:
        try:
            nsxv.add_bgp_neighbours(edge_id, [nbr])
        except exceptions.ResourceNotFound:
            LOG.error("Edge %s was not found", edge_id)
            return

    res = [{'edge_id': edge_id,
            'ip_address': properties['ip-address'],
            'remote_as': properties['remote-as'],
            'hold_down_timer': cfg.CONF.nsxv.bgp_neighbour_hold_down_timer,
            'keep_alive_timer': cfg.CONF.nsxv.bgp_neighbour_keep_alive_timer}
           for edge_id in edge_ids]
    headers = ['edge_id', 'ip_address', 'remote_as',
               'hold_down_timer', 'keep_alive_timer']
    LOG.info(formatters.output_formatter('New BPG neighbour',
                                         res, headers))


def remove_bgp_neighbour(resource, event, trigger, **kwargs):
    usage = ("nsxadmin -r bgp-neighbour -o delete "
             "--property gw-edge-ids=<GW_EDGE_ID>[,...] "
             "--property ip-address=<IP_ADDRESS>")
    required_params = ('gw-edge-ids', 'ip-address')
    properties = admin_utils.parse_multi_keyval_opt(kwargs.get('property', []))
    if not properties or not set(required_params) <= set(properties.keys()):
        LOG.error(usage)
        return

    nbr = nsxv_bgp.gw_bgp_neighbour(properties['ip-address'], '', '')

    edge_ids = properties['gw-edge-ids'].split(',')
    for edge_id in edge_ids:
        try:
            nsxv.remove_bgp_neighbours(edge_id, [nbr])
        except exceptions.ResourceNotFound:
            LOG.error("Edge %s was not found", edge_id)
            return


registry.subscribe(create_bgp_gw,
                   constants.BGP_GW_EDGE,
                   shell.Operations.CREATE.value)
registry.subscribe(delete_bgp_gw,
                   constants.BGP_GW_EDGE,
                   shell.Operations.DELETE.value)
registry.subscribe(list_bgp_edges,
                   constants.BGP_GW_EDGE,
                   shell.Operations.LIST.value)
registry.subscribe(create_redis_rule,
                   constants.ROUTING_REDIS_RULE,
                   shell.Operations.CREATE.value)
registry.subscribe(delete_redis_rule,
                   constants.ROUTING_REDIS_RULE,
                   shell.Operations.DELETE.value)
registry.subscribe(add_bgp_neighbour,
                   constants.BGP_NEIGHBOUR,
                   shell.Operations.CREATE.value)
registry.subscribe(remove_bgp_neighbour,
                   constants.BGP_NEIGHBOUR,
                   shell.Operations.DELETE.value)
