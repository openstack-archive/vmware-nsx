# Copyright 2012 VMware, Inc.
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

from oslo_config import cfg

from vmware_nsx._i18n import _, _LW
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.extensions import routersize

LOG = logging.getLogger(__name__)


class AgentModes:
    AGENT = 'agent'
    AGENTLESS = 'agentless'
    COMBINED = 'combined'


class MetadataModes:
    DIRECT = 'access_network'
    INDIRECT = 'dhcp_host_route'


class ReplicationModes:
    SERVICE = 'service'
    SOURCE = 'source'


base_opts = [
    cfg.IntOpt('max_lp_per_bridged_ls', default=5000,
               deprecated_group='NVP',
               help=_("Maximum number of ports of a logical switch on a "
                      "bridged transport zone (default 5000)")),
    cfg.IntOpt('max_lp_per_overlay_ls', default=256,
               deprecated_group='NVP',
               help=_("Maximum number of ports of a logical switch on an "
                      "overlay transport zone (default 256)")),
    cfg.IntOpt('concurrent_connections', default=10,
               deprecated_group='NVP',
               help=_("Maximum concurrent connections to each NSX "
                      "controller.")),
    cfg.IntOpt('nsx_gen_timeout', default=-1,
               deprecated_name='nvp_gen_timeout',
               deprecated_group='NVP',
               help=_("Number of seconds a generation id should be valid for "
                      "(default -1 meaning do not time out)")),
    cfg.StrOpt('metadata_mode', default=MetadataModes.DIRECT,
               deprecated_group='NVP',
               help=_("If set to access_network this enables a dedicated "
                      "connection to the metadata proxy for metadata server "
                      "access via Neutron router. If set to dhcp_host_route "
                      "this enables host route injection via the dhcp agent. "
                      "This option is only useful if running on a host that "
                      "does not support namespaces otherwise access_network "
                      "should be used.")),
    cfg.StrOpt('default_transport_type', default='stt',
               deprecated_group='NVP',
               help=_("The default network tranport type to use (stt, gre, "
                      "bridge, ipsec_gre, or ipsec_stt)")),
    cfg.StrOpt('agent_mode', default=AgentModes.AGENT,
               deprecated_group='NVP',
               help=_("The mode used to implement DHCP/metadata services.")),
    cfg.StrOpt('replication_mode', default=ReplicationModes.SERVICE,
               choices=(ReplicationModes.SERVICE, ReplicationModes.SOURCE),
               help=_("The default option leverages service nodes to perform"
                      " packet replication though one could set to this to "
                      "'source' to perform replication locally. This is useful"
                      " if one does not want to deploy a service node(s). "
                      "It must be set to 'service' for leveraging distributed "
                      "routers.")),
]

sync_opts = [
    cfg.IntOpt('state_sync_interval', default=10,
               deprecated_group='NVP_SYNC',
               help=_("Interval in seconds between runs of the state "
                      "synchronization task. Set it to 0 to disable it")),
    cfg.IntOpt('max_random_sync_delay', default=0,
               deprecated_group='NVP_SYNC',
               help=_("Maximum value for the additional random "
                      "delay in seconds between runs of the state "
                      "synchronization task")),
    cfg.IntOpt('min_sync_req_delay', default=1,
               deprecated_group='NVP_SYNC',
               help=_('Minimum delay, in seconds, between two state '
                      'synchronization queries to NSX. It must not '
                      'exceed state_sync_interval')),
    cfg.IntOpt('min_chunk_size', default=500,
               deprecated_group='NVP_SYNC',
               help=_('Minimum number of resources to be retrieved from NSX '
                      'during state synchronization')),
    cfg.BoolOpt('always_read_status', default=False,
                deprecated_group='NVP_SYNC',
                help=_('Always read operational status from backend on show '
                       'operations. Enabling this option might slow down '
                       'the system.'))
]

connection_opts = [
    cfg.StrOpt('nsx_user',
               default='admin',
               deprecated_name='nvp_user',
               help=_('User name for NSX controllers in this cluster')),
    cfg.StrOpt('nsx_password',
               default='admin',
               deprecated_name='nvp_password',
               secret=True,
               help=_('Password for NSX controllers in this cluster')),
    cfg.IntOpt('http_timeout',
               default=75,
               help=_('Time before aborting a request')),
    cfg.IntOpt('retries',
               default=2,
               help=_('Number of time a request should be retried')),
    cfg.IntOpt('redirects',
               default=2,
               help=_('Number of times a redirect should be followed')),
    cfg.ListOpt('nsx_controllers',
                deprecated_name='nvp_controllers',
                help=_("Lists the NSX controllers in this cluster")),
    cfg.IntOpt('conn_idle_timeout',
               default=900,
               help=_('Reconnect connection to nsx if not used within this '
                      'amount of time.')),
]

cluster_opts = [
    cfg.StrOpt('default_tz_uuid',
               help=_("This is uuid of the default NSX Transport zone that "
                      "will be used for creating tunneled isolated "
                      "\"Neutron\" networks. It needs to be created in NSX "
                      "before starting Neutron with the nsx plugin.")),
    cfg.StrOpt('default_l3_gw_service_uuid',
               help=_("Unique identifier of the NSX L3 Gateway service "
                      "which will be used for implementing routers and "
                      "floating IPs")),
    cfg.StrOpt('default_l2_gw_service_uuid',
               help=_("Unique identifier of the NSX L2 Gateway service "
                      "which will be used by default for network gateways")),
    cfg.StrOpt('default_service_cluster_uuid',
               help=_("Unique identifier of the Service Cluster which will "
                      "be used by logical services like dhcp and metadata")),
    cfg.StrOpt('nsx_default_interface_name', default='breth0',
               deprecated_name='default_interface_name',
               help=_("Name of the interface on a L2 Gateway transport node "
                      "which should be used by default when setting up a "
                      "network connection")),
]

nsx_common_opts = [
    cfg.StrOpt('nsx_l2gw_driver',
               help=_("Class path for the L2 gateway backend driver")),
    cfg.StrOpt('locking_coordinator_url',
               deprecated_group='nsxv',
               help=_('A URL to a locking mechanism coordinator')),
]

nsx_v3_opts = [
    cfg.StrOpt('nsx_api_user',
               deprecated_name='nsx_user',
               default='admin',
               help=_('User name for the NSX manager')),
    cfg.StrOpt('nsx_api_password',
               deprecated_name='nsx_password',
               default='default',
               secret=True,
               help=_('Password for the NSX manager')),
    cfg.ListOpt('nsx_api_managers',
                deprecated_name='nsx_manager',
                help=_('IP address of one or more NSX managers separated '
                       'by commas. The IP address can optionally specify a '
                       'scheme (e.g. http or https) and port using the format '
                       '<scheme>://<ip_address>:<port>')),
    cfg.StrOpt('default_overlay_tz_uuid',
               deprecated_name='default_tz_uuid',
               help=_("This is the UUID of the default NSX overlay transport "
                      "zone that will be used for creating tunneled isolated "
                      "Neutron networks. It needs to be created in NSX "
                      "before starting Neutron with the NSX plugin.")),
    cfg.StrOpt('default_vlan_tz_uuid',
               help=_("This is the UUID of the default NSX VLAN transport "
                      "zone that will be used for bridging between Neutron "
                      "networks. It needs to be created in NSX before "
                      "starting Neutron with the NSX plugin.")),
    cfg.StrOpt('default_edge_cluster_uuid',
               help=_("Default edge cluster identifier")),
    cfg.StrOpt('default_bridge_cluster_uuid',
               help=_("Default bridge cluster identifier for L2 gateway. "
                      "This needs to be created in NSX before using the L2 "
                      "gateway service plugin.")),
    cfg.IntOpt('retries',
               default=10,
               help=_('Maximum number of times to retry API requests upon '
                      'stale revision errors.')),
    cfg.StrOpt('ca_file',
               help=_('Specify a CA bundle file to use in verifying the NSX '
                      'Manager server certificate. This option is ignored if '
                      '"insecure" is set to True. If "insecure" is set to '
                      'False and ca_file is unset, the system root CAs will '
                      'be used to verify the server certificate.')),
    cfg.BoolOpt('insecure',
                default=True,
                help=_('If true, the NSX Manager server certificate is not '
                       'verified. If false the CA bundle specified via '
                       '"ca_file" will be used or if unsest the default '
                       'system root CAs will be used.')),
    cfg.IntOpt('http_timeout',
               default=10,
               help=_('Time before aborting a HTTP connection to a '
                      'NSX manager.')),
    cfg.IntOpt('http_read_timeout',
               default=180,
               help=_('The time in seconds before aborting a HTTP read '
                      'response from a NSX manager.')),
    cfg.IntOpt('http_retries',
               default=3,
               help=_('Maximum number of times to retry a HTTP connection.')),
    cfg.IntOpt('concurrent_connections', default=10,
               help=_("Maximum concurrent connections to each NSX "
                      "manager.")),
    cfg.IntOpt('conn_idle_timeout',
               default=10,
               help=_('Ensure connectivity to the NSX manager if a connection '
                      'is not used within timeout seconds.')),
    cfg.IntOpt('redirects',
               default=2,
               help=_('Number of times a HTTP redirect should be followed.')),
    cfg.StrOpt('default_tier0_router_uuid',
               help=_("Default tier0 router identifier")),
    cfg.IntOpt('number_of_nested_groups',
               default=8,
               help=_("The number of nested NSGroups to use.")),
    cfg.StrOpt('metadata_mode',
               default=MetadataModes.DIRECT,
               help=_("If set to access_network this enables a dedicated "
                      "connection to the metadata proxy for metadata server "
                      "access via Neutron router. If set to dhcp_host_route "
                      "this enables host route injection via the dhcp agent. "
                      "This option is only useful if running on a host that "
                      "does not support namespaces otherwise access_network "
                      "should be used.")),
    cfg.BoolOpt('metadata_on_demand',
                default=False,
                help=_("If true, an internal metadata network will be created "
                       "for a router only when the router is attached to a "
                       "DHCP-disabled subnet.")),
]

DEFAULT_STATUS_CHECK_INTERVAL = 2000
DEFAULT_MINIMUM_POOLED_EDGES = 1
DEFAULT_MAXIMUM_POOLED_EDGES = 3
DEFAULT_MAXIMUM_TUNNELS_PER_VNIC = 20

nsxv_opts = [
    cfg.StrOpt('user',
               default='admin',
               deprecated_group="vcns",
               help=_('User name for vsm')),
    cfg.StrOpt('password',
               default='default',
               deprecated_group="vcns",
               secret=True,
               help=_('Password for vsm')),
    cfg.StrOpt('manager_uri',
               deprecated_group="vcns",
               help=_('uri for vsm')),
    cfg.StrOpt('ca_file',
               help=_('Specify a CA bundle file to use in verifying the NSXv '
                      'server certificate.')),
    cfg.BoolOpt('insecure',
                default=True,
                help=_('If true, the NSXv server certificate is not verified. '
                       'If false, then the default CA truststore is used for '
                       'verification. This option is ignored if "ca_file" is '
                       'set.')),
    cfg.ListOpt('cluster_moid',
                default=[],
                help=_('Parameter listing the IDs of the clusters '
                       'which are used by OpenStack.')),
    cfg.StrOpt('datacenter_moid',
               deprecated_group="vcns",
               help=_('Optional parameter identifying the ID of datacenter '
                      'to deploy NSX Edges')),
    cfg.StrOpt('deployment_container_id',
               deprecated_group="vcns",
               help=_('Optional parameter identifying the ID of datastore to '
                      'deploy NSX Edges')),
    cfg.StrOpt('resource_pool_id',
               deprecated_group="vcns",
               help=_('Optional parameter identifying the ID of resource to '
                      'deploy NSX Edges')),
    cfg.StrOpt('datastore_id',
               deprecated_group="vcns",
               help=_('Optional parameter identifying the ID of datastore to '
                      'deploy NSX Edges')),
    cfg.StrOpt('external_network',
               deprecated_group="vcns",
               help=_('Network ID for physical network connectivity')),
    cfg.IntOpt('task_status_check_interval',
               default=DEFAULT_STATUS_CHECK_INTERVAL,
               deprecated_group="vcns",
               help=_("Task status check interval")),
    cfg.StrOpt('vdn_scope_id',
               help=_('Network scope ID for VXLAN virtual wires')),
    cfg.StrOpt('dvs_id',
               help=_('DVS ID for VLANs')),
    cfg.IntOpt('maximum_tunnels_per_vnic',
               default=DEFAULT_MAXIMUM_TUNNELS_PER_VNIC,
               min=1, max=110,
               help=_('Maximum number of sub interfaces supported '
                      'per vnic in edge.')),
    cfg.ListOpt('backup_edge_pool',
                default=['service:large:4:10',
                         'service:compact:4:10',
                         'vdr:large:4:10'],
                help=_('Defines edge pool using the format: '
                       '<edge_type>:[edge_size]:<min_edges>:<max_edges>.'
                       'edge_type: service,vdr. '
                       'edge_size: compact, large, xlarge, quadlarge '
                       'and default is large.')),
    cfg.IntOpt('retries',
               default=20,
               help=_('Maximum number of API retries on endpoint.')),
    cfg.StrOpt('mgt_net_moid',
               help=_('Network ID for management network connectivity')),
    cfg.ListOpt('mgt_net_proxy_ips',
                help=_('Management network IP address for metadata proxy')),
    cfg.StrOpt('mgt_net_proxy_netmask',
               help=_('Management network netmask for metadata proxy')),
    cfg.StrOpt('mgt_net_default_gateway',
               help=_('Management network default gateway for '
                      'metadata proxy')),
    cfg.ListOpt('nova_metadata_ips',
                help=_('IP addresses used by Nova metadata service')),
    cfg.PortOpt('nova_metadata_port',
                default=8775,
                help=_("TCP Port used by Nova metadata server")),
    cfg.StrOpt('metadata_shared_secret',
               secret=True,
               help=_('Shared secret to sign metadata requests')),
    cfg.BoolOpt('metadata_insecure',
                default=True,
                help=_('If True, the end to end connection for metadata '
                       'service is not verified. If False, the default CA '
                       'truststore is used for verification')),
    cfg.StrOpt('metadata_nova_client_cert',
               help=_('Client certificate for nova metadata api server')),
    cfg.StrOpt('metadata_nova_client_priv_key',
               help=_('Private key of client certificate')),
    cfg.BoolOpt('spoofguard_enabled',
                default=True,
                help=_("If True then plugin will use NSXV spoofguard "
                       "component for port-security feature.")),
    cfg.ListOpt('tenant_router_types',
                default=['shared', 'distributed', 'exclusive'],
                help=_("Ordered list of router_types to allocate as tenant "
                       "routers.")),
    cfg.StrOpt('edge_appliance_user',
               secret=True,
               help=_('Username to configure for Edge appliance login')),
    cfg.StrOpt('edge_appliance_password',
               secret=True,
               help=_('Password to configure for Edge appliance login')),
    cfg.IntOpt('dhcp_lease_time',
               default=86400,
               help=_('DHCP default lease time.')),
    cfg.BoolOpt('metadata_initializer',
                default=True,
                help=_("If True, the server instance will attempt to "
                       "initialize the metadata infrastructure")),
    cfg.ListOpt('metadata_service_allowed_ports',
                help=_('List of tcp ports, to be allowed access to the '
                       'metadata proxy, in addition to the default '
                       '80,443,8775 tcp ports')),
    cfg.BoolOpt('edge_ha',
                default=False,
                help=_("Enable HA for NSX Edges")),
    cfg.StrOpt('exclusive_router_appliance_size',
               default="compact",
               choices=routersize.VALID_EDGE_SIZES,
               help=_("Edge appliance size to be used for creating exclusive "
                      "router. This edge_appliance_size will be picked up if "
                      "--router-size parameter is not specified while doing "
                      "neutron router-create")),
    cfg.ListOpt('nameservers',
                default=[],
                help=_('List of nameservers to configure for the DHCP binding '
                       'entries. These will be used if there are no '
                       'nameservers defined on the subnet.')),
]

# Register the configuration options
cfg.CONF.register_opts(connection_opts)
cfg.CONF.register_opts(cluster_opts)
cfg.CONF.register_opts(nsx_common_opts)
cfg.CONF.register_opts(nsx_v3_opts, group="nsx_v3")
cfg.CONF.register_opts(nsxv_opts, group="nsxv")
cfg.CONF.register_opts(base_opts, group="NSX")
cfg.CONF.register_opts(sync_opts, group="NSX_SYNC")


def validate_nsxv_config_options():
    if (cfg.CONF.nsxv.manager_uri is None or
        cfg.CONF.nsxv.user is None or
        cfg.CONF.nsxv.password is None):
        error = _("manager_uri, user, and password must be configured!")
        raise nsx_exc.NsxPluginException(err_msg=error)
    if cfg.CONF.nsxv.dvs_id is None:
        LOG.warning(_LW("dvs_id must be configured to support VLANs!"))
    if cfg.CONF.nsxv.vdn_scope_id is None:
        LOG.warning(_LW("vdn_scope_id must be configured to support VXLANs!"))
