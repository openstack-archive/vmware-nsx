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
from vmware_nsx.dvs import dvs_utils
from vmware_nsx.extensions import routersize

LOG = logging.getLogger(__name__)


class AgentModes(object):
    AGENT = 'agent'
    AGENTLESS = 'agentless'
    COMBINED = 'combined'


class MetadataModes(object):
    DIRECT = 'access_network'
    INDIRECT = 'dhcp_host_route'


class ReplicationModes(object):
    SERVICE = 'service'
    SOURCE = 'source'


base_opts = [
    cfg.IntOpt('max_lp_per_bridged_ls', default=5000,
               deprecated_group='NVP',
               help=_("Maximum number of ports of a logical switch on a "
                      "bridged transport zone. The recommended value for "
                      "this parameter varies with NSX version.\nPlease use:\n"
                      "NSX 2.x -> 64\nNSX 3.0, 3.1 -> 5000\n"
                      "NSX 3.2 -> 10000")),
    cfg.IntOpt('max_lp_per_overlay_ls', default=256,
               deprecated_group='NVP',
               help=_("Maximum number of ports of a logical switch on an "
                      "overlay transport zone")),
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
               help=_("Specifies in which mode the plugin needs to operate "
                      "in order to provide DHCP and metadata proxy services "
                      "to tenant instances. If 'agent' is chosen (default) "
                      "the NSX plugin relies on external RPC agents (i.e. "
                      "dhcp and metadata agents) to provide such services. "
                      "In this mode, the plugin supports API extensions "
                      "'agent' and 'dhcp_agent_scheduler'. If 'agentless' "
                      "is chosen (experimental in Icehouse), the plugin will "
                      "use NSX logical services for DHCP and metadata proxy. "
                      "This simplifies the deployment model for Neutron, in "
                      "that the plugin no longer requires the RPC agents to "
                      "operate. When 'agentless' is chosen, the config option "
                      "metadata_mode becomes ineffective. The 'agentless' "
                      "mode works only on NSX 4.1. Furthermore, a 'combined' "
                      "mode is also provided and is used to support existing "
                      "deployments that want to adopt the agentless mode. "
                      "With this mode, existing networks keep being served by "
                      "the existing infrastructure (thus preserving backward "
                      "compatibility, whereas new networks will be served by "
                      "the new infrastructure. Migration tools are provided "
                      "to 'move' one network from one model to another; with "
                      "agent_mode set to 'combined', option "
                      "'network_auto_schedule' in neutron.conf is ignored, as "
                      "new networks will no longer be scheduled to existing "
                      "dhcp agents.")),
    cfg.StrOpt('replication_mode', default=ReplicationModes.SERVICE,
               choices=(ReplicationModes.SERVICE, ReplicationModes.SOURCE),
               help=_("Specifies which mode packet replication should be done "
                      "in. If set to service a service node is required in "
                      "order to perform packet replication. This can also be "
                      "set to source if one wants replication to be performed "
                      "locally (NOTE: usually only useful for testing if one "
                      "does not want to deploy a service node). In order to "
                      "leverage distributed routers, replication_mode should "
                      "be set to 'service'.")),
    #TODO(asarfaty): add min/max values to FloatOpt. This value should be > 1
    cfg.FloatOpt('qos_peak_bw_multiplier', default=2.0,
                 help=_("The QoS rules peak bandwidth value will be the "
                        "configured maximum bandwidth of the QoS rule, "
                        "multiplied by this value. Value must be bigger than"
                        " 1")),
]

sync_opts = [
    cfg.IntOpt('state_sync_interval', default=10,
               deprecated_group='NVP_SYNC',
               help=_("Interval in seconds between runs of the status "
                      "synchronization task. The plugin will aim at "
                      "resynchronizing operational status for all resources "
                      "in this interval, and it should be therefore large "
                      "enough to ensure the task is feasible. Otherwise the "
                      "plugin will be constantly synchronizing resource "
                      "status, ie: a new task is started as soon as the "
                      "previous is completed. If this value is set to 0, the "
                      "state synchronization thread for this Neutron instance "
                      "will be disabled.")),
    cfg.IntOpt('max_random_sync_delay', default=0,
               deprecated_group='NVP_SYNC',
               help=_("Random additional delay between two runs of the state "
                      "synchronization task. An additional wait time between "
                      "0 and max_random_sync_delay seconds will be added on "
                      "top of state_sync_interval.")),
    cfg.IntOpt('min_sync_req_delay', default=1,
               deprecated_group='NVP_SYNC',
               help=_("Minimum delay, in seconds, between two status "
                      "synchronization requests for NSX. Depending on chunk "
                      "size, controller load, and other factors, state "
                      "synchronization requests might be pretty heavy. This "
                      "means the controller might take time to respond, and "
                      "its load might be quite increased by them. This "
                      "parameter allows to specify a minimum interval between "
                      "two subsequent requests. The value for this parameter "
                      "must never exceed state_sync_interval. If this does, "
                      "an error will be raised at startup.")),
    cfg.IntOpt('min_chunk_size', default=500,
               deprecated_group='NVP_SYNC',
               help=_("Minimum number of resources to be retrieved from NSX "
                      "in a single status synchronization request. The actual "
                      "size of the chunk will increase if the number of "
                      "resources is such that using the minimum chunk size "
                      "will cause the interval between two requests to be "
                      "less than min_sync_req_delay")),
    cfg.BoolOpt('always_read_status', default=False,
                deprecated_group='NVP_SYNC',
                help=_("Enable this option to allow punctual state "
                       "synchronization on show operations. In this way, show "
                       "operations will always fetch the operational status "
                       "of the resource from the NSX backend, and this might "
                       "have a considerable impact on overall performance."))
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
               help=_('Time before aborting a request on an '
                      'unresponsive controller (Seconds)')),
    cfg.IntOpt('retries',
               default=2,
               help=_('Maximum number of times a particular request '
                      'should be retried')),
    cfg.IntOpt('redirects',
               default=2,
               help=_('Maximum number of times a redirect response '
                      'should be followed')),
    cfg.ListOpt('nsx_controllers',
                default=[],
                deprecated_name='nvp_controllers',
                help=_('Comma-separated list of NSX controller '
                       'endpoints (<ip>:<port>). When port is omitted, '
                       '443 is assumed. This option MUST be specified. '
                       'e.g.: aa.bb.cc.dd, ee.ff.gg.hh.ee:80')),
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
               help=_("(Optional) UUID of the NSX L3 Gateway "
                      "service which will be used for implementing routers "
                      "and floating IPs")),
    cfg.StrOpt('default_l2_gw_service_uuid',
               help=_("(Optional) UUID of the NSX L2 Gateway service "
                      "which will be used by default for network gateways")),
    cfg.StrOpt('default_service_cluster_uuid',
               help=_("(Optional) UUID of the Service Cluster which will "
                      "be used by logical services like dhcp and metadata")),
    cfg.StrOpt('nsx_default_interface_name', default='breth0',
               deprecated_name='default_interface_name',
               help=_("Name of the interface on a L2 Gateway transport node "
                      "which should be used by default when setting up a "
                      "network connection")),
]

nsx_common_opts = [
    cfg.StrOpt('nsx_l2gw_driver',
               help=_("Specify the class path for the Layer 2 gateway "
                      "backend driver(i.e. NSXv3/NSX-V). This field will be "
                      "used when a L2 Gateway service plugin is configured.")),
    cfg.StrOpt('locking_coordinator_url',
               deprecated_group='nsxv',
               help=_("(Optional) URL for distributed locking coordination "
                      "resource for lock manager. This value is passed as a "
                      "parameter to tooz coordinator. By default, value is "
                      "None and oslo_concurrency is used for single-node "
                      "lock management.")),
    cfg.BoolOpt('api_replay_mode',
                default=False,
                help=_("If true, the server then allows the caller to "
                       "specify the id of resources. This should only "
                       "be enabled in order to allow one to migrate an "
                       "existing install of neutron to the nsx-v3 plugin.")),
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
                default=[],
                deprecated_name='nsx_manager',
                help=_("IP address of one or more NSX managers separated "
                       "by commas. The IP address should be of the form:\n"
                       "[<scheme>://]<ip_adress>[:<port>]\nIf scheme is not "
                       "provided https is used. If port is not provided port "
                       "80 is used for http and port 443 for https.")),
    cfg.StrOpt('default_overlay_tz',
               deprecated_name='default_overlay_tz_uuid',
               help=_("This is the name or UUID of the default NSX overlay "
                      "transport zone that will be used for creating "
                      "tunneled isolated Neutron networks. It needs to be "
                      "created in NSX before starting Neutron with the NSX "
                      "plugin.")),
    cfg.StrOpt('default_vlan_tz',
               deprecated_name='default_vlan_tz_uuid',
               help=_("(Optional) Only required when creating VLAN or flat "
                      "provider networks. Name or UUID of default NSX VLAN "
                      "transport zone that will be used for bridging between "
                      "Neutron networks, if no physical network has been "
                      "specified")),
    cfg.StrOpt('default_bridge_cluster',
               deprecated_name='default_bridge_cluster_uuid',
               help=_("(Optional) Name or UUID of the default NSX bridge "
                      "cluster that will be used to perform L2 gateway "
                      "bridging between VXLAN and VLAN networks. If default "
                      "bridge cluster UUID is not specified, admin will have "
                      "to manually create a L2 gateway corresponding to a "
                      "NSX Bridge Cluster using L2 gateway APIs. This field "
                      "must be specified on one of the active neutron "
                      "servers only.")),
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
               help=_('The time in seconds before aborting a HTTP connection '
                      'to a NSX manager.')),
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
               help=_("The amount of time in seconds to wait before ensuring "
                      "connectivity to the NSX manager if no manager "
                      "connection has been used.")),
    cfg.IntOpt('redirects',
               default=2,
               help=_('Number of times a HTTP redirect should be followed.')),
    cfg.StrOpt('default_tier0_router',
               deprecated_name='default_tier0_router_uuid',
               help=_("Name or UUID of the default tier0 router that will be "
                      "used for connecting to tier1 logical routers and "
                      "configuring external networks")),
    cfg.IntOpt('number_of_nested_groups',
               default=8,
               help=_("(Optional) The number of nested groups which are used "
                      "by the plugin, each Neutron security-groups is added "
                      "to one nested group, and each nested group can contain "
                      "as maximum as 500 security-groups, therefore, the "
                      "maximum number of security groups that can be created "
                      "is 500 * number_of_nested_groups. The default is 8 "
                      "nested groups, which allows a maximum of 4k "
                      "security-groups, to allow creation of more "
                      "security-groups, modify this figure.")),
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
    cfg.BoolOpt('native_dhcp_metadata',
                default=False,
                help=_("If true, DHCP and metadata proxy services will be "
                       "provided by NSX backend.")),
    cfg.StrOpt('native_metadata_route',
               default="169.254.169.254/31",
               help=_("The metadata route used for native metadata proxy "
                      "service.")),
    cfg.StrOpt('dhcp_profile_uuid',
               help=_("This is the UUID of the NSX DHCP Profile that will be "
                      "used to enable native DHCP service. It needs to be "
                      "created in NSX before starting Neutron with the NSX "
                      "plugin.")),
    cfg.IntOpt('dhcp_lease_time',
               default=86400,
               help=_("DHCP default lease time.")),
    cfg.StrOpt('dns_domain',
               default='openstacklocal',
               help=_("Domain to use for building the hostnames.")),
    cfg.ListOpt('nameservers',
                default=[],
                help=_("List of nameservers to configure for the DHCP "
                       "binding entries. These will be used if there are no "
                       "nameservers defined on the subnet.")),
    cfg.StrOpt('metadata_proxy_uuid',
               help=_("This is the UUID of the NSX Metadata Proxy that will "
                      "be used to enable native metadata service. It needs "
                      "to be created in NSX before starting Neutron with "
                      "the NSX plugin.")),
    cfg.BoolOpt('log_security_groups_blocked_traffic',
                default=False,
                help=_("(Optional) Indicates whether distributed-firewall "
                       "rule for security-groups blocked traffic is logged.")),
    cfg.BoolOpt('log_security_groups_allowed_traffic',
                default=False,
                help=_("(Optional) Indicates whether distributed-firewall "
                       "security-groups rules are logged.")),
]

DEFAULT_STATUS_CHECK_INTERVAL = 2000
DEFAULT_MINIMUM_POOLED_EDGES = 1
DEFAULT_MAXIMUM_POOLED_EDGES = 3
DEFAULT_MAXIMUM_TUNNELS_PER_VNIC = 20

nsxv_opts = [
    cfg.StrOpt('user',
               default='admin',
               deprecated_group="vcns",
               help=_('User name for NSXv manager')),
    cfg.StrOpt('password',
               default='default',
               deprecated_group="vcns",
               secret=True,
               help=_('Password for NSXv manager')),
    cfg.StrOpt('manager_uri',
               deprecated_group="vcns",
               help=_('URL for NSXv manager')),
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
                help=_('(Required) Parameter listing the IDs of the clusters '
                       'which are used by OpenStack.')),
    cfg.StrOpt('datacenter_moid',
               deprecated_group="vcns",
               help=_('Required parameter identifying the ID of datacenter '
                      'to deploy NSX Edges')),
    cfg.StrOpt('deployment_container_id',
               deprecated_group="vcns",
               help=_('Optional parameter identifying the ID of datastore to '
                      'deploy NSX Edges')),
    cfg.StrOpt('resource_pool_id',
               deprecated_group="vcns",
               help=_('Optional parameter identifying the ID of resource to '
                      'deploy NSX Edges')),
    cfg.ListOpt('availability_zones',
                default=[],
                help=_('Optional parameter defining the availability zones '
                       'for deploying NSX Edges with the format: <zone name>:'
                       '<resource pool id]:<datastore id>:<edge_ha True/False>'
                       '<(optional)HA datastore id>.')),
    cfg.StrOpt('datastore_id',
               deprecated_group="vcns",
               help=_('Optional parameter identifying the ID of datastore to '
                      'deploy NSX Edges')),
    cfg.StrOpt('ha_datastore_id',
               help=_('Optional parameter identifying the ID of datastore to '
                      'deploy NSX Edges in addition to data_store_id in case'
                      'edge_ha is True')),
    cfg.StrOpt('external_network',
               deprecated_group="vcns",
               help=_('(Required) Network ID for physical network '
                      'connectivity')),
    cfg.IntOpt('task_status_check_interval',
               default=DEFAULT_STATUS_CHECK_INTERVAL,
               deprecated_group="vcns",
               help=_("(Optional) Asynchronous task status check interval. "
                      "Default is 2000 (millisecond)")),
    cfg.StrOpt('vdn_scope_id',
               help=_('(Optional) Network scope ID for VXLAN virtual wires')),
    cfg.StrOpt('dvs_id',
               help=_('(Optional) DVS MoRef ID for DVS connected to '
                      'Management / Edge cluster')),
    cfg.IntOpt('maximum_tunnels_per_vnic',
               default=DEFAULT_MAXIMUM_TUNNELS_PER_VNIC,
               min=1, max=110,
               help=_('(Optional) Maximum number of sub interfaces supported '
                      'per vnic in edge.')),
    cfg.ListOpt('backup_edge_pool',
                default=['service:compact:4:10',
                         'vdr:compact:4:10'],
                help=_("Defines edge pool's management range with the format: "
                       "<edge_type>:[edge_size]:<min_edges>:<max_edges>."
                       "edge_type: service,vdr. "
                       "edge_size: compact, large, xlarge, quadlarge "
                       "and default is compact. By default, edge pool manager "
                       "would manage service edge with compact size "
                       "and distributed edge with compact size as following: "
                       "service:compact:4:10,vdr:compact:"
                       "4:10")),
    cfg.IntOpt('retries',
               default=20,
               help=_('Maximum number of API retries on endpoint.')),
    cfg.StrOpt('mgt_net_moid',
               help=_('(Optional) Portgroup MoRef ID for metadata proxy '
                      'management network')),
    cfg.ListOpt('mgt_net_proxy_ips',
                default=[],
                help=_('(Optional) Comma separated list of management network '
                       'IP addresses for metadata proxy.')),
    cfg.StrOpt('mgt_net_proxy_netmask',
               help=_("(Optional) Management network netmask for metadata "
                      "proxy.")),
    cfg.StrOpt('mgt_net_default_gateway',
               help=_("(Optional) Management network default gateway for "
                      "metadata proxy.")),
    cfg.ListOpt('nova_metadata_ips',
                default=[],
                help=_("(Optional) IP addresses used by Nova metadata "
                       "service.")),
    cfg.PortOpt('nova_metadata_port',
                default=8775,
                help=_("(Optional) TCP Port used by Nova metadata server.")),
    cfg.StrOpt('metadata_shared_secret',
               secret=True,
               help=_("(Optional) Shared secret to sign metadata requests.")),
    cfg.BoolOpt('metadata_insecure',
                default=True,
                help=_("(Optional) If True, the end to end connection for "
                       "metadata service is not verified. If False, the "
                       "default CA truststore is used for verification.")),
    cfg.StrOpt('metadata_nova_client_cert',
               help=_('(Optional) Client certificate to use when metadata '
                      'connection is to be verified. If not provided, '
                      'a self signed certificate will be used.')),
    cfg.StrOpt('metadata_nova_client_priv_key',
               help=_("(Optional) Private key of client certificate.")),
    cfg.BoolOpt('spoofguard_enabled',
                default=True,
                help=_("(Optional) If True then plugin will use NSXV "
                       "spoofguard component for port-security feature.")),
    cfg.BoolOpt('use_exclude_list',
                default=True,
                help=_("(Optional) If True then plugin will use NSXV exclude "
                       "list component when port security is disabled and "
                       "spoofguard is enabled.")),
    cfg.ListOpt('tenant_router_types',
                default=['shared', 'distributed', 'exclusive'],
                help=_("Ordered list of router_types to allocate as tenant "
                       "routers. It limits the router types that the Nsxv "
                       "can support for tenants:\ndistributed: router is "
                       "supported by distributed edge at the backend.\n"
                       "shared: multiple routers share the same service "
                       "edge at the backend.\nexclusive: router exclusively "
                       "occupies one service edge at the backend.\nNsxv would "
                       "select the first available router type from "
                       "tenant_router_types list if router-type is not "
                       "specified. If the tenant defines the router type with "
                       "'--distributed','--router_type exclusive' or "
                       "'--router_type shared', Nsxv would verify that the "
                       "router type is in tenant_router_types. Admin supports "
                       "all these three router types.")),
    cfg.StrOpt('edge_appliance_user',
               secret=True,
               help=_("(Optional) Username to configure for Edge appliance "
                      "login.")),
    cfg.StrOpt('edge_appliance_password',
               secret=True,
               help=_("(Optional) Password to configure for Edge appliance "
                      "login.")),
    cfg.IntOpt('dhcp_lease_time',
               default=86400,
               help=_("(Optional) DHCP default lease time.")),
    cfg.BoolOpt('metadata_initializer',
                default=True,
                help=_("If True, the server instance will attempt to "
                       "initialize the metadata infrastructure")),
    cfg.ListOpt('metadata_service_allowed_ports',
                default=[],
                help=_('List of tcp ports, to be allowed access to the '
                       'metadata proxy, in addition to the default '
                       '80,443,8775 tcp ports')),
    cfg.BoolOpt('edge_ha',
                default=False,
                help=_("(Optional) Enable HA for NSX Edges.")),
    cfg.StrOpt('exclusive_router_appliance_size',
               default="compact",
               choices=routersize.VALID_EDGE_SIZES,
               help=_("(Optional) Edge appliance size to be used for creating "
                      "exclusive router. Valid values: "
                      "['compact', 'large', 'xlarge', 'quadlarge']. This "
                      "exclusive_router_appliance_size will be picked up if "
                      "--router-size parameter is not specified while doing "
                      "neutron router-create")),
    cfg.ListOpt('nameservers',
                default=[],
                help=_('List of nameservers to configure for the DHCP binding '
                       'entries. These will be used if there are no '
                       'nameservers defined on the subnet.')),
    cfg.BoolOpt('use_dvs_features',
                default=False,
                help=_('If True, dvs features will be supported which '
                       'involves configuring the dvs backing nsx_v directly. '
                       'If False, only features exposed via nsx_v will be '
                       'supported')),
    cfg.BoolOpt('log_security_groups_blocked_traffic',
                default=False,
                help=_("(Optional) Indicates whether distributed-firewall "
                       "rule for security-groups blocked traffic is logged.")),
    cfg.BoolOpt('log_security_groups_allowed_traffic',
                default=False,
                help=_("(Optional) Indicates whether distributed-firewall "
                       "security-groups allowed traffic is logged.")),
    cfg.BoolOpt('dhcp_force_metadata', default=True,
                help=_("(Optional) In some cases the Neutron router is not "
                       "present to provide the metadata IP but the DHCP "
                       "server can be used to provide this info. Setting this "
                       "value will force the DHCP server to append specific "
                       "host routes to the DHCP request. If this option is "
                       "set, then the metadata service will be activated for "
                       "all the dhcp enabled networks.\nNote: this option can "
                       "only be supported at NSX manager version 6.2.3 or "
                       "higher.")),
    cfg.StrOpt('service_insertion_profile_id',
               help=_("(Optional) The profile id of the redirect firewall "
                      "rules that will be used for the Service Insertion "
                      "feature.")),
    cfg.BoolOpt('service_insertion_redirect_all', default=False,
                help=_("(Optional) If set to True, the plugin will create "
                       "a redirect rule to send all the traffic to the "
                       "security partner")),
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
    if cfg.CONF.nsxv.use_dvs_features and not dvs_utils.dvs_is_enabled(
                                                 dvs_id=cfg.CONF.nsxv.dvs_id):
        error = _("dvs host/vcenter credentials must be defined to use "
                  "dvs features")
        raise nsx_exc.NsxPluginException(err_msg=error)
