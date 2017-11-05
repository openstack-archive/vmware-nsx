# Copyright 2015 VMware, Inc.
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

LB_METHOD_ROUND_ROBIN = 'ROUND_ROBIN'
LB_METHOD_LEAST_CONNECTIONS = 'LEAST_CONNECTIONS'
LB_METHOD_SOURCE_IP = 'SOURCE_IP'

BALANCE_MAP = {
    LB_METHOD_ROUND_ROBIN: 'round-robin',
    LB_METHOD_LEAST_CONNECTIONS: 'leastconn',
    LB_METHOD_SOURCE_IP: 'ip-hash'}

LB_PROTOCOL_TCP = 'TCP'
LB_PROTOCOL_HTTP = 'HTTP'
LB_PROTOCOL_HTTPS = 'HTTPS'
LB_PROTOCOL_TERMINATED_HTTPS = 'TERMINATED_HTTPS'

PROTOCOL_MAP = {
    LB_PROTOCOL_TCP: 'tcp',
    LB_PROTOCOL_HTTP: 'http',
    LB_PROTOCOL_HTTPS: 'https',
    LB_PROTOCOL_TERMINATED_HTTPS: 'https'}

LB_HEALTH_MONITOR_PING = 'PING'
LB_HEALTH_MONITOR_TCP = 'TCP'
LB_HEALTH_MONITOR_HTTP = 'HTTP'
LB_HEALTH_MONITOR_HTTPS = 'HTTPS'

HEALTH_MONITOR_MAP = {
    LB_HEALTH_MONITOR_PING: 'icmp',
    LB_HEALTH_MONITOR_TCP: 'tcp',
    LB_HEALTH_MONITOR_HTTP: 'http',
    LB_HEALTH_MONITOR_HTTPS: 'tcp'}

LB_SESSION_PERSISTENCE_SOURCE_IP = 'SOURCE_IP'
LB_SESSION_PERSISTENCE_HTTP_COOKIE = 'HTTP_COOKIE'
LB_SESSION_PERSISTENCE_APP_COOKIE = 'APP_COOKIE'

SESSION_PERSISTENCE_METHOD_MAP = {
    LB_SESSION_PERSISTENCE_SOURCE_IP: 'sourceip',
    LB_SESSION_PERSISTENCE_APP_COOKIE: 'cookie',
    LB_SESSION_PERSISTENCE_HTTP_COOKIE: 'cookie'}

SESSION_PERSISTENCE_COOKIE_MAP = {
    LB_SESSION_PERSISTENCE_APP_COOKIE: 'app',
    LB_SESSION_PERSISTENCE_HTTP_COOKIE: 'insert'}

L7_POLICY_ACTION_REJECT = 'REJECT'
L7_POLICY_ACTION_REDIRECT_TO_POOL = 'REDIRECT_TO_POOL'
L7_POLICY_ACTION_REDIRECT_TO_URL = 'REDIRECT_TO_URL'

L7_RULE_TYPE_HOST_NAME = 'HOST_NAME'
L7_RULE_TYPE_PATH = 'PATH'
L7_RULE_TYPE_FILE_TYPE = 'FILE_TYPE'
L7_RULE_TYPE_HEADER = 'HEADER'
L7_RULE_TYPE_COOKIE = 'COOKIE'

L7_RULE_COMPARE_TYPE_REGEX = 'REGEX'
L7_RULE_COMPARE_TYPE_STARTS_WITH = 'STARTS_WITH'
L7_RULE_COMPARE_TYPE_ENDS_WITH = 'ENDS_WITH'
L7_RULE_COMPARE_TYPE_CONTAINS = 'CONTAINS'
L7_RULE_COMPARE_TYPE_EQUAL_TO = 'EQUAL_TO'

# Resource type for resources created on NSX backend
LB_LB_TYPE = 'os-lbaas-lb-id'
LB_LB_NAME = 'os-lbaas-lb-name'
LB_LISTENER_TYPE = 'os-lbaas-listener-id'
LB_HM_TYPE = 'os-lbaas-hm-id'
LB_POOL_TYPE = 'os-lbaas-pool-id'
LB_L7RULE_TYPE = 'os-lbaas-l7rule-id'
LB_HTTP_PROFILE = 'LbHttpProfile'
LB_TCP_PROFILE = 'LbFastTcpProfile'
LB_UDP_PROFILE = 'LbFastUdpProfile'
NSXV3_MONITOR_MAP = {LB_HEALTH_MONITOR_PING: 'LbIcmpMonitor',
                     LB_HEALTH_MONITOR_TCP: 'LbTcpMonitor',
                     LB_HEALTH_MONITOR_HTTP: 'LbHttpMonitor',
                     LB_HEALTH_MONITOR_HTTPS: 'LbHttpsMonitor'}
LB_POOL_ALGORITHM_MAP = {
    LB_METHOD_ROUND_ROBIN: 'WEIGHTED_ROUND_ROBIN',
    LB_METHOD_LEAST_CONNECTIONS: 'LEAST_CONNECTION',
    LB_METHOD_SOURCE_IP: 'IP_HASH',
}
LB_STATS_MAP = {'active_connections': 'current_sessions',
                'bytes_in': 'bytes_in',
                'bytes_out': 'bytes_out',
                'total_connections': 'total_sessions'}
LR_ROUTER_TYPE = 'os-neutron-router-id'
LR_PORT_TYPE = 'os-neutron-rport-id'
LB_CERT_RESOURCE_TYPE = ['certificate_signed', 'certificate_self_signed']
DEFAULT_LB_SIZE = 'SMALL'
LB_FLAVOR_SIZES = ['SMALL', 'MEDIUM', 'LARGE', 'small', 'medium', 'large']
LB_RULE_MATCH_TYPE = {
    L7_RULE_COMPARE_TYPE_CONTAINS: 'CONTAINS',
    L7_RULE_COMPARE_TYPE_ENDS_WITH: 'ENDS_WITH',
    L7_RULE_COMPARE_TYPE_EQUAL_TO: 'EQUALS',
    L7_RULE_COMPARE_TYPE_REGEX: 'REGEX',
    L7_RULE_COMPARE_TYPE_STARTS_WITH: 'STARTS_WITH'}
LB_SELECT_POOL_ACTION = 'LbSelectPoolAction'
LB_HTTP_REDIRECT_ACTION = 'LbHttpRedirectAction'
LB_REJECT_ACTION = 'LbHttpRejectAction'
LB_HTTP_REDIRECT_STATUS = '302'
LB_HTTP_REJECT_STATUS = '403'
LB_RULE_HTTP_REQUEST_REWRITE = 'HTTP_REQUEST_REWRITE'
LB_RULE_HTTP_FORWARDING = 'HTTP_FORWARDING'
LB_RULE_HTTP_RESPONSE_REWRITE = 'HTTP_RESPONSE_REWRITE'
