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
