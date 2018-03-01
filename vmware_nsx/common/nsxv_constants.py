# Copyright 2014 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

# Edge size
COMPACT = 'compact'
LARGE = 'large'
XLARGE = 'xlarge'
QUADLARGE = 'quadlarge'


EXCLUSIVE = "exclusive"

# Edge type
SERVICE_EDGE = 'service'
VDR_EDGE = 'vdr'

# Internal element purpose
INTER_EDGE_PURPOSE = 'inter_edge_net'

# etc
INTERNAL_TENANT_ID = 'metadata_internal_project'

# L2 gateway edge name prefix
L2_GATEWAY_EDGE = 'L2 bridging'

# An artificial limit for router name length - subtract 1 for the - separator
ROUTER_NAME_LENGTH = (78 - 1)

# LoadBalancer Certificate constants
#NOTE(abhiraut): Number of days specify the total number of days for which the
#                certificate will be active. This certificate will expire in
#                10 years. Once the backend API allows creation of certs which
#                do not expire, the following constant should be removed.
CERT_NUMBER_OF_DAYS = 3650
CSR_REQUEST = ("<csr><subject>"
               "<attribute><key>CN</key><value>metadata.nsx.local</value>"
               "</attribute>"
               "<attribute><key>O</key><value>Organization</value></attribute>"
               "<attribute><key>OU</key><value>Unit</value></attribute>"
               "<attribute><key>L</key><value>Locality</value></attribute>"
               "<attribute><key>ST</key><value>State</value></attribute>"
               "<attribute><key>C</key><value>US</value></attribute>"
               "</subject><algorithm>RSA</algorithm><keySize>2048</keySize>"
               "</csr>")

# Reserved IPs that cannot overlap defined subnets
RESERVED_IPS = ["169.254.128.0/17",
                "169.254.1.0/24",
                "169.254.64.192/26"]

# VPNaaS constants
ENCRYPTION_ALGORITHM_MAP = {
    '3des': '3des',
    'aes-128': 'aes',
    'aes-256': 'aes256'
}

PFS_MAP = {
    'group2': 'dh2',
    'group5': 'dh5'
}

TRANSFORM_PROTOCOL_ALLOWED = ('esp',)

ENCAPSULATION_MODE_ALLOWED = ('tunnel',)
