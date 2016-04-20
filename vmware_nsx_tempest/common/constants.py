# Copyright 2016 VMware, Inc.
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

from oslo_log import log

LOG = log.getLogger(__name__)

# L2GW constants.
L2GW = "l2_gateway"
L2GWS = L2GW + "s"
L2_GWS_BASE_URI = "/l2-gateways"
EXPECTED_HTTP_RESPONSE_200 = "200"
EXPECTED_HTTP_RESPONSE_201 = "201"
EXPECTED_HTTP_RESPONSE_204 = "204"
L2GWC = "l2_gateway_connection"
