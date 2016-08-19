# Copyright 2015 VMware, Inc.
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

# Admin statuses
ADMIN_STATE_UP = "UP"
ADMIN_STATE_DOWN = "DOWN"

ADMIN_STATUSES = [ADMIN_STATE_UP, ADMIN_STATE_DOWN]

# Port attachment types
ATTACHMENT_VIF = "VIF"
ATTACHMENT_LR = "LOGICALROUTER"
ATTACHMENT_DHCP = "DHCP_SERVICE"
ATTACHMENT_MDPROXY = "METADATA_PROXY"
ATTACHMENT_CIF = "CIF"
CIF_RESOURCE_TYPE = "CifAttachmentContext"

ATTACHMENT_TYPES = [ATTACHMENT_VIF, ATTACHMENT_LR]

# Replication modes
MTEP = "MTEP"
SOURCE = "SOURCE"

REPLICATION_MODES = [MTEP, SOURCE]

# Router type
ROUTER_TYPE_TIER0 = "TIER0"
ROUTER_TYPE_TIER1 = "TIER1"

ROUTER_TYPES = [ROUTER_TYPE_TIER0, ROUTER_TYPE_TIER1]

LROUTERPORT_UPLINK = "LogicalRouterUplinkPort"
LROUTERPORT_DOWNLINK = "LogicalRouterDownLinkPort"
LROUTERPORT_LINKONTIER0 = "LogicalRouterLinkPortOnTIER0"
LROUTERPORT_LINKONTIER1 = "LogicalRouterLinkPortOnTIER1"

LROUTER_TYPES = [LROUTERPORT_UPLINK,
                 LROUTERPORT_DOWNLINK,
                 LROUTERPORT_LINKONTIER0,
                 LROUTERPORT_LINKONTIER1]

# L2 agent vif type
VIF_TYPE_DVS = 'dvs'

# NSXv3 L2 Gateway constants
BRIDGE_ENDPOINT = "BRIDGEENDPOINT"

# NSX service type
SERVICE_DHCP = "dhcp"

# NSXv3 CORE PLUGIN PATH
VMWARE_NSX_V3_PLUGIN_NAME = 'vmware_nsx.plugin.NsxV3Plugin'
