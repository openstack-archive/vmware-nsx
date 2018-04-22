# Copyright 2013 OpenStack Foundation.
# All Rights Reserved.
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

from oslo_config import cfg

from vmware_nsx.common import nsxv_constants

EDGE_ID = 'edge_id'
ROUTER_ID = 'router_id'
DHCP_EDGE_PREFIX = 'dhcp-'
PLR_EDGE_PREFIX = 'plr-'
BACKUP_ROUTER_PREFIX = 'backup-'
EDGE_NAME_LEN = 20

# Interface
EXTERNAL_VNIC_INDEX = 0
INTERNAL_VNIC_INDEX = 1
EXTERNAL_VNIC_NAME = "external"
INTERNAL_VNIC_NAME = "internal"
MAX_VNIC_NUM = 10
# we can add at most 8 interfaces on service edge. Other two interfaces
# are used for metadata and external network access.
MAX_INTF_NUM = 8
MAX_TUNNEL_NUM = (cfg.CONF.nsxv.maximum_tunnels_per_vnic if
                  (cfg.CONF.nsxv.maximum_tunnels_per_vnic < 110 and
                   cfg.CONF.nsxv.maximum_tunnels_per_vnic > 0)
                  else 10)

# SNAT rule location
PREPEND = 0
APPEND = -1

# error code
NSX_ERROR_ALREADY_EXISTS = 210
VCNS_ERROR_CODE_EDGE_NOT_RUNNING = 10013
NSX_ERROR_DHCP_OVERLAPPING_IP = 12501
NSX_ERROR_DHCP_DUPLICATE_HOSTNAME = 12504
NSX_ERROR_DHCP_DUPLICATE_MAC = 12518

NSX_ERROR_IPAM_ALLOCATE_ALL_USED = 120051
NSX_ERROR_IPAM_ALLOCATE_IP_USED = 120056

NSX_ERROR_ALREADY_HAS_SG_POLICY = 120508

SUFFIX_LENGTH = 8

#Edge size
SERVICE_SIZE_MAPPING = {
    'router': nsxv_constants.COMPACT,
    'dhcp': nsxv_constants.COMPACT,
    'lb': nsxv_constants.COMPACT
}
ALLOWED_EDGE_SIZES = (nsxv_constants.COMPACT,
                      nsxv_constants.LARGE,
                      nsxv_constants.XLARGE,
                      nsxv_constants.QUADLARGE)

#Edge type
ALLOWED_EDGE_TYPES = (nsxv_constants.SERVICE_EDGE,
                      nsxv_constants.VDR_EDGE)

SUPPORTED_DHCP_OPTIONS = {
    'interface-mtu': 'option26',
    'tftp-server-name': 'option66',
    'bootfile-name': 'option67',
    'classless-static-route': 'option121',
    'tftp-server-address': 'option150',
    'tftp-server': 'option150',
    'server-ip-address': 'option150',
}


# router status by number
class RouterStatus(object):
    ROUTER_STATUS_ACTIVE = 0
    ROUTER_STATUS_DOWN = 1
    ROUTER_STATUS_PENDING_CREATE = 2
    ROUTER_STATUS_PENDING_DELETE = 3
    ROUTER_STATUS_ERROR = 4


class InternalEdgePurposes(object):
    INTER_EDGE_PURPOSE = 'inter_edge_net'
