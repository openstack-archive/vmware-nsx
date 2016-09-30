# Copyright (c) 2016 VMware, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from oslo_utils import uuidutils

FAKE_NAME = "fake_name"
FAKE_SWITCH_UUID = uuidutils.generate_uuid()

FAKE_PORT_UUID = uuidutils.generate_uuid()
FAKE_PORT = {
    "id": FAKE_PORT_UUID,
    "display_name": FAKE_NAME,
    "resource_type": "LogicalPort",
    "address_bindings": [],
    "logical_switch_id": FAKE_SWITCH_UUID,
    "admin_state": "UP",
    "attachment": {
        "id": "9ca8d413-f7bf-4276-b4c9-62f42516bdb2",
        "attachment_type": "VIF"
    },
    "switching_profile_ids": [
        {
            "value": "64814784-7896-3901-9741-badeff705639",
            "key": "IpDiscoverySwitchingProfile"
        },
        {
            "value": "fad98876-d7ff-11e4-b9d6-1681e6b88ec1",
            "key": "SpoofGuardSwitchingProfile"
        },
        {
            "value": "93b4b7e8-f116-415d-a50c-3364611b5d09",
            "key": "PortMirroringSwitchingProfile"
        },
        {
            "value": "fbc4fb17-83d9-4b53-a286-ccdf04301888",
            "key": "SwitchSecuritySwitchingProfile"
        },
        {
            "value": "f313290b-eba8-4262-bd93-fab5026e9495",
            "key": "QosSwitchingProfile"
        }
    ]
}

FAKE_CONTAINER_PORT = {
    "id": FAKE_PORT_UUID,
    "display_name": FAKE_NAME,
    "resource_type": "LogicalPort",
    "address_bindings": [
        {
            "ip_address": "192.168.1.110",
            "mac_address": "aa:bb:cc:dd:ee:ff"
        }
    ],
    "logical_switch_id": FAKE_SWITCH_UUID,
    "admin_state": "UP",
    "attachment": {
        "id": "9ca8d413-f7bf-4276-b4c9-62f42516bdb2",
        "attachment_type": "CIF",
        "context": {
            "vlan_tag": 122,
            "container_host_vif_id": "c6f817a0-4e36-421e-98a6-8a2faed880bc",
            "key_values": [],
            "resource_type": "CifAttachmentContext",
        }
    },
    "switching_profile_ids": [
        {
            "value": "64814784-7896-3901-9741-badeff705639",
            "key": "IpDiscoverySwitchingProfile"
        },
        {
            "value": "fad98876-d7ff-11e4-b9d6-1681e6b88ec1",
            "key": "SpoofGuardSwitchingProfile"
        },
        {
            "value": "93b4b7e8-f116-415d-a50c-3364611b5d09",
            "key": "PortMirroringSwitchingProfile"
        },
        {
            "value": "fbc4fb17-83d9-4b53-a286-ccdf04301888",
            "key": "SwitchSecuritySwitchingProfile"
        },
        {
            "value": "f313290b-eba8-4262-bd93-fab5026e9495",
            "key": "QosSwitchingProfile"
        }
    ]
}


FAKE_ROUTER_UUID = uuidutils.generate_uuid()
FAKE_ROUTER = {
    "resource_type": "LogicalRouter",
    "revision": 0,
    "id": FAKE_ROUTER_UUID,
    "display_name": FAKE_NAME
}

FAKE_ROUTER_PORT_UUID = uuidutils.generate_uuid()
FAKE_ROUTER_PORT = {
    "resource_type": "LogicalRouterLinkPort",
    "revision": 0,
    "id": FAKE_ROUTER_PORT_UUID,
    "display_name": FAKE_NAME,
    "logical_router_id": FAKE_ROUTER_UUID
}

FAKE_QOS_PROFILE = {
    "resource_type": "QosSwitchingProfile",
    "id": uuidutils.generate_uuid(),
    "display_name": FAKE_NAME,
    "system_defined": False,
    "dscp": {
        "priority": 25,
        "mode": "UNTRUSTED"
    },
    "tags": [],
    "description": FAKE_NAME,
    "class_of_service": 0,
    "shaper_configuration": [
        {
            "resource_type": "IngressRateShaper",
            "enabled": False,
            "peak_bandwidth_mbps": 0,
            "burst_size_bytes": 0,
            "average_bandwidth_mbps": 0
        },
        {
            "resource_type": "IngressBroadcastRateShaper",
            "enabled": False,
            "peak_bandwidth_kbps": 0,
            "average_bandwidth_kbps": 0,
            "burst_size_bytes": 0
        },
        {
            "resource_type": "EgressRateShaper",
            "enabled": False,
            "peak_bandwidth_mbps": 0,
            "burst_size_bytes": 0,
            "average_bandwidth_mbps": 0
        }
    ],
    "_last_modified_user": "admin",
    "_last_modified_time": 1438383180608,
    "_create_time": 1438383180608,
    "_create_user": "admin",
    "_revision": 0
}
