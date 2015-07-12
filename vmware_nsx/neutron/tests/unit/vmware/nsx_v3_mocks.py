# Copyright (c) 2015 VMware, Inc.
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

from vmware_nsx.neutron.plugins.vmware.common import nsx_constants


FAKE_NAME = "fake_name"


def create_logical_switch(display_name, transport_zone_id, tags,
                          replication_mode=nsx_constants.MTEP,
                          admin_state=nsx_constants.ADMIN_STATE_UP):
    FAKE_TZ_UUID = uuidutils.generate_uuid()
    FAKE_SWITCH_UUID = uuidutils.generate_uuid()

    FAKE_SWITCH = {
        "id": FAKE_SWITCH_UUID,
        "display_name": FAKE_NAME,
        "resource_type": "LogicalSwitch",
        "address_bindings": [],
        "transport_zone_id": FAKE_TZ_UUID,
        "replication_mode": "MTEP",
        "admin_state": "UP",
        "vni": 50056,
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
        ],
    }
    return FAKE_SWITCH


def create_logical_port(lswitch_id, vif_uuid, tags,
                        attachment_type=nsx_constants.ATTACHMENT_VIF,
                        admin_state=True, name=None, address_bindings=None):
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
    return FAKE_PORT
