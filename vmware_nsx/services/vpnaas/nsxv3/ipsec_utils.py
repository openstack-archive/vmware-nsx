# Copyright 2017 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from vmware_nsxlib.v3 import vpn_ipsec

VPN_PORT_OWNER = 'vpnservice'

ENCRYPTION_ALGORITHM_MAP = {
    'aes-128': vpn_ipsec.EncryptionAlgorithmTypes.ENCRYPTION_ALGORITHM_128,
    'aes-256': vpn_ipsec.EncryptionAlgorithmTypes.ENCRYPTION_ALGORITHM_256,
}

AUTH_ALGORITHM_MAP = {
    'sha1': vpn_ipsec.DigestAlgorithmTypes.DIGEST_ALGORITHM_SHA1,
    'sha256': vpn_ipsec.DigestAlgorithmTypes.DIGEST_ALGORITHM_SHA256,
}

PFS_MAP = {
    'group14': vpn_ipsec.DHGroupTypes.DH_GROUP_14
}

IKE_VERSION_MAP = {
    'v1': vpn_ipsec.IkeVersionTypes.IKE_VERSION_V1,
    'v2': vpn_ipsec.IkeVersionTypes.IKE_VERSION_V2,
}

ENCAPSULATION_MODE_MAP = {
    'tunnel': vpn_ipsec.EncapsulationModeTypes.ENCAPSULATION_MODE_TUNNEL
}

TRANSFORM_PROTOCOL_MAP = {
    'esp': vpn_ipsec.TransformProtocolTypes.TRANSFORM_PROTOCOL_ESP
}

DPD_ACTION_MAP = {
    'hold': vpn_ipsec.DpdProfileActionTypes.DPD_PROFILE_ACTION_HOLD,
    'disabled': None
}

INITIATION_MODE_MAP = {
    'bi-directional': (vpn_ipsec.ConnectionInitiationModeTypes.
        INITIATION_MODE_INITIATOR),
    'response-only': (vpn_ipsec.ConnectionInitiationModeTypes.
        INITIATION_MODE_RESPOND_ONLY)
}

DEFAULT_LOG_LEVEL = vpn_ipsec.IkeLogLevelTypes.LOG_LEVEL_ERROR
