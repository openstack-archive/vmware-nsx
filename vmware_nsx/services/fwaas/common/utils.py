# Copyright 2017 VMware, Inc.
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

from neutron_lib.plugins import directory

try:
    from neutron_fwaas.common import fwaas_constants
except ImportError:
    # FWaaS project no found
    from vmware_nsx.services.fwaas.common import fwaas_mocks \
        as fwaas_constants


def is_fwaas_v2_plugin_enabled():
    fwaas_plugin = directory.get_plugin(fwaas_constants.FIREWALL_V2)
    if fwaas_plugin:
        return True
