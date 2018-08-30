# Copyright 2014 VMware, Inc.
#
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
#

# Note: this import should be here in order to appear before NeutronDbPluginV2
#  in each of the plugins. If not: security-group/-rule will not have all the
# relevant extend dict registries.
from neutron.db.models import securitygroup  # noqa

from vmware_nsx.plugins.dvs import plugin as dvs
from vmware_nsx.plugins.nsx import plugin as nsx
from vmware_nsx.plugins.nsx_mh import plugin as nsx_mh
from vmware_nsx.plugins.nsx_p import plugin as nsx_p
from vmware_nsx.plugins.nsx_v import plugin as nsx_v
from vmware_nsx.plugins.nsx_v3 import plugin as nsx_v3

NsxDvsPlugin = dvs.NsxDvsV2
NsxPlugin = nsx_mh.NsxPluginV2
NsxVPlugin = nsx_v.NsxVPluginV2
NsxV3Plugin = nsx_v3.NsxV3Plugin
NsxPolicyPlugin = nsx_p.NsxPolicyPlugin
NsxTVDPlugin = nsx.NsxTVDPlugin
