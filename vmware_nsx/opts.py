#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import itertools

import vmware_nsx.common.config
import vmware_nsx.dhcp_meta.lsnmanager
import vmware_nsx.dhcp_meta.nsx
import vmware_nsx.dvs.dvs_utils
import vmware_nsx.extensions.networkgw


def list_opts():
    return [('DEFAULT',
             itertools.chain(
                 vmware_nsx.common.config.cluster_opts,
                 vmware_nsx.common.config.connection_opts,
                 vmware_nsx.common.config.nsx_common_opts)),
            ('NSX', vmware_nsx.common.config.base_opts),
            ('NSX_SYNC', vmware_nsx.common.config.sync_opts),
            ('nsxv', vmware_nsx.common.config.nsxv_opts),
            ('nsx_v3', vmware_nsx.common.config.nsx_v3_opts),
            ('QUOTAS', vmware_nsx.extensions.networkgw.nw_gw_quota_opts),
            ('dvs', vmware_nsx.dvs.dvs_utils.dvs_opts),
            ('NSX_DHCP', vmware_nsx.dhcp_meta.nsx.dhcp_opts),
            ('NSX_METADATA', vmware_nsx.dhcp_meta.nsx.metadata_opts),
            ('NSX_LSN', vmware_nsx.dhcp_meta.lsnmanager.lsn_opts)]
