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

from vmware_nsx.services.lbaas import nsx_plugin

from vmware_nsx.plugins.nsx import utils as tvd_utils


@tvd_utils.filter_plugins
class LoadBalancerTVPluginV2(nsx_plugin.LoadBalancerNSXPluginV2):
    """NSX-TV plugin for LBaaS V2.

    This plugin adds separation between T/V instances
    """
    methods_to_separate = ['get_loadbalancers',
                           'get_listeners',
                           'get_pools',
                           'get_healthmonitors',
                           'get_l7policies']
