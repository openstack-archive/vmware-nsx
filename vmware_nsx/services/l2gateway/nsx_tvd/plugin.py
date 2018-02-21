# Copyright 2018 VMware, Inc.
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

from networking_l2gw.services.l2gateway import plugin

from vmware_nsx.plugins.nsx import utils as tvd_utils


@tvd_utils.filter_plugins
class L2GatewayPlugin(plugin.L2GatewayPlugin):
    """NSX-TV plugin for L2GW.

    This plugin adds separation between T/V instances
    """
    methods_to_separate = ['get_l2_gateways',
                           'get_l2_gateway_connections']
