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

from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory

from neutron_fwaas.services.firewall import fwaas_plugin

from vmware_nsx.plugins.nsx import utils as tvd_utils


@tvd_utils.filter_plugins
class FwaasTVPluginV1(fwaas_plugin.FirewallPlugin):
    """NSX-TV plugin for Firewall As A Service - V1.

    This plugin adds separation between T/V instances
    """
    methods_to_separate = ['get_firewalls',
                           'get_firewall_policies',
                           'get_firewall_rules']

    def validate_firewall_routers_not_in_use(
        self, context, router_ids, fwid=None):
        # Override this method to verify that the router & firewall belongs to
        # the same plugin
        context_plugin_type = tvd_utils.get_tvd_plugin_type_for_project(
            context.project_id, context)
        core_plugin = directory.get_plugin()
        for rtr_id in router_ids:
            rtr_plugin = core_plugin._get_plugin_from_router_id(
                context, rtr_id)
            if rtr_plugin.plugin_type() != context_plugin_type:
                err_msg = (_('Router should belong to the %s plugin '
                             'as the firewall') % context_plugin_type)
                raise n_exc.InvalidInput(error_message=err_msg)
