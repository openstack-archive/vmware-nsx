# Copyright 2014 VMware, Inc
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

from vmware_nsx.neutron.plugins.vmware.plugins import nsx_v
from vmware_nsx.neutron.plugins.vmware.plugins.nsx_v_drivers import (
    abstract_router_driver as router_driver)


class RouterSharedDriver(router_driver.RouterBaseDriver):

    def get_type(self):
        return "shared"

    def create_router(self, context, lrouter, allow_metadata=True):
        pass

    def update_router(self, context, router_id, router):
        return super(nsx_v.NsxVPluginV2, self.plugin).update_router(
            context, router_id, router)

    def delete_router(self, context, router_id):
        pass

    def update_routes(self, context, router_id, nexthop):
        #TODO(berlin) do non-exclusive router op.
        pass

    def _update_router_gw_info(self, context, router_id, info):
        #TODO(berlin) do non-exclusive router op.
        router = self.plugin._get_router(context, router_id)
        super(nsx_v.NsxVPluginV2, self.plugin)._update_router_gw_info(
            context, router_id, info, router=router)
        pass

    def add_router_interface(self, context, router_id, interface_info):
        #TODO(berlin): add router interface.
        info = super(nsx_v.NsxVPluginV2, self.plugin).add_router_interface(
            context, router_id, interface_info)
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        #TODO(berlin) do non-exclusive router op.
        info = super(nsx_v.NsxVPluginV2, self.plugin).remove_router_interface(
            context, router_id, interface_info)
        return info

    def _update_edge_router(self, context, router_id):
        #TODO(berlin) do non-exclusive router op.
        pass
