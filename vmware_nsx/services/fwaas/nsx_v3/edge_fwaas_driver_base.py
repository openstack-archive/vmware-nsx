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

from neutron_lib import context as n_context
from neutron_lib.exceptions import firewall_v2 as exceptions
from oslo_log import log as logging

from vmware_nsx.services.fwaas.common import fwaas_driver_base

LOG = logging.getLogger(__name__)


class CommonEdgeFwaasV3Driver(fwaas_driver_base.EdgeFwaasDriverBaseV2):
    """Base class for NSX-V3/Policy driver for Firewall As A Service  V2."""

    def __init__(self, driver_name):
        super(CommonEdgeFwaasV3Driver, self).__init__(driver_name)
        self.backend_support = True
        self.driver_exception = exceptions.FirewallInternalDriverError
        self._core_plugin = None

    @property
    def core_plugin(self):
        """Get the core plugin - should be implemented by each driver"""
        pass

    def validate_backend_version(self):
        """Validate NSX backend supports FWaaS
        Can be implemented by each driver
        """
        pass

    def _update_backend_routers(self, apply_list, fwg_id):
        """Update all the affected router on the backend"""
        self.validate_backend_version()
        LOG.info("Updating routers firewall for firewall group %s", fwg_id)
        context = n_context.get_admin_context()
        routers = set()
        # the apply_list is a list of tuples: routerInfo, port-id
        for router_info, port_id in apply_list:
            # Skip dummy entries that were added only to avoid errors
            if isinstance(router_info, str):
                continue
            # Skip unsupported routers
            if not self.should_apply_firewall_to_router(router_info.router):
                continue
            routers.add(router_info.router_id)

        # update each router once
        for router_id in routers:
            self.core_plugin.update_router_firewall(context, router_id,
                                                    from_fw=True)

    def should_apply_firewall_to_router(self, router_data):
        """Return True if the firewall rules should be added the router"""
        if not router_data.get('external_gateway_info'):
            LOG.info("Cannot apply firewall to router %s with no gateway",
                     router_data['id'])
            return False
        return True
