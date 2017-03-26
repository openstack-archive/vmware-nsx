# Copyright 2014 VMware, Inc.
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

from oslo_config import cfg
import stevedore

from oslo_log import log

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc

LOG = log.getLogger(__name__)
ROUTER_TYPE_DRIVERS = ["distributed", "exclusive", "shared"]


class RouterTypeManager(stevedore.named.NamedExtensionManager):
    """Manage router segment types using drivers."""

    def __init__(self, plugin):
        # Mapping from type name to DriverManager
        self.drivers = {}

        LOG.info("Configured router type driver names: %s",
                 ROUTER_TYPE_DRIVERS)
        super(RouterTypeManager, self).__init__(
            'vmware_nsx.neutron.nsxv.router_type_drivers',
            ROUTER_TYPE_DRIVERS,
            invoke_on_load=True,
            invoke_args=(plugin,))
        LOG.info("Loaded type driver names: %s", self.names())
        self._register_types()
        self._check_tenant_router_types(cfg.CONF.nsxv.tenant_router_types)

    def _register_types(self):
        for ext in self:
            router_type = ext.obj.get_type()
            if router_type in self.drivers:
                LOG.error("Type driver '%(new_driver)s' ignored because "
                          "type driver '%(old_driver)s' is already "
                          "registered for type '%(type)s'",
                          {'new_driver': ext.name,
                           'old_driver': self.drivers[router_type].name,
                           'type': router_type})
            else:
                self.drivers[router_type] = ext
        LOG.info("Registered types: %s", self.drivers.keys())

    def _check_tenant_router_types(self, types):
        self.tenant_router_types = []
        for router_type in types:
            if router_type in self.drivers:
                self.tenant_router_types.append(router_type)
            else:
                msg = _("No type driver for tenant router_type: %s. "
                        "Service terminated!") % router_type
                LOG.error(msg)
                raise SystemExit(msg)
        LOG.info("Tenant router_types: %s", self.tenant_router_types)

    def get_tenant_router_driver(self, context, router_type):
        driver = self.drivers.get(router_type)
        if driver:
            return driver.obj
        raise nsx_exc.NoRouterAvailable()

    def decide_tenant_router_type(self, context, router_type=None):
        if router_type is None:
            for rt in self.tenant_router_types:
                driver = self.drivers.get(rt)
                if driver:
                    return rt
            raise nsx_exc.NoRouterAvailable()
        elif context.is_admin:
            driver = self.drivers.get(router_type)
            if driver:
                return router_type
        elif router_type in self.tenant_router_types:
            driver = self.drivers.get(router_type)
            if driver:
                return router_type
        raise nsx_exc.NoRouterAvailable()
