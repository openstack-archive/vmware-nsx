# Copyright (c) 2013 OpenStack Foundation
# All Rights Reserved.
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
from oslo_log import log
from oslo_utils import excutils
import stevedore

LOG = log.getLogger(__name__)


class ExtensionManager(stevedore.named.NamedExtensionManager):
    """Manage extension drivers using drivers."""

    def __init__(self, extension_drivers=None):
        # Ordered list of extension drivers, defining
        # the order in which the drivers are called.
        self.ordered_ext_drivers = []

        if extension_drivers is None:
            extension_drivers = cfg.CONF.nsx_extension_drivers

        LOG.info("Configured extension driver names: %s",
                 extension_drivers)
        super(ExtensionManager, self).__init__('vmware_nsx.extension_drivers',
                                               extension_drivers,
                                               invoke_on_load=True,
                                               name_order=True)
        LOG.info("Loaded extension driver names: %s", self.names())
        self._register_drivers()

    def _register_drivers(self):
        """Register all extension drivers.

        This method should only be called once in the ExtensionManager
        constructor.
        """
        for ext in self:
            self.ordered_ext_drivers.append(ext)
        LOG.info("Registered extension drivers: %s",
                 [driver.name for driver in self.ordered_ext_drivers])

    def initialize(self):
        # Initialize each driver in the list.
        for driver in self.ordered_ext_drivers:
            LOG.info("Initializing extension driver '%s'", driver.name)
            driver.obj.initialize()

    def extension_aliases(self):
        exts = []
        for driver in self.ordered_ext_drivers:
            alias = driver.obj.extension_alias
            if alias:
                exts.append(alias)
                LOG.info("Got %(alias)s extension from driver '%(drv)s'",
                         {'alias': alias, 'drv': driver.name})
        return exts

    def _call_on_ext_drivers(self, method_name, plugin_context, data, result):
        """Helper method for calling a method across all extension drivers."""
        for driver in self.ordered_ext_drivers:
            try:
                getattr(driver.obj, method_name)(plugin_context, data, result)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.info("Extension driver '%(name)s' failed in "
                             "%(method)s",
                             {'name': driver.name, 'method': method_name})

    def process_create_network(self, plugin_context, data, result):
        """Notify all extension drivers during network creation."""
        self._call_on_ext_drivers("process_create_network", plugin_context,
                                  data, result)

    def process_update_network(self, plugin_context, data, result):
        """Notify all extension drivers during network update."""
        self._call_on_ext_drivers("process_update_network", plugin_context,
                                  data, result)

    def process_create_subnet(self, plugin_context, data, result):
        """Notify all extension drivers during subnet creation."""
        self._call_on_ext_drivers("process_create_subnet", plugin_context,
                                  data, result)

    def process_update_subnet(self, plugin_context, data, result):
        """Notify all extension drivers during subnet update."""
        self._call_on_ext_drivers("process_update_subnet", plugin_context,
                                  data, result)

    def process_create_port(self, plugin_context, data, result):
        """Notify all extension drivers during port creation."""
        self._call_on_ext_drivers("process_create_port", plugin_context,
                                  data, result)

    def process_update_port(self, plugin_context, data, result):
        """Notify all extension drivers during port update."""
        self._call_on_ext_drivers("process_update_port", plugin_context,
                                  data, result)

    def _call_on_dict_driver(self, method_name, session, base_model, result):
        for driver in self.ordered_ext_drivers:
            try:
                getattr(driver.obj, method_name)(session, base_model, result)
            except Exception:
                LOG.error("Extension driver '%(name)s' failed in "
                          "%(method)s",
                          {'name': driver.name, 'method': method_name})
                raise

    def extend_network_dict(self, session, base_model, result):
        """Notify all extension drivers to extend network dictionary."""
        self._call_on_dict_driver("extend_network_dict", session, base_model,
                                  result)

    def extend_subnet_dict(self, session, base_model, result):
        """Notify all extension drivers to extend subnet dictionary."""
        self._call_on_dict_driver("extend_subnet_dict", session, base_model,
                                  result)

    def extend_port_dict(self, session, base_model, result):
        """Notify all extension drivers to extend port dictionary."""
        self._call_on_dict_driver("extend_port_dict", session, base_model,
                                  result)
