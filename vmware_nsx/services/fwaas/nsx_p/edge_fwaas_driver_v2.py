# Copyright 2019 VMware, Inc.
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
from oslo_log import log as logging

from vmware_nsx.services.fwaas.nsx_v3 import edge_fwaas_driver_base \
    as base_driver

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas V2 NSX-P driver'


class EdgeFwaasPDriverV2(base_driver.CommonEdgeFwaasV3Driver):
    """NSX-P driver for Firewall As A Service V2."""

    def __init__(self):
        super(EdgeFwaasPDriverV2, self).__init__(FWAAS_DRIVER_NAME)
        self._core_plugin = None

    @property
    def core_plugin(self):
        """Get the NSX-P core plugin"""
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
            # make sure plugin init was completed
            if not self._core_plugin.init_is_complete:
                self._core_plugin.init_complete(None, None, {})
        return self._core_plugin
