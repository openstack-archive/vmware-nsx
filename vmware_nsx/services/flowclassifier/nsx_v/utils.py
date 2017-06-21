# Copyright 2016 VMware, Inc.
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

from neutron_lib.plugins import directory
from oslo_log import log as logging

LOG = logging.getLogger(__name__)
SERVICE_INSERTION_SG_NAME = 'Service Insertion Security Group'
SERVICE_INSERTION_RESOURCE = 'Service Insertion'

# Using the constant defined here to avoid the need to clone networking-sfc
# if the driver is not used.
FLOW_CLASSIFIER_EXT = "flow_classifier"


class NsxvServiceInsertionHandler(object):

    def __init__(self, core_plugin):
        super(NsxvServiceInsertionHandler, self).__init__()
        self._nsxv = core_plugin.nsx_v
        self._initialized = False

    def _initialize_handler(self):
        if not self._initialized:
            self._enabled = False
            self._sg_id = None
            if self.is_service_insertion_enabled():
                self._sg_id = self.get_service_inserion_sg_id()
                if not self._sg_id:
                    # failed to create the security group or the driver
                    # was not configured
                    LOG.error("Failed to enable service insertion. "
                              "Security group not found.")
                    self._enabled = False
                else:
                    self._enabled = True
            self._initialized = True

    def is_service_insertion_enabled(self):
        # Note - this cannot be called during init, since the manager is busy
        if (directory.get_plugin(FLOW_CLASSIFIER_EXT)):
            return True
        return False

    def get_service_inserion_sg_id(self):
        # Note - this cannot be called during init, since the nsxv flow
        # classifier driver creates this group
        return self._nsxv.vcns.get_security_group_id(
            SERVICE_INSERTION_SG_NAME)

    @property
    def enabled(self):
        self._initialize_handler()
        return self._enabled

    @property
    def sg_id(self):
        self._initialize_handler()
        return self._sg_id
