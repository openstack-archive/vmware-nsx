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

from oslo_log import log as logging

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.services.fwaas.common import fwaas_callbacks as com_callbacks
from vmware_nsxlib.v3 import nsx_constants as consts

LOG = logging.getLogger(__name__)


class Nsxv3FwaasCallbacks(com_callbacks.NsxFwaasCallbacks):
    """NSX-V3 RPC callbacks for Firewall As A Service - V1."""

    def __init__(self, nsxlib):
        super(Nsxv3FwaasCallbacks, self).__init__()
        # Verify that the nsx backend supports FWaaS
        if self.fwaas_enabled:
            self.verify_backend_version(nsxlib)

    def verify_backend_version(self, nsxlib):
        if not nsxlib.feature_supported(consts.FEATURE_ROUTER_FIREWALL):
            # router firewall is not supported
            msg = (_("FWaaS is not supported by the NSX backend (version %s): "
                     "Router firewall is not supported") %
                   self.nsxlib.get_version())
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def should_apply_firewall_to_router(self, context, router_id):
        """Return True if the FWaaS rules should be added to this router."""
        if not super(Nsxv3FwaasCallbacks,
                     self).should_apply_firewall_to_router(context,
                                                           router_id):
            return False

        # get all the relevant router info
        ctx_elevated = context.elevated()
        router_data = self.core_plugin.get_router(ctx_elevated, router_id)
        if not router_data:
            LOG.error("Couldn't read router %s data", router_id)
            return False

        # Check if the FWaaS driver supports this router
        if not self.fwaas_driver.should_apply_firewall_to_router(router_data):
            return False

        return True
