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

from neutron_lib import exceptions as n_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from vmware_nsx._i18n import _
from vmware_nsx.services.lbaas import base_mgr

LOG = logging.getLogger(__name__)


class EdgeL7PolicyManager(base_mgr.Nsxv3LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeL7PolicyManager, self).__init__()

    @log_helpers.log_method_call
    def _l7policy_action(self, context, policy, action, delete=False):
        try:
            self.lbv2_driver.l7policy.successful_completion(
                context, policy, delete=delete)
        except Exception as e:
            self.lbv2_driver.l7policy.failed_completion(context, policy)
            msg = (_('Failed to %(action)s l7policy %(err)s') %
                   {'action': action, 'err': e})
            resource = 'lbaas-l7policy-%s' % action
            raise n_exc.BadRequest(resource=resource, msg=msg)

    @log_helpers.log_method_call
    def create(self, context, policy):
        self._l7policy_action(context, policy, 'create')

    @log_helpers.log_method_call
    def update(self, context, old_policy, new_policy):
        self._l7policy_action(context, new_policy, 'update')

    @log_helpers.log_method_call
    def delete(self, context, policy):
        self._l7policy_action(context, policy, 'delete', delete=True)
