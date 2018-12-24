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
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeL7PolicyManagerFromDict(base_mgr.NsxpLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def create(self, context, policy, completor):
        vs_client = self.core_plugin.nsxpolicy.load_balancer.virtual_server
        policy_name = utils.get_name_and_uuid(policy['name'] or 'policy',
                                              policy['id'])
        rule_body = lb_utils.convert_l7policy_to_lb_rule(policy)
        try:

            vs_client.add_lb_rule(policy['listener_id'],
                                  name=policy_name,
                                  position=policy.get('position', 0) - 1,
                                  **rule_body)
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to add rule %(rule)% to virtual server '
                          '%(vs)s at NSX backend',
                          {'rule': policy['id'], 'vs': policy['listener_id']})

        completor(success=True)

    @log_helpers.log_method_call
    def update(self, context, old_policy, new_policy, completor):
        vs_client = self.core_plugin.nsxpolicy.load_balancer.virtual_server
        policy_name = utils.get_name_and_uuid(old_policy['name'] or 'policy',
                                              old_policy['id'])
        rule_body = lb_utils.convert_l7policy_to_lb_rule(context, new_policy)
        try:
            vs_client.update_lb_rule(
                new_policy['listener_id'],
                name=policy_name,
                position=new_policy.get('position', 0) - 1,
                **rule_body)

        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to update L7policy %(policy)s: '
                          '%(err)s', {'policy': old_policy['id'], 'err': e})
        completor(success=True)

    def delete(self, context, policy, completor):
        vs_client = self.core_plugin.nsxpolicy.load_balancer.virtual_server
        policy_name = utils.get_name_and_uuid(policy['name'] or 'policy',
                                              policy['id'])
        try:
            vs_client.remove_lb_rule(policy['listener_id'],
                                     policy_name)
        except nsx_exc.NsxResourceNotFound:
            pass
        except nsxlib_exc.ManagerError:
            completor(success=False)
            msg = (_('Failed to delete L7 policy: %(policy)s') %
                   {'policy': policy['id']})
            raise n_exc.BadRequest(resource='lbaas-l7policy', msg=msg)
        completor(success=True)

    @log_helpers.log_method_call
    def delete_cascade(self, context, policy, completor):
        self.delete(context, policy, completor)
