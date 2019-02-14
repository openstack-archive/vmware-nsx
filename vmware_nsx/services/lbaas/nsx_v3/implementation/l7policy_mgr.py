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
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc

LOG = logging.getLogger(__name__)


class EdgeL7PolicyManagerFromDict(base_mgr.Nsxv3LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def _update_policy_position(self, vs_id, rule_id, position):
        vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server
        vs = vs_client.get(vs_id)
        lb_rules = vs.get('rule_ids', [])
        if rule_id in lb_rules:
            lb_rules.remove(rule_id)
        if len(lb_rules) < position:
            lb_rules.append(rule_id)
        else:
            lb_rules.insert(position - 1, rule_id)
        vs_client.update(vs_id, rule_ids=lb_rules)

    @log_helpers.log_method_call
    def create(self, context, policy, completor):
        lb_id = policy['listener']['loadbalancer_id']
        listener_id = policy['listener_id']
        rule_client = self.core_plugin.nsxlib.load_balancer.rule
        tags = lb_utils.get_tags(self.core_plugin, policy['id'],
                                 lb_const.LB_L7POLICY_TYPE,
                                 policy['tenant_id'], context.project_name)

        binding = nsx_db.get_nsx_lbaas_listener_binding(
            context.session, lb_id, listener_id)
        if not binding:
            completor(success=False)
            msg = _('Cannot find nsx lbaas binding for listener '
                    '%(listener_id)s') % {'listener_id': listener_id}
            raise n_exc.BadRequest(resource='lbaas-l7policy-create', msg=msg)

        vs_id = binding['lb_vs_id']
        rule_body = lb_utils.convert_l7policy_to_lb_rule(context, policy)
        try:
            lb_rule = rule_client.create(tags=tags, **rule_body)
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to create lb rule at NSX backend')
        try:
            self._update_policy_position(vs_id, lb_rule['id'],
                                         policy['position'])
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to add rule %(rule)% to virtual server '
                          '%(vs)s at NSX backend', {'rule': lb_rule['id'],
                                                    'vs': vs_id})

        nsx_db.add_nsx_lbaas_l7policy_binding(
            context.session, policy['id'], lb_rule['id'], vs_id)
        completor(success=True)

    @log_helpers.log_method_call
    def update(self, context, old_policy, new_policy, completor):
        rule_client = self.core_plugin.nsxlib.load_balancer.rule
        binding = nsx_db.get_nsx_lbaas_l7policy_binding(context.session,
                                                        old_policy['id'])
        if not binding:
            completor(success=False)
            msg = _('Cannot find nsx lbaas binding for policy '
                    '%(policy_id)s') % {'policy_id': old_policy['id']}
            raise n_exc.BadRequest(resource='lbaas-l7policy-update', msg=msg)

        vs_id = binding['lb_vs_id']
        lb_rule_id = binding['lb_rule_id']
        rule_body = lb_utils.convert_l7policy_to_lb_rule(context, new_policy)
        try:
            rule_client.update(lb_rule_id, **rule_body)
            if new_policy['position'] != old_policy['position']:
                self._update_policy_position(vs_id, lb_rule_id,
                                             new_policy['position'])

        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to update L7policy %(policy)s: '
                          '%(err)s', {'policy': old_policy['id'], 'err': e})

        completor(success=True)

    @log_helpers.log_method_call
    def delete(self, context, policy, completor):
        vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server
        rule_client = self.core_plugin.nsxlib.load_balancer.rule
        binding = nsx_db.get_nsx_lbaas_l7policy_binding(context.session,
                                                        policy['id'])
        if binding:
            vs_id = binding['lb_vs_id']
            rule_id = binding['lb_rule_id']
            try:
                # Update virtual server to remove lb rule
                vs_client.remove_rule(vs_id, rule_id)
                rule_client.delete(rule_id)
            except nsxlib_exc.ResourceNotFound:
                LOG.warning('LB rule %(rule)s is not found on NSX',
                            {'rule': rule_id})
            except nsxlib_exc.ManagerError:
                completor(success=False)
                msg = (_('Failed to delete lb rule: %(rule)s') %
                       {'rule': rule_id})
                raise n_exc.BadRequest(resource='lbaas-l7policy-delete',
                                       msg=msg)
            nsx_db.delete_nsx_lbaas_l7policy_binding(
                context.session, policy['id'])

        completor(success=True)

    @log_helpers.log_method_call
    def delete_cascade(self, context, policy, completor):
        self.delete(context, policy, completor)
