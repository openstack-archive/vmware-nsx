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

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from neutron_lib import constants
from neutron_lib import exceptions as n_exc

from vmware_nsx._i18n import _
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common

LOG = logging.getLogger(__name__)

type_by_compare_type = {
    lb_const.L7_RULE_COMPARE_TYPE_EQUAL_TO: '',
    lb_const.L7_RULE_COMPARE_TYPE_REGEX: '_reg',
    lb_const.L7_RULE_COMPARE_TYPE_STARTS_WITH: '_beg',
    lb_const.L7_RULE_COMPARE_TYPE_ENDS_WITH: '_end',
    lb_const.L7_RULE_COMPARE_TYPE_CONTAINS: '_sub'
}


def policy_to_application_rule(policy):
    condition = ''
    rule_lines = []
    for rule in policy['rules']:
        if rule['provisioning_status'] == constants.PENDING_DELETE:
            # skip this rule as it is being deleted
            continue

        type_by_comp = type_by_compare_type.get(rule['compare_type'])
        if type_by_comp is None:
            type_by_comp = ''
            LOG.warnning('Unsupported compare type %(type)s is used in '
                         'policy %(id)s', {'type': rule['compare_type'],
                                           'id': policy['id']})

        if rule['type'] == lb_const.L7_RULE_TYPE_COOKIE:
            # Example: acl <id> hdr_sub(cookie) SEEN=1
            hdr_type = 'hdr' + type_by_comp
            rule_line = ('acl %(rule_id)s %(hdr_type)s(cookie) '
                         '%(key)s=%(val)s' % {'rule_id': rule['id'],
                                              'hdr_type': hdr_type,
                                              'key': rule['key'],
                                              'val': rule['value']})
        elif rule['type'] == lb_const.L7_RULE_TYPE_HEADER:
            # Example: acl <id> hdr(user-agent) -i test
            hdr_type = 'hdr' + type_by_comp
            rule_line = ('acl %(rule_id)s %(hdr_type)s(%(key)s) '
                         '-i %(val)s' % {'rule_id': rule['id'],
                                         'hdr_type': hdr_type,
                                         'key': rule['key'],
                                         'val': rule['value']})
        elif rule['type'] == lb_const.L7_RULE_TYPE_HOST_NAME:
            # Example: acl <id> hdr_beg(host) -i abcd
            hdr_type = 'hdr' + type_by_comp
            # -i for case insensitive host name
            rule_line = ('acl %(rule_id)s %(hdr_type)s(host) '
                         '-i %(val)s' % {'rule_id': rule['id'],
                                         'hdr_type': hdr_type,
                                         'val': rule['value']})
        elif rule['type'] == lb_const.L7_RULE_TYPE_PATH:
            # Example: acl <id> path_beg -i /images
            # -i for case insensitive path
            path_type = 'path' + type_by_comp
            rule_line = ('acl %(rule_id)s %(path_type)s '
                         '-i %(val)s' % {'rule_id': rule['id'],
                                         'path_type': path_type,
                                         'val': rule['value']})
        elif rule['type'] == lb_const.L7_RULE_TYPE_FILE_TYPE:
            # Example: acl <id> path_sub -i .jpg
            # Regardless of the compare type, always check contained in path.
            # -i for case insensitive file type
            val = rule['value']
            if not val.startswith('.'):
                val = '.' + val
            rule_line = ('acl %(rule_id)s path_sub '
                         '-i %(val)s' % {'rule_id': rule['id'],
                                         'val': val})
        else:
            msg = _('Unsupported L7rule type %s') % rule['type']
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

        rule_lines.append(rule_line)
        invert_sign = '!' if rule['invert'] else ''
        condition = condition + invert_sign + rule['id'] + ' '

    if rule_lines:
        # concatenate all the rules with new lines
        all_rules = '\n'.join(rule_lines + [''])
        # remove he last space from the condition
        condition = condition[:-1]
    else:
        all_rules = ''
        condition = 'TRUE'

    # prepare the action
    if policy['action'] == lb_const.L7_POLICY_ACTION_REJECT:
        # return HTTP 403 response
        action = 'http-request deny'
    elif policy['action'] == lb_const.L7_POLICY_ACTION_REDIRECT_TO_POOL:
        action = 'use_backend pool_%s' % policy['redirect_pool_id']
    elif policy['action'] == lb_const.L7_POLICY_ACTION_REDIRECT_TO_URL:
        action = 'redirect location %s' % policy['redirect_url']
    else:
        msg = _('Unsupported L7policy action %s') % policy['action']
        raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

    # Build the final script
    script = all_rules + '%(action)s if %(cond)s' % {
        'action': action, 'cond': condition}
    app_rule = {'name': 'pol_' + policy['id'], 'script': script}
    return app_rule


def policy_to_edge_and_rule_id(context, policy_id):
    # get the nsx application rule id and edge id
    binding = nsxv_db.get_nsxv_lbaas_l7policy_binding(
        context.session, policy_id)
    if not binding:
        msg = _('No suitable Edge found for policy %s') % policy_id
        raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
    return binding['edge_id'], binding['edge_app_rule_id']


class EdgeL7PolicyManagerFromDict(base_mgr.EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeL7PolicyManagerFromDict, self).__init__(vcns_driver)

    def _add_app_rule_to_virtual_server(self, edge_id, vse_id, app_rule_id,
                                        policy_position):
        """Add the new nsx application rule to the virtual server"""
        # Get the current virtual server configuration
        vse = self.vcns.get_vip(edge_id, vse_id)[1]
        if 'applicationRuleId' not in vse:
            vse['applicationRuleId'] = []

        # Add the policy (=application rule) in the correct position
        # (position begins at 1)
        if len(vse['applicationRuleId']) < policy_position:
            vse['applicationRuleId'].append(app_rule_id)
        else:
            vse['applicationRuleId'].insert(policy_position - 1, app_rule_id)

        # update the backend with the new configuration
        self.vcns.update_vip(edge_id, vse_id, vse)

    def _del_app_rule_from_virtual_server(self, edge_id, vse_id, app_rule_id):
        """Delete nsx application rule from the virtual server"""
        # Get the current virtual server configuration
        vse = self.vcns.get_vip(edge_id, vse_id)[1]
        if 'applicationRuleId' not in vse:
            vse['applicationRuleId'] = []

        # Remove the rule from the list
        if (app_rule_id in vse['applicationRuleId']):
            vse['applicationRuleId'].remove(app_rule_id)

        # update the backend with the new configuration
        self.vcns.update_vip(edge_id, vse_id, vse)

    def _update_app_rule_possition_in_virtual_server(self, edge_id, vse_id,
                                                     app_rule_id,
                                                     policy_position):
        """Move the new nsx application rule to another position"""
        # Get the current virtual server configuration
        vse = self.vcns.get_vip(edge_id, vse_id)[1]

        # delete the policy (= application rule) from the list
        if app_rule_id in vse['applicationRuleId']:
            vse['applicationRuleId'].remove(app_rule_id)

        # Add the policy (=application rule) in the correct position
        # (position begins at 1)
        if len(vse['applicationRuleId']) < policy_position:
            vse['applicationRuleId'].append(app_rule_id)
        else:
            vse['applicationRuleId'].insert(policy_position - 1, app_rule_id)

        # update the backend with the new configuration
        self.vcns.update_vip(edge_id, vse_id, vse)

    def _get_vse_id(self, context, pol):
        lb_id = pol['listener']['loadbalancer_id']
        list_id = pol['listener']['id']
        listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
            context.session, lb_id, list_id)
        if listener_binding:
            return listener_binding['vse_id']

    def create(self, context, pol, completor):
        # find out the edge to be updated, by the listener of this policy
        listener = pol['listener']
        lb_id = listener['loadbalancer_id']
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        if not lb_binding:
            msg = _(
                'No suitable Edge found for listener %s') % listener['id']
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

        if (listener['protocol'] == lb_const.LB_PROTOCOL_HTTPS or
            listener['protocol'] == lb_const.LB_PROTOCOL_TERMINATED_HTTPS):
            msg = _(
                'L7 policy is not supported for %(prot)s listener %(ls)s') % {
                'prot': listener['protocol'], 'ls': pol['listener_id']}
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

        edge_id = lb_binding['edge_id']
        app_rule = policy_to_application_rule(pol)
        app_rule_id = None
        try:
            with locking.LockManager.get_lock(edge_id):
                # create the backend application rule for this policy
                h = (self.vcns.create_app_rule(edge_id, app_rule))[0]
                app_rule_id = lb_common.extract_resource_id(h['location'])

                # add the nsx application rule (neutron policy) to the nsx
                # virtual server (neutron listener)
                vse_id = self._get_vse_id(context, pol)
                if vse_id:
                    self._add_app_rule_to_virtual_server(
                        edge_id, vse_id, app_rule_id, pol['position'])
        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to create L7policy on edge %(edge)s: '
                          '%(err)s',
                          {'edge': edge_id, 'err': e})
                if app_rule_id:
                    # Failed to add the rule to the vip: delete the rule
                    # from the backend.
                    try:
                        self.vcns.delete_app_rule(edge_id, app_rule_id)
                    except Exception:
                        pass

        # save the nsx application rule id in the DB
        nsxv_db.add_nsxv_lbaas_l7policy_binding(context.session, pol['id'],
                                                edge_id, app_rule_id)
        # complete the transaction
        completor(success=True)

    def update(self, context, old_pol, new_pol, completor):
        # get the nsx application rule id and edge id from the nsx DB
        edge_id, app_rule_id = policy_to_edge_and_rule_id(
            context, new_pol['id'])
        # create the script for the new policy data
        app_rule = policy_to_application_rule(new_pol)
        try:
            with locking.LockManager.get_lock(edge_id):
                # update the backend application rule for the new policy
                self.vcns.update_app_rule(edge_id, app_rule_id, app_rule)

                # if the position changed - update it too
                if old_pol['position'] != new_pol['position']:
                    vse_id = self._get_vse_id(context, new_pol)
                    if vse_id:
                        self._update_app_rule_possition_in_virtual_server(
                            edge_id, vse_id, app_rule_id, new_pol['position'])

        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to update L7policy on edge %(edge)s: '
                          '%(err)s',
                          {'edge': edge_id, 'err': e})

        # complete the transaction
        completor(success=True)

    def delete(self, context, pol, completor):
        # get the nsx application rule id and edge id from the nsx DB
        try:
            edge_id, app_rule_id = policy_to_edge_and_rule_id(
                context, pol['id'])
        except n_exc.BadRequest:
            # This is probably a policy that we failed to create properly.
            # We should allow deleting it
            completor(success=True)
            return

        with locking.LockManager.get_lock(edge_id):
            try:
                # remove the nsx application rule from the virtual server
                vse_id = self._get_vse_id(context, pol)
                if vse_id:
                    self._del_app_rule_from_virtual_server(
                        edge_id, vse_id, app_rule_id)

                # delete the nsx application rule
                self.vcns.delete_app_rule(edge_id, app_rule_id)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    completor(success=False)
                    LOG.error('Failed to delete L7policy on edge '
                              '%(edge)s: %(err)s',
                              {'edge': edge_id, 'err': e})

        # delete the nsxv db entry
        nsxv_db.del_nsxv_lbaas_l7policy_binding(context.session, pol['id'])

        # complete the transaction
        completor(success=True)

    def delete_cascade(self, context, policy, completor):
        self.delete(context, policy, completor)
