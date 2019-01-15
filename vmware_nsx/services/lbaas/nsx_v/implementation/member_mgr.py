# Copyright 2015 VMware, Inc.
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
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from neutron_lib import exceptions as n_exc

from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as nsxv_exc
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common

LOG = logging.getLogger(__name__)


class EdgeMemberManagerFromDict(base_mgr.EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeMemberManagerFromDict, self).__init__(vcns_driver)
        self._fw_section_id = None

    def _get_pool_lb_id(self, member):
        if not member.get('pool'):
            return
        listener = member['pool']['listener']
        if listener:
            lb_id = listener['loadbalancer_id']
        else:
            lb_id = member['pool']['loadbalancer']['id']
        return lb_id

    def _get_pool_member_ips(self, pool, operation, address):
        member_ips = [member['address'] for member in pool['members']]
        if operation == 'add' and address not in member_ips:
            member_ips.append(address)
        elif operation == 'del' and address in member_ips:
            member_ips.remove(address)
        return member_ips

    def _get_lbaas_fw_section_id(self):
        if not self._fw_section_id:
            self._fw_section_id = lb_common.get_lbaas_fw_section_id(self.vcns)
        return self._fw_section_id

    def create(self, context, member, completor):
        lb_id = self._get_pool_lb_id(member)
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        edge_id = lb_binding['edge_id']

        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, member['pool_id'])
        if not pool_binding:
            completor(success=False)
            msg = _('Failed to create member on edge: %s. '
                    'Binding not found') % edge_id
            LOG.error(msg)
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

        edge_pool_id = pool_binding['edge_pool_id']
        old_lb = lb_common.is_lb_on_router_edge(
            context, self.core_plugin, edge_id)
        with locking.LockManager.get_lock(edge_id):
            if not cfg.CONF.nsxv.use_routers_as_lbaas_platform and not old_lb:
                # Verify that Edge appliance is connected to the member's
                # subnet (only if this is a dedicated loadbalancer edge)
                if not lb_common.get_lb_interface(
                        context, self.core_plugin, lb_id, member['subnet_id']):
                    lb_common.create_lb_interface(
                        context, self.core_plugin, lb_id, member['subnet_id'],
                        member['tenant_id'])

            edge_pool = self.vcns.get_pool(edge_id, edge_pool_id)[1]
            edge_member = {
                'ipAddress': member['address'],
                'weight': member['weight'],
                'port': member['protocol_port'],
                'monitorPort': member['protocol_port'],
                'name': lb_common.get_member_id(member['id']),
                'condition':
                    'enabled' if member['admin_state_up'] else 'disabled'}

            if edge_pool.get('member'):
                edge_pool['member'].append(edge_member)
            else:
                edge_pool['member'] = [edge_member]

            try:
                self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)
                completor(success=True)

                if old_lb:
                    member_ips = self._get_pool_member_ips(member['pool'],
                                                           'add',
                                                           member['address'])
                    lb_common.update_pool_fw_rule(
                        self.vcns, member['pool_id'],
                        edge_id,
                        self._get_lbaas_fw_section_id(),
                        member_ips)

            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    completor(success=False)
                    LOG.error('Failed to create member on edge: %s',
                              edge_id)

    def update(self, context, old_member, new_member, completor):
        lb_id = self._get_pool_lb_id(new_member)
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, new_member['pool_id'])

        edge_id = lb_binding['edge_id']
        edge_pool_id = pool_binding['edge_pool_id']

        edge_member = {
            'ipAddress': new_member['address'],
            'weight': new_member['weight'],
            'port': new_member['protocol_port'],
            'monitorPort': new_member['protocol_port'],
            'name': lb_common.get_member_id(new_member['id']),
            'condition':
                'enabled' if new_member['admin_state_up'] else 'disabled'}

        with locking.LockManager.get_lock(edge_id):
            edge_pool = self.vcns.get_pool(edge_id, edge_pool_id)[1]

            if edge_pool.get('member'):
                for i, m in enumerate(edge_pool['member']):
                    if m['name'] == lb_common.get_member_id(new_member['id']):
                        edge_pool['member'][i] = edge_member
                        break

                try:
                    self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)
                    completor(success=True)

                except nsxv_exc.VcnsApiException:
                    with excutils.save_and_reraise_exception():
                        completor(success=False)
                        LOG.error('Failed to update member on edge: %s',
                                  edge_id)
            else:
                LOG.error('Pool %(pool_id)s on Edge %(edge_id)s has no '
                          'members to update',
                          {'pool_id': new_member['pool']['id'],
                           'edge_id': edge_id})

    def delete(self, context, member, completor):
        lb_id = self._get_pool_lb_id(member)
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, member['pool_id'])
        edge_id = lb_binding['edge_id']

        old_lb = lb_common.is_lb_on_router_edge(
            context, self.core_plugin, edge_id)

        with locking.LockManager.get_lock(edge_id):
            if not cfg.CONF.nsxv.use_routers_as_lbaas_platform:
                # we should remove LB subnet interface if no members are
                # attached and this is not the LB's VIP interface
                remove_interface = True
                pool = member['pool']
                subnet_id = member['subnet_id']
                if subnet_id == pool['loadbalancer']['vip_subnet_id']:
                    remove_interface = False
                else:
                    for m in pool['members']:
                        if (m['subnet_id'] == subnet_id and
                            m['id'] != member['id']):
                            remove_interface = False
                if remove_interface:
                    lb_common.delete_lb_interface(context, self.core_plugin,
                                                  lb_id, subnet_id)

                if not pool_binding:
                    completor(success=True)
                    return

            edge_pool_id = pool_binding['edge_pool_id']
            edge_pool = self.vcns.get_pool(edge_id, edge_pool_id)[1]

            for i, m in enumerate(edge_pool['member']):
                if m['name'] == lb_common.get_member_id(member['id']):
                    edge_pool['member'].pop(i)
                    break

            try:
                self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)
                if old_lb:
                    member_ips = self._get_pool_member_ips(member['pool'],
                                                           'del',
                                                           member['address'])
                    lb_common.update_pool_fw_rule(
                        self.vcns, member['pool_id'],
                        edge_id,
                        self._get_lbaas_fw_section_id(),
                        member_ips)

                completor(success=True)

            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    completor(success=False)
                    LOG.error('Failed to delete member on edge: %s', edge_id)

    def delete_cascade(self, context, member, completor):
        self.delete(context, member, completor)
