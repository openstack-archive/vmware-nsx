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

from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _LE
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as nsxv_exc
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common
from vmware_nsx.services.lbaas.nsx_v.v2 import base_mgr

LOG = logging.getLogger(__name__)


class EdgeMemberManager(base_mgr.EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeMemberManager, self).__init__(vcns_driver)
        self._fw_section_id = None

    def _get_pool_member_ips(self, pool, operation, address):
        member_ips = [member.address for member in pool.members]
        if operation == 'add' and address not in member_ips:
            member_ips.append(address)
        elif operation == 'del' and address in member_ips:
            member_ips.remove(address)
        return member_ips

    def _get_lbaas_fw_section_id(self):
        if not self._fw_section_id:
            self._fw_section_id = lb_common.get_lbaas_fw_section_id(self.vcns)
        return self._fw_section_id

    @log_helpers.log_method_call
    def create(self, context, member):
        listener = member.pool.listener
        lb_id = listener.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, member.pool_id)

        edge_id = lb_binding['edge_id']
        edge_pool_id = pool_binding['edge_pool_id']
        with locking.LockManager.get_lock(edge_id):
            edge_pool = self.vcns.get_pool(edge_id, edge_pool_id)[1]
            edge_member = {
                'ipAddress': member.address,
                'weight': member.weight,
                'port': member.protocol_port,
                'monitorPort': member.protocol_port,
                'name': lb_common.get_member_id(member.id),
                'condition':
                    'enabled' if member.admin_state_up else 'disabled'}

            if edge_pool.get('member'):
                edge_pool['member'].append(edge_member)
            else:
                edge_pool['member'] = [edge_member]

            try:
                self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)

                member_ips = self._get_pool_member_ips(member.pool, 'add',
                                                       member.address)
                lb_common.update_pool_fw_rule(self.vcns, member.pool_id,
                                              edge_id,
                                              self._get_lbaas_fw_section_id(),
                                              member_ips)

                self.lbv2_driver.member.successful_completion(context, member)

            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lbv2_driver.member.failed_completion(context, member)
                    LOG.error(_LE('Failed to create member on edge: %s'),
                              edge_id)

    @log_helpers.log_method_call
    def update(self, context, old_member, new_member):
        listener = new_member.pool.listener
        lb_id = listener.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(context.session,
                                                           lb_id,
                                                           new_member.pool_id)

        edge_id = lb_binding['edge_id']
        edge_pool_id = pool_binding['edge_pool_id']

        edge_member = {
            'ipAddress': new_member.address,
            'weight': new_member.weight,
            'port': new_member.protocol_port,
            'monitorPort': new_member.protocol_port,
            'name': lb_common.get_member_id(new_member.id),
            'condition':
                'enabled' if new_member.admin_state_up else 'disabled'}

        with locking.LockManager.get_lock(edge_id):
            edge_pool = self.vcns.get_pool(edge_id, edge_pool_id)[1]

            if edge_pool.get('member'):
                for i, m in enumerate(edge_pool['member']):
                    if m['name'] == lb_common.get_member_id(new_member.id):
                        edge_pool['member'][i] = edge_member
                        break

                try:
                    self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)

                    self.lbv2_driver.member.successful_completion(
                        context, new_member)

                except nsxv_exc.VcnsApiException:
                    with excutils.save_and_reraise_exception():
                        self.lbv2_driver.member.failed_completion(
                            context, new_member)
                        LOG.error(_LE('Failed to update member on edge: %s'),
                                  edge_id)
            else:
                LOG.error(_LE('Pool %(pool_id)s on Edge %(edge_id)s has no '
                              'members to update')
                          % {'pool_id': new_member.pool.id,
                             'edge_id': edge_id})

    @log_helpers.log_method_call
    def delete(self, context, member):
        listener = member.pool.listener
        lb_id = listener.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, member.pool_id)

        edge_id = lb_binding['edge_id']
        edge_pool_id = pool_binding['edge_pool_id']

        with locking.LockManager.get_lock(edge_id):
            edge_pool = self.vcns.get_pool(edge_id, edge_pool_id)[1]

            for i, m in enumerate(edge_pool['member']):
                if m['name'] == lb_common.get_member_id(member.id):
                    edge_pool['member'].pop(i)
                    break

            try:
                self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)

                self.lbv2_driver.member.successful_completion(
                    context, member, delete=True)

            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lbv2_driver.member.failed_completion(context, member)
                    LOG.error(_LE('Failed to delete member on edge: %s'),
                              edge_id)
