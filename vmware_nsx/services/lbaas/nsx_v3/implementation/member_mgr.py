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
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import locking
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc

LOG = logging.getLogger(__name__)


class EdgeMemberManagerFromDict(base_mgr.Nsxv3LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def _get_info_from_fip(self, context, fip):
        filters = {'floating_ip_address': [fip]}
        floating_ips = self.core_plugin.get_floatingips(context,
                                                        filters=filters)
        if floating_ips:
            return (floating_ips[0]['fixed_ip_address'],
                    floating_ips[0]['router_id'])
        else:
            msg = (_('Member IP %(fip)s is an external IP, and is expected to '
                     'be a floating IP') % {'fip': fip})
            raise n_exc.BadRequest(resource='lbaas-vip', msg=msg)

    @log_helpers.log_method_call
    def _get_updated_pool_members(self, context, lb_pool, member):
        network = lb_utils.get_network_from_subnet(
            context, self.core_plugin, member['subnet_id'])
        if network.get('router:external'):
            fixed_ip, router_id = self._get_info_from_fip(
                context, member['address'])
        else:
            fixed_ip = member['address']
        for m in lb_pool['members']:
            if m['ip_address'] == fixed_ip:
                m['display_name'] = member['name'][:219] + '_' + member['id']
                m['weight'] = member['weight']
        return lb_pool['members']

    @log_helpers.log_method_call
    def create(self, context, member, completor):
        with locking.LockManager.get_lock(
            'member-%s' % str(member['pool']['loadbalancer_id'])):
            self._member_create(context, member, completor)

    @log_helpers.log_method_call
    def _member_create(self, context, member, completor):
        lb_id = member['pool']['loadbalancer_id']
        pool_id = member['pool']['id']
        loadbalancer = member['pool']['loadbalancer']
        if not lb_utils.validate_lb_member_subnet(context, self.core_plugin,
                                                  member['subnet_id'],
                                                  loadbalancer):
            completor(success=False)
            msg = (_('Cannot add member %(member)s to pool as member subnet '
                     '%(subnet)s is neither public nor connected to the LB '
                     'router') %
                   {'member': member['id'], 'subnet': member['subnet_id']})
            raise n_exc.BadRequest(resource='lbaas-subnet', msg=msg)

        pool_client = self.core_plugin.nsxlib.load_balancer.pool
        service_client = self.core_plugin.nsxlib.load_balancer.service

        network = lb_utils.get_network_from_subnet(
            context, self.core_plugin, member['subnet_id'])
        if network.get('router:external'):
            fixed_ip, router_id = self._get_info_from_fip(
                context, member['address'])
            if not router_id:
                completor(success=False)
                msg = (_('Floating ip %(fip)s has no router') % {
                    'fip': member['address']})
                raise n_exc.BadRequest(resource='lbaas-vip', msg=msg)
        else:
            router_id = lb_utils.get_router_from_network(
                context, self.core_plugin, member['subnet_id'])
            fixed_ip = member['address']

        binding = nsx_db.get_nsx_lbaas_pool_binding(context.session,
                                                    lb_id, pool_id)
        if binding:
            lb_pool_id = binding.get('lb_pool_id')
            lb_binding = nsx_db.get_nsx_lbaas_loadbalancer_binding(
                context.session, lb_id)
            if not lb_binding:
                completor(success=False)
                msg = (_('Failed to get LB binding for member %s') %
                       member['id'])
                raise nsx_exc.NsxPluginException(err_msg=msg)
            if lb_binding.lb_router_id == lb_utils.NO_ROUTER_ID:
                # Need to attach the LB service to the router now
                # This will happen here in case of external vip
                nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                         router_id)
                try:
                    tags = lb_utils.get_tags(self.core_plugin, router_id,
                                             lb_const.LR_ROUTER_TYPE,
                                             member['tenant_id'],
                                             context.project_name)
                    service_client.update_service_with_attachment(
                        lb_binding.lb_service_id, nsx_router_id, tags=tags)
                    # TODO(asarfaty): Also update the tags
                except nsxlib_exc.ManagerError as e:
                    # This will happen if there is another service already
                    # attached to this router.
                    # This is currently a limitation.
                    completor(success=False)
                    msg = (_('Failed to attach router %(rtr)s to LB service '
                             '%(srv)s: %(e)s') %
                           {'rtr': router_id, 'srv': lb_binding.lb_service_id,
                            'e': e})
                    raise nsx_exc.NsxPluginException(err_msg=msg)
                # Update the nsx router in the DB binding
                nsx_db.update_nsx_lbaas_loadbalancer_binding(
                    context.session, lb_id, nsx_router_id)
                # Add rule to advertise external vips
                router = self.core_plugin.get_router(context, router_id)
                lb_utils.update_router_lb_vip_advertisement(
                    context, self.core_plugin, router, nsx_router_id)

            with locking.LockManager.get_lock('pool-member-%s' % lb_pool_id):
                lb_pool = pool_client.get(lb_pool_id)
                old_m = lb_pool.get('members', None)
                new_m = [{
                    'display_name': member['name'][:219] + '_' + member['id'],
                    'ip_address': fixed_ip,
                    'port': member['protocol_port'],
                    'weight': member['weight']}]
                members = (old_m + new_m) if old_m else new_m
                pool_client.update_pool_with_members(lb_pool_id, members)

        else:
            completor(success=False)
            msg = (_('Failed to get pool binding to add member %s') %
                   member['id'])
            raise nsx_exc.NsxPluginException(err_msg=msg)

        completor(success=True)

    @log_helpers.log_method_call
    def update(self, context, old_member, new_member, completor):
        lb_id = old_member['pool']['loadbalancer_id']
        pool_id = old_member['pool']['id']
        pool_client = self.core_plugin.nsxlib.load_balancer.pool
        pool_binding = nsx_db.get_nsx_lbaas_pool_binding(
            context.session, lb_id, pool_id)
        if pool_binding:
            lb_pool_id = pool_binding.get('lb_pool_id')
            try:
                with locking.LockManager.get_lock('pool-member-%s' %
                                                  lb_pool_id):
                    lb_pool = pool_client.get(lb_pool_id)
                    updated_members = self._get_updated_pool_members(
                        context, lb_pool, new_member)
                    pool_client.update_pool_with_members(lb_pool_id,
                                                         updated_members)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    completor(success=False)
                    LOG.error('Failed to update member %(member)s: '
                              '%(err)s',
                              {'member': old_member['id'], 'err': e})
        completor(success=True)

    @log_helpers.log_method_call
    def delete(self, context, member, completor):
        lb_id = member['pool']['loadbalancer_id']
        pool_id = member['pool']['id']
        pool_client = self.core_plugin.nsxlib.load_balancer.pool
        pool_binding = nsx_db.get_nsx_lbaas_pool_binding(
            context.session, lb_id, pool_id)
        if pool_binding:
            lb_pool_id = pool_binding.get('lb_pool_id')
            try:
                with locking.LockManager.get_lock('pool-member-%s' %
                                                  lb_pool_id):
                    lb_pool = pool_client.get(lb_pool_id)
                    network = lb_utils.get_network_from_subnet(
                        context, self.core_plugin, member['subnet_id'])
                    if network.get('router:external'):
                        fixed_ip, router_id = self._get_info_from_fip(
                            context, member['address'])
                    else:
                        fixed_ip = member['address']
                    if 'members' in lb_pool:
                        m_list = lb_pool['members']
                        members = [m for m in m_list
                                if m['ip_address'] != fixed_ip]
                        pool_client.update_pool_with_members(lb_pool_id,
                                                            members)
            except nsxlib_exc.ResourceNotFound:
                pass
            except nsxlib_exc.ManagerError:
                completor(success=False)
                msg = _('Failed to remove member from pool on NSX backend')
                raise n_exc.BadRequest(resource='lbaas-member', msg=msg)

        completor(success=True)

    @log_helpers.log_method_call
    def delete_cascade(self, context, member, completor):
        # No action should be taken on members delete cascade
        pass
