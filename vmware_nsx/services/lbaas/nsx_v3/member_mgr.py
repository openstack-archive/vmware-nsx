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
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3 import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeMemberManager(base_mgr.Nsxv3LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeMemberManager, self).__init__()

    @log_helpers.log_method_call
    def _get_info_from_fip(self, context, fip):
        filters = {'floating_ip_address': [fip]}
        floating_ips = self.core_plugin.get_floatingips(context,
                                                        filters=filters)
        if floating_ips:
            return (floating_ips[0]['fixed_ip_address'],
                    floating_ips[0]['router_id'])
        else:
            msg = (_('Cannot get floating ip %(fip)s provided from '
                     'neutron db') % {'fip': fip})
            raise nsx_exc.BadRequest(resource='lbaas-vip', msg=msg)

    @log_helpers.log_method_call
    def _create_lb_service(self, context, service_client, tenant_id,
                           router_id, nsx_router_id, lb_id, lb_size):
        router = self.core_plugin.get_router(context, router_id)
        lb_name = utils.get_name_and_uuid(router['name'],
                                          router_id)
        tags = lb_utils.get_tags(self.core_plugin, router_id,
                                 lb_const.LR_ROUTER_TYPE,
                                 tenant_id, context.project_name)
        attachment = {'target_id': nsx_router_id,
                      'target_type': 'LogicalRouter'}
        lb_service = service_client.create(display_name=lb_name,
                                           tags=tags,
                                           attachment=attachment,
                                           size=lb_size)
        return lb_service

    @log_helpers.log_method_call
    def _add_loadbalancer_binding(self, context, lb_id, lbs_id,
                                  nsx_router_id, vip_address):
        # First check if there is already binding for the lb.
        # If there is no binding for the lb, add the db binding.
        binding = nsx_db.get_nsx_lbaas_loadbalancer_binding(
            context.session, lb_id)
        if not binding:
            nsx_db.add_nsx_lbaas_loadbalancer_binding(
                context.session, lb_id, lbs_id,
                nsx_router_id, vip_address)
        else:
            LOG.debug("LB binding has already been added, and no need "
                      "to add here.")

    @log_helpers.log_method_call
    def create(self, context, member):
        lb_id = member.pool.loadbalancer_id
        pool_id = member.pool.id
        loadbalancer = member.pool.loadbalancer
        if not lb_utils.validate_lb_subnet(context, self.core_plugin,
                                           member.subnet_id):
            msg = (_('Cannot add member %(member)s to pool as member subnet '
                     '%(subnet)s is neither public nor connected to router') %
                   {'member': member.id, 'subnet': member.subnet_id})
            raise n_exc.BadRequest(resource='lbaas-subnet', msg=msg)

        pool_client = self.core_plugin.nsxlib.load_balancer.pool
        service_client = self.core_plugin.nsxlib.load_balancer.service
        pool_members = self.lbv2_driver.plugin.get_pool_members(
            context, pool_id)

        network = lb_utils.get_network_from_subnet(
            context, self.core_plugin, member.subnet_id)
        if network.get('router:external'):
            router_id, fixed_ip = self._get_info_from_fip(
                context, member.address)
        else:
            router_id = lb_utils.get_router_from_network(
                context, self.core_plugin, member.subnet_id)
            fixed_ip = member.address

        binding = nsx_db.get_nsx_lbaas_pool_binding(context.session,
                                                    lb_id, pool_id)
        if binding:
            vs_id = binding.get('lb_vs_id')
            lb_pool_id = binding.get('lb_pool_id')
            lb_binding = nsx_db.get_nsx_lbaas_loadbalancer_binding(
                context.session, lb_id)
            if not lb_binding and len(pool_members) == 1:
                nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                         router_id)
                lb_service = service_client.get_router_lb_service(
                    nsx_router_id)
                if not lb_service:
                    lb_size = lb_utils.get_lb_flavor_size(
                        self.flavor_plugin, context, loadbalancer.flavor_id)
                    lb_service = self._create_lb_service(
                        context, service_client, member.tenant_id,
                        router_id, nsx_router_id, loadbalancer.id, lb_size)
                if lb_service:
                    lb_service_id = lb_service['id']
                    self._add_loadbalancer_binding(
                        context, loadbalancer.id, lb_service_id,
                        nsx_router_id, loadbalancer.vip_address)
                    if vs_id:
                        try:
                            service_client.add_virtual_server(lb_service_id,
                                                              vs_id)
                        except nsxlib_exc.ManagerError:
                            self.lbv2_driver.member.failed_completion(context,
                                                                      member)
                            msg = (_('Failed to attach virtual server %(vs)s '
                                   'to lb service %(service)s') %
                                   {'vs': vs_id, 'service': lb_service_id})
                            raise n_exc.BadRequest(resource='lbaas-member',
                                                   msg=msg)
                else:
                    msg = (_('Failed to get lb service to attach virtual '
                             'server %(vs)s for member %(member)s') %
                           {'vs': vs_id, 'member': member['id']})
                    raise nsx_exc.NsxPluginException(err_msg=msg)

            lb_pool = pool_client.get(lb_pool_id)
            old_m = lb_pool.get('members', None)
            new_m = [{'display_name': member.name[:219] + '_' + member.id,
                      'ip_address': fixed_ip,
                      'port': member.protocol_port,
                      'weight': member.weight}]
            members = (old_m + new_m) if old_m else new_m
            pool_client.update_pool_with_members(lb_pool_id, members)
        else:
            msg = (_('Failed to get pool binding to add member %s') %
                   member['id'])
            raise nsx_exc.NsxPluginException(err_msg=msg)

        self.lbv2_driver.member.successful_completion(context, member)

    @log_helpers.log_method_call
    def update(self, context, old_member, new_member):
        try:
            self.lbv2_driver.member.successful_completion(
                context, new_member)

        except nsx_exc.NsxPluginException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.member.failed_completion(
                    context, new_member)

    @log_helpers.log_method_call
    def delete(self, context, member):
        lb_id = member.pool.loadbalancer_id
        pool_id = member.pool.id
        pool_client = self.core_plugin.nsxlib.load_balancer.pool
        pool_binding = nsx_db.get_nsx_lbaas_pool_binding(
            context.session, lb_id, pool_id)
        if pool_binding:
            lb_pool_id = pool_binding.get('lb_pool_id')
            try:
                lb_pool = pool_client.get(lb_pool_id)
                network = lb_utils.get_network_from_subnet(
                    context, self.core_plugin, member.subnet_id)
                if network.get('router:external'):
                    fixed_ip, router_id = self._get_info_from_fip(
                        context, member.address)
                else:
                    fixed_ip = member.address
                if 'members' in lb_pool:
                    m_list = lb_pool['members']
                    members = [m for m in m_list
                               if m['ip_address'] != fixed_ip]
                    pool_client.update_pool_with_members(lb_pool_id, members)
            except nsxlib_exc.ManagerError:
                self.lbv2_driver.member.failed_completion(context, member)
                msg = _('Failed to remove member from pool on NSX backend')
                raise n_exc.BadRequest(resource='lbaas-member', msg=msg)
        self.lbv2_driver.member.successful_completion(
            context, member, delete=True)
