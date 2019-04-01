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
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_p.implementation import lb_utils as p_utils
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeLoadBalancerManagerFromDict(base_mgr.NsxpLoadbalancerBaseManager):

    @log_helpers.log_method_call
    def _validate_lb_network(self, context, lb):
        router_id = lb_utils.get_router_from_network(
            context, self.core_plugin, lb['vip_subnet_id'])

        return router_id

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
    def create(self, context, lb, completor):
        lb_id = lb['id']

        network = lb_utils.get_network_from_subnet(
            context, self.core_plugin, lb['vip_subnet_id'])

        router_id = self._validate_lb_network(context, lb)
        if not router_id and not network.get('router:external'):
            completor(success=False)
            msg = (_('Cannot create a loadbalancer %(lb_id)s on subnet. '
                     '%(subnet)s is neither public nor connected to the LB '
                     'router') %
                   {'lb_id': lb_id, 'subnet': lb['vip_subnet_id']})
            raise n_exc.BadRequest(resource='lbaas-subnet', msg=msg)

        if router_id and not self.core_plugin.service_router_has_services(
                context, router_id):
            self.core_plugin.create_service_router(context, router_id)

        lb_name = utils.get_name_and_uuid(lb['name'] or 'lb',
                                          lb_id)
        tags = lb_utils.get_tags(self.core_plugin, router_id,
                                 lb_const.LR_ROUTER_TYPE,
                                 lb['tenant_id'], context.project_name)

        lb_size = lb_utils.get_lb_flavor_size(self.flavor_plugin, context,
                                              lb.get('flavor_id'))

        service_client = self.core_plugin.nsxpolicy.load_balancer.lb_service
        try:
            if network.get('router:external'):
                connectivity_path = None
            else:
                connectivity_path = self.core_plugin.nsxpolicy.tier1.get_path(
                    router_id)
            service_client.create_or_overwrite(
                lb_name, lb_service_id=lb['id'], description=lb['description'],
                tags=tags, size=lb_size, connectivity_path=connectivity_path)

            # Add rule to advertise external vips
            p_utils.update_router_lb_vip_advertisement(
                context, self.core_plugin, router_id)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to create loadbalancer %(lb)s for lb with '
                          'exception %(e)s', {'lb': lb['id'], 'e': e})

        completor(success=True)

    @log_helpers.log_method_call
    def update(self, context, old_lb, new_lb, completor):
        completor(success=True)

    @log_helpers.log_method_call
    def delete(self, context, lb, completor):
        service_client = self.core_plugin.nsxpolicy.load_balancer.lb_service
        router_id = lb_utils.get_router_from_network(
            context, self.core_plugin, lb['vip_subnet_id'])

        if router_id:
            try:
                service_client.delete(lb['id'])

                if not self.core_plugin.service_router_has_services(context,
                                                                    router_id):
                    self.core_plugin.delete_service_router(router_id)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    completor(success=False)
                    LOG.error('Failed to delete loadbalancer %(lb)s for lb '
                              'with error %(err)s',
                              {'lb': lb['id'], 'err': e})
        else:
            LOG.warning('Router not found for loadbalancer %s', lb['id'])
        completor(success=True)

    @log_helpers.log_method_call
    def delete_cascade(self, context, lb, completor):
        """Delete all backend and DB resources of this loadbalancer"""
        self.delete(context, lb, completor)

    @log_helpers.log_method_call
    def refresh(self, context, lb):
        # TODO(kobis): implement
        pass

    @log_helpers.log_method_call
    def _get_lb_virtual_servers(self, context, lb):
        # Get all virtual servers that belong to this loadbalancer
        vs_list = [vs['id'] for vs in lb['listeners']]
        return vs_list

    @log_helpers.log_method_call
    def stats(self, context, lb):
        # Since multiple LBaaS loadbalancer can share the same LB service,
        # get the corresponding virtual servers' stats instead of LB service.
        stats = {'active_connections': 0,
                 'bytes_in': 0,
                 'bytes_out': 0,
                 'total_connections': 0}

        service_client = self.core_plugin.nsxpolicy.load_balancer.lb_service
        vs_list = self._get_lb_virtual_servers(context, lb)
        try:
            rsp = service_client.get_stats(lb['id'])
            if rsp:
                for vs in rsp.get('virtual_servers', []):
                    # Skip the virtual server that doesn't belong
                    # to this loadbalancer
                    if vs['virtual_server_id'] not in vs_list:
                        continue
                    vs_stats = vs.get('statistics', {})
                    for stat in lb_const.LB_STATS_MAP:
                        lb_stat = lb_const.LB_STATS_MAP[stat]
                        stats[stat] += vs_stats.get(lb_stat, 0)

        except nsxlib_exc.ManagerError:
            msg = _('Failed to retrieve stats from LB service '
                    'for loadbalancer %(lb)s') % {'lb': lb['id']}
            raise n_exc.BadRequest(resource='lbaas-lb', msg=msg)
        return stats

    @log_helpers.log_method_call
    def get_operating_status(self, context, id, with_members=False):
        service_client = self.core_plugin.nsxpolicy.load_balancer.lb_service
        try:
            service_status = service_client.get_status(id)
            if not isinstance(service_status, dict):
                service_status = {}

            vs_statuses = service_client.get_status(id)
            if not isinstance(vs_statuses, dict):
                vs_statuses = {}
        except nsxlib_exc.ManagerError:
            LOG.warning("LB service %(lbs)s is not found",
                        {'lbs': id})
            return {}

        # get the loadbalancer status from the LB service
        lb_status = self._nsx_status_to_lb_status(
            service_status.get('service_status'))
        statuses = {lb_const.LOADBALANCERS: [{'id': id, 'status': lb_status}],
                    lb_const.LISTENERS: [],
                    lb_const.POOLS: [],
                    lb_const.MEMBERS: []}

        # Add the listeners statuses from the virtual servers statuses
        for vs in vs_statuses.get('results', []):
            vs_status = self._nsx_status_to_lb_status(vs.get('status'))
            vs_id = vs.get('virtual_server_id')
            statuses[lb_const.LISTENERS].append(
                {'id': vs_id, 'status': vs_status})

    @log_helpers.log_method_call
    def _nsx_status_to_lb_status(self, nsx_status):
        if not nsx_status:
            # default fallback
            return lb_const.ONLINE

        # Statuses that are considered ONLINE:
        if nsx_status.upper() in ['UP', 'UNKNOWN', 'PARTIALLY_UP',
                                  'NO_STANDBY']:
            return lb_const.ONLINE
        # Statuses that are considered OFFLINE:
        if nsx_status.upper() in ['PRIMARY_DOWN', 'DETACHED', 'DOWN', 'ERROR']:
            return lb_const.OFFLINE
        if nsx_status.upper() == 'DISABLED':
            return lb_const.DISABLED

        # default fallback
        LOG.debug("NSX LB status %s - interpreted as ONLINE", nsx_status)
        return lb_const.ONLINE
