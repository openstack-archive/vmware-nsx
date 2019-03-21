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
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeLoadBalancerManagerFromDict(base_mgr.Nsxv3LoadbalancerBaseManager):

    @log_helpers.log_method_call
    def create(self, context, lb, completor):
        if not lb_utils.validate_lb_subnet(context, self.core_plugin,
                                           lb['vip_subnet_id']):
            completor(success=False)
            msg = (_('Cannot create lb on subnet %(sub)s for '
                     'loadbalancer %(lb)s. The subnet needs to connect a '
                     'router which is already set gateway.') %
                   {'sub': lb['vip_subnet_id'], 'lb': lb['id']})
            raise n_exc.BadRequest(resource='lbaas-subnet', msg=msg)

        service_client = self.core_plugin.nsxlib.load_balancer.service
        nsx_router_id = None
        lb_service = None
        nsx_router_id = lb_utils.NO_ROUTER_ID
        router_id = lb_utils.get_router_from_network(
            context, self.core_plugin, lb['vip_subnet_id'])
        if router_id:
            nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                     router_id)
            lb_service = service_client.get_router_lb_service(nsx_router_id)
        if not lb_service:
            lb_size = lb_utils.get_lb_flavor_size(
                self.flavor_plugin, context, lb.get('flavor_id'))
            if router_id:
                # Make sure the NSX service router exists
                if not self.core_plugin.service_router_has_services(
                        context, router_id):
                    self.core_plugin.create_service_router(context, router_id)
                lb_service = self._create_lb_service(
                    context, service_client, lb['tenant_id'],
                    router_id, nsx_router_id, lb['id'], lb_size)
            else:
                lb_service = self._create_lb_service_without_router(
                    context, service_client, lb['tenant_id'],
                    lb, lb_size)
            if not lb_service:
                completor(success=False)
                msg = (_('Failed to create lb service for loadbalancer '
                         '%s') % lb['id'])
                raise nsx_exc.NsxPluginException(err_msg=msg)

        nsx_db.add_nsx_lbaas_loadbalancer_binding(
            context.session, lb['id'], lb_service['id'],
            nsx_router_id, lb['vip_address'])

        completor(success=True)

    @log_helpers.log_method_call
    def _create_lb_service(self, context, service_client, tenant_id,
                           router_id, nsx_router_id, lb_id, lb_size):
        """Create NSX LB service for a specific neutron router"""
        router = self.core_plugin.get_router(context, router_id)
        if not router.get('external_gateway_info'):
            msg = (_('Tenant router %(router)s does not connect to '
                     'external gateway') % {'router': router['id']})
            raise n_exc.BadRequest(resource='lbaas-lbservice-create',
                                   msg=msg)
        lb_name = utils.get_name_and_uuid(router['name'] or 'router',
                                          router_id)
        tags = lb_utils.get_tags(self.core_plugin, router_id,
                                 lb_const.LR_ROUTER_TYPE,
                                 tenant_id, context.project_name)
        attachment = {'target_id': nsx_router_id,
                      'target_type': 'LogicalRouter'}
        try:
            lb_service = service_client.create(display_name=lb_name,
                                               tags=tags,
                                               attachment=attachment,
                                               size=lb_size)
        except nsxlib_exc.ManagerError as e:
            LOG.error("Failed to create LB service: %s", e)
            return

        # Add rule to advertise external vips
        lb_utils.update_router_lb_vip_advertisement(
            context, self.core_plugin, router, nsx_router_id)

        return lb_service

    @log_helpers.log_method_call
    def _create_lb_service_without_router(self, context, service_client,
                                          tenant_id, lb, lb_size):
        """Create NSX LB service for an external VIP
        This service will not be attached to a router yet, and it will be
        updated once the first member is created.
        """
        lb_id = lb['id']
        lb_name = utils.get_name_and_uuid(lb['name'] or 'loadbalancer',
                                          lb_id)
        tags = lb_utils.get_tags(self.core_plugin, '',
                                 lb_const.LR_ROUTER_TYPE,
                                 tenant_id, context.project_name)
        try:
            lb_service = service_client.create(display_name=lb_name,
                                               tags=tags,
                                               size=lb_size)
        except nsxlib_exc.ManagerError as e:
            LOG.error("Failed to create LB service: %s", e)
            return

        return lb_service

    @log_helpers.log_method_call
    def update(self, context, old_lb, new_lb, completor):
        vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server
        app_client = self.core_plugin.nsxlib.load_balancer.application_profile
        if new_lb['name'] != old_lb['name']:
            for listener in new_lb['listeners']:
                binding = nsx_db.get_nsx_lbaas_listener_binding(
                    context.session, new_lb['id'], listener['id'])
                if binding:
                    vs_id = binding['lb_vs_id']
                    app_profile_id = binding['app_profile_id']
                    new_lb_name = new_lb['name'][:utils.MAX_TAG_LEN]
                    try:
                        # Update tag on virtual server with new lb name
                        vs = vs_client.get(vs_id)
                        updated_tags = utils.update_v3_tags(
                            vs['tags'], [{'scope': lb_const.LB_LB_NAME,
                                          'tag': new_lb_name}])
                        vs_client.update(vs_id, tags=updated_tags)
                        # Update tag on application profile with new lb name
                        app_profile = app_client.get(app_profile_id)
                        app_client.update(
                            app_profile_id, tags=updated_tags,
                            resource_type=app_profile['resource_type'])

                    except nsxlib_exc.ManagerError:
                        with excutils.save_and_reraise_exception():
                            completor(success=False)
                            LOG.error('Failed to update tag %(tag)s for lb '
                                      '%(lb)s', {'tag': updated_tags,
                                                 'lb': new_lb['name']})

        completor(success=True)

    @log_helpers.log_method_call
    def delete(self, context, lb, completor):
        service_client = self.core_plugin.nsxlib.load_balancer.service
        router_client = self.core_plugin.nsxlib.logical_router
        lb_binding = nsx_db.get_nsx_lbaas_loadbalancer_binding(
            context.session, lb['id'])
        if lb_binding:
            lb_service_id = lb_binding['lb_service_id']
            nsx_router_id = lb_binding['lb_router_id']
            try:
                lb_service = service_client.get(lb_service_id)
            except nsxlib_exc.ManagerError:
                LOG.warning("LB service %(lbs)s is not found",
                            {'lbs': lb_service_id})
            else:
                vs_list = lb_service.get('virtual_server_ids')
                if not vs_list:
                    try:
                        service_client.delete(lb_service_id)
                        # If there is no lb service attached to the router,
                        # delete the router advertise_lb_vip rule.
                        if nsx_router_id != lb_utils.NO_ROUTER_ID:
                            router_client.update_advertisement_rules(
                                nsx_router_id, [],
                                name_prefix=lb_utils.ADV_RULE_NAME)
                    except nsxlib_exc.ManagerError:
                        completor(success=False)
                        msg = (_('Failed to delete lb service %(lbs)s from nsx'
                                 ) % {'lbs': lb_service_id})
                        raise n_exc.BadRequest(resource='lbaas-lb', msg=msg)
            nsx_db.delete_nsx_lbaas_loadbalancer_binding(
                context.session, lb['id'])
            if nsx_router_id != lb_utils.NO_ROUTER_ID:
                router_id = nsx_db.get_neutron_from_nsx_router_id(
                    context.session, nsx_router_id)
                # Service router is needed only when the LB exist, and
                # no other services are using it.
                if not self.core_plugin.service_router_has_services(
                        context,
                        router_id):
                    self.core_plugin.delete_service_router(context,
                                                           router_id)
        completor(success=True)

    @log_helpers.log_method_call
    def delete_cascade(self, context, lb, completor):
        """Delete all backend and DB resources of this loadbalancer"""
        self.delete(context, lb, completor)

    @log_helpers.log_method_call
    def refresh(self, context, lb):
        # TODO(tongl): implement
        pass

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

    @log_helpers.log_method_call
    def get_lb_pool_members_statuses(self, nsx_pool_id, members_statuses):
        # Combine the NSX pool members data and the NSX statuses to provide
        # member statuses list
        # Get the member id from the suffix of the member in the NSX pool list
        # and find the matching ip+port member in the statuses list
        # get the members list from the NSX
        nsx_pool = self.core_plugin.nsxlib.load_balancer.pool.get(nsx_pool_id)
        if not nsx_pool or not nsx_pool.get('members'):
            return []
        # create a map of existing members: ip+port -> lbaas ID (which is the
        # suffix of the member name)
        members_map = {}
        for member in nsx_pool['members']:
            ip = member['ip_address']
            port = member['port']
            if ip not in members_map:
                members_map[ip] = {}
            members_map[ip][port] = member['display_name'][-36:]
        # go over the statuses map, and match the member ip_port, to the ID
        # in the map
        statuses = []
        for member in members_statuses:
            ip = member['ip_address']
            port = member['port']
            if ip in members_map and port in members_map[ip]:
                member_id = members_map[ip][port]
                member_status = self._nsx_status_to_lb_status(member['status'])
                statuses.append({'id': member_id, 'status': member_status})
        return statuses

    @log_helpers.log_method_call
    def get_operating_status(self, context, id, with_members=False):
        """Return a map of the operating status of all connected LB objects """
        service_client = self.core_plugin.nsxlib.load_balancer.service
        lb_binding = nsx_db.get_nsx_lbaas_loadbalancer_binding(
            context.session, id)
        if not lb_binding:
            LOG.warning("Failed to get loadbalancer %s operating status. "
                        "Mapping was not found", id)
            return {}

        lb_service_id = lb_binding['lb_service_id']
        try:
            service_status = service_client.get_status(lb_service_id)
            if not isinstance(service_status, dict):
                service_status = {}

            vs_statuses = service_client.get_virtual_servers_status(
                lb_service_id)
            if not isinstance(vs_statuses, dict):
                vs_statuses = {}
        except nsxlib_exc.ManagerError:
            LOG.warning("LB service %(lbs)s is not found",
                        {'lbs': lb_service_id})
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
            list_binding = nsx_db.get_nsx_lbaas_listener_binding_by_lb_and_vs(
                context.session, id, vs_id)
            if list_binding:
                listener_id = list_binding['listener_id']
                statuses[lb_const.LISTENERS].append(
                    {'id': listener_id, 'status': vs_status})

        # Add the pools statuses from the LB service status
        for pool in service_status.get('pools', []):
            nsx_pool_id = pool.get('pool_id')
            pool_status = self._nsx_status_to_lb_status(pool.get('status'))
            pool_binding = nsx_db.get_nsx_lbaas_pool_binding_by_lb_pool(
                context.session, id, nsx_pool_id)
            if pool_binding:
                pool_id = pool_binding['pool_id']
                statuses[lb_const.POOLS].append(
                    {'id': pool_id, 'status': pool_status})
                # Add the pools members
                if with_members and pool.get('members'):
                    statuses[lb_const.MEMBERS].extend(
                        self.get_lb_pool_members_statuses(
                            nsx_pool_id, pool['members']))

        return statuses

    @log_helpers.log_method_call
    def stats(self, context, lb):
        # Since multiple LBaaS loadbalancer can share the same LB service,
        # get the corresponding virtual servers' stats instead of LB service.
        stats = {'active_connections': 0,
                 'bytes_in': 0,
                 'bytes_out': 0,
                 'total_connections': 0}

        service_client = self.core_plugin.nsxlib.load_balancer.service
        lb_binding = nsx_db.get_nsx_lbaas_loadbalancer_binding(
            context.session, lb['id'])
        vs_list = self._get_lb_virtual_servers(context, lb)
        if lb_binding:
            lb_service_id = lb_binding.get('lb_service_id')
            try:
                rsp = service_client.get_stats(lb_service_id)
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
    def _get_lb_virtual_servers(self, context, lb):
        # Get all virtual servers that belong to this loadbalancer
        vs_list = []
        for listener in lb['listeners']:
            vs_binding = nsx_db.get_nsx_lbaas_listener_binding(
                context.session, lb['id'], listener['id'])
            if vs_binding:
                vs_list.append(vs_binding.get('lb_vs_id'))
        return vs_list
