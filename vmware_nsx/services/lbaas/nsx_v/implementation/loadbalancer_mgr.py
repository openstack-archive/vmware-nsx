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

from neutron.services.flavors import flavors_plugin
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import (
    constants as vcns_const)
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as nsxv_exc
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common
from vmware_nsx.services.lbaas.octavia import constants as oct_const

LOG = logging.getLogger(__name__)


class EdgeLoadBalancerManagerFromDict(base_mgr.EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeLoadBalancerManagerFromDict, self).__init__(vcns_driver)
        registry.subscribe(
            self._handle_subnet_gw_change,
            resources.SUBNET, events.AFTER_UPDATE)

    def _get_lb_flavor_size(self, context, flavor_id):
        if not flavor_id:
            return vcns_const.SERVICE_SIZE_MAPPING['lb']
        else:
            flavor = flavors_plugin.FlavorsPlugin.get_flavor(
                self.flavor_plugin, context, flavor_id)
            flavor_size = flavor['name']
            if flavor_size.lower() in vcns_const.ALLOWED_EDGE_SIZES:
                return flavor_size.lower()
            else:
                err_msg = (_("Invalid flavor size %(flavor)s, only %(sizes)s "
                             "are supported") %
                           {'flavor': flavor_size,
                            'sizes': vcns_const.ALLOWED_EDGE_SIZES})
                raise n_exc.InvalidInput(error_message=err_msg)

    def create(self, context, lb, completor):
        sub_id = lb['vip_subnet_id']
        if cfg.CONF.nsxv.use_routers_as_lbaas_platform:
            edge_id = lb_common.get_lbaas_edge_id_for_subnet(
                context, self.core_plugin, sub_id, lb['tenant_id'])
            if not edge_id:
                msg = _('No suitable Edge found for subnet %s') % sub_id
                raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
        else:
            lb_size = self._get_lb_flavor_size(context, lb.get('flavor_id'))
            edge_id = lb_common.get_lbaas_edge_id(
                context, self.core_plugin, lb['id'], lb['vip_address'],
                sub_id, lb['tenant_id'], lb_size)

        if not edge_id:
            msg = _('Failed to allocate Edge on subnet %(sub)s for '
                    'loadbalancer %(lb)s') % {'sub': sub_id, 'lb': lb['id']}
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

        try:
            if cfg.CONF.nsxv.use_routers_as_lbaas_platform:
                if not nsxv_db.get_nsxv_lbaas_loadbalancer_binding_by_edge(
                        context.session, edge_id):
                    lb_common.enable_edge_acceleration(self.vcns, edge_id)
                lb_common.add_vip_as_secondary_ip(self.vcns, edge_id,
                                                  lb['vip_address'])
            else:
                lb_common.enable_edge_acceleration(self.vcns, edge_id)

            edge_fw_rule_id = lb_common.add_vip_fw_rule(
                self.vcns, edge_id, lb['id'], lb['vip_address'])

            # set LB default rule
            if not cfg.CONF.nsxv.use_routers_as_lbaas_platform:
                lb_common.set_lb_firewall_default_rule(self.vcns, edge_id,
                                                       'accept')

            nsxv_db.add_nsxv_lbaas_loadbalancer_binding(
                context.session, lb['id'], edge_id, edge_fw_rule_id,
                lb['vip_address'])
            completor(success=True)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to create loadbalancer %s', lb['id'])

    def update(self, context, old_lb, new_lb, completor):
        completor(success=True)

    def delete(self, context, lb, completor):
        # Discard any ports which are associated with LB
        filters = {
            'device_id': [lb['id'], oct_const.DEVICE_ID_PREFIX + lb['id']],
            'device_owner': [constants.DEVICE_OWNER_NEUTRON_PREFIX + 'LB']}
        lb_ports = self.core_plugin.get_ports(context.elevated(),
                                              filters=filters)
        for lb_port in lb_ports:
            self.core_plugin.delete_port(context.elevated(), lb_port['id'])

        binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb['id'])
        if binding:
            edge_binding = nsxv_db.get_nsxv_router_binding_by_edge(
                context.session, binding['edge_id'])

            # set LB default rule
            lb_common.set_lb_firewall_default_rule(
                self.vcns, binding['edge_id'], 'deny')
            if edge_binding:
                old_lb = lb_common.is_lb_on_router_edge(
                    context, self.core_plugin, binding['edge_id'])
                if not old_lb:
                    resource_id = lb_common.get_lb_resource_id(lb['id'])
                    self.core_plugin.edge_manager.delete_lrouter(
                        context, resource_id, dist=False)
                else:
                    # Edge was created on an exclusive router with the old code
                    try:
                        lb_common.del_vip_fw_rule(
                            self.vcns, binding['edge_id'],
                            binding['edge_fw_rule_id'])
                    except nsxv_exc.VcnsApiException as e:
                        LOG.error('Failed to delete loadbalancer %(lb)s '
                                  'FW rule. exception is %(exc)s',
                                  {'lb': lb['id'], 'exc': e})
                    try:
                        lb_common.del_vip_as_secondary_ip(self.vcns,
                                                          binding['edge_id'],
                                                          lb['vip_address'])
                    except Exception as e:
                        LOG.error('Failed to delete loadbalancer %(lb)s '
                                  'interface IP. exception is %(exc)s',
                                  {'lb': lb['id'], 'exc': e})

            nsxv_db.del_nsxv_lbaas_loadbalancer_binding(
                context.session, lb['id'])
        completor(success=True)

    def delete_cascade(self, context, lb, completor):
        #TODO(asarfaty): implement a better delete cascade for NSX-V
        self.delete(context, lb, completor)

    def refresh(self, context, lb):
        # TODO(kobis): implement
        pass

    def stats(self, context, lb):
        binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(context.session,
                                                              lb['id'])

        stats = _get_edge_loadbalancer_statistics(self.vcns,
                                                  binding['edge_id'])

        return stats

    def get_operating_status(self, context, id, with_members=False):
        """Return a map of the operating status of all connected LB objects """
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, id)
        if not lb_binding or not lb_binding['edge_id']:
            return {}
        edge_id = lb_binding['edge_id']

        lb_stats = self.vcns.get_loadbalancer_statistics(edge_id)
        lb_status = (lb_const.ONLINE if lb_stats is not None
                     else lb_const.OFFLINE)

        statuses = {lb_const.LOADBALANCERS: [{'id': id, 'status': lb_status}],
                    lb_const.LISTENERS: [],
                    lb_const.POOLS: [],
                    lb_const.MEMBERS: []}

        for vs in lb_stats[1].get('virtualServer', []):
            vs_id = vs['name'][4:]
            vs_status = (lb_const.ONLINE if vs['status'] == 'OPEN'
                         else lb_const.OFFLINE)
            statuses[lb_const.LISTENERS].append(
                {'id': vs_id, 'status': vs_status})

        for pool in lb_stats[1].get('pool', []):
            pool_id = pool['name'][5:]
            pool_status = (lb_const.ONLINE if pool['status'] == 'UP'
                           else lb_const.OFFLINE)
            statuses[lb_const.POOLS].append(
                {'id': pool_id, 'status': pool_status})
            if with_members:
                for member in pool.get('member', []):
                    member_id = member['name'][7:]
                    member_status = (lb_const.ONLINE
                                     if member['status'] == 'UP'
                                     else lb_const.OFFLINE)

                    statuses[lb_const.MEMBERS].append(
                        {'id': member_id, 'status': member_status})

        return statuses

    def _handle_subnet_gw_change(self, *args, **kwargs):
        # As the Edge appliance doesn't use DHCP, we should change the
        # default gateway here when the subnet GW changes.
        context = kwargs.get('context')
        orig = kwargs['original_subnet']
        updated = kwargs['subnet']
        if (orig['gateway_ip'] == updated['gateway_ip'] and
            self._routes_equal(orig['host_routes'], updated['host_routes'])):
            return

        subnet_id = updated['id']
        subnet = self.core_plugin.get_subnet(context.elevated(), subnet_id)

        filters = {'fixed_ips': {'subnet_id': [subnet_id]},
                   'device_owner': [constants.DEVICE_OWNER_LOADBALANCERV2,
                                    oct_const.DEVICE_OWNER_OCTAVIA]}
        lb_ports = self.core_plugin.get_ports(context.elevated(),
                                              filters=filters)

        if lb_ports:
            for lb_port in lb_ports:
                if lb_port['device_id']:
                    device_id = lb_port['device_id']
                    if device_id.startswith(oct_const.DEVICE_ID_PREFIX):
                        device_id = device_id[len(oct_const.DEVICE_ID_PREFIX):]
                    edge_bind = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
                        context.session, device_id)
                    edge_id = edge_bind['edge_id']

                    routes = [{'cidr': r['destination'],
                               'nexthop': r['nexthop']} for r in
                              subnet['host_routes']]

                    self.core_plugin.nsx_v.update_routes(
                        edge_id, subnet['gateway_ip'], routes)

    def _routes_equal(self, a, b):
        if len(a) != len(b):
            return False
        for a_item in a:
            found = False
            for b_item in b:
                # compare values as keysets should be same
                if set(a_item.values()) == set(b_item.values()):
                    found = True
            if not found:
                return False
        return True


def _get_edge_loadbalancer_statistics(vcns, edge_id):
    stats = {'bytes_in': 0,
             'bytes_out': 0,
             'active_connections': 0,
             'total_connections': 0}

    try:
        lb_stats = vcns.get_loadbalancer_statistics(edge_id)

    except nsxv_exc.VcnsApiException:
        msg = (_('Failed to read load balancer statistics, edge: %s') %
               edge_id)
        raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

    pools_stats = lb_stats[1].get('pool', [])
    for pool_stats in pools_stats:
        stats['bytes_in'] += pool_stats.get('bytesIn', 0)
        stats['bytes_out'] += pool_stats.get('bytesOut', 0)
        stats['active_connections'] += pool_stats.get('curSessions', 0)
        stats['total_connections'] += pool_stats.get('totalSessions', 0)

    return stats
