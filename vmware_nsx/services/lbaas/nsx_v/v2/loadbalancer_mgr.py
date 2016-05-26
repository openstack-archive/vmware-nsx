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

from neutron_lib import exceptions as n_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _, _LE
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as nsxv_exc
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common
from vmware_nsx.services.lbaas.nsx_v.v2 import base_mgr

LOG = logging.getLogger(__name__)


class EdgeLoadBalancerManager(base_mgr.EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeLoadBalancerManager, self).__init__(vcns_driver)

    @log_helpers.log_method_call
    def create(self, context, lb):
        edge_id = lb_common.get_lbaas_edge_id_for_subnet(
            context, self.core_plugin, lb.vip_subnet_id, lb.tenant_id)

        if not edge_id:
            msg = _(
                'No suitable Edge found for subnet %s') % lb.vip_subnet_id
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

        try:
            if not nsxv_db.get_nsxv_lbaas_loadbalancer_binding_by_edge(
                    context.session, edge_id):
                lb_common.enable_edge_acceleration(self.vcns, edge_id)

            lb_common.add_vip_as_secondary_ip(self.vcns, edge_id,
                                              lb.vip_address)
            edge_fw_rule_id = lb_common.add_vip_fw_rule(
                self.vcns, edge_id, lb.id, lb.vip_address)

            nsxv_db.add_nsxv_lbaas_loadbalancer_binding(
                context.session, lb.id, edge_id, edge_fw_rule_id,
                lb.vip_address)
            self.lbv2_driver.load_balancer.successful_completion(context, lb)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.load_balancer.failed_completion(context, lb)
                LOG.error(_LE('Failed to create pool %s'), lb.id)

    @log_helpers.log_method_call
    def update(self, context, old_lb, new_lb):
        self.lbv2_driver.load_balancer.successful_completion(context, new_lb)

    @log_helpers.log_method_call
    def delete(self, context, lb):
        binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb.id)
        if binding:
            try:
                lb_common.del_vip_fw_rule(self.vcns, binding['edge_id'],
                                          binding['edge_fw_rule_id'])
            except nsxv_exc.VcnsApiException as e:
                LOG.error(_LE('Failed to delete loadbalancer %(lb)s FW rule. '
                              'exception is %(exc)s'), {'lb': lb.id, 'exc': e})
            try:
                lb_common.del_vip_as_secondary_ip(self.vcns,
                                                  binding['edge_id'],
                                                  lb.vip_address)
            except Exception as e:
                LOG.error(_LE('Failed to delete loadbalancer %(lb)s interface'
                              ' IP. exception is %(exc)s'),
                          {'lb': lb.id, 'exc': e})

            nsxv_db.del_nsxv_lbaas_loadbalancer_binding(context.session, lb.id)
        self.lbv2_driver.load_balancer.successful_completion(context, lb,
                                                             delete=True)

    @log_helpers.log_method_call
    def refresh(self, context, lb):
        # TODO(kobis): implememnt
        pass

    @log_helpers.log_method_call
    def stats(self, context, lb):
        # TODO(kobis): implement
        stats = {'bytes_in': 0,
                 'bytes_out': 0,
                 'active_connections': 0,
                 'total_connections': 0}

        return stats
