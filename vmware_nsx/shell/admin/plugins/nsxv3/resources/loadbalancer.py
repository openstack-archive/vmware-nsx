# Copyright 2015 VMware, Inc.  All rights reserved.
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

from oslo_log import log as logging

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
from vmware_nsxlib.v3 import nsx_constants as consts

LOG = logging.getLogger(__name__)


@admin_utils.list_handler(constants.LB_SERVICES)
@admin_utils.output_header
def nsx_list_lb_services(resource, event, trigger, **kwargs):
    """List LB services on NSX backend"""

    nsxlib = utils.get_connected_nsxlib()
    if not nsxlib.feature_supported(consts.FEATURE_LOAD_BALANCER):
        LOG.error("This utility is not available for NSX version %s",
                  nsxlib.get_version())
        return

    lb_services = nsxlib.load_balancer.service.list()
    LOG.info(formatters.output_formatter(
        constants.LB_SERVICES, lb_services,
        ['display_name', 'id', 'virtual_server_ids', 'attachment']))
    return bool(lb_services)


@admin_utils.list_handler(constants.LB_VIRTUAL_SERVERS)
@admin_utils.output_header
def nsx_list_lb_virtual_servers(resource, event, trigger, **kwargs):
    """List LB virtual servers on NSX backend"""

    nsxlib = utils.get_connected_nsxlib()
    if not nsxlib.feature_supported(consts.FEATURE_LOAD_BALANCER):
        LOG.error("This utility is not available for NSX version %s",
                  nsxlib.get_version())
        return

    lb_virtual_servers = nsxlib.load_balancer.virtual_server.list()
    LOG.info(formatters.output_formatter(
        constants.LB_VIRTUAL_SERVERS, lb_virtual_servers,
        ['display_name', 'id', 'ip_address', 'pool_id']))
    return bool(lb_virtual_servers)


@admin_utils.list_handler(constants.LB_POOLS)
@admin_utils.output_header
def nsx_list_lb_pools(resource, event, trigger, **kwargs):

    nsxlib = utils.get_connected_nsxlib()
    if not nsxlib.feature_supported(consts.FEATURE_LOAD_BALANCER):
        LOG.error("This utility is not available for NSX version %s",
                  nsxlib.get_version())
        return

    lb_pools = nsxlib.load_balancer.pool.list()
    LOG.info(formatters.output_formatter(
        constants.LB_POOLS, lb_pools,
        ['display_name', 'id', 'active_monitor_ids', 'members']))
    return bool(lb_pools)


@admin_utils.list_handler(constants.LB_MONITORS)
@admin_utils.output_header
def nsx_list_lb_monitors(resource, event, trigger, **kwargs):

    nsxlib = utils.get_connected_nsxlib()
    if not nsxlib.feature_supported(consts.FEATURE_LOAD_BALANCER):
        LOG.error("This utility is not available for NSX version %s",
                  nsxlib.get_version())
        return

    lb_monitors = nsxlib.load_balancer.monitor.list()
    LOG.info(formatters.output_formatter(
        constants.LB_MONITORS, lb_monitors,
        ['display_name', 'id', 'resource_type']))
    return bool(lb_monitors)
