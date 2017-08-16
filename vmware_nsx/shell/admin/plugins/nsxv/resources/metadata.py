# Copyright 2016 VMware, Inc.
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

import hashlib
import hmac

from neutron.db import models_v2
from neutron_lib.callbacks import registry
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.common import config
from vmware_nsx.common import locking
from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v import availability_zones as nsx_az
from vmware_nsx.plugins.nsx_v import md_proxy
from vmware_nsx.plugins.nsx_v.vshield.common import constants as vcns_constants
from vmware_nsx.plugins.nsx_v.vshield import nsxv_loadbalancer as nsxv_lb
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils as utils
from vmware_nsx.shell import resources as shell


LOG = logging.getLogger(__name__)
nsxv = utils.get_nsxv_client()


@admin_utils.output_header
def nsx_redo_metadata_cfg(resource, event, trigger, **kwargs):
    edgeapi = utils.NeutronDbClient()

    config.register_nsxv_azs(cfg.CONF, cfg.CONF.nsxv.availability_zones)
    conf_az = nsx_az.NsxVAvailabilityZones()
    az_list = conf_az.list_availability_zones_objects()
    for az in az_list:
        if az.supports_metadata():
            nsx_redo_metadata_cfg_for_az(az, edgeapi)
        else:
            LOG.info("Skipping availability zone: %s - no metadata "
                     "configuration", az.name)


def nsx_redo_metadata_cfg_for_az(az, edgeapi):
    LOG.info("Updating MetaData for availability zone: %s", az.name)

    # Get the list of internal networks for this AZ
    db_net = nsxv_db.get_nsxv_internal_network_for_az(
        edgeapi.context.session,
        vcns_constants.InternalEdgePurposes.INTER_EDGE_PURPOSE,
        az.name)

    internal_net = None
    internal_subnet = None
    if db_net:
        internal_net = db_net['network_id']
        internal_subnet = edgeapi.context.session.query(
            models_v2.Subnet).filter_by(
            network_id=internal_net).first().get('id')

    # Get the list of internal edges for this AZ
    edge_list = nsxv_db.get_nsxv_internal_edges_by_purpose(
        edgeapi.context.session,
        vcns_constants.InternalEdgePurposes.INTER_EDGE_PURPOSE)
    edge_az_list = [edge for edge in edge_list if
        nsxv_db.get_router_availability_zone(
            edgeapi.context.session, edge['router_id']) == az.name]

    md_rtr_ids = [edge['router_id'] for edge in edge_az_list]

    edge_internal_ips = []
    for edge in edge_az_list:
        edge_internal_port = edgeapi.context.session.query(
            models_v2.Port).filter_by(network_id=internal_net,
                                      device_id=edge['router_id']).first()
        if edge_internal_port:
            edge_internal_ip = edgeapi.context.session.query(
                models_v2.IPAllocation).filter_by(
                port_id=edge_internal_port['id']).first()
            edge_internal_ips.append(edge_internal_ip['ip_address'])

    if not internal_net or not internal_subnet or not edge_internal_ips:
        LOG.error("Metadata infrastructure is missing or broken. "
                  "It is recommended to restart neutron service before "
                  "proceeding with configuration restoration")
        return

    router_bindings = nsxv_db.get_nsxv_router_bindings(
        edgeapi.context.session,
        filters={'edge_type': [nsxv_constants.SERVICE_EDGE],
                 'availability_zones': az.name})
    edge_ids = list(set([binding['edge_id'] for binding in router_bindings
                         if (binding['router_id'] not in set(md_rtr_ids)
                             and not binding['router_id'].startswith(
                                 vcns_constants.BACKUP_ROUTER_PREFIX)
                             and not binding['router_id'].startswith(
                                    vcns_constants.PLR_EDGE_PREFIX))]))

    for edge_id in edge_ids:
        with locking.LockManager.get_lock(edge_id):
            lb = nsxv_lb.NsxvLoadbalancer.get_loadbalancer(nsxv, edge_id)
            virt = lb.virtual_servers.get(md_proxy.METADATA_VSE_NAME)
            if virt:
                pool = virt.default_pool
                pool.members = {}

                i = 0
                s_port = cfg.CONF.nsxv.nova_metadata_port
                for member_ip in edge_internal_ips:
                    i += 1
                    member = nsxv_lb.NsxvLBPoolMember(
                        name='Member-%d' % i,
                        ip_address=member_ip,
                        port=s_port,
                        monitor_port=s_port)
                    pool.add_member(member)

                lb.submit_to_backend(nsxv, edge_id)


@admin_utils.output_header
def update_shared_secret(resource, event, trigger, **kwargs):
    edgeapi = utils.NeutronDbClient()
    edge_list = nsxv_db.get_nsxv_internal_edges_by_purpose(
        edgeapi.context.session,
        vcns_constants.InternalEdgePurposes.INTER_EDGE_PURPOSE)
    md_rtr_ids = [edge['router_id'] for edge in edge_list]
    router_bindings = nsxv_db.get_nsxv_router_bindings(
        edgeapi.context.session,
        filters={'edge_type': [nsxv_constants.SERVICE_EDGE]})
    edge_ids = list(set([binding['edge_id'] for binding in router_bindings
                         if (binding['router_id'] not in set(md_rtr_ids)
                             and not binding['router_id'].startswith(
                                 vcns_constants.BACKUP_ROUTER_PREFIX)
                             and not binding['router_id'].startswith(
                                 vcns_constants.PLR_EDGE_PREFIX))]))

    for edge_id in edge_ids:
        with locking.LockManager.get_lock(edge_id):
            lb = nsxv_lb.NsxvLoadbalancer.get_loadbalancer(nsxv, edge_id)
            virt = lb.virtual_servers.get(md_proxy.METADATA_VSE_NAME)
            if not virt:
                LOG.error("Virtual server not found for edge: %s", edge_id)
                continue

            virt.del_app_rule('insert-auth')
            if cfg.CONF.nsxv.metadata_shared_secret:
                signature = hmac.new(cfg.CONF.nsxv.metadata_shared_secret,
                                     edge_id,
                                     hashlib.sha256).hexdigest()
                sign = 'reqadd X-Metadata-Provider-Signature:' + signature
                sign_app_rule = nsxv_lb.NsxvLBAppRule('insert-auth', sign)
                virt.add_app_rule(sign_app_rule)

            lb.submit_to_backend(nsxv, edge_id)


def _md_member_status(title, edge_ids):
    for edge_id in edge_ids:
        lb_stats = nsxv.get_loadbalancer_statistics(
            edge_id)
        pools_stats = lb_stats[1].get('pool', [])
        members = []
        for pool_stats in pools_stats:
            if pool_stats['name'] == md_proxy.METADATA_POOL_NAME:
                for member in pool_stats.get('member', []):
                    members.append({'member_ip': member['ipAddress'],
                                    'member_status': member['status']})

        LOG.info(formatters.output_formatter(
            title % edge_id,
            members, ['member_ip', 'member_status']))


@admin_utils.output_header
def get_metadata_status(resource, event, trigger, **kwargs):
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        net_id = properties.get('network_id')
    else:
        net_id = None

    edgeapi = utils.NeutronDbClient()
    edge_list = nsxv_db.get_nsxv_internal_edges_by_purpose(
        edgeapi.context.session,
        vcns_constants.InternalEdgePurposes.INTER_EDGE_PURPOSE)
    md_rtr_ids = [edge['router_id'] for edge in edge_list]
    router_bindings = nsxv_db.get_nsxv_router_bindings(
        edgeapi.context.session,
        filters={'router_id': md_rtr_ids})
    edge_ids = [b['edge_id'] for b in router_bindings]
    _md_member_status('Metadata edge appliance: %s members', edge_ids)

    if net_id:
        as_provider_data = nsxv_db.get_edge_vnic_bindings_by_int_lswitch(
            edgeapi.context.session, net_id)
        providers = [asp['edge_id'] for asp in as_provider_data]
        if providers:
            LOG.info('Metadata providers for network %s', net_id)
            _md_member_status('Edge  %s', providers)
        else:
            LOG.info('No providers found for network %s', net_id)


registry.subscribe(nsx_redo_metadata_cfg,
                   constants.METADATA,
                   shell.Operations.NSX_UPDATE.value)

registry.subscribe(update_shared_secret,
                   constants.METADATA,
                   shell.Operations.NSX_UPDATE_SECRET.value)

registry.subscribe(get_metadata_status, constants.METADATA,
                   shell.Operations.STATUS.value)
