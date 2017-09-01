# Copyright 2016 VMware, Inc.  All rights reserved.
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

from neutron_lib.callbacks import registry
from neutron_lib import context
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
import vmware_nsx.shell.resources as shell
from vmware_nsxlib.v3 import nsx_constants

LOG = logging.getLogger(__name__)
neutron_client = utils.NeutronDbClient()


def _get_dhcp_profile_uuid(**kwargs):
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        dhcp_profile_uuid = properties.get('dhcp_profile_uuid')
        if dhcp_profile_uuid:
            return dhcp_profile_uuid

    nsxlib = utils.get_connected_nsxlib()
    if cfg.CONF.nsx_v3.dhcp_profile:
        return nsxlib.native_dhcp_profile.get_id_by_name_or_id(
            cfg.CONF.nsx_v3.dhcp_profile)


def _get_orphaned_dhcp_servers(dhcp_profile_uuid):
    # An orphaned DHCP server means the associated neutron network
    # does not exist or has no DHCP-enabled subnet.

    orphaned_servers = []
    server_net_pairs = []

    # Find matching DHCP servers for a given dhcp_profile_uuid.
    nsxlib = utils.get_connected_nsxlib()
    response = nsxlib.dhcp_server.list()
    for dhcp_server in response['results']:
        if dhcp_server['dhcp_profile_id'] != dhcp_profile_uuid:
            continue
        found = False
        for tag in dhcp_server['tags']:
            if tag['scope'] == 'os-neutron-net-id':
                server_net_pairs.append((dhcp_server, tag['tag']))
                found = True
                break
        if not found:
            # The associated neutron network is not defined.
            dhcp_server['neutron_net_id'] = None
            orphaned_servers.append(dhcp_server)

    # Check if there is DHCP-enabled subnet in each network.
    for dhcp_server, net_id in server_net_pairs:
        try:
            network = neutron_client.get_network(net_id)
        except Exception:
            # The associated neutron network is not found in DB.
            dhcp_server['neutron_net_id'] = None
            orphaned_servers.append(dhcp_server)
            continue
        dhcp_enabled = False
        for subnet_id in network['subnets']:
            subnet = neutron_client.get_subnet(subnet_id)
            if subnet['enable_dhcp']:
                dhcp_enabled = True
                break
        if not dhcp_enabled:
            dhcp_server['neutron_net_id'] = net_id
            orphaned_servers.append(dhcp_server)

    return orphaned_servers


@admin_utils.output_header
def nsx_list_orphaned_dhcp_servers(resource, event, trigger, **kwargs):
    """List logical DHCP servers without associated DHCP-enabled subnet."""

    nsxlib = utils.get_connected_nsxlib()
    nsx_version = nsxlib.get_version()
    if not nsx_utils.is_nsx_version_1_1_0(nsx_version):
        LOG.error("This utility is not available for NSX version %s",
                  nsx_version)
        return

    dhcp_profile_uuid = _get_dhcp_profile_uuid(**kwargs)
    if not dhcp_profile_uuid:
        LOG.error("dhcp_profile_uuid is not defined")
        return

    orphaned_servers = _get_orphaned_dhcp_servers(dhcp_profile_uuid)
    LOG.info(formatters.output_formatter(constants.ORPHANED_DHCP_SERVERS,
                                         orphaned_servers,
                                         ['id', 'neutron_net_id']))


@admin_utils.output_header
def nsx_clean_orphaned_dhcp_servers(resource, event, trigger, **kwargs):
    """Remove logical DHCP servers without associated DHCP-enabled subnet."""

    # For each orphaned DHCP server,
    # (1) delete the attached logical DHCP port,
    # (2) delete the logical DHCP server,
    # (3) clean corresponding neutron DB entry.

    nsxlib = utils.get_connected_nsxlib()
    nsx_version = nsxlib.get_version()
    if not nsx_utils.is_nsx_version_1_1_0(nsx_version):
        LOG.error("This utility is not available for NSX version %s",
                  nsx_version)
        return

    dhcp_profile_uuid = _get_dhcp_profile_uuid(**kwargs)
    if not dhcp_profile_uuid:
        LOG.error("dhcp_profile_uuid is not defined")
        return

    cfg.CONF.set_override('dhcp_agent_notification', False)
    cfg.CONF.set_override('native_dhcp_metadata', True, 'nsx_v3')
    cfg.CONF.set_override('dhcp_profile', dhcp_profile_uuid, 'nsx_v3')

    orphaned_servers = _get_orphaned_dhcp_servers(dhcp_profile_uuid)

    for server in orphaned_servers:
        try:
            # TODO(asarfaty): should add this as api to nsxlib instead of
            # abusing it
            resource = ('?attachment_type=DHCP_SERVICE&attachment_id=%s' %
                        server['id'])
            response = nsxlib.logical_port.get(resource)
            if response and response['result_count'] > 0:
                nsxlib.logical_port.delete(response['results'][0]['id'])
            nsxlib.dhcp_server.delete(server['id'])
            net_id = server.get('neutron_net_id')
            if net_id:
                # Delete neutron_net_id -> dhcp_service_id mapping from the DB.
                nsx_db.delete_neutron_nsx_service_binding(
                    context.get_admin_context().session, net_id,
                    nsx_constants.SERVICE_DHCP)
            LOG.info("Removed orphaned DHCP server %s", server['id'])
        except Exception as e:
            LOG.error("Failed to clean orphaned DHCP server %(id)s. "
                      "Exception: %(e)s", {'id': server['id'], 'e': e})


registry.subscribe(nsx_list_orphaned_dhcp_servers,
                   constants.ORPHANED_DHCP_SERVERS,
                   shell.Operations.NSX_LIST.value)
registry.subscribe(nsx_clean_orphaned_dhcp_servers,
                   constants.ORPHANED_DHCP_SERVERS,
                   shell.Operations.NSX_CLEAN.value)
