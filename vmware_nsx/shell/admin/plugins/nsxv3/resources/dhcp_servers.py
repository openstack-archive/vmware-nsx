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
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
import vmware_nsx.shell.resources as shell

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

    orphaned_servers = v3_utils.get_orphaned_dhcp_servers(
        context.get_admin_context(),
        neutron_client, nsxlib, dhcp_profile_uuid)
    LOG.info(formatters.output_formatter(
        constants.ORPHANED_DHCP_SERVERS,
        orphaned_servers,
        ['id', 'neutron_net_id', 'display_name']))


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

    orphaned_servers = v3_utils.get_orphaned_dhcp_servers(
        context.get_admin_context(),
        neutron_client, nsxlib, dhcp_profile_uuid)

    for server in orphaned_servers:
        success, error = v3_utils.delete_orphaned_dhcp_server(
            context.get_admin_context(), nsxlib, server)
        if success:
            LOG.info("Removed orphaned DHCP server %s", server['id'])
        else:
            LOG.error("Failed to clean orphaned DHCP server %(id)s. "
                      "Exception: %(e)s", {'id': server['id'], 'e': error})


registry.subscribe(nsx_list_orphaned_dhcp_servers,
                   constants.ORPHANED_DHCP_SERVERS,
                   shell.Operations.NSX_LIST.value)
registry.subscribe(nsx_clean_orphaned_dhcp_servers,
                   constants.ORPHANED_DHCP_SERVERS,
                   shell.Operations.NSX_CLEAN.value)
