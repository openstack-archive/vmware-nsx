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

import sys

from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
from vmware_nsx.shell import resources as shell
from vmware_nsxlib.v3 import exceptions as nsx_exc
from vmware_nsxlib.v3 import nsx_constants

from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron_lib.callbacks import registry
from neutron_lib import context as neutron_context
from oslo_log import log as logging

LOG = logging.getLogger(__name__)
neutron_client = utils.NeutronDbClient()


class RoutersPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                    l3_db.L3_NAT_db_mixin):
    pass


@admin_utils.output_header
def list_missing_routers(resource, event, trigger, **kwargs):
    """List neutron routers that are missing the NSX backend router
    """
    nsxlib = utils.get_connected_nsxlib()
    plugin = RoutersPlugin()
    admin_cxt = neutron_context.get_admin_context()
    filters = utils.get_plugin_filters(admin_cxt)
    neutron_routers = plugin.get_routers(admin_cxt, filters=filters)
    routers = []
    for router in neutron_routers:
        neutron_id = router['id']
        # get the router nsx id from the mapping table
        nsx_id = nsx_db.get_nsx_router_id(admin_cxt.session,
                                          neutron_id)
        if not nsx_id:
            routers.append({'name': router['name'],
                            'neutron_id': neutron_id,
                            'nsx_id': None})
        else:
            try:
                nsxlib.logical_router.get(nsx_id)
            except nsx_exc.ResourceNotFound:
                routers.append({'name': router['name'],
                              'neutron_id': neutron_id,
                              'nsx_id': nsx_id})
    if len(routers) > 0:
        title = ("Found %d routers missing from the NSX "
                 "manager:") % len(routers)
        LOG.info(formatters.output_formatter(
            title, routers,
            ['name', 'neutron_id', 'nsx_id']))
    else:
        LOG.info("All routers exist on the NSX manager")


@admin_utils.output_header
def update_nat_rules(resource, event, trigger, **kwargs):
    """Update all routers NAT rules to not bypass the firewall"""
    # This feature is supported only since nsx version 2
    nsxlib = utils.get_connected_nsxlib()
    version = nsxlib.get_version()
    if not nsx_utils.is_nsx_version_2_0_0(version):
        LOG.info("NAT rules update only supported from 2.0 onwards")
        LOG.info("Version is %s", version)
        return

    # Go over all neutron routers
    plugin = RoutersPlugin()
    admin_cxt = neutron_context.get_admin_context()
    filters = utils.get_plugin_filters(admin_cxt)
    neutron_routers = plugin.get_routers(admin_cxt, filters=filters)
    num_of_updates = 0
    for router in neutron_routers:
        neutron_id = router['id']
        # get the router nsx id from the mapping table
        nsx_id = nsx_db.get_nsx_router_id(admin_cxt.session,
                                          neutron_id)
        if nsx_id:
            # get all NAT rules:
            rules = nsxlib.logical_router.list_nat_rules(nsx_id)['results']
            for rule in rules:
                if rule['action'] not in ["NO_SNAT", "NO_DNAT", "NO_NAT"]:
                    if 'nat_pass' not in rule or rule['nat_pass']:
                        nsxlib.logical_router.update_nat_rule(
                            nsx_id, rule['id'], nat_pass=False)
                        num_of_updates = num_of_updates + 1
    if num_of_updates:
        LOG.info("Done updating %s NAT rules", num_of_updates)
    else:
        LOG.info("Did not find any NAT rule to update")


@admin_utils.output_header
def update_enable_standby_relocation(resource, event, trigger, **kwargs):
    """Enable standby relocation on all routers """
    # This feature is supported only since nsx version 2.4
    nsxlib = utils.get_connected_nsxlib()
    version = nsxlib.get_version()
    if not nsx_utils.is_nsx_version_2_4_0(version):
        LOG.info("Standby relocation update is only supported from 2.4 "
                 "onwards")
        LOG.info("Version is %s", version)
        return

    # Go over all neutron routers
    plugin = RoutersPlugin()
    admin_cxt = neutron_context.get_admin_context()
    filters = utils.get_plugin_filters(admin_cxt)
    neutron_routers = plugin.get_routers(admin_cxt, filters=filters)
    for router in neutron_routers:
        neutron_id = router['id']
        # get the router nsx id from the mapping table
        nsx_id = nsx_db.get_nsx_router_id(admin_cxt.session,
                                          neutron_id)
        try:
            nsxlib.logical_router.update(lrouter_id=nsx_id,
                                         enable_standby_relocation=True)
        except Exception as e:
            # This may fail if the service router is not created
            LOG.warning("Router %s cannot enable standby relocation: %s",
                        neutron_id, e)
        else:
            LOG.info("Router %s was enabled with standby relocation",
                     neutron_id)
    LOG.info("Done")


@admin_utils.output_header
def list_orphaned_routers(resource, event, trigger, **kwargs):
    nsxlib = utils.get_connected_nsxlib()
    admin_cxt = neutron_context.get_admin_context()
    missing_routers = v3_utils.get_orphaned_routers(admin_cxt, nsxlib)
    LOG.info(formatters.output_formatter(constants.ORPHANED_ROUTERS,
                                         missing_routers,
                                         ['id', 'display_name']))


@admin_utils.output_header
def delete_backend_router(resource, event, trigger, **kwargs):
    nsxlib = utils.get_connected_nsxlib()
    errmsg = ("Need to specify nsx-id property. Add --property nsx-id=<id>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    nsx_id = properties.get('nsx-id')
    if not nsx_id:
        LOG.error("%s", errmsg)
        return

    # check if the router exists
    try:
        nsxlib.logical_router.get(nsx_id, silent=True)
    except nsx_exc.ResourceNotFound:
        # prevent logger from logging this exception
        sys.exc_clear()
        LOG.warning("Backend router %s was not found.", nsx_id)
        return

    # try to delete it
    success, error = v3_utils.delete_orphaned_router(nsxlib, nsx_id)
    if not success:
        LOG.error("Failed to delete backend router %(id)s : %(e)s.", {
            'id': nsx_id, 'e': error})
        return

    # Verify that the router was deleted since the backend does not always
    # throws errors
    try:
        nsxlib.logical_router.get(nsx_id, silent=True)
    except nsx_exc.ResourceNotFound:
        # prevent logger from logging this exception
        sys.exc_clear()
        LOG.info("Backend router %s was deleted.", nsx_id)
    else:
        LOG.error("Failed to delete backend router %s.", nsx_id)


@admin_utils.output_header
def update_dhcp_relay(resource, event, trigger, **kwargs):
    """Update all routers dhcp relay service by the current configuration"""
    nsxlib = utils.get_connected_nsxlib()
    if not nsxlib.feature_supported(nsx_constants.FEATURE_DHCP_RELAY):
        version = nsxlib.get_version()
        LOG.error("DHCP relay is not supported by NSX version %s", version)
        return

    admin_cxt = neutron_context.get_admin_context()
    filters = utils.get_plugin_filters(admin_cxt)
    with utils.NsxV3PluginWrapper() as plugin:
        # Make sure FWaaS was initialized
        plugin.init_fwaas_for_admin_utils()

        # get all neutron routers and  interfaces ports
        routers = plugin.get_routers(admin_cxt, filters=filters)
        for router in routers:
            LOG.info("Updating router %s", router['id'])
            port_filters = {'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                            'device_id': [router['id']]}
            ports = plugin.get_ports(admin_cxt, filters=port_filters)
            for port in ports:
                # get the backend router port by the tag
                nsx_port_id = nsxlib.get_id_by_resource_and_tag(
                    'LogicalRouterDownLinkPort',
                    'os-neutron-rport-id', port['id'])
                if not nsx_port_id:
                    LOG.warning("Couldn't find nsx router port for interface "
                                "%s", port['id'])
                    continue
                # get the network of this port
                network_id = port['network_id']
                # check the relay service on the az of the network
                az = plugin.get_network_az_by_net_id(admin_cxt, network_id)
                nsxlib.logical_router_port.update(
                    nsx_port_id, relay_service_uuid=az.dhcp_relay_service)

            # if FWaaS is enables, also update the firewall rules
            try:
                plugin.update_router_firewall(admin_cxt, router['id'])
            except Exception as e:
                LOG.warning("Updating router firewall was skipped because of "
                            "an error %s", e)

    LOG.info("Done.")


registry.subscribe(list_missing_routers,
                   constants.ROUTERS,
                   shell.Operations.LIST_MISMATCHES.value)

registry.subscribe(update_nat_rules,
                   constants.ROUTERS,
                   shell.Operations.NSX_UPDATE_RULES.value)

registry.subscribe(list_orphaned_routers,
                   constants.ORPHANED_ROUTERS,
                   shell.Operations.LIST.value)

registry.subscribe(delete_backend_router,
                   constants.ORPHANED_ROUTERS,
                   shell.Operations.NSX_CLEAN.value)

registry.subscribe(update_dhcp_relay,
                   constants.ROUTERS,
                   shell.Operations.NSX_UPDATE_DHCP_RELAY.value)
registry.subscribe(update_enable_standby_relocation,
                   constants.ROUTERS,
                   shell.Operations.NSX_ENABLE_STANDBY_RELOCATION.value)
