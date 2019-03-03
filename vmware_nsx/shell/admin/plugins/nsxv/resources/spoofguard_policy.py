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


from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters

import vmware_nsx.shell.admin.plugins.common.utils as admin_utils
import vmware_nsx.shell.admin.plugins.nsxv.resources.utils as utils
import vmware_nsx.shell.resources as shell

from neutron_lib.callbacks import registry
from neutron_lib import exceptions

from vmware_nsx.db import nsxv_db
from vmware_nsx.extensions import (
    vnicindex as ext_vnic_idx)

from oslo_log import log as logging

LOG = logging.getLogger(__name__)
nsxv = utils.get_nsxv_client()


def get_spoofguard_policies():
    nsxv = utils.get_nsxv_client()
    return nsxv.get_spoofguard_policies()[1].get("policies")


def get_spoofguard_policy_data(policy_id):
    nsxv = utils.get_nsxv_client()
    return nsxv.get_spoofguard_policy_data(policy_id)[1].get(
        'spoofguardList', [])


@admin_utils.output_header
def nsx_list_spoofguard_policies(resource, event, trigger, **kwargs):
    """List spoofguard policies from NSXv backend"""
    policies = get_spoofguard_policies()
    LOG.info(formatters.output_formatter(constants.SPOOFGUARD_POLICY, policies,
                                         ['policyId', 'name']))


def get_spoofguard_policy_network_mappings():
    spgapi = utils.NeutronDbClient()
    return nsxv_db.get_nsxv_spoofguard_policy_network_mappings(
        spgapi.context)


@admin_utils.output_header
def neutron_list_spoofguard_policy_mappings(resource, event, trigger,
                                            **kwargs):
    mappings = get_spoofguard_policy_network_mappings()
    LOG.info(formatters.output_formatter(constants.SPOOFGUARD_POLICY, mappings,
                                         ['network_id', 'policy_id']))


def get_missing_spoofguard_policy_mappings(reverse=None):
    nsxv_spoofguard_policies = set()
    for spg in get_spoofguard_policies():
        nsxv_spoofguard_policies.add(spg.get('policyId'))

    neutron_spoofguard_policy_mappings = set()
    for binding in get_spoofguard_policy_network_mappings():
        neutron_spoofguard_policy_mappings.add(binding.policy_id)

    if reverse:
        return nsxv_spoofguard_policies - neutron_spoofguard_policy_mappings
    else:
        return neutron_spoofguard_policy_mappings - nsxv_spoofguard_policies


@admin_utils.output_header
def nsx_list_missing_spoofguard_policies(resource, event, trigger,
                                         **kwargs):
    """List missing spoofguard policies on NSXv.

    Spoofguard policies that have a binding in Neutron Db but there is
    no policy on NSXv backend to back it.
    """
    props = kwargs.get('property')
    reverse = True if props and props[0] == 'reverse' else False
    if reverse:
        LOG.info("Spoofguard policies on NSXv but not present in "
                 "Neutron Db")
    else:
        LOG.info("Spoofguard policies in Neutron Db but not present "
                 "on NSXv")
    missing_policies = get_missing_spoofguard_policy_mappings(reverse)
    if not missing_policies:
        LOG.info("\nNo missing spoofguard policies found."
                 "\nNeutron DB and NSXv backend are in sync\n")
    else:
        LOG.info(missing_policies)
        missing_policies = [{'policy_id': pid} for pid in missing_policies]
        LOG.info(formatters.output_formatter(
            constants.SPOOFGUARD_POLICY, missing_policies, ['policy_id']))


def get_port_vnic_id(plugin, port):
    vnic_idx = port.get(ext_vnic_idx.VNIC_INDEX)
    device_id = port.get('device_id')
    return plugin._get_port_vnic_id(vnic_idx, device_id)


def nsx_list_mismatch_addresses_for_net(context, plugin, network_id,
                                        policy_id):
    policy_data = get_spoofguard_policy_data(policy_id)
    missing = []
    # Get all neutron compute ports on this network
    port_filters = {'network_id': [network_id]}
    neutron_ports = plugin.get_ports(context, filters=port_filters)
    comp_ports = [port for port in neutron_ports
                  if port.get('device_owner', '').startswith('compute:')]

    for port in comp_ports:
        if not port['port_security_enabled']:
            # This port is not in spoofguard
            continue
        error_data = None
        port_ips = []
        for pair in port.get('allowed_address_pairs'):
            port_ips.append(pair['ip_address'])
        for fixed in port.get('fixed_ips'):
            port_ips.append(fixed['ip_address'])
        if not port_ips:
            continue
        port_ips.sort()
        mac_addr = port['mac_address']
        vnic_id = get_port_vnic_id(plugin, port)

        # look for this port in the spoofguard data
        found_port = False
        for spd in policy_data:
            if spd['id'] == vnic_id:
                found_port = True
                actual_ips = spd.get('publishedIpAddress',
                                     {}).get('ipAddresses', [])
                actual_ips.sort()
                if actual_ips != port_ips:
                    error_data = ('Different IPs (%s/%s)' % (
                        len(actual_ips), len(port_ips)))
                elif spd.get('publishedMacAddress') != mac_addr:
                    error_data = ('Different MAC address (%s/%s)' % (
                        spd.get('publishedMacAddress'), mac_addr))
                continue

        if not found_port:
            error_data = 'Port missing from SG policy'

        if error_data:
            missing.append({'network': network_id,
                            'policy': policy_id,
                            'port': port['id'],
                            'data': error_data})
    return missing


@admin_utils.output_header
def nsx_list_mismatch_addresses(resource, event, trigger, **kwargs):
    """List missing spoofguard policies approved addresses on NSXv.

    Address pairs defined on neutron compute ports that are missing from the
    NSX-V spoofguard policy of a specific/all networks.
    """
    network_id = None
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        network_id = properties.get('network')

    spgapi = utils.NeutronDbClient()

    if network_id:
        policy_id = nsxv_db.get_spoofguard_policy_id(
                spgapi.context.session, network_id)
        if not policy_id:
            LOG.error("Could not find spoofguard policy for neutron network "
                      "%s", network_id)
            return
        with utils.NsxVPluginWrapper() as plugin:
            missing_data = nsx_list_mismatch_addresses_for_net(
                spgapi.context, plugin, network_id, policy_id)
    else:
        with utils.NsxVPluginWrapper() as plugin:
            missing_data = []
            # Go over all the networks with spoofguard policies
            mappings = get_spoofguard_policy_network_mappings()
            for entry in mappings:
                missing_data.extend(nsx_list_mismatch_addresses_for_net(
                    spgapi.context, plugin, entry['network_id'],
                    entry['policy_id']))

    if missing_data:
        LOG.info(formatters.output_formatter(
            constants.SPOOFGUARD_POLICY, missing_data,
            ['network', 'policy', 'port', 'data']))
    else:
        LOG.info("No mismatches found.")


@admin_utils.output_header
def nsx_fix_mismatch_addresses(resource, event, trigger, **kwargs):
    """Fix missing spoofguard policies approved addresses for a port."""

    port_id = None
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        port_id = properties.get('port')
    if not port_id:
        usage_msg = ("Need to specify the id of the neutron port. "
                     "Add --property port=<port_id>")
        LOG.error(usage_msg)
        return

    spgapi = utils.NeutronDbClient()
    with utils.NsxVPluginWrapper() as plugin:
        try:
            port = plugin.get_port(spgapi.context, port_id)
        except exceptions.PortNotFound:
            LOG.error("Could not find neutron port %s", port_id)
            return
        vnic_id = get_port_vnic_id(plugin, port)
        plugin._update_vnic_assigned_addresses(
            spgapi.context.session, port, vnic_id)
        LOG.info("Done.")


def nsx_clean_spoofguard_policy(resource, event, trigger, **kwargs):
    """Delete spoofguard policy"""
    errmsg = ("Need to specify policy-id. Add --property "
              "policy-id=<policy-id>")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    policy_id = properties.get('policy-id')
    if not policy_id:
        LOG.error("%s", errmsg)
        return
    try:
        h, c = nsxv.get_spoofguard_policy(policy_id)
    except exceptions.NeutronException as e:
        LOG.error("Unable to retrieve policy %(p)s: %(e)s",
                  {'p': policy_id, 'e': str(e)})
    else:
        if not c.get('spoofguardList'):
            LOG.error("Policy %s does not exist", policy_id)
            return
        confirm = admin_utils.query_yes_no(
            "Do you want to delete spoofguard-policy: %s" % policy_id,
            default="no")
        if not confirm:
            LOG.info("spoofguard-policy deletion aborted by user")
            return
        try:
            nsxv.delete_spoofguard_policy(policy_id)
        except Exception as e:
            LOG.error("%s", str(e))
        LOG.info('spoofguard-policy successfully deleted.')


registry.subscribe(neutron_list_spoofguard_policy_mappings,
                   constants.SPOOFGUARD_POLICY,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_list_spoofguard_policies,
                   constants.SPOOFGUARD_POLICY,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_list_missing_spoofguard_policies,
                   constants.SPOOFGUARD_POLICY,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_list_mismatch_addresses,
                   constants.SPOOFGUARD_POLICY,
                   shell.Operations.LIST_MISMATCHES.value)
registry.subscribe(nsx_fix_mismatch_addresses,
                   constants.SPOOFGUARD_POLICY,
                   shell.Operations.FIX_MISMATCH.value)
registry.subscribe(nsx_clean_spoofguard_policy,
                   constants.SPOOFGUARD_POLICY,
                   shell.Operations.CLEAN.value)
