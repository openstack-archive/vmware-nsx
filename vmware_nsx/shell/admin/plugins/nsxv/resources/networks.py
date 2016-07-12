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


import logging
from oslo_serialization import jsonutils
import xml.etree.ElementTree as et

from vmware_nsx._i18n import _LE, _LI
from vmware_nsx.db import db as nsx_db
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils as utils
from vmware_nsx.shell import resources as shell

from neutron.callbacks import registry
from neutron import context

LOG = logging.getLogger(__name__)
nsxv = utils.get_nsxv_client()
network_types = ['Network', 'VirtualWire', 'DistributedVirtualPortgroup']


def get_networks_from_backend():
    nsxv = utils.get_nsxv_client()
    so_list = nsxv.get_scoping_objects()
    return et.fromstring(so_list)


def get_networks():
    """Create an array of all the backend networks and their data
    """
    root = get_networks_from_backend()
    networks = []
    for obj in root.iter('object'):
        if obj.find('objectTypeName').text in network_types:
            networks.append({'type': obj.find('objectTypeName').text,
                             'moref': obj.find('objectId').text,
                             'name': obj.find('name').text})
    return networks


def get_networks_name_map():
    """Create a dictionary mapping moref->backend name
    """
    root = get_networks_from_backend()
    networks = {}
    for obj in root.iter('object'):
        if obj.find('objectTypeName').text in network_types:
            networks[obj.find('objectId').text] = obj.find('name').text
    return networks


@admin_utils.output_header
def neutron_list_networks(resource, event, trigger,
                          **kwargs):
    LOG.info(formatters.output_formatter(constants.NETWORKS, get_networks(),
                                         ['type', 'moref', 'name']))


@admin_utils.output_header
def nsx_update_switch(resource, event, trigger, **kwargs):
    nsxv = utils.get_nsxv_client()
    if not kwargs.get('property'):
        LOG.error(_LE("Need to specify dvs-id parameter and "
                      "attribute to update. Add --property dvs-id=<dvs-id> "
                      "--property teamingpolicy=<policy>"))
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    dvs_id = properties.get('dvs-id')
    if not dvs_id:
        LOG.error(_LE("Need to specify dvs-id. "
                      "Add --property dvs-id=<dvs-id>"))
        return
    try:
        h, switch = nsxv.get_vdn_switch(dvs_id)
    except exceptions.ResourceNotFound:
        LOG.error(_LE("DVS %s not found"), dvs_id)
        return
    supported_policies = ['ETHER_CHANNEL', 'LOADBALANCE_LOADBASED',
                          'LOADBALANCE_SRCID', 'LOADBALANCE_SRCMAC',
                          'FAILOVER_ORDER']
    policy = properties.get('teamingpolicy')
    if policy in supported_policies:
        if switch['teamingPolicy'] == policy:
            LOG.info(_LI("Policy already set!"))
            return
        LOG.info(_LI("Updating NSXv switch %(dvs)s teaming policy to "
                     "%(policy)s"), {'dvs': dvs_id, 'policy': policy})
        switch['teamingPolicy'] = policy
        try:
            switch = nsxv.update_vdn_switch(switch)
        except exceptions.VcnsApiException as e:
            desc = jsonutils.loads(e.response)
            details = desc.get('details')
            if details.startswith("No enum constant"):
                LOG.error(_LE("Unknown teaming policy %s"), policy)
            else:
                LOG.error(_LE("Unexpected error occurred: %s"), details)
            return

        LOG.info(_LI("Switch value after update: %s"), switch)
    else:
        LOG.info(_LI("Current switch value is: %s"), switch)
        LOG.error(_LE("Invalid teaming policy. "
                      "Add --property teamingpolicy=<policy>"))
        LOG.error(_LE("Possible values: %s"), ', '.join(supported_policies))


@admin_utils.output_header
def list_missing_networks(resource, event, trigger, **kwargs):
    """List the neutron networks which are missing the backend moref
    """
    # get the neutron-nsx networks mapping from DB
    admin_context = context.get_admin_context()
    mappings = nsx_db.get_nsx_networks_mapping(admin_context.session)
    # get the list of backend networks:
    backend_networks = get_networks_name_map()
    missing_networks = []

    # For each neutron network - check if there is a matching backend network
    for entry in mappings:
        nsx_id = entry['nsx_id']
        dvs_id = entry['dvs_id']
        if nsx_id not in backend_networks.keys():
            missing_networks.append({'neutron_id': entry['neutron_id'],
                                     'moref': nsx_id,
                                     'dvs_id': dvs_id})
        elif dvs_id:
            netname = backend_networks[nsx_id]
            if not netname.startswith(dvs_id):
                missing_networks.append({'neutron_id': entry['neutron_id'],
                                         'moref': nsx_id,
                                         'dvs_id': dvs_id})

    LOG.info(formatters.output_formatter(constants.MISSING_NETWORKS,
                                         missing_networks,
                                         ['neutron_id', 'moref', 'dvs_id']))


registry.subscribe(neutron_list_networks,
                   constants.NETWORKS,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_update_switch,
                   constants.NETWORKS,
                   shell.Operations.NSX_UPDATE.value)
registry.subscribe(list_missing_networks,
                   constants.MISSING_NETWORKS,
                   shell.Operations.LIST.value)
