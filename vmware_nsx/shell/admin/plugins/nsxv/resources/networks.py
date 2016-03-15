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
import xml.etree.ElementTree as et

from vmware_nsx._i18n import _LE, _LI
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters

from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils as utils
from vmware_nsx.shell import nsxadmin as shell

from neutron.callbacks import registry

LOG = logging.getLogger(__name__)
nsxv = utils.get_nsxv_client()


def get_networks():
    nsxv = utils.get_nsxv_client()
    so_list = nsxv.get_scoping_objects()
    networks = []
    root = et.fromstring(so_list)
    for obj in root.iter('object'):
        if (obj.find('objectTypeName').text == 'Network' or
            obj.find('objectTypeName').text == 'VirtualWire' or
            obj.find('objectTypeName').text == 'DistributedVirtualPortgroup'):
            networks.append({'type': obj.find('objectTypeName').text,
                             'moref': obj.find('objectId').text,
                             'name': obj.find('name').text})
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
    h, switch = nsxv.get_vdn_switch(dvs_id)
    policy = properties.get('teamingpolicy')
    if policy:
        if switch['teamingPolicy'] == policy:
            LOG.info(_LI("Policy already set!"))
            return
        LOG.info(_LI("Updating NSXv switch %(dvs)s teaming policy to "
                     "%(policy)s"), {'dvs': dvs_id, 'policy': policy})
        switch['teamingPolicy'] = policy
        switch = nsxv.update_vdn_switch(switch)
        LOG.info(_LI("Switch value after update: %s"), switch)
    else:
        LOG.error(_LE("No teaming policy set. "
                      "Add --property teamingpolicy=<policy>"))
        LOG.info(_LI("Current switch value is: %s"), switch)


registry.subscribe(neutron_list_networks,
                   constants.NETWORKS,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_update_switch,
                   constants.NETWORKS,
                   shell.Operations.NSX_UPDATE.value)
