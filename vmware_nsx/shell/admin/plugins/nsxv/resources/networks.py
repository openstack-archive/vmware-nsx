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


registry.subscribe(neutron_list_networks,
                   constants.NETWORKS,
                   shell.Operations.LIST.value)
