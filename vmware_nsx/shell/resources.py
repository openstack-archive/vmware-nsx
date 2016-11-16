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

import enum
import glob
import importlib
import logging
import os

from oslo_config import cfg
import requests

from vmware_nsx.common import config  # noqa
from vmware_nsx.shell.admin.plugins.common import constants

# Suppress the Insecure request warning
requests.packages.urllib3.disable_warnings()

LOG = logging.getLogger(__name__)


class Operations(enum.Enum):
    LIST = 'list'
    CLEAN = 'clean'
    LIST_MISMATCHES = 'list-mismatches'
    FIX_MISMATCH = 'fix-mismatch'

    NEUTRON_LIST = 'neutron-list'
    NEUTRON_CLEAN = 'neutron-clean'
    NEUTRON_UPDATE = 'neutron-update'

    NSX_LIST = 'nsx-list'
    NSX_CLEAN = 'nsx-clean'
    NSX_UPDATE = 'nsx-update'
    NSX_UPDATE_SECRET = 'nsx-update-secret'
    NSX_RECREATE = 'nsx-recreate'
    MIGRATE_TO_DYNAMIC_CRITERIA = 'migrate-to-dynamic-criteria'
    NSX_MIGRATE_V_V3 = 'nsx-migrate-v-v3'
    STATUS = 'status'

ops = [op.value for op in Operations]


class Resource(object):
    def __init__(self, name, ops):
        self.name = name
        self.supported_ops = ops


# Add supported NSX-V3 resources in this dictionary
nsxv3_resources = {
    constants.SECURITY_GROUPS: Resource(constants.SECURITY_GROUPS,
                                        [Operations.LIST.value,
                                         Operations.FIX_MISMATCH.value]),
    constants.FIREWALL_SECTIONS: Resource(constants.FIREWALL_SECTIONS,
                                          [Operations.LIST.value,
                                           Operations.LIST_MISMATCHES.value]),
    constants.FIREWALL_NSX_GROUPS: Resource(
        constants.FIREWALL_NSX_GROUPS, [
            Operations.LIST.value,
            Operations.LIST_MISMATCHES.value,
            Operations.MIGRATE_TO_DYNAMIC_CRITERIA.value]),
    constants.NETWORKS: Resource(constants.NETWORKS,
                                 [Operations.LIST_MISMATCHES.value]),
    constants.PORTS: Resource(constants.PORTS,
                              [Operations.LIST_MISMATCHES.value,
                               Operations.NSX_MIGRATE_V_V3.value]),
    constants.ROUTERS: Resource(constants.ROUTERS,
                                [Operations.LIST_MISMATCHES.value]),
    constants.DHCP_BINDING: Resource(constants.DHCP_BINDING,
                                     [Operations.LIST.value,
                                      Operations.NSX_UPDATE.value]),
    constants.METADATA_PROXY: Resource(constants.METADATA_PROXY,
                                       [Operations.LIST.value,
                                        Operations.NSX_UPDATE.value]),
    constants.ORPHANED_DHCP_SERVERS: Resource(constants.ORPHANED_DHCP_SERVERS,
                                              [Operations.NSX_LIST.value,
                                               Operations.NSX_CLEAN.value]),
}

# Add supported NSX-V resources in this dictionary
nsxv_resources = {
    constants.EDGES: Resource(constants.EDGES,
                              [Operations.NSX_LIST.value,
                               Operations.NEUTRON_LIST.value,
                               Operations.NSX_UPDATE.value]),
    constants.BACKUP_EDGES: Resource(constants.BACKUP_EDGES,
                                     [Operations.LIST.value,
                                      Operations.CLEAN.value,
                                      Operations.LIST_MISMATCHES.value,
                                      Operations.FIX_MISMATCH.value]),
    constants.ORPHANED_EDGES: Resource(constants.ORPHANED_EDGES,
                                       [Operations.LIST.value,
                                        Operations.CLEAN.value]),
    constants.MISSING_EDGES: Resource(constants.MISSING_EDGES,
                                      [Operations.LIST.value]),
    constants.SPOOFGUARD_POLICY: Resource(constants.SPOOFGUARD_POLICY,
                                          [Operations.LIST.value,
                                           Operations.CLEAN.value]),
    constants.DHCP_BINDING: Resource(constants.DHCP_BINDING,
                                     [Operations.LIST.value,
                                      Operations.NSX_UPDATE.value,
                                      Operations.NSX_RECREATE.value]),
    constants.NETWORKS: Resource(constants.NETWORKS,
                                 [Operations.LIST.value,
                                  Operations.NSX_UPDATE.value]),
    constants.MISSING_NETWORKS: Resource(constants.MISSING_NETWORKS,
                                [Operations.LIST.value]),
    constants.ORPHANED_NETWORKS: Resource(constants.ORPHANED_NETWORKS,
                                 [Operations.LIST.value,
                                  Operations.NSX_CLEAN.value]),
    constants.SECURITY_GROUPS: Resource(constants.SECURITY_GROUPS,
                                        [Operations.LIST.value,
                                         Operations.FIX_MISMATCH.value]),
    constants.FIREWALL_SECTIONS: Resource(constants.FIREWALL_SECTIONS,
                                          [Operations.LIST.value,
                                           Operations.LIST_MISMATCHES.value]),
    constants.FIREWALL_NSX_GROUPS: Resource(
        constants.FIREWALL_NSX_GROUPS, [Operations.LIST.value,
                                        Operations.LIST_MISMATCHES.value]),
    constants.METADATA: Resource(
        constants.METADATA, [Operations.NSX_UPDATE.value,
                             Operations.NSX_UPDATE_SECRET.value,
                             Operations.STATUS.value]),
    constants.ROUTERS: Resource(constants.ROUTERS,
                                [Operations.NSX_RECREATE.value]),
}

nsxv3_resources_names = list(nsxv3_resources.keys())
nsxv_resources_names = list(nsxv_resources.keys())


def get_resources(plugin_dir):
    modules = glob.glob(plugin_dir + "/*.py")
    return map(lambda module: os.path.splitext(os.path.basename(module))[0],
               modules)


def get_plugin():
    plugin = cfg.CONF.core_plugin
    plugin_name = ''
    if plugin == constants.NSXV3_PLUGIN:
        plugin_name = 'nsxv3'
    elif plugin == constants.NSXV_PLUGIN:
        plugin_name = 'nsxv'
    return plugin_name


def _get_choices():
    plugin = get_plugin()
    if plugin == 'nsxv3':
        return nsxv3_resources_names
    elif plugin == 'nsxv':
        return nsxv_resources_names


def _get_resources():
    plugin = get_plugin()
    if plugin == 'nsxv3':
        return 'NSX-V3 resources: %s' % (', '.join(nsxv3_resources_names))
    elif plugin == 'nsxv':
        return 'NSX-V resources: %s' % (', '.join(nsxv_resources_names))


cli_opts = [cfg.StrOpt('fmt',
                       short='f',
                       default='psql',
                       choices=['psql', 'json'],
                       help='Supported output formats: json, psql'),
            cfg.StrOpt('resource',
                       short='r',
                       choices=_get_choices(),
                       help=_get_resources()),
            cfg.StrOpt('operation',
                       short='o',
                       help='Supported list of operations: {}'
                             .format(', '.join(ops))),
            cfg.BoolOpt('force',
                        default=False,
                        help='Enables \'force\' mode. No confirmations will '
                             'be made before deletions.'),
            cfg.MultiStrOpt('property',
                            short='p',
                            help='Key-value pair containing the information '
                                 'to be updated. For ex: key=value.')
            ]


def init_resource_plugin(plugin_name, plugin_dir):
    plugin_resources = get_resources(plugin_dir)
    for resource in plugin_resources:
        if (resource != '__init__'):
            importlib.import_module(
                "vmware_nsx.shell.admin.plugins."
                "{}.resources.".format(plugin_name) + resource)


def get_plugin_dir(plugin_name):
    plugin_dir = (os.path.dirname(os.path.realpath(__file__)) +
                  "/admin/plugins")
    return '{}/{}/resources'.format(plugin_dir, plugin_name)
