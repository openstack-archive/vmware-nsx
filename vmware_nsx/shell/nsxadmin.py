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

"""
Purpose of this script is to build a framework which can be leveraged
to build utilities to help the on-field ops in system debugging.


TODO: Use Cliff https://pypi.python.org/pypi/cliff
TODO: Define commands instead of -r -o like get-security-groups,
delete-security-groups, nsx neutron nsxv3 can be options
TODO: Add support for other resources, ports, logical switches etc.
TODO: Autocomplete command line args
"""

import enum
import glob
import importlib
import logging
import os
import requests
import sys

from neutron.callbacks import registry
from neutron.common import config as neutron_config

from vmware_nsx._i18n import _LE, _LI
from vmware_nsx.common import config  # noqa

from oslo_config import cfg
from oslo_log import _options

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin import version

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


ops = [op.value for op in Operations]


class Resource(object):
    def __init__(self, name, ops):
        self.name = name
        self.supported_ops = ops


# Add supported NSX-V3 resources in this dictionary
nsxv3_resources = {
    constants.SECURITY_GROUPS: Resource(constants.SECURITY_GROUPS,
                                        [Operations.CLEAN.value,
                                         Operations.LIST.value,
                                         Operations.NSX_LIST.value,
                                         Operations.NSX_CLEAN.value,
                                         Operations.NEUTRON_LIST.value,
                                         Operations.NEUTRON_CLEAN.value])
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
                                      Operations.NSX_UPDATE.value]),
    constants.NETWORKS: Resource(constants.NETWORKS,
                                 [Operations.LIST.value,
                                  Operations.NSX_UPDATE.value]),
    constants.SECURITY_GROUPS: Resource(constants.SECURITY_GROUPS,
                                        [Operations.LIST.value]),
    constants.FIREWALL_SECTIONS: Resource(constants.FIREWALL_SECTIONS,
                                          [Operations.LIST.value,
                                           Operations.LIST_MISMATCHES.value]),
    constants.FIREWALL_NSX_GROUPS: Resource(
        constants.FIREWALL_NSX_GROUPS, [Operations.LIST.value,
                                        Operations.LIST_MISMATCHES.value]),
    constants.METADATA: Resource(
        constants.METADATA, [Operations.NSX_UPDATE.value]),
}

nsxv3_resources_names = map(lambda res: res.name, nsxv3_resources.itervalues())
nsxv_resources_names = map(lambda res: res.name, nsxv_resources.itervalues())


def _get_plugin():
    plugin = cfg.CONF.core_plugin
    plugin_name = ''
    if plugin == constants.NSXV3_PLUGIN:
        plugin_name = 'nsxv3'
    elif plugin == constants.NSXV_PLUGIN:
        plugin_name = 'nsxv'
    return plugin_name


def _get_plugin_dir():
    plugin_dir = os.path.dirname(os.path.realpath(__file__)) + "/admin/plugins"
    return '{}/{}/resources'.format(plugin_dir, _get_plugin())


def _get_resources():
    modules = glob.glob(_get_plugin_dir() + "/*.py")
    return map(lambda module: os.path.splitext(os.path.basename(module))[0],
               modules)


cli_opts = [cfg.StrOpt('fmt',
                       short='f',
                       default='psql',
                       choices=['psql', 'json'],
                       help='Supported output formats: json, psql'),
            cfg.StrOpt('resource',
                       short='r',
                       choices=nsxv_resources_names + nsxv3_resources_names,
                       help='Supported list of resources: NSX-V3: %s  '
                            'NSX-V: %s' % (', '.join(nsxv3_resources_names),
                                           ', '.join(nsxv_resources_names))),
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


def _init_resource_plugin():
    resources = _get_resources()
    for resource in resources:
        if resource != '__init__':
            importlib.import_module("." + resource,
                                    "vmware_nsx.shell.admin.plugins."
                                    "{}.resources".format(_get_plugin()))


def _init_cfg():
    cfg.CONF.register_cli_opts(cli_opts)

    # NOTE(gangila): neutron.common.config registers some options by default
    # which are then shown in the help message. We don't need them
    # so we unregister these options
    cfg.CONF.unregister_opts(_options.common_cli_opts)
    cfg.CONF.unregister_opts(_options.logging_cli_opts)
    cfg.CONF.unregister_opts(neutron_config.core_cli_opts)

    cfg.CONF(args=sys.argv[1:], project='NSX',
             prog='Admin Utility',
             version=version.__version__,
             usage='nsxadmin -r <resources> -o <operation>',
             default_config_files=[constants.NEUTRON_CONF,
                                   constants.NSX_INI])


def _validate_resource_choice(resource, nsx_plugin):
    if nsx_plugin == 'nsxv' and resource not in nsxv_resources:
        LOG.error(_LE('Supported list of NSX-V resources: %s'),
                  nsxv_resources_names)
        sys.exit(1)
    elif nsx_plugin == 'nsxv3'and resource not in nsxv3_resources:
        LOG.error(_LE('Supported list of NSX-V3 resources: %s'),
                  nsxv3_resources_names)
        sys.exit(1)


def _validate_op_choice(choice, nsx_plugin):
    if nsx_plugin == 'nsxv':
        supported_resource_ops = \
            nsxv_resources[cfg.CONF.resource].supported_ops
        if choice not in supported_resource_ops:
            LOG.error(_LE('Supported list of operations for the NSX-V '
                          'resource %s'), supported_resource_ops)
            sys.exit(1)

    elif nsx_plugin == 'nsxv3':
        supported_resource_ops = \
            nsxv3_resources[cfg.CONF.resource].supported_ops
        if choice not in supported_resource_ops:
            LOG.error(_LE('Supported list of operations for the NSX-V3 '
                          'resource %s'), supported_resource_ops)
            sys.exit(1)


def main(argv=sys.argv[1:]):
    _init_cfg()
    _init_resource_plugin()
    nsx_plugin_in_use = _get_plugin()
    LOG.info(_LI('NSX Plugin in use: %s'), nsx_plugin_in_use)

    _validate_resource_choice(cfg.CONF.resource, nsx_plugin_in_use)
    _validate_op_choice(cfg.CONF.operation, nsx_plugin_in_use)

    registry.notify(cfg.CONF.resource, cfg.CONF.operation, 'nsxadmin',
                    force=cfg.CONF.force, property=cfg.CONF.property)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
