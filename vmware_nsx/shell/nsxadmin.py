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

import sys

from neutron.common import config as neutron_config
from neutron.conf import common as neutron_common_config
from neutron_lib.callbacks import registry
from oslo_config import cfg
from oslo_log import _options
from oslo_log import log as logging
import requests

from vmware_nsx.common import config  # noqa
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin import version
from vmware_nsx.shell import resources

# Suppress the Insecure request warning
requests.packages.urllib3.disable_warnings()

LOG = logging.getLogger(__name__)


def _init_cfg():

    # NOTE(gangila): neutron.common.config registers some options by default
    # which are then shown in the help message. We don't need them
    # so we unregister these options
    cfg.CONF.unregister_opts(_options.common_cli_opts)
    cfg.CONF.unregister_opts(_options.logging_cli_opts)
    cfg.CONF.unregister_opts(neutron_common_config.core_cli_opts)

    # register must come after above unregister to avoid duplicates
    cfg.CONF.register_cli_opts(resources.cli_opts)

    # Init the neutron config
    neutron_config.init(args=['--config-file', constants.NEUTRON_CONF,
                              '--config-file', constants.NSX_INI])

    cfg.CONF(args=sys.argv[1:], project='NSX',
             prog='Admin Utility',
             version=version.__version__,
             usage='nsxadmin -r <resources> -o <operation>',
             default_config_files=[constants.NEUTRON_CONF,
                                   constants.NSX_INI])


def _validate_resource_choice(resource, nsx_plugin):
    if nsx_plugin == 'nsxv' and resource not in resources.nsxv_resources:
        LOG.error('Supported list of NSX-V resources: %s',
                  resources.nsxv_resources_names)
        sys.exit(1)
    elif nsx_plugin == 'nsxv3'and resource not in resources.nsxv3_resources:
        LOG.error('Supported list of NSX-V3 resources: %s',
                  resources.nsxv3_resources_names)
        sys.exit(1)


def _validate_op_choice(choice, nsx_plugin):
    if nsx_plugin == 'nsxv':
        supported_resource_ops = \
            resources.nsxv_resources[cfg.CONF.resource].supported_ops
        if choice not in supported_resource_ops:
            LOG.error('Supported list of operations for the NSX-V '
                      'resource %s', supported_resource_ops)
            sys.exit(1)

    elif nsx_plugin == 'nsxv3':
        supported_resource_ops = \
            resources.nsxv3_resources[cfg.CONF.resource].supported_ops
        if choice not in supported_resource_ops:
            LOG.error('Supported list of operations for the NSX-V3 '
                      'resource %s', supported_resource_ops)
            sys.exit(1)


def main(argv=sys.argv[1:]):
    _init_cfg()
    nsx_plugin_in_use = resources.get_plugin()
    resources.init_resource_plugin(
        nsx_plugin_in_use,
        resources.get_plugin_dir(nsx_plugin_in_use))
    LOG.info('NSX Plugin in use: %s', nsx_plugin_in_use)

    _validate_resource_choice(cfg.CONF.resource, nsx_plugin_in_use)
    _validate_op_choice(cfg.CONF.operation, nsx_plugin_in_use)

    registry.notify(cfg.CONF.resource, cfg.CONF.operation, 'nsxadmin',
                    force=cfg.CONF.force, property=cfg.CONF.property,
                    verbose=cfg.CONF.verbose)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
