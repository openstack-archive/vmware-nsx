# Copyright 2017 VMware, Inc.  All rights reserved.
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
from oslo_log import log as logging

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
from vmware_nsx.shell import resources as shell

LOG = logging.getLogger(__name__)


@admin_utils.output_header
def validate_configuration(resource, event, trigger, **kwargs):
    """Validate the nsxv3 configuration"""
    try:
        utils.NsxV3PluginWrapper()
    except Exception as e:
        LOG.error("Configuration validation failed: %s", e)
    else:
        LOG.info("Configuration validation succeeded")


registry.subscribe(validate_configuration,
                   constants.CONFIG,
                   shell.Operations.VALIDATE.value)
