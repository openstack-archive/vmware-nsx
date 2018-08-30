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
from oslo_log import log as logging

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
import vmware_nsx.shell.resources as shell
from vmware_nsxlib.v3 import nsx_constants

LOG = logging.getLogger(__name__)
neutron_client = utils.NeutronDbClient()


@admin_utils.output_header
def nsx_rate_limit_show(resource, event, trigger, **kwargs):
    """Show the current NSX rate limit."""

    nsxlib = utils.get_connected_nsxlib()
    if not nsxlib.feature_supported(nsx_constants.FEATURE_RATE_LIMIT):
        LOG.error("This utility is not available for NSX version %s",
                  nsxlib.get_version())
        return

    rate_limit = nsxlib.http_services.get_rate_limit()
    LOG.info("Current NSX rate limit is %s", rate_limit)


@admin_utils.output_header
def nsx_rate_limit_update(resource, event, trigger, **kwargs):
    """Set the NSX rate limit

    The default value is 40. 0 means no limit
    """
    nsxlib = utils.get_connected_nsxlib()
    if not nsxlib.feature_supported(nsx_constants.FEATURE_RATE_LIMIT):
        LOG.error("This utility is not available for NSX version %s",
                  nsxlib.get_version())
        return

    rate_limit = None
    if kwargs.get('property'):
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        rate_limit = properties.get('value', None)
    if rate_limit is None or not rate_limit.isdigit():
        usage = ("nsxadmin -r rate-limit -o nsx-update "
                 "--property value=<new limit>")
        LOG.error("Missing parameters. Usage: %s", usage)
        return

    nsxlib.http_services.update_rate_limit(rate_limit)
    LOG.info("NSX rate limit was updated to %s", rate_limit)


registry.subscribe(nsx_rate_limit_show,
                   constants.RATE_LIMIT,
                   shell.Operations.SHOW.value)

registry.subscribe(nsx_rate_limit_update,
                   constants.RATE_LIMIT,
                   shell.Operations.NSX_UPDATE.value)
