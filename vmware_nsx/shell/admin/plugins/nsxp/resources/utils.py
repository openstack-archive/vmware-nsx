# Copyright 2018 VMware, Inc.  All rights reserved.
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

from oslo_config import cfg

from neutron.db import l3_dvr_db  # noqa
from neutron_lib import context
from neutron_lib.plugins import constants as const
from neutron_lib.plugins import directory
from oslo_log import log as logging

from vmware_nsx.common import config
from vmware_nsx.plugins.nsx_p import plugin
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils
from vmware_nsx.shell.admin.plugins.common import formatters

LOG = logging.getLogger(__name__)
_NSXPOLICY = None


def get_nsxp_client(nsx_username=None, nsx_password=None,
                    use_basic_auth=False):

    return get_connected_nsxpolicy(nsx_username,
                                   nsx_password,
                                   use_basic_auth).client


def get_connected_nsxpolicy(nsx_username=None, nsx_password=None,
                            use_basic_auth=False):
    global _NSXPOLICY

    # for non-default agruments, initiate new lib
    if nsx_username or use_basic_auth:
        return v3_utils.get_nsxpolicy_wrapper(nsx_username,
                                              nsx_password,
                                              use_basic_auth)
    if _NSXPOLICY is None:
        _NSXPOLICY = v3_utils.get_nsxpolicy_wrapper()
    return _NSXPOLICY


def log_info(resource, data, attrs=['display_name', 'id']):
    LOG.info(formatters.output_formatter(resource, data, attrs))


def get_realization_info(resource, *realization_args):
    try:
        nsx_info = resource.get_realization_info(*realization_args)
        if not nsx_info:
            info_text = "MISSING"
        else:
            state = nsx_info.get('state')
            nsx_id = nsx_info.get('realization_specific_identifier')
            info_text = "%s (ID: %s)" % (state, nsx_id)
    except Exception as e:
        LOG.warning("Failed to get realization info for %s(%s): %s",
                    resource, str(realization_args), e)
        info_text = "UNKNOWN"
    return info_text


class NsxPolicyPluginWrapper(plugin.NsxPolicyPlugin):
    def __init__(self):
        # initialize the availability zones
        config.register_nsxp_azs(cfg.CONF, cfg.CONF.nsx_p.availability_zones)
        super(NsxPolicyPluginWrapper, self).__init__()
        self.context = context.get_admin_context()

    def __enter__(self):
        directory.add_plugin(const.CORE, self)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        directory.add_plugin(const.CORE, None)
