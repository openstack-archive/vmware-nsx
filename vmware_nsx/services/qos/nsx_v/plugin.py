# Copyright 2016 VMware, Inc.
#
# All Rights Reserved
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

from neutron.services.qos import qos_plugin
from neutron_lib.api.definitions import qos as qos_apidef
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc

LOG = logging.getLogger(__name__)


class NsxVQosPlugin(qos_plugin.QoSPlugin):

    """Service plugin for VMware NSX-v to implement Neutron's Qos API."""

    supported_extension_aliases = [qos_apidef.ALIAS]

    def __init__(self):
        LOG.info("Loading VMware NSX-V Qos Service Plugin")
        super(NsxVQosPlugin, self).__init__()

        if not cfg.CONF.nsxv.use_dvs_features:
            error = _("Cannot use the NSX-V QoS plugin without "
                      "enabling the dvs features")
            raise nsx_exc.NsxPluginException(err_msg=error)
