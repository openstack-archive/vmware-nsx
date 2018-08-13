# Copyright 2018 VMware, Inc.
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

from oslo_log import log as logging

from neutron_vpnaas.services.vpn import plugin

LOG = logging.getLogger(__name__)


class NsxVPNPlugin(plugin.VPNDriverPlugin):
    """NSX plugin for VPNaaS.

    This plugin overrides get connection/s calls to issue a status update
    before them, and make sure the connections status is up to date
    """
    def _update_nsx_connection_status(self, context, ipsec_site_conn_id):
        driver = self.drivers[self.default_provider]
        if hasattr(driver, 'get_ipsec_site_connection_status'):
            status = driver.get_ipsec_site_connection_status(
                context, ipsec_site_conn_id)
            if status:
                self._update_connection_status(context, ipsec_site_conn_id,
                                               status, False)

    def update_all_connection_status(self, context):
        connections = super(NsxVPNPlugin, self).get_ipsec_site_connections(
            context)
        if not connections:
            return
        # TODO(asarfaty): This will not scale well. Should use a bulk action
        # instead for the NSX api
        for connection in connections:
            self._update_nsx_connection_status(context, connection['id'])

    def get_ipsec_site_connection(self, context,
                                  ipsec_site_conn_id, fields=None):
        # update connection status
        if not fields or 'status' in fields:
            self._update_nsx_connection_status(context, ipsec_site_conn_id)

        # call super
        return super(NsxVPNPlugin, self).get_ipsec_site_connection(
            context, ipsec_site_conn_id, fields=fields)

    def get_ipsec_site_connections(self, context, filters=None, fields=None):
        # update connection status
        if not fields or 'status' in fields:
            self.update_all_connection_status(context)

        # call super
        return super(NsxVPNPlugin, self).get_ipsec_site_connections(
            context, filters=filters, fields=fields)
