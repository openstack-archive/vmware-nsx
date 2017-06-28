# Copyright 2017 VMware, Inc.
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

from neutron.db import _resource_extend as resource_extend
from neutron.db import address_scope_db
from neutron.db import api as db_api
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib import context as n_context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory

from vmware_nsx._i18n import _

LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
class NsxPluginBase(db_base_plugin_v2.NeutronDbPluginV2,
                    address_scope_db.AddressScopeDbMixin):
    """Common methods for NSX-V and NSX-V3 plugins"""

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME])
    def _ext_extend_network_dict(result, netdb):
        ctx = n_context.get_admin_context()
        # get the core plugin as this is a static method with no 'self'
        plugin = directory.get_plugin()
        with db_api.context_manager.writer.using(ctx):
            plugin._extension_manager.extend_network_dict(
                ctx.session, netdb, result)

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _ext_extend_port_dict(result, portdb):
        ctx = n_context.get_admin_context()
        # get the core plugin as this is a static method with no 'self'
        plugin = directory.get_plugin()
        with db_api.context_manager.writer.using(ctx):
            plugin._extension_manager.extend_port_dict(
                ctx.session, portdb, result)

    @staticmethod
    @resource_extend.extends([subnet_def.COLLECTION_NAME])
    def _ext_extend_subnet_dict(result, subnetdb):
        ctx = n_context.get_admin_context()
        # get the core plugin as this is a static method with no 'self'
        plugin = directory.get_plugin()
        with db_api.context_manager.writer.using(ctx):
            plugin._extension_manager.extend_subnet_dict(
                ctx.session, subnetdb, result)

    def get_network_az_by_net_id(self, context, network_id):
        try:
            network = self.get_network(context, network_id)
        except Exception:
            return self.get_default_az()

        return self.get_network_az(network)

    def _get_router_interface_ports_by_network(
        self, context, router_id, network_id):
        port_filters = {'device_id': [router_id],
                        'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                        'network_id': [network_id]}
        return self.get_ports(context, filters=port_filters)

    def get_router_for_floatingip(self, context, internal_port,
                                  internal_subnet, external_network_id):
        router_id = super(NsxPluginBase, self).get_router_for_floatingip(
            context, internal_port, internal_subnet, external_network_id)
        if router_id:
            router = self._get_router(context.elevated(), router_id)
            if not router.enable_snat:
                msg = _("Unable to assign a floating IP to a router that "
                        "has SNAT disabled")
                raise n_exc.InvalidInput(error_message=msg)
        return router_id
