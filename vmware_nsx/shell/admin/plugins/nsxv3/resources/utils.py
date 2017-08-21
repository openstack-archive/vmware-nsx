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


from neutron.db import db_base_plugin_v2
from neutron_lib import context
from neutron_lib.plugins import constants as const
from neutron_lib.plugins import directory

from vmware_nsx.db import db as nsx_db
from vmware_nsx.plugins.nsx_v3 import plugin
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils
from vmware_nsxlib.v3 import nsx_constants

_NSXLIB = None


def get_nsxv3_client(nsx_username=None, nsx_password=None,
                     use_basic_auth=False):

    return get_connected_nsxlib(nsx_username,
                                nsx_password,
                                use_basic_auth).client


def get_connected_nsxlib(nsx_username=None, nsx_password=None,
                         use_basic_auth=False):
    global _NSXLIB

    # for non-default agruments, initiate new lib
    if nsx_username or use_basic_auth:
        return v3_utils.get_nsxlib_wrapper(nsx_username,
                                           nsx_password,
                                           use_basic_auth)
    if _NSXLIB is None:
        _NSXLIB = v3_utils.get_nsxlib_wrapper()
    return _NSXLIB


class NeutronDbClient(db_base_plugin_v2.NeutronDbPluginV2):
    def __init__(self):
        super(NeutronDbClient, self).__init__()
        self.context = context.get_admin_context()

    def get_ports(self, filters=None, fields=None):
        return super(NeutronDbClient, self).get_ports(
            self.context, filters=filters, fields=fields)

    def get_networks(self, filters=None, fields=None):
        return super(NeutronDbClient, self).get_networks(
            self.context, filters=filters, fields=fields)

    def get_network(self, network_id):
        return super(NeutronDbClient, self).get_network(
            self.context, network_id)

    def get_subnet(self, subnet_id):
        return super(NeutronDbClient, self).get_subnet(self.context, subnet_id)

    def get_lswitch_and_lport_id(self, port_id):
        return nsx_db.get_nsx_switch_and_port_id(self.context.session, port_id)

    def lswitch_id_to_net_id(self, lswitch_id):
        net_ids = nsx_db.get_net_ids(self.context.session, lswitch_id)
        return net_ids[0] if net_ids else None

    def lrouter_id_to_router_id(self, lrouter_id):
        return nsx_db.get_neutron_from_nsx_router_id(self.context.session,
                                                     lrouter_id)

    def net_id_to_lswitch_id(self, net_id):
        lswitch_ids = nsx_db.get_nsx_switch_ids(self.context.session, net_id)
        return lswitch_ids[0] if lswitch_ids else None

    def add_dhcp_service_binding(self, network_id, port_id, server_id):
        return nsx_db.add_neutron_nsx_service_binding(
            self.context.session, network_id, port_id,
            nsx_constants.SERVICE_DHCP, server_id)

    def add_dhcp_static_binding(self, port_id, subnet_id, ip_address,
                                server_id, binding_id):
        return nsx_db.add_neutron_nsx_dhcp_binding(
            self.context.session, port_id, subnet_id, ip_address, server_id,
            binding_id)


class NsxV3PluginWrapper(plugin.NsxV3Plugin):
    def __init__(self):
        super(NsxV3PluginWrapper, self).__init__()
        self.context = context.get_admin_context()

    def __enter__(self):
        directory.add_plugin(const.CORE, self)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        directory.add_plugin(const.CORE, None)

    def _init_dhcp_metadata(self):
        pass

    def _process_security_group_logging(self):
        pass

    def _init_port_security_profile(self):
        return True

    def _init_dhcp_switching_profile(self):
        pass

    def _extend_get_network_dict_provider(self, context, net):
        self._extend_network_dict_provider(context, net)
        # skip getting the Qos policy ID because get_object calls
        # plugin init again on admin-util environment

    def _extend_get_port_dict_binding(self, context, port):
        self._extend_port_dict_binding(context, port)
        # skip getting the Qos policy ID because get_object calls
        # plugin init again on admin-util environment

    def delete_network(self, network_id):
        return super(NsxV3PluginWrapper, self).delete_network(
            self.context, network_id)

    def remove_router_interface(self, router_id, interface):
        return super(NsxV3PluginWrapper, self).remove_router_interface(
            self.context, router_id, interface)
