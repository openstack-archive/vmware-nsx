# Copyright 2015 VMware, Inc.
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

from networking_l2gw.db.l2gateway import l2gateway_db
from networking_l2gw.db.l2gateway import l2gateway_models as models
from networking_l2gw.services.l2gateway.common import constants as l2gw_const
from networking_l2gw.services.l2gateway import exceptions as l2gw_exc
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_log import log as logging
from oslo_utils import uuidutils

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import nsxv_db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.nsx_v import availability_zones as nsx_az
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions

LOG = logging.getLogger(__name__)


class NsxvL2GatewayDriver(l2gateway_db.L2GatewayMixin):

    """Class to handle API calls for L2 gateway and NSXv backend."""

    def __init__(self, plugin):
        super(NsxvL2GatewayDriver, self).__init__()
        self._plugin = plugin
        self.__core_plugin = None

    @property
    def _core_plugin(self):
        if not self.__core_plugin:
            self.__core_plugin = directory.get_plugin()
            if self.__core_plugin.is_tvd_plugin():
                self.__core_plugin = self.__core_plugin.get_plugin_by_type(
                    projectpluginmap.NsxPlugins.NSX_V)
        return self.__core_plugin

    @property
    def _nsxv(self):
        return self._core_plugin.nsx_v

    @property
    def _edge_manager(self):
        return self._core_plugin.edge_manager

    def _validate_device_list(self, devices):
        # In NSX-v, one L2 gateway is mapped to one DLR.
        # So we expect only one device to be configured as part of
        # a L2 gateway resource.
        if len(devices) != 1:
            msg = _("Only a single device is supported for one L2 gateway")
            raise n_exc.InvalidInput(error_message=msg)

    def _get_l2gateway_interface(self, context, interface_name):
        """Get all l2gateway_interfaces_by interface_name."""
        session = context.session
        with session.begin():
            return session.query(models.L2GatewayInterface).filter_by(
                interface_name=interface_name).all()

    def _validate_interface_list(self, context, interfaces):
        # In NSXv, interface is mapped to a vDS VLAN port group.
        # Since HA is not supported, only one interface is expected
        if len(interfaces) != 1:
            msg = _("Only a single interface is supported for one L2 gateway")
            raise n_exc.InvalidInput(error_message=msg)
        if not self._nsxv.vcns.validate_network(interfaces[0]['name']):
            msg = _("Configured interface not found")
            raise n_exc.InvalidInput(error_message=msg)
        interface = self._get_l2gateway_interface(context,
                                                  interfaces[0]['name'])
        if interface:
            msg = _("%s is already used.") % interfaces[0]['name']
            raise n_exc.InvalidInput(error_message=msg)

    def create_l2_gateway_precommit(self, context, l2_gateway):
        pass

    def create_l2_gateway_postcommit(self, context, l2_gateway):
        pass

    def create_l2_gateway(self, context, l2_gateway):
        """Create a logical L2 gateway."""
        self._admin_check(context, 'CREATE')
        gw = l2_gateway[self.gateway_resource]
        devices = gw['devices']
        self._validate_device_list(devices)
        interfaces = devices[0]['interfaces']
        self._validate_interface_list(context, interfaces)
        # Create a dedicated DLR
        try:
            edge_id = self._create_l2_gateway_edge(context)
        except nsx_exc.NsxL2GWDeviceNotFound:
            LOG.exception("Failed to create backend device "
                          "for L2 gateway")
            raise

        devices[0]['device_name'] = edge_id
        l2_gateway[self.gateway_resource]['devices'] = devices
        return

    def update_l2_gateway_precommit(self, context, l2_gateway):
        pass

    def update_l2_gateway_postcommit(self, context, l2_gateway):
        pass

    def _create_l2_gateway_edge(self, context):
        # Create a dedicated DLR
        lrouter = {'name': nsxv_constants.L2_GATEWAY_EDGE,
                   'id': uuidutils.generate_uuid()}
        # Create the router on the default availability zone
        availability_zone = (nsx_az.NsxVAvailabilityZones().
            get_default_availability_zone())
        self._edge_manager.create_lrouter(context,
                                          lrouter, lswitch=None, dist=True,
                                          availability_zone=availability_zone)
        edge_binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                       lrouter['id'])
        if not edge_binding:
            raise nsx_exc.NsxL2GWDeviceNotFound()
        # Enable edge HA on the DLR
        if availability_zone.edge_ha:
            edge_id = edge_binding['edge_id']
            self._edge_manager.nsxv_manager.update_edge_ha(edge_id)
        return edge_binding['edge_id']

    def _get_device(self, context, l2gw_id):
        devices = self._get_l2_gateway_devices(context, l2gw_id)
        return devices[0]

    def create_l2_gateway_connection_precommit(self, contex, gw_connection):
        pass

    def create_l2_gateway_connection_postcommit(self, context, gw_connection):
        network_id = gw_connection.get('network_id')
        virtual_wire = nsx_db.get_nsx_switch_ids(context.session, network_id)

        # In NSX-v, there will be only one device configured per L2 gateway.
        # The name of the device shall carry the backend DLR.
        l2gw_id = gw_connection.get(l2gw_const.L2GATEWAY_ID)
        device = self._get_device(context, l2gw_id)
        device_name = device.get('device_name')
        device_id = device.get('id')
        interface = self._get_l2_gw_interfaces(context, device_id)
        interface_name = interface[0].get("interface_name")
        # bridge name length cannot exceed 40 characters
        bridge_name = "brg-" + uuidutils.generate_uuid()
        bridge_dict = {"bridges":
                       {"bridge":
                        {"name": bridge_name,
                         "virtualWire": virtual_wire[0],
                         "dvportGroup": interface_name}}}
        try:
            self._nsxv.create_bridge(device_name, bridge_dict)
        except exceptions.VcnsApiException:
            LOG.exception("Failed to update NSX, "
                          "rolling back changes on neutron.")
            raise l2gw_exc.L2GatewayServiceDriverError(
                method='create_l2_gateway_connection_postcommit')
        return

    def create_l2_gateway_connection(self, context, l2_gateway_connection):
        """Create a L2 gateway connection."""
        gw_connection = l2_gateway_connection.get(l2gw_const.
                                                  CONNECTION_RESOURCE_NAME)
        l2gw_id = gw_connection.get(l2gw_const.L2GATEWAY_ID)
        gw_db = self._get_l2_gateway(context, l2gw_id)
        if gw_db.network_connections:
            raise nsx_exc.NsxL2GWInUse(gateway_id=l2gw_id)
        return

    def delete_l2_gateway_connection_precommit(self, context,
                                               l2_gateway_connection):
        pass

    def delete_l2_gateway_connection_postcommit(self, context,
                                                l2_gateway_connection):
        pass

    def delete_l2_gateway_connection(self, context, l2_gateway_connection):
        """Delete a L2 gateway connection."""
        self._admin_check(context, 'DELETE')
        gw_connection = self.get_l2_gateway_connection(context,
                                                       l2_gateway_connection)
        if not gw_connection:
            raise l2gw_exc.L2GatewayConnectionNotFound(
                l2_gateway_connection)
        l2gw_id = gw_connection.get(l2gw_const.L2GATEWAY_ID)
        device = self._get_device(context, l2gw_id)
        device_name = device.get('device_name')
        self._nsxv.delete_bridge(device_name)

    def delete_l2_gateway(self, context, l2_gateway):
        """Delete a L2 gateway."""
        self._admin_check(context, 'DELETE')
        device = self._get_device(context, l2_gateway)
        edge_id = device.get('device_name')
        rtr_binding = nsxv_db.get_nsxv_router_binding_by_edge(
                        context.session, edge_id)
        if rtr_binding:
            self._edge_manager.delete_lrouter(context,
                                              rtr_binding['router_id'])

    def delete_l2_gateway_precommit(self, context, l2_gateway):
        pass

    def delete_l2_gateway_postcommit(self, context, l2_gateway):
        pass

    def add_port_mac(self, context, port_dict):
        """Process a created Neutron port."""
        pass

    def delete_port_mac(self, context, port):
        """Process a deleted Neutron port."""
        pass
