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
from networking_l2gw.services.l2gateway.common import constants as l2gw_const
from networking_l2gw.services.l2gateway import exceptions as l2gw_exc
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils

from neutron.plugins.common import utils as n_utils
from neutron_lib.api.definitions import provider_net as providernet
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory

from vmware_nsx._i18n import _
from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.db import db as nsx_db
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import nsx_constants

LOG = logging.getLogger(__name__)


class NsxV3Driver(l2gateway_db.L2GatewayMixin):

    """Class to handle API calls for L2 gateway and NSXv3 backend."""
    gateway_resource = l2gw_const.GATEWAY_RESOURCE_NAME

    def __init__(self, plugin):
        # Create a default L2 gateway if default_bridge_cluster is
        # provided in nsx.ini
        super(NsxV3Driver, self).__init__()
        self._plugin = plugin
        LOG.debug("Starting service plugin for NSX L2Gateway")
        self.subscribe_callback_notifications()
        LOG.debug("Initialization complete for NSXv3 driver for "
                  "L2 gateway service plugin.")

    @property
    def _core_plugin(self):
        return directory.get_plugin()

    def subscribe_callback_notifications(self):
        registry.subscribe(self._prevent_l2gw_port_delete, resources.PORT,
                           events.BEFORE_DELETE)
        registry.subscribe(self._ensure_default_l2_gateway, resources.PROCESS,
                           events.BEFORE_SPAWN)

    def _ensure_default_l2_gateway(self, resource, event, trigger, **kwargs):
        """
        Create a default logical L2 gateway.

        Create a logical L2 gateway in the neutron database if the
        default_bridge_cluster config parameter is set and if it is
        not previously created. If not set, return.
        """
        def_l2gw_name = cfg.CONF.nsx_v3.default_bridge_cluster
        # Return if no default_bridge_cluster set in config
        if not def_l2gw_name:
            LOG.info("NSX: Default bridge cluster not configured "
                     "in nsx.ini. No default L2 gateway created.")
            return
        admin_ctx = context.get_admin_context()

        def_l2gw_uuid = (
            self._core_plugin.nsxlib.bridge_cluster.get_id_by_name_or_id(
                def_l2gw_name))

        # Optimistically create the default L2 gateway in neutron DB
        device = {'device_name': def_l2gw_uuid,
                  'interfaces': [{'name': 'default-bridge-cluster'}]}
        def_l2gw = {'name': 'default-l2gw',
                    'devices': [device]}
        l2gw_dict = {self.gateway_resource: def_l2gw}
        self.create_l2_gateway(admin_ctx, l2gw_dict)
        l2_gateway = super(NsxV3Driver, self).create_l2_gateway(admin_ctx,
                                                                l2gw_dict)
        # Verify that only one default L2 gateway is created
        def_l2gw_exists = False
        l2gateways = self._get_l2_gateways(admin_ctx)
        for l2gateway in l2gateways:
            # Since we ensure L2 gateway is created with only 1 device, we use
            # the first device in the list.
            if l2gateway['devices'][0]['device_name'] == def_l2gw_uuid:
                if def_l2gw_exists:
                    LOG.info("Default L2 gateway is already created.")
                    try:
                        # Try deleting this duplicate default L2 gateway
                        self.validate_l2_gateway_for_delete(
                            admin_ctx, l2gateway['id'])
                        super(NsxV3Driver, self).delete_l2_gateway(
                            admin_ctx, l2gateway['id'])
                    except l2gw_exc.L2GatewayInUse:
                        # If the L2 gateway we are trying to delete is in
                        # use then we should delete the L2 gateway which
                        # we just created ensuring there is only one
                        # default L2 gateway in the database.
                        super(NsxV3Driver, self).delete_l2_gateway(
                            admin_ctx, l2_gateway['id'])
                else:
                    def_l2gw_exists = True
        return l2_gateway

    def _prevent_l2gw_port_delete(self, resource, event, trigger, **kwargs):
        context = kwargs.get('context')
        port_id = kwargs.get('port_id')
        port_check = kwargs.get('port_check')
        if port_check:
            self.prevent_l2gw_port_deletion(context, port_id)

    def _validate_device_list(self, devices):
        # In NSXv3, one L2 gateway is mapped to one bridge cluster.
        # So we expect only one device to be configured as part of
        # a L2 gateway resource. The name of the device must be the bridge
        # cluster's UUID.
        if len(devices) != 1:
            msg = _("Only a single device is supported for one L2 gateway")
            raise n_exc.InvalidInput(error_message=msg)
        if not uuidutils.is_uuid_like(devices[0]['device_name']):
            msg = _("Device name must be configured with a UUID")
            raise n_exc.InvalidInput(error_message=msg)
        # Make sure the L2GW device ID exists as Bridge Cluster on NSX.
        try:
            self._core_plugin.nsxlib.bridge_cluster.get(
                devices[0]['device_name'])
        except nsxlib_exc.ResourceNotFound:
            msg = _("Could not find Bridge Cluster for L2 gateway device "
                    "%s on NSX backend") % devices[0]['device_name']
            LOG.error(msg)
            raise n_exc.InvalidInput(error_message=msg)
        # One L2 gateway must have only one interface defined.
        interfaces = devices[0].get(l2gw_const.IFACE_NAME_ATTR)
        if len(interfaces) > 1:
            msg = _("Maximum of one interface is supported for one L2 gateway")
            raise n_exc.InvalidInput(error_message=msg)

    def create_l2_gateway(self, context, l2_gateway):
        """Create a logical L2 gateway."""
        gw = l2_gateway[self.gateway_resource]
        devices = gw['devices']
        self._validate_device_list(devices)

    def create_l2_gateway_precommit(self, context, l2_gateway):
        pass

    def create_l2_gateway_postcommit(self, context, l2_gateway):
        pass

    def update_l2_gateway_precommit(self, context, l2_gateway):
        pass

    def update_l2_gateway_postcommit(self, context, l2_gateway):
        pass

    def delete_l2_gateway(self, context, l2_gateway_id):
        pass

    def delete_l2_gateway_precommit(self, context, l2_gateway_id):
        pass

    def delete_l2_gateway_postcommit(self, context, l2_gateway_id):
        pass

    def _validate_network(self, context, network_id):
        network = self._core_plugin.get_network(context, network_id)
        network_type = network.get(providernet.NETWORK_TYPE)
        # If network is a provider network, verify whether it is of type VXLAN
        if network_type and network_type != nsx_utils.NsxV3NetworkTypes.VXLAN:
            msg = (_("Unsupported network type %s for L2 gateway "
                     "connection. Only VXLAN network type supported") %
                   network_type)
            raise n_exc.InvalidInput(error_message=msg)

    def _validate_segment_id(self, seg_id):
        if not seg_id:
            raise l2gw_exc.L2GatewaySegmentationRequired
        return n_utils.is_valid_vlan_tag(seg_id)

    def create_l2_gateway_connection(self, context, l2_gateway_connection):
        gw_connection = l2_gateway_connection.get(self.connection_resource)
        network_id = gw_connection.get(l2gw_const.NETWORK_ID)
        self._validate_network(context, network_id)

    def create_l2_gateway_connection_precommit(self, context, gw_connection):
        pass

    def create_l2_gateway_connection_postcommit(self, context, gw_connection):
        """Create a L2 gateway connection."""
        l2gw_id = gw_connection.get(l2gw_const.L2GATEWAY_ID)
        network_id = gw_connection.get(l2gw_const.NETWORK_ID)
        devices = self._get_l2_gateway_devices(context, l2gw_id)
        # In NSXv3, there will be only one device configured per L2 gateway.
        # The name of the device shall carry the backend bridge cluster's UUID.
        device_name = devices[0].get('device_name')
        # The seg-id will be provided either during gateway create or gateway
        # connection create. l2gateway_db_mixin makes sure that it is
        # configured one way or the other.
        seg_id = gw_connection.get(l2gw_const.SEG_ID)
        if not seg_id:
            # Seg-id was not passed as part of connection-create. Retrieve
            # seg-id from L2 gateway's interface.
            interface = self._get_l2_gw_interfaces(context, devices[0]['id'])
            seg_id = interface[0].get(l2gw_const.SEG_ID)
        self._validate_segment_id(seg_id)
        tenant_id = gw_connection['tenant_id']
        if context.is_admin and not tenant_id:
            tenant_id = context.tenant_id
            gw_connection['tenant_id'] = tenant_id
        try:
            tags = self._core_plugin.nsxlib.build_v3_tags_payload(
                gw_connection, resource_type='os-neutron-l2gw-id',
                project_name=context.tenant_name)
            bridge_endpoint = self._core_plugin.nsxlib.bridge_endpoint.create(
                device_name=device_name,
                seg_id=seg_id,
                tags=tags)
        except nsxlib_exc.ManagerError as e:
            LOG.exception("Unable to create bridge endpoint, rolling back "
                          "changes on neutron. Exception is %s", e)
            raise l2gw_exc.L2GatewayServiceDriverError(
                method='create_l2_gateway_connection_postcommit')
        #TODO(abhiraut): Consider specifying the name of the port
        # Create a logical port and connect it to the bridge endpoint.
        port_dict = {'port': {
                        'tenant_id': tenant_id,
                        'network_id': network_id,
                        'mac_address': constants.ATTR_NOT_SPECIFIED,
                        'admin_state_up': True,
                        'fixed_ips': [],
                        'device_id': bridge_endpoint['id'],
                        'device_owner': nsx_constants.BRIDGE_ENDPOINT,
                        'name': '', }}
        try:
            #TODO(abhiraut): Consider adding UT for port check once UTs are
            #                refactored
            port = self._core_plugin.create_port(context, port_dict,
                                                 l2gw_port_check=True)
            # Deallocate IP address from the port.
            for fixed_ip in port.get('fixed_ips', []):
                self._core_plugin._delete_ip_allocation(context, network_id,
                                                        fixed_ip['subnet_id'],
                                                        fixed_ip['ip_address'])
            LOG.debug("IP addresses deallocated on port %s", port['id'])
        except (nsxlib_exc.ManagerError,
                n_exc.NeutronException):
            LOG.exception("Unable to create L2 gateway port, "
                          "rolling back changes on neutron")
            self._core_plugin.nsxlib.bridge_endpoint.delete(
                bridge_endpoint['id'])
            raise l2gw_exc.L2GatewayServiceDriverError(
                method='create_l2_gateway_connection_postcommit')
        try:
            # Update neutron's database with the mappings.
            nsx_db.add_l2gw_connection_mapping(
                session=context.session,
                connection_id=gw_connection['id'],
                bridge_endpoint_id=bridge_endpoint['id'],
                port_id=port['id'])
        except db_exc.DBError:
            with excutils.save_and_reraise_exception():
                LOG.exception("Unable to add L2 gateway connection "
                              "mappings, rolling back changes on neutron")
                self._core_plugin.nsxlib.bridge_endpoint.delete(
                    bridge_endpoint['id'])
                super(NsxV3Driver,
                      self).delete_l2_gateway_connection(
                          context,
                          gw_connection['id'])
        return gw_connection

    def delete_l2_gateway_connection(self, context, gw_connection):
        pass

    def delete_l2_gateway_connection_precommit(self, context, gw_connection):
        pass

    def delete_l2_gateway_connection_postcommit(self, context, gw_connection):
        """Delete a L2 gateway connection."""
        conn_mapping = nsx_db.get_l2gw_connection_mapping(
            session=context.session,
            connection_id=gw_connection)
        bridge_endpoint_id = conn_mapping.get('bridge_endpoint_id')
        # Delete the logical port from the bridge endpoint.
        self._core_plugin.delete_port(context=context,
                                      port_id=conn_mapping.get('port_id'),
                                      l2gw_port_check=False)
        try:
            self._core_plugin.nsxlib.bridge_endpoint.delete(bridge_endpoint_id)
        except nsxlib_exc.ManagerError as e:
            LOG.exception("Unable to delete bridge endpoint %(id)s on the "
                          "backend due to exc: %(exc)s",
                          {'id': bridge_endpoint_id, 'exc': e})
            raise l2gw_exc.L2GatewayServiceDriverError(
                method='delete_l2_gateway_connection_postcommit')

    def prevent_l2gw_port_deletion(self, context, port_id):
        """Prevent core plugin from deleting L2 gateway port."""
        try:
            port = self._core_plugin.get_port(context, port_id)
        except n_exc.PortNotFound:
            return
        if port['device_owner'] == nsx_constants.BRIDGE_ENDPOINT:
            reason = _("has device owner %s") % port['device_owner']
            raise n_exc.ServicePortInUse(port_id=port_id, reason=reason)

    def add_port_mac(self, context, port_dict):
        """Process a created Neutron port."""
        pass

    def delete_port_mac(self, context, port):
        """Process a deleted Neutron port."""
        pass
