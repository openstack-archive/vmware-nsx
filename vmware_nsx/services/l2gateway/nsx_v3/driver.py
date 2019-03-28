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

from neutron_lib.api.definitions import provider_net as providernet
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as plugin_utils

from vmware_nsx._i18n import _
from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import utils as nsxlib_utils


LOG = logging.getLogger(__name__)


class _NotUniqueL2GW(Exception):
    """Raised if validation of default L2 GW uniqueness fails."""


class NsxV3Driver(l2gateway_db.L2GatewayMixin):

    """Class to handle API calls for L2 gateway and NSXv3 backend."""
    gateway_resource = l2gw_const.GATEWAY_RESOURCE_NAME

    def __init__(self, plugin):
        super(NsxV3Driver, self).__init__()
        self._plugin = plugin
        LOG.debug("Starting service plugin for NSX L2Gateway")
        self.subscribe_callback_notifications()
        LOG.debug("Initialization complete for NSXv3 driver for "
                  "L2 gateway service plugin.")
        self.__core_plugin = None

    @property
    def _core_plugin(self):
        if not self.__core_plugin:
            self.__core_plugin = directory.get_plugin()
            if self.__core_plugin.is_tvd_plugin():
                self.__core_plugin = self.__core_plugin.get_plugin_by_type(
                    projectpluginmap.NsxPlugins.NSX_T)
        return self.__core_plugin

    def subscribe_callback_notifications(self):
        registry.subscribe(self._prevent_l2gw_port_delete, resources.PORT,
                           events.BEFORE_DELETE)
        registry.subscribe(self._ensure_default_l2_gateway, resources.PROCESS,
                           events.BEFORE_SPAWN)

    def _find_default_l2_gateway(self, admin_ctx, def_device_id):
        for l2gateway in self._get_l2_gateways(admin_ctx):
            if l2gateway['devices'][0]['device_name'] == def_device_id:
                return l2gateway

    @nsxlib_utils.retry_random_upon_exception(_NotUniqueL2GW, max_attempts=10)
    def _create_default_l2_gateway(self, admin_ctx, l2gw_dict, def_device_id):
        LOG.debug("Creating default layer-2 gateway with: %s", l2gw_dict)
        def_l2gw = super(NsxV3Driver, self).create_l2_gateway(admin_ctx,
                                                              l2gw_dict)
        # Verify that no other instance of neutron-server had the same
        # brilliant idea...
        l2gateways = self._get_l2_gateways(admin_ctx)
        for l2gateway in l2gateways:
            # Since we ensure L2 gateway is created with only 1 device, we use
            # the first device in the list.
            if l2gateway['devices'][0]['device_name'] == def_device_id:
                if l2gateway['id'] == def_l2gw['id']:
                    # Nothing to worry about, that's our gateway
                    continue
                LOG.info("Default L2 gateway is already created with "
                         "id %s, deleting L2 gateway with id %s",
                         l2gateway['id'], def_l2gw['id'])
                # Commit suicide!
                self.validate_l2_gateway_for_delete(
                     admin_ctx, def_l2gw)
                # We can be sure the gateway is not in use...
                super(NsxV3Driver, self).delete_l2_gateway(
                    admin_ctx, def_l2gw['id'])
                # The operation should be retried to avoid the situation where
                # every instance deletes the gateway it created
                raise _NotUniqueL2GW

        return def_l2gw

    def _get_bridge_vlan_tz_id(self, bep_data):
        nsxlib = self._core_plugin.nsxlib
        # Edge cluster Id is mandatory, do not fear KeyError
        edge_cluster_id = bep_data['edge_cluster_id']
        member_indexes = bep_data.get('edge_cluster_member_indexes', [])
        # NSX should not allow bridge endpoint profiles attached to
        # non-existing edge clusters
        edge_cluster = nsxlib.edge_cluster.get(edge_cluster_id)
        member_map = dict((member['member_index'],
                           member['transport_node_id'])
                          for member in edge_cluster['members'])
        # By default consider all transport nodes in the cluster for
        # retrieving the VLAN transprtzone
        tn_ids = member_map.values()
        if member_indexes:
            try:
                tn_ids = [member_map[idx] for idx in member_indexes]
            except KeyError:
                LOG.warning("Invalid member indexes specified in bridge "
                            "endpoint profile: %(bep_id)s: %(indexes)s",
                            {'bep_id': bep_data['id'],
                             'indexes': member_indexes})

        # Retrieve VLAN transport zones
        vlan_transport_zones = nsxlib.search_all_resource_by_attributes(
                nsxlib.transport_zone.resource_type,
                transport_type='VLAN')
        vlan_tz_map = dict((vlan_tz['id'], [])
                           for vlan_tz in vlan_transport_zones)
        for tn_id in tn_ids:
            tn_data = nsxlib.transport_node.get(tn_id)
            for tz_endpoint in tn_data.get('transport_zone_endpoints', []):
                tz_id = tz_endpoint['transport_zone_id']
                if tz_id in vlan_tz_map:
                    vlan_tz_map[tz_id].append(tn_id)

        # Find the VLAN transport zone that is used by all transport nodes
        results = []
        for (tz_id, nodes) in vlan_tz_map.items():
            if set(nodes) != set(tn_ids):
                continue
            results.append(tz_id)

        return results

    def _ensure_default_l2_gateway(self, resource, event,
                                   trigger, payload=None):
        """
        Create a default logical L2 gateway.

        Create a logical L2 gateway in the neutron database for the
        default bridge endpoint profile, if specified in the configuration.
        Ensure only one gateway is configured in presence of multiple
        neutron servers.
        """
        if cfg.CONF.nsx_v3.default_bridge_cluster:
            LOG.warning("Attention! The default_bridge_cluster option is "
                        "still set to %s. This option won't have any effect "
                        "as L2 gateways based on bridge clusters are not "
                        "implemented anymore",
                        cfg.CONF.nsx_v3.default_bridge_cluster)
        def_bep = cfg.CONF.nsx_v3.default_bridge_endpoint_profile
        # Return if no default_endpoint_profile set in config
        if not def_bep:
            LOG.info("NSX Default bridge endpoint profile not set. "
                     "Default L2 gateway will not be processed.")
            return
        admin_ctx = context.get_admin_context()
        nsx_bep_client = self._core_plugin.nsxlib.bridge_endpoint_profile
        bep_id = nsx_bep_client.get_id_by_name_or_id(def_bep)
        def_l2gw = self._find_default_l2_gateway(admin_ctx, bep_id)
        # If there is already an existing gateway, use that one
        if def_l2gw:
            LOG.info("A default L2 gateway for bridge endpoint profile "
                     "%(bep_id)s already exists. Reusing L2 gateway "
                     "%(def_l2gw_id)s)",
                     {'bep_id': bep_id, 'def_l2gw_id': def_l2gw['id']})
            return def_l2gw
        bep_data = nsx_bep_client.get(bep_id)
        vlan_tzs = self._get_bridge_vlan_tz_id(bep_data)
        if not vlan_tzs:
            LOG.info("No NSX VLAN transport zone could be used for bridge "
                     "endpoint profile: %s. Default L2 gateway will not "
                     "be processed", bep_id)
            return
        # TODO(salv-orlando): Implement support for multiple VLAN TZ
        vlan_tz = vlan_tzs[0]
        if len(vlan_tzs) > 1:
            LOG.info("The NSX L2 gateway driver currenly supports a single "
                     "VLAN transport zone for bridging, but %(num_tz)d "
                     "were specified. Transport zone %(tz)s will be used "
                     "for L2 gateways",
                     {'num_tz': len(vlan_tzs), 'tz': vlan_tz})
        device = {'device_name': bep_id,
                  'interfaces': [{'name': vlan_tz}]}
        # TODO(asarfaty): Add a default v3 tenant-id to allow TVD filtering
        l2gw_dict = {self.gateway_resource: {
            'name': 'default-nsxedge-l2gw',
            'devices': [device]}}
        self._create_default_l2_gateway(admin_ctx, l2gw_dict, bep_id)
        return def_l2gw

    def _prevent_l2gw_port_delete(self, resource, event,
                                  trigger, payload=None):
        context = payload.context
        port_id = payload.resource_id
        port_check = payload.metadata['port_check']
        if port_check:
            self.prevent_l2gw_port_deletion(context, port_id)

    def _validate_device_list(self, devices, check_backend=True):
        # In NSXv3, one L2 gateway is mapped to one bridge endpoint profle.
        # So we expect only one device to be configured as part of
        # a L2 gateway resource. The name of the device must be the bridge
        # endpoint profile UUID.
        if len(devices) != 1:
            msg = _("Only a single device is supported by the NSX L2"
                    "gateway driver")
            raise n_exc.InvalidInput(error_message=msg)
        dev_name = devices[0]['device_name']
        if not uuidutils.is_uuid_like(dev_name):
            msg = _("Device name must be configured with a UUID")
            raise n_exc.InvalidInput(error_message=msg)
        # Ensure the L2GW device is a valid bridge endpoint profile in NSX
        if check_backend:
            try:
                self._core_plugin.nsxlib.bridge_endpoint_profile.get(
                    dev_name)
            except nsxlib_exc.ResourceNotFound:
                msg = _("Could not find Bridge Endpoint Profile for L2 "
                        "gateway device %s on NSX backend") % dev_name
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)
        # One L2 gateway must have only one interface defined.
        interfaces = devices[0].get(l2gw_const.IFACE_NAME_ATTR)
        if len(interfaces) > 1:
            msg = _("Maximum of one interface is supported by the NSX L2 "
                    "gateway driver")
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
        # If network is a provider network, verify whether it is of type GENEVE
        if network_type and network_type != nsx_utils.NsxV3NetworkTypes.GENEVE:
            msg = (_("Unsupported network type %s for L2 gateway connection") %
                   network_type)
            raise n_exc.InvalidInput(error_message=msg)

    def _validate_segment_id(self, seg_id):
        if not seg_id:
            raise l2gw_exc.L2GatewaySegmentationRequired
        return plugin_utils.is_valid_vlan_tag(seg_id)

    def create_l2_gateway_connection(self, context, l2_gateway_connection):
        gw_connection = l2_gateway_connection.get(self.connection_resource)
        network_id = gw_connection.get(l2gw_const.NETWORK_ID)
        self._validate_network(context, network_id)

    def _get_bep(self, context, l2gw_id):
        # In NSXv3, there will be only one device configured per L2 gateway.
        # The name of the device shall carry the bridge endpoint profile id.
        devices = self._get_l2_gateway_devices(context, l2gw_id)
        return devices[0].get('device_name')

    def _get_conn_parameters(self, context, gw_connection):
        """Return interface and segmenantion id for a connection. """
        if not gw_connection:
            return
        l2gw_id = gw_connection.get(l2gw_const.L2GATEWAY_ID)
        seg_id = gw_connection.get(l2gw_const.SEG_ID)
        devices = self._get_l2_gateway_devices(context, l2gw_id)
        # TODO(salv-orlando): support more than a single interface
        interface = self._get_l2_gw_interfaces(context, devices[0]['id'])[0]
        if not seg_id:
            # Seg-id was not passed as part of connection-create. Retrieve
            # seg-id from L2 gateway's interface.
            seg_id = interface.get('segmentation_id')
        return interface['interface_name'], seg_id

    def create_l2_gateway_connection_precommit(self, context, gw_connection):
        """Validate the L2 gateway connection
        Do not allow another connection with the same bride cluster and seg_id
        """
        admin_ctx = context.elevated()
        nsxlib = self._core_plugin.nsxlib
        l2gw_id = gw_connection.get(l2gw_const.L2GATEWAY_ID)
        devices = self._get_l2_gateway_devices(context, l2gw_id)
        bep_id = devices[0].get('device_name')
        # Check for bridge endpoint profile existence
        # if bridge endpoint profile is not found, this is likely an old
        # connection, fail with error.
        try:
            nsxlib.bridge_endpoint_profile.get_id_by_name_or_id(bep_id)
        except nsxlib_exc.ManagerError as e:
            msg = (_("Error while retrieving bridge endpoint profile "
                     "%(bep_id)s from NSX backend. Check that the profile "
                     "exits and there are not multiple profiles with "
                     "the given name. Exception: %(exc)s") %
                   {'bep_id': bep_id, 'exc': e})
            raise n_exc.InvalidInput(error_message=msg)

        interface_name, seg_id = self._get_conn_parameters(
            admin_ctx, gw_connection)
        try:
            # Use search API for listing bridge endpoints on NSX for provided
            # VLAN id, transport zone id, and Bridge endpoint profile
            endpoints = nsxlib.search_all_resource_by_attributes(
                nsxlib.bridge_endpoint.resource_type,
                bridge_endpoint_profile_id=bep_id,
                vlan_transport_zone_id=interface_name,
                vlan=seg_id)
            endpoint_map = dict((endpoint['id'],
                                 endpoint['bridge_endpoint_profile_id'])
                            for endpoint in endpoints)
        except nsxlib_exc.ManagerError as e:
            msg = (_("Error while retrieving endpoints for bridge endpoint "
                     "profile %(bep_id)s s from NSX backend. "
                     "Exception: %(exc)s") % {'bep_id': bep_id, 'exc': e})
            raise n_exc.InvalidInput(error_message=msg)

        # get all bridge endpoint ports
        with db_api.CONTEXT_WRITER.using(admin_ctx):
            port_filters = {'device_owner': [nsx_constants.BRIDGE_ENDPOINT]}
            ports = self._core_plugin.get_ports(
                admin_ctx, filters=port_filters)
            for port in ports:
                device_id = port.get('device_id')
                if endpoint_map.get(device_id) == bep_id:
                    # This device is using the same vlan id and bridge endpoint
                    # profile as the one requested. Not ok.
                    msg = (_("Cannot create multiple connections with the "
                             "same segmentation id %(seg_id)s for bridge "
                             "endpoint profile %(bep_id)s") %
                           {'seg_id': seg_id,
                            'bep_id': bep_id})
                    raise n_exc.InvalidInput(error_message=msg)

    def create_l2_gateway_connection_postcommit(self, context, gw_connection):
        """Create a L2 gateway connection on the backend"""
        nsxlib = self._core_plugin.nsxlib
        l2gw_id = gw_connection.get(l2gw_const.L2GATEWAY_ID)
        network_id = gw_connection.get(l2gw_const.NETWORK_ID)
        device_name = self._get_bep(context, l2gw_id)
        interface_name, seg_id = self._get_conn_parameters(
            context, gw_connection)
        self._validate_segment_id(seg_id)
        tenant_id = gw_connection['tenant_id']
        if context.is_admin and not tenant_id:
            tenant_id = context.tenant_id
            gw_connection['tenant_id'] = tenant_id
        try:
            tags = nsxlib.build_v3_tags_payload(
                gw_connection, resource_type='os-neutron-l2gw-id',
                project_name=context.tenant_name)
            bridge_endpoint = nsxlib.bridge_endpoint.create(
                device_name=device_name,
                vlan_transport_zone_id=interface_name,
                vlan_id=seg_id,
                tags=tags)
        except nsxlib_exc.ManagerError as e:
            LOG.exception("Unable to create bridge endpoint. "
                          "Exception is %s", e)
            raise l2gw_exc.L2GatewayServiceDriverError(
                method='create_l2_gateway_connection_postcommit')

        port_dict = {'port': {
                        'name': 'l2gw-conn-%s-%s' % (
                            l2gw_id, seg_id),
                        'tenant_id': tenant_id,
                        'network_id': network_id,
                        'mac_address': constants.ATTR_NOT_SPECIFIED,
                        'admin_state_up': True,
                        'fixed_ips': [],
                        'device_id': bridge_endpoint['id'],
                        'device_owner': nsx_constants.BRIDGE_ENDPOINT}}
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
                n_exc.NeutronException) as e:
            with excutils.save_and_reraise_exception():
                LOG.exception("Unable to create L2 gateway port, "
                              "rolling back changes on backend: %s", e)
                self._core_plugin.nsxlib.bridge_endpoint.delete(
                    bridge_endpoint['id'])
                super(NsxV3Driver,
                      self).delete_l2_gateway_connection(
                          context,
                          gw_connection['id'])

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
                              "mappings for %(conn_id)s on network "
                              "%(net_id)s. rolling back changes.",
                              {'conn_id': gw_connection['id'],
                               'net_id': network_id})
                self._core_plugin.nsxlib.bridge_endpoint.delete(
                    bridge_endpoint['id'])
                super(NsxV3Driver,
                      self).delete_l2_gateway_connection(
                          context,
                          gw_connection['id'])
        return gw_connection

    def delete_l2_gateway_connection_postcommit(self, context, gw_connection):
        pass

    def delete_l2_gateway_connection_precommit(self, context, gw_connection):
        pass

    def delete_l2_gateway_connection(self, context, gw_connection):
        """Delete a L2 gateway connection."""
        conn_mapping = nsx_db.get_l2gw_connection_mapping(
            session=context.session,
            connection_id=gw_connection)
        if not conn_mapping:
            LOG.error("Unable to delete gateway connection %(id)s: mapping "
                      "not found", {'id': gw_connection})
            # Do not block the deletion
            return
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
                method='delete_l2_gateway_connection')

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
