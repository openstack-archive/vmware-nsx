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

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from neutron.services.trunk.drivers import base
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.services.trunk import constants as trunk_consts

from vmware_nsx.common import nsx_constants as nsx_consts
from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.db import db as nsx_db
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import nsx_constants

LOG = logging.getLogger(__name__)

SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_OVS,
)
SUPPORTED_SEGMENTATION_TYPES = (
    trunk_consts.SEGMENTATION_TYPE_VLAN,
)


class NsxV3TrunkHandler(object):
    """Class to handle trunk events."""

    def __init__(self, plugin_driver):
        self.plugin_driver = plugin_driver

    @property
    def _nsxlib(self):
        return self.plugin_driver.nsxlib

    def _build_switching_profile_ids(self, profiles):
        switching_profile = self._nsxlib.switching_profile
        return switching_profile.build_switch_profile_ids(
            switching_profile.client, *profiles)

    def _update_port_at_backend(self, context, parent_port_id, subport):
        # Retrieve the child port details
        child_port = self.plugin_driver.get_port(context, subport.port_id)
        # Retrieve the logical port ID based on the child port's neutron ID
        nsx_child_port_id = nsx_db.get_nsx_switch_and_port_id(
            session=context.session, neutron_id=subport.port_id)[1]
        # Retrieve child logical port from the backend
        try:
            nsx_child_port = self._nsxlib.logical_port.get(
                nsx_child_port_id)
        except nsxlib_exc.ResourceNotFound:
            with excutils.save_and_reraise_exception():
                LOG.error("Child port %s not found on the backend. "
                          "Setting trunk status to ERROR.",
                          nsx_child_port_id)
        # Build address bindings and switch profiles otherwise backend will
        # clear that information during port update
        address_bindings = self.plugin_driver._build_address_bindings(
            child_port)
        switching_profile_ids = self._build_switching_profile_ids(
            nsx_child_port.get('switching_profile_ids', []))
        seg_id = None
        tags_update = []
        attachment_type = nsx_constants.ATTACHMENT_VIF
        if parent_port_id:
            # Set properties for VLAN trunking
            if subport.segmentation_type == nsx_utils.NsxV3NetworkTypes.VLAN:
                seg_id = subport.segmentation_id
            tags_update.append({'scope': 'os-neutron-trunk-id',
                                'tag': subport.trunk_id})
            vif_type = nsx_constants.VIF_TYPE_CHILD
        else:
            # Unset the parent port properties from child port
            seg_id = None
            vif_type = None
            tags_update.append({'scope': 'os-neutron-trunk-id',
                                'tag': None})
        # Update logical port in the backend to set/unset parent port
        try:
            self._nsxlib.logical_port.update(
                lport_id=nsx_child_port.get('id'),
                vif_uuid=subport.port_id,
                name=nsx_child_port.get('display_name'),
                admin_state=nsx_child_port.get('admin_state'),
                address_bindings=address_bindings,
                switch_profile_ids=switching_profile_ids,
                attachment_type=attachment_type,
                parent_vif_id=parent_port_id,
                vif_type=vif_type,
                traffic_tag=seg_id,
                tags_update=tags_update)
        except nsxlib_exc.ManagerError as e:
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to update subport for attachment "
                          "type. Setting trunk status to ERROR. "
                          "Exception is %s", e)

    def _set_subports(self, context, parent_port_id, subports):
        for subport in subports:
            # Update port with parent port for backend.
            self._update_port_at_backend(context, parent_port_id, subport)

    def _unset_subports(self, context, subports):
        for subport in subports:
            # Update port and remove parent port attachment in the backend
            self._update_port_at_backend(
                context=context, parent_port_id=None, subport=subport)

    def trunk_created(self, context, trunk):
        # Retrieve the logical port ID based on the parent port's neutron ID
        nsx_parent_port_id = nsx_db.get_nsx_switch_and_port_id(
            session=context.session, neutron_id=trunk.port_id)[1]
        tags_update = [{'scope': 'os-neutron-trunk-id',
                        'tag': trunk.id}]
        self.plugin_driver.nsxlib.logical_port.update(
                nsx_parent_port_id,
                vif_uuid=trunk.port_id,
                vif_type=nsx_constants.VIF_TYPE_PARENT,
                tags_update=tags_update)
        try:
            if trunk.sub_ports:
                self._set_subports(context, trunk.port_id, trunk.sub_ports)
            trunk.update(status=trunk_consts.TRUNK_ACTIVE_STATUS)
        except (nsxlib_exc.ManagerError, nsxlib_exc.ResourceNotFound):
            trunk.update(status=trunk_consts.TRUNK_ERROR_STATUS)

    def trunk_deleted(self, context, trunk):
        # Retrieve the logical port ID based on the parent port's neutron ID
        nsx_parent_port_id = nsx_db.get_nsx_switch_and_port_id(
            session=context.session, neutron_id=trunk.port_id)[1]
        tags_update = [{'scope': 'os-neutron-trunk-id',
                        'tag': None}]
        self.plugin_driver.nsxlib.logical_port.update(
                nsx_parent_port_id,
                vif_uuid=trunk.port_id,
                vif_type=None,
                tags_update=tags_update)
        self._unset_subports(context, trunk.sub_ports)

    def subports_added(self, context, trunk, subports):
        try:
            self._set_subports(context, trunk.port_id, subports)
            trunk.update(status=trunk_consts.TRUNK_ACTIVE_STATUS)
        except (nsxlib_exc.ManagerError, nsxlib_exc.ResourceNotFound):
            trunk.update(status=trunk_consts.TRUNK_ERROR_STATUS)

    def subports_deleted(self, context, trunk, subports):
        try:
            self._unset_subports(context, subports)
        except (nsxlib_exc.ManagerError, nsxlib_exc.ResourceNotFound):
            trunk.update(status=trunk_consts.TRUNK_ERROR_STATUS)

    def trunk_event(self, resource, event, trunk_plugin, payload):
        if event == events.AFTER_CREATE:
            self.trunk_created(payload.context, payload.current_trunk)
        elif event == events.AFTER_DELETE:
            self.trunk_deleted(payload.context, payload.original_trunk)

    def subport_event(self, resource, event, trunk_plugin, payload):
        if event == events.AFTER_CREATE:
            self.subports_added(
                payload.context, payload.original_trunk, payload.subports)
        elif event == events.AFTER_DELETE:
            self.subports_deleted(
                payload.context, payload.original_trunk, payload.subports)


class NsxV3TrunkDriver(base.DriverBase):
    """Driver to implement neutron's trunk extensions."""

    @property
    def is_loaded(self):
        try:
            return nsx_consts.VMWARE_NSX_V3_PLUGIN_NAME == cfg.CONF.core_plugin
        except cfg.NoSuchOptError:
            return False

    @classmethod
    def create(cls, plugin_driver):
        cls.plugin_driver = plugin_driver
        return cls(nsx_consts.VMWARE_NSX_V3_PLUGIN_NAME, SUPPORTED_INTERFACES,
                   SUPPORTED_SEGMENTATION_TYPES,
                   agent_type=None, can_trunk_bound_port=True)

    @registry.receives(resources.TRUNK_PLUGIN, [events.AFTER_INIT])
    def register(self, resource, event, trigger, payload=None):
        super(NsxV3TrunkDriver, self).register(
            resource, event, trigger, payload=payload)
        self._handler = NsxV3TrunkHandler(self.plugin_driver)
        for event in (events.AFTER_CREATE, events.AFTER_DELETE):
            registry.subscribe(self._handler.trunk_event,
                               resources.TRUNK,
                               event)
            registry.subscribe(self._handler.subport_event,
                               resources.SUBPORTS,
                               event)
        LOG.debug("VMware NSXv3 trunk driver initialized.")
