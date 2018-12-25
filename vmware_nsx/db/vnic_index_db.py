# Copyright 2014 VMware, Inc.
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

from sqlalchemy.orm import exc

from neutron_lib.api.definitions import port as port_def
from neutron_lib.db import resource_extend

from oslo_db import exception as db_exc
from oslo_log import log as logging

from vmware_nsx.db import nsxv_models
from vmware_nsx.extensions import vnicindex as vnicidx

LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
class VnicIndexDbMixin(object):

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _extend_port_vnic_index_binding(port_res, port_db):
        state = port_db.vnic_index
        port_res[vnicidx.VNIC_INDEX] = state.index if state else None

    def _get_port_vnic_index(self, context, port_id):
        """Returns the vnic index for the given port.
        If the port is not associated with any vnic then return None
        """
        session = context.session
        try:
            mapping = (session.query(nsxv_models.NsxvPortIndexMapping).
                       filter_by(port_id=port_id).one())
            return mapping['index']
        except exc.NoResultFound:
            LOG.debug("No record in DB for vnic-index of port %s", port_id)

    def _get_mappings_for_device_id(self, context, device_id):
        session = context.session
        mappings = (session.query(nsxv_models.NsxvPortIndexMapping).
                    filter_by(device_id=device_id))
        return mappings

    def _create_port_vnic_index_mapping(self, context, port_id,
                                        device_id, index):
        """Save the port vnic-index to DB."""
        session = context.session
        with session.begin(subtransactions=True):
            index_mapping_model = nsxv_models.NsxvPortIndexMapping(
                port_id=port_id, device_id=device_id, index=index)
            session.add(index_mapping_model)

    def _update_port_vnic_index_mapping(self, context, port_id,
                                        device_id, index):
        session = context.session
        # delete original entry
        query = (session.query(nsxv_models.NsxvPortIndexMapping).
                 filter_by(device_id=device_id, index=index))
        query.delete()
        # create a new one
        self._create_port_vnic_index_mapping(context, port_id, device_id,
                                             index)

    def _set_port_vnic_index_mapping(self, context, port_id, device_id, index):
        """Save the port vnic-index to DB."""
        try:
            self._create_port_vnic_index_mapping(context, port_id,
                                                 device_id, index)
        except db_exc.DBDuplicateEntry:
            # A retry for the nova scheduling could result in this error.
            LOG.debug("Entry already exists for %s %s %s", port_id,
                      device_id, index)
            mappings = self._get_mappings_for_device_id(context, device_id)
            for mapping in mappings:
                if (mapping['port_id'] != port_id and
                    mapping['index'] == index):
                    # a new port is using this device - update!
                    self._update_port_vnic_index_mapping(context, port_id,
                                                         device_id, index)
                    return
                if (mapping['port_id'] == port_id and
                    mapping['index'] != index):
                    raise

    def _delete_port_vnic_index_mapping(self, context, port_id):
        """Delete the port vnic-index association."""
        session = context.session
        query = (session.query(nsxv_models.NsxvPortIndexMapping).
                 filter_by(port_id=port_id))
        query.delete()
