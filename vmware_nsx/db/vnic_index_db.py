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

from neutron.api.v2 import attributes as attr
from neutron.db import db_base_plugin_v2

from oslo_log import log as logging

from vmware_nsx.db import nsxv_models
from vmware_nsx.extensions import vnicindex as vnicidx

LOG = logging.getLogger(__name__)


class VnicIndexDbMixin(object):

    def _extend_port_vnic_index_binding(self, port_res, port_db):
        state = port_db.vnic_index
        port_res[vnicidx.VNIC_INDEX] = state.index if state else None

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attr.PORTS, ['_extend_port_vnic_index_binding'])

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

    def _set_port_vnic_index_mapping(self, context, port_id, device_id, index):
        """Save the port vnic-index to DB."""
        session = context.session
        with session.begin(subtransactions=True):
            index_mapping_model = nsxv_models.NsxvPortIndexMapping(
                port_id=port_id, device_id=device_id, index=index)
            session.add(index_mapping_model)

    def _delete_port_vnic_index_mapping(self, context, port_id):
        """Delete the port vnic-index association."""
        session = context.session
        query = (session.query(nsxv_models.NsxvPortIndexMapping).
                 filter_by(port_id=port_id))
        query.delete()
