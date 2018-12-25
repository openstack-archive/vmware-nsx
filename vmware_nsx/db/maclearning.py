# Copyright 2013 VMware, Inc.  All rights reserved.
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
#

from sqlalchemy.orm import exc

from neutron_lib.api.definitions import port as port_def
from neutron_lib.db import api as db_api
from neutron_lib.db import model_query
from neutron_lib.db import resource_extend
from neutron_lib.db import utils as db_utils

from oslo_log import log as logging

from vmware_nsx.db import nsx_models
from vmware_nsx.extensions import maclearning as mac

LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
class MacLearningDbMixin(object):
    """Mixin class for mac learning."""

    def _make_mac_learning_state_dict(self, port, fields=None):
        res = {'port_id': port['port_id'],
               mac.MAC_LEARNING: port[mac.MAC_LEARNING]}
        return db_utils.resource_fields(res, fields)

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _extend_port_mac_learning_state(port_res, port_db):
        state = port_db.mac_learning_state
        if state:
            port_res[mac.MAC_LEARNING] = state.mac_learning_enabled

    def _update_mac_learning_state(self, context, port_id, enabled):
        try:
            query = model_query.query_with_hooks(
                context, nsx_models.MacLearningState)
            state = query.filter(
                nsx_models.MacLearningState.port_id == port_id).one()
            state.update({mac.MAC_LEARNING: enabled})
        except exc.NoResultFound:
            self._create_mac_learning_state(context,
                                            {'id': port_id,
                                             mac.MAC_LEARNING: enabled})

    def _create_mac_learning_state(self, context, port):
        with db_api.CONTEXT_WRITER.using(context):
            enabled = port[mac.MAC_LEARNING]
            state = nsx_models.MacLearningState(
                port_id=port['id'],
                mac_learning_enabled=enabled)
            context.session.add(state)
        return self._make_mac_learning_state_dict(state)

    def get_mac_learning_state(self, context, port_id):
        try:
            query = model_query.query_with_hooks(
                context, nsx_models.MacLearningState)
            state = query.filter(
                nsx_models.MacLearningState.port_id == port_id).one()
            return state.mac_learning_enabled
        except exc.NoResultFound:
            return None
