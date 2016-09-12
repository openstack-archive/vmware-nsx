# Copyright 2013 VMware, Inc.
#
# All Rights Reserved.
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

from neutron_lib.db import model_base
import sqlalchemy as sa

from oslo_db.sqlalchemy import models


class VcnsRouterBinding(model_base.BASEV2, model_base.HasStatusDescription,
                        models.TimestampMixin):
    """Represents the mapping between neutron router and vShield Edge."""

    __tablename__ = 'vcns_router_bindings'

    # no ForeignKey to routers.id because for now, a router can be removed
    # from routers when delete_router is executed, but the binding is only
    # removed after the Edge is deleted
    router_id = sa.Column(sa.String(36),
                          primary_key=True)
    edge_id = sa.Column(sa.String(16),
                        nullable=True)
    lswitch_id = sa.Column(sa.String(36),
                           nullable=False)
