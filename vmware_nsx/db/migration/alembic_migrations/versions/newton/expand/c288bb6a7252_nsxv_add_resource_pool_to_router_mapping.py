# Copyright 2016 VMware, Inc.
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

"""NSXv add resource pool to the router bindings table

Revision ID: c288bb6a7252
Revises: b7f41687cbad
Create Date: 2016-05-15 06:12:09.450116
"""

from alembic import op
from oslo_config import cfg
import sqlalchemy as sa

from vmware_nsx.common import config  # noqa

# revision identifiers, used by Alembic.
revision = 'c288bb6a7252'
down_revision = 'b7f41687cbad'


def upgrade():
    op.add_column('nsxv_router_bindings',
                  sa.Column('resource_pool', sa.String(36), nullable=True,
                            server_default=cfg.CONF.nsxv.resource_pool_id))
