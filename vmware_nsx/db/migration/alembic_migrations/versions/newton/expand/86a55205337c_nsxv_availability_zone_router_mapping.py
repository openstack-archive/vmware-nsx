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

"""NSXv add availability zone to the router bindings table instead of
the resource pool column

Revision ID: 86a55205337c
Revises: 7e46906f8997
Create Date: 2016-07-12 09:18:44.450116
"""

from alembic import op
import sqlalchemy as sa

from vmware_nsx.common import config  # noqa

# revision identifiers, used by Alembic.
revision = '86a55205337c'
down_revision = '7e46906f8997'


def upgrade():
    op.alter_column('nsxv_router_bindings', 'resource_pool',
                    new_column_name='availability_zone',
                    existing_type=sa.String(36),
                    existing_nullable=True,
                    existing_server_default='default')
