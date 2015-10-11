# Copyright 2015 OpenStack Foundation
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

"""NSXv3 Add l2gwconnection table

Revision ID: 279b70ac3ae8
Revises: 28430956782d
Create Date: 2015-08-14 02:04:09.807926

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '279b70ac3ae8'
down_revision = '28430956782d'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.LIBERTY]


def upgrade():
    op.create_table(
        'nsx_l2gw_connection_mappings',
        sa.Column('connection_id', sa.String(length=36), nullable=False),
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('bridge_endpoint_id', sa.String(length=36),
                  nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('connection_id'),
    )
