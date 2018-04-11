# Copyright 2017 VMware, Inc.
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

"""Port vnic_type support

Revision ID: e4c503f4133f
Revises: 01a33f93f5fd
Create Date: 2017-02-20 00:05:30.894680

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e4c503f4133f'
down_revision = '01a33f93f5fd'


def upgrade():
    op.create_table(
        'nsxv_port_ext_attributes',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('vnic_type', sa.String(length=64), nullable=False,
                  server_default='normal'),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'))
