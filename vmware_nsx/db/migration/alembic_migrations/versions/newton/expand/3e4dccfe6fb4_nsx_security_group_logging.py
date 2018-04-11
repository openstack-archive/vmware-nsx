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

"""NSXv add dns search domain to subnets

Revision ID: 3e4dccfe6fb4
Revises: 2c87aedb206f
Create Date: 2016-03-20 07:28:35.369938

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '3e4dccfe6fb4'
down_revision = '2c87aedb206f'


def upgrade():
    op.create_table(
        'nsx_extended_security_group_properties',
        sa.Column('security_group_id', sa.String(36), nullable=False),
        sa.Column('logging', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['security_group_id'],
                                ['securitygroups.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('security_group_id')
    )
