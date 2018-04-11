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

Revision ID: 69fb78b33d41
Revises: 2af850eb3970
Create Date: 2016-01-27 07:28:35.369938

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '69fb78b33d41'
down_revision = '2af850eb3970'


def upgrade():
    op.create_table(
        'nsxv_subnet_ext_attributes',
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.Column('dns_search_domain', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['subnet_id'],
                                ['subnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('subnet_id')
    )
