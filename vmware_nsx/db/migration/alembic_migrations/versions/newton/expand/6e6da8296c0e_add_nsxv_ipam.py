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

"""Add support for IPAM in NSXv

Revision ID: 6e6da8296c0e
Revises: 1b4eaffe4f31
Create Date: 2016-09-01 10:17:16.770021

"""

from alembic import op
import sqlalchemy as sa

revision = '6e6da8296c0e'
down_revision = '1b4eaffe4f31'


def upgrade():
    op.create_table(
        'nsxv_subnet_ipam',
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.Column('nsx_pool_id', sa.String(length=36), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('nsx_pool_id'),
    )
