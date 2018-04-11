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

"""NSX Adds certificate table for client certificate management

Revision ID: dd9fe5a3a526
Revises: e816d4fe9d4f
Create Date: 2017-01-06 12:30:01.070022

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'dd9fe5a3a526'
down_revision = 'e816d4fe9d4f'


def upgrade():

    op.create_table('nsx_certificates',
        sa.Column('purpose', sa.String(length=32), nullable=False),
        sa.Column('certificate', sa.String(length=9216), nullable=False),
        sa.Column('private_key', sa.String(length=5120), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('purpose'))
