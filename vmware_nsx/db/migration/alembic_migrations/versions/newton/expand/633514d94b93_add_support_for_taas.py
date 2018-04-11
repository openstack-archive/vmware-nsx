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

"""Add support for TaaS

Revision ID: 633514d94b93
Revises: 86a55205337c
Create Date: 2016-05-09 14:11:31.940021

"""

from alembic import op
import sqlalchemy as sa

revision = '633514d94b93'
down_revision = '86a55205337c'


def upgrade():
    op.create_table(
        'nsx_port_mirror_session_mappings',
        sa.Column('tap_flow_id', sa.String(length=36), nullable=False),
        sa.Column('port_mirror_session_id', sa.String(length=36),
                  nullable=False),
        sa.PrimaryKeyConstraint('tap_flow_id'),
    )
