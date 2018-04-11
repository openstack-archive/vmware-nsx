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

"""add dvs_id column to neutron_nsx_network_mappings

Revision ID: 967462f585e1
Revises: 3e4dccfe6fb4
Create Date: 2016-02-23 18:22:01.998540

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '967462f585e1'
down_revision = '3e4dccfe6fb4'


def upgrade():
    op.add_column('neutron_nsx_network_mappings',
                  sa.Column('dvs_id', sa.String(36), nullable=True))
