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

"""NSX Adds a 'policy' attribute to security-group

Revision ID: e816d4fe9d4f
Revises: 7b5ec3caa9a4
Create Date: 2016-10-06 11:30:31.263918

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e816d4fe9d4f'
down_revision = '7b5ec3caa9a4'


def upgrade():
    op.add_column('nsx_extended_security_group_properties',
                  sa.Column('policy', sa.String(36)))
