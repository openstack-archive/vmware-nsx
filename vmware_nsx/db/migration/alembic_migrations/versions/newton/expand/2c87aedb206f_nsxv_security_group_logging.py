# Copyright 2016 OpenStack Foundation
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

"""nsxv_security_group_logging

Revision ID: 2c87aedb206f
Revises: 4c45bcadccf9
Create Date: 2016-03-15 06:06:06.680092

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '2c87aedb206f'
down_revision = '4c45bcadccf9'


def upgrade():
    op.add_column('nsxv_security_group_section_mappings',
                  sa.Column('logging', sa.Boolean(), nullable=False))
