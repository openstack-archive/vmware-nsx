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

"""Update the primary key constraint of nsx_subnet_ipam

Revision ID: 8c0a81a07691
Revises: 14a89ddf96e2
Create Date: 2017-02-15 15:25:21.163418

"""

from alembic import op
from sqlalchemy.engine import reflection

# revision identifiers, used by Alembic.
revision = '8c0a81a07691'
down_revision = '14a89ddf96e2'


def upgrade():
    table_name = 'nsx_subnet_ipam'
    # replace the old primary key constraint with a new one for both
    # subnet and nsx-pool
    inspector = reflection.Inspector.from_engine(op.get_bind())
    pk_constraint = inspector.get_pk_constraint(table_name)
    op.drop_constraint(pk_constraint.get('name'), table_name, type_='primary')
    op.create_primary_key(None, table_name,
                          ['subnet_id', 'nsx_pool_id'])
