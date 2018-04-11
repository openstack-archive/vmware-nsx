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

"""NSX Adds a 'availability_zone' attribute to internal-networks table

Revision ID: 14a89ddf96e2
Revises: 5c8f451290b7
Create Date: 2017-02-05 14:34:21.163418

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import reflection

from neutron.db import migration

# revision identifiers, used by Alembic.
revision = '14a89ddf96e2'
down_revision = '5c8f451290b7'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.OCATA]


def upgrade():
    table_name = 'nsxv_internal_networks'
    # Add the new column
    op.add_column(table_name, sa.Column(
        'availability_zone', sa.String(36), server_default='default'))
    # replace the old primary key constraint with a new one for both
    # purpose & az
    inspector = reflection.Inspector.from_engine(op.get_bind())
    pk_constraint = inspector.get_pk_constraint(table_name)
    op.drop_constraint(pk_constraint.get('name'), table_name, type_='primary')
    op.create_primary_key(None, table_name,
                          ['network_purpose', 'availability_zone'])
