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

"""Fix NSX Lbaas L7 policy table creation

Revision ID: 7c4704ad37df
Revises: e4c503f4133f
Create Date: 2017-02-22 10:10:59.990122

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

# revision identifiers, used by Alembic.
revision = '7c4704ad37df'
down_revision = 'e4c503f4133f'


def upgrade():
    # On a previous upgrade this table was created conditionally.
    # It should always be created, and just the ForeignKeyConstraint
    # should be conditional
    if not migration.schema_has_table('nsxv_lbaas_l7policy_bindings'):
        op.create_table(
            'nsxv_lbaas_l7policy_bindings',
            sa.Column('policy_id', sa.String(length=36), nullable=False),
            sa.Column('edge_id', sa.String(length=36), nullable=False),
            sa.Column('edge_app_rule_id',
                      sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.Column('updated_at', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('policy_id'))

        if migration.schema_has_table('lbaas_l7policies'):
            op.create_foreign_key(
                'fk_lbaas_l7policies_id', 'nsxv_lbaas_l7policy_bindings',
                'lbaas_l7policies', ['policy_id'], ['id'], ondelete='CASCADE')
