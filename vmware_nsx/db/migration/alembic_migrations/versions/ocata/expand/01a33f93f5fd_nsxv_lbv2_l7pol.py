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

"""nsxv_lbv2_l7policy

Revision ID: 01a33f93f5fd
Revises: dd9fe5a3a526
Create Date: 2017-01-04 10:10:59.990122

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

# revision identifiers, used by Alembic.
revision = '01a33f93f5fd'
down_revision = 'dd9fe5a3a526'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.OCATA]


def upgrade():
    if migration.schema_has_table('lbaas_l7policies'):
        op.create_table(
            'nsxv_lbaas_l7policy_bindings',
            sa.Column('policy_id', sa.String(length=36), nullable=False),
            sa.Column('edge_id', sa.String(length=36), nullable=False),
            sa.Column('edge_app_rule_id',
                      sa.String(length=36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.Column('updated_at', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('policy_id'),
            sa.ForeignKeyConstraint(['policy_id'],
                                    ['lbaas_l7policies.id'],
                                    ondelete='CASCADE'))
