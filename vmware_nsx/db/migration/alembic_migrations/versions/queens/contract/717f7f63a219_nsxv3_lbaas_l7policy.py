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

"""nsxv3_lbaas_l7policy

Revision ID: 717f7f63a219
Revises: a1be06050b41
Create Date: 2017-10-26 08:32:40.846088

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration

# revision identifiers, used by Alembic.
revision = '717f7f63a219'
down_revision = 'a1be06050b41'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.QUEENS, migration.ROCKY]


def upgrade():

    if migration.schema_has_table('nsxv3_lbaas_l7rules'):
        op.drop_constraint('fk_nsxv3_lbaas_l7rules_id', 'nsxv3_lbaas_l7rules',
                           'foreignkey')
        op.drop_constraint('l7rule_id', 'nsxv3_lbaas_l7rules', 'primary')
        op.drop_column('nsxv3_lbaas_l7rules', 'loadbalancer_id')
        op.drop_column('nsxv3_lbaas_l7rules', 'l7rule_id')
        op.rename_table('nsxv3_lbaas_l7rules', 'nsxv3_lbaas_l7policies')

        if migration.schema_has_table('lbaas_l7policies'):
            op.create_foreign_key(
                'fk_nsxv3_lbaas_l7policies_id', 'nsxv3_lbaas_l7policies',
                'lbaas_l7policies', ['l7policy_id'], ['id'],
                ondelete='CASCADE')
    else:
        op.create_table(
            'nsxv3_lbaas_l7policies',
            sa.Column('l7policy_id', sa.String(36), nullable=False),
            sa.Column('lb_rule_id', sa.String(36), nullable=False),
            sa.Column('lb_vs_id', sa.String(36), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.Column('updated_at', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('l7policy_id'))

        if migration.schema_has_table('lbaas_l7policies'):
            op.create_foreign_key(
                'fk_nsxv3_lbaas_l7policies_id', 'nsxv3_lbaas_l7policies',
                'lbaas_l7policies', ['l7policy_id'], ['id'],
                ondelete='CASCADE')
