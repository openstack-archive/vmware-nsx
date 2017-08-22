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


from alembic import op
import sqlalchemy as sa

from neutron.db import migration

"""nsxv3_lbaas_mapping

Revision ID: ea7a72ab9643
Revises: 53eb497903a4
Create Date: 2017-06-12 16:59:48.021909

"""

# revision identifiers, used by Alembic.
revision = 'ea7a72ab9643'
down_revision = '53eb497903a4'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.PIKE]


def upgrade():
    op.create_table(
        'nsxv3_lbaas_loadbalancers',
        sa.Column('loadbalancer_id', sa.String(36), nullable=False),
        sa.Column('lb_router_id', sa.String(36), nullable=False),
        sa.Column('lb_service_id', sa.String(36), nullable=False),
        sa.Column('vip_address', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('loadbalancer_id'))
    op.create_table(
        'nsxv3_lbaas_listeners',
        sa.Column('loadbalancer_id', sa.String(36), nullable=False),
        sa.Column('listener_id', sa.String(36), nullable=False),
        sa.Column('app_profile_id', sa.String(36), nullable=False),
        sa.Column('lb_vs_id', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('loadbalancer_id', 'listener_id'))

    op.create_table(
        'nsxv3_lbaas_pools',
        sa.Column('loadbalancer_id', sa.String(36), nullable=False),
        sa.Column('pool_id', sa.String(36), nullable=False),
        sa.Column('lb_pool_id', sa.String(36), nullable=False),
        sa.Column('lb_vs_id', sa.String(36), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('loadbalancer_id', 'pool_id'))

    op.create_table(
        'nsxv3_lbaas_monitors',
        sa.Column('loadbalancer_id', sa.String(36), nullable=False),
        sa.Column('pool_id', sa.String(36), nullable=False),
        sa.Column('hm_id', sa.String(36), nullable=False),
        sa.Column('lb_monitor_id', sa.String(36), nullable=False),
        sa.Column('lb_pool_id', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('loadbalancer_id', 'pool_id', 'hm_id'))

    op.create_table(
        'nsxv3_lbaas_l7rules',
        sa.Column('loadbalancer_id', sa.String(36), nullable=False),
        sa.Column('l7policy_id', sa.String(36), nullable=False),
        sa.Column('l7rule_id', sa.String(36), nullable=False),
        sa.Column('lb_rule_id', sa.String(36), nullable=False),
        sa.Column('lb_vs_id', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('loadbalancer_id', 'l7policy_id',
                                'l7rule_id'))

    if migration.schema_has_table('lbaas_loadbalancers'):
        op.create_foreign_key(
            'fk_nsxv3_lbaas_loadbalancers_id', 'nsxv3_lbaas_loadbalancers',
            'lbaas_loadbalancers', ['loadbalancer_id'], ['id'],
            ondelete='CASCADE')

    if migration.schema_has_table('lbaas_listeners'):
        op.create_foreign_key(
            'fk_nsxv3_lbaas_listeners_id', 'nsxv3_lbaas_listeners',
            'lbaas_listeners', ['listener_id'], ['id'], ondelete='CASCADE')

    if migration.schema_has_table('lbaas_pools'):
        op.create_foreign_key(
            'fk_nsxv3_lbaas_pools_id', 'nsxv3_lbaas_pools',
            'lbaas_pools', ['pool_id'], ['id'], ondelete='CASCADE')

    if migration.schema_has_table('lbaas_healthmonitors'):
        op.create_foreign_key(
            'fk_nsxv3_lbaas_healthmonitors_id', 'nsxv3_lbaas_monitors',
            'lbaas_healthmonitors', ['hm_id'], ['id'], ondelete='CASCADE')

    if migration.schema_has_table('lbaas_l7rules'):
        op.create_foreign_key(
            'fk_nsxv3_lbaas_l7rules_id', 'nsxv3_lbaas_l7rules',
            'lbaas_l7rules', ['l7rule_id'], ['id'], ondelete='CASCADE')
