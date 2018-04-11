# Copyright 2015 VMware, Inc.
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

"""nsxv_lbv2

Revision ID: 312211a5725f
Revises: 279b70ac3ae8
Create Date: 2015-09-09 02:02:59.990122

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '312211a5725f'
down_revision = '279b70ac3ae8'


def upgrade():
    op.create_table(
        'nsxv_lbaas_loadbalancer_bindings',
        sa.Column('loadbalancer_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('edge_fw_rule_id', sa.String(length=36), nullable=False),
        sa.Column('vip_address', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('loadbalancer_id'))
    op.create_table(
        'nsxv_lbaas_listener_bindings',
        sa.Column('loadbalancer_id', sa.String(length=36), nullable=False),
        sa.Column('listener_id', sa.String(length=36), nullable=False),
        sa.Column('app_profile_id', sa.String(length=36), nullable=False),
        sa.Column('vse_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('loadbalancer_id', 'listener_id'))
    op.create_table(
        'nsxv_lbaas_pool_bindings',
        sa.Column('loadbalancer_id', sa.String(length=36), nullable=False),
        sa.Column('listener_id', sa.String(length=36), nullable=False),
        sa.Column('pool_id', sa.String(length=36), nullable=False),
        sa.Column('edge_pool_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('loadbalancer_id', 'listener_id', 'pool_id'))
    op.create_table(
        'nsxv_lbaas_monitor_bindings',
        sa.Column('loadbalancer_id', sa.String(length=36), nullable=False),
        sa.Column('listener_id', sa.String(length=36), nullable=False),
        sa.Column('pool_id', sa.String(length=36), nullable=False),
        sa.Column('hm_id', sa.String(length=36), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('edge_mon_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('loadbalancer_id', 'listener_id', 'pool_id',
                                'hm_id', 'edge_id'))
    op.create_table(
        'nsxv_lbaas_certificate_bindings',
        sa.Column('cert_id', sa.String(length=128), nullable=False),
        sa.Column('edge_id', sa.String(length=36), nullable=False),
        sa.Column('edge_cert_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('cert_id', 'edge_id'))
