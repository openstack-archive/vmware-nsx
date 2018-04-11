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

"""NSXv3 add nsx_service_bindings and nsx_dhcp_bindings tables

Revision ID: c644ec62c585
Revises: c288bb6a7252
Create Date: 2016-04-29 23:19:39.523196

"""

from alembic import op
import sqlalchemy as sa

from vmware_nsxlib.v3 import nsx_constants

# revision identifiers, used by Alembic.
revision = 'c644ec62c585'
down_revision = 'c288bb6a7252'

nsx_service_type_enum = sa.Enum(
    nsx_constants.SERVICE_DHCP,
    name='neutron_nsx_service_bindings_service_type')


def upgrade():
    op.create_table(
        'neutron_nsx_service_bindings',
        sa.Column('network_id', sa.String(36), nullable=False),
        sa.Column('port_id', sa.String(36), nullable=True),
        sa.Column('nsx_service_type', nsx_service_type_enum, nullable=False),
        sa.Column('nsx_service_id', sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id', 'nsx_service_type'))

    op.create_table(
        'neutron_nsx_dhcp_bindings',
        sa.Column('port_id', sa.String(36), nullable=False),
        sa.Column('subnet_id', sa.String(36), nullable=False),
        sa.Column('ip_address', sa.String(64), nullable=False),
        sa.Column('nsx_service_id', sa.String(36), nullable=False),
        sa.Column('nsx_binding_id', sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id', 'nsx_binding_id'))
