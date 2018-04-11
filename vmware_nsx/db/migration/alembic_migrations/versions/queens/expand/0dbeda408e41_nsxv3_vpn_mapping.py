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

"""nsxv3_vpn_mapping

Revision ID: 0dbeda408e41
Revises: 9799427fc0e1
Create Date: 2017-11-26 12:27:40.846088

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0dbeda408e41'
down_revision = '9799427fc0e1'


def upgrade():

    op.create_table(
        'neutron_nsx_vpn_connection_mappings',
        sa.Column('neutron_id', sa.String(36), nullable=False),
        sa.Column('session_id', sa.String(36), nullable=False),
        sa.Column('dpd_profile_id', sa.String(36), nullable=False),
        sa.Column('ike_profile_id', sa.String(36), nullable=False),
        sa.Column('ipsec_profile_id', sa.String(36), nullable=False),
        sa.Column('peer_ep_id', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('neutron_id'))
