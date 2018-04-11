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

"""nsxv_bgp_speaker_mapping

Revision ID: 8699700cd95c
Revises: 7c4704ad37df
Create Date: 2017-02-16 03:13:39.775670

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '8699700cd95c'
down_revision = '7c4704ad37df'


def upgrade():
    op.create_table(
        'nsxv_bgp_speaker_bindings',
        sa.Column('edge_id', sa.String(36), nullable=False),
        sa.Column('bgp_speaker_id', sa.String(36), nullable=False),
        sa.Column('bgp_identifier', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['bgp_speaker_id'], ['bgp_speakers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('edge_id'))

    op.create_table(
        'nsxv_bgp_peer_edge_bindings',
        sa.Column('peer_id', sa.String(36), nullable=False),
        sa.Column('edge_id', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['peer_id'], ['bgp_peers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('peer_id'))
