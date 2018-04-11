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

"""nsxv3_qos_policy_mapping

Revision ID: b7f41687cbad
Revises: 967462f585e1
Create Date: 2016-03-17 06:12:09.450116
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b7f41687cbad'
down_revision = '967462f585e1'


def upgrade():
    op.create_table(
        'neutron_nsx_qos_policy_mappings',
        sa.Column('qos_policy_id', sa.String(36), nullable=False),
        sa.Column('switch_profile_id', sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(['qos_policy_id'], ['qos_policies.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('qos_policy_id'))
