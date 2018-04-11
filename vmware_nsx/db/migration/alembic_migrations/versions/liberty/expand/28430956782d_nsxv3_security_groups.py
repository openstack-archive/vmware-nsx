# Copyright 2015 OpenStack Foundation
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

"""nsxv3_security_groups

Revision ID: 28430956782d
Revises: 53a3254aa95e
Create Date: 2015-08-24 18:19:09.397813

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '28430956782d'
down_revision = '53a3254aa95e'


def upgrade():
    op.create_table(
        'neutron_nsx_firewall_section_mappings',
        sa.Column('neutron_id', sa.String(36), nullable=False),
        sa.Column('nsx_id', sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(['neutron_id'], ['securitygroups.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('neutron_id'))

    op.create_table(
        'neutron_nsx_rule_mappings',
        sa.Column('neutron_id', sa.String(36), nullable=False),
        sa.Column('nsx_id', sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(['neutron_id'], ['securitygrouprules.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('neutron_id'))
