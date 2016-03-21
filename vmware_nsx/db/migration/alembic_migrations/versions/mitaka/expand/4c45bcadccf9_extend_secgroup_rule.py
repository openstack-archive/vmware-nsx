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

"""extend_secgroup_rule

Revision ID: 4c45bcadccf9
Revises: 20483029f1ff
Create Date: 2016-03-01 06:12:09.450116

"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '4c45bcadccf9'
down_revision = '20483029f1ff'

neutron_milestone = [migration.MITAKA]


def upgrade():
    op.create_table(
        'nsxv_extended_security_group_rule_properties',
        sa.Column('rule_id', sa.String(36), nullable=False),
        sa.Column('local_ip_prefix', sa.String(255), nullable=False),
        sa.ForeignKeyConstraint(['rule_id'], ['securitygrouprules.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('rule_id'))
