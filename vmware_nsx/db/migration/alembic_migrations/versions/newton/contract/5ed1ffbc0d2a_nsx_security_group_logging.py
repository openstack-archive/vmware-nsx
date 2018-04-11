# Copyright 2016 OpenStack Foundation
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

"""nsxv_security_group_logging

Revision ID: 5ed1ffbc0d2a
Revises: 3e4dccfe6fb4
Create Date: 2016-03-24 06:06:06.680092

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '5ed1ffbc0d2a'
down_revision = '3c88bdea3054'
depends_on = ('3e4dccfe6fb4',)


def upgrade():
    secgroup_prop_table = sa.Table(
        'nsx_extended_security_group_properties',
        sa.MetaData(),
        sa.Column('security_group_id', sa.String(36), nullable=False),
        sa.Column('logging', sa.Boolean(), nullable=False))

    op.bulk_insert(secgroup_prop_table, get_values())
    op.drop_column('nsxv_security_group_section_mappings', 'logging')


def get_values():
    values = []
    session = sa.orm.Session(bind=op.get_bind())
    section_mapping_table = sa.Table('nsxv_security_group_section_mappings',
                                     sa.MetaData(),
                                     sa.Column('neutron_id', sa.String(36)),
                                     sa.Column('logging', sa.Boolean(),
                                               nullable=False))

    secgroup_table = sa.Table('securitygroups',
                              sa.MetaData(),
                              sa.Column('id', sa.String(36)))

    # If we run NSX-V plugin then we want the current values for security-group
    # logging, taken from the section mapping table.
    for row in session.query(section_mapping_table).all():
        values.append({'security_group_id': row.neutron_id,
                       'logging': row.logging})

    # If we run NSX-V3 plugin then previous table is empty, since
    # security-group logging isn't supported on previous versions, we set the
    # current value to false (the default).
    if not values:
        for row in session.query(secgroup_table).all():
            values.append({'security_group_id': row.id,
                           'logging': False})

    session.commit()
    return values
