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

"""update nsx binding types

Revision ID: a1be06050b41
Revises: 84ceffa27115
Create Date: 2017-09-04 23:58:22.003350
"""

from alembic import op
import sqlalchemy as sa

from neutron.db import migration as neutron_op

# revision identifiers, used by Alembic.
revision = 'a1be06050b41'
down_revision = '84ceffa27115'
depends_on = ('aede17d51d0f')

all_tz_binding_type_enum = sa.Enum('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                                   'vxlan', 'geneve', 'portgroup', 'nsx-net',
                                   name='tz_network_bindings_binding_type')

new_tz_binding_type_enum = sa.Enum('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                                   'geneve', 'portgroup', 'nsx-net',
                                   name='tz_network_bindings_binding_type')


def upgrade():
    # add the new network types to the enum
    neutron_op.alter_enum_add_value(
        'tz_network_bindings',
        'binding_type',
        all_tz_binding_type_enum,
        False)

    # change existing entries with type 'vxlan' to 'geneve'
    op.execute("UPDATE tz_network_bindings SET binding_type='geneve' "
               "where binding_type='vxlan'")

    # remove 'vxlan' from the enum
    op.alter_column(
        'tz_network_bindings',
        'binding_type',
        type_=new_tz_binding_type_enum,
        existing_type=all_tz_binding_type_enum,
        existing_nullable=False)
