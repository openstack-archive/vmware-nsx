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

"""update nsxv tz binding type

Revision ID: 2af850eb3970
Revises: 312211a5725f
Create Date: 2015-11-24 13:44:08.664653

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '2af850eb3970'
down_revision = '312211a5725f'

tz_binding_type_enum = sa.Enum('flat', 'vlan', 'portgroup',
                               name='nsxv_tz_network_bindings_binding_type')
new_tz_binding_type_enum = sa.Enum(
                               'flat', 'vlan', 'portgroup', 'vxlan',
                               name='nsxv_tz_network_bindings_binding_type')


def upgrade():
    op.alter_column(
        'nsxv_tz_network_bindings',
        'binding_type',
        type_=new_tz_binding_type_enum,
        existing_type=tz_binding_type_enum,
        existing_nullable=False)
