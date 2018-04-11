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

"""add nsx binding type

Revision ID: 5e564e781d77
Revises: c644ec62c585
Create Date: 2016-06-27 23:58:22.003350

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '5e564e781d77'
down_revision = 'c644ec62c585'


tz_binding_type_enum = sa.Enum('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                               'vxlan',
                               name='tz_network_bindings_binding_type')
new_tz_binding_type_enum = sa.Enum('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                                   'vxlan', 'portgroup',
                                   name='tz_network_bindings_binding_type')


def upgrade():
    op.alter_column(
        'tz_network_bindings',
        'binding_type',
        type_=new_tz_binding_type_enum,
        existing_type=tz_binding_type_enum,
        existing_nullable=False)
