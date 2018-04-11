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

"""nsxv_subnet_ipam rename to nsx_subnet_ipam

Revision ID: 5c8f451290b7
Revises: d49ac91b560e
Create Date: 2016-12-25 11:08:30.300482

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '5c8f451290b7'
down_revision = 'd49ac91b560e'
depends_on = ('6e6da8296c0e',)


def upgrade():
    op.rename_table('nsxv_subnet_ipam',
                    'nsx_subnet_ipam')
