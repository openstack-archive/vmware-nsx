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

"""Drop VDR DHCP bindings table

Revision ID: 53eb497903a4
Revises: 8699700cd95c
Create Date: 2017-02-22 10:10:59.990122

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '53eb497903a4'
down_revision = '8699700cd95c'


def upgrade():
    op.drop_table('nsxv_vdr_dhcp_bindings')
