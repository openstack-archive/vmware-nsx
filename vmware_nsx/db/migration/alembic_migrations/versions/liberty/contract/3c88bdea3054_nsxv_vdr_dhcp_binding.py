# Copyright 2015 VMware, Inc.
# All Rights Reserved
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

"""nsxv_vdr_dhcp_binding.py

Revision ID: 3c88bdea3054
Revises: 393bf843b96
Create Date: 2015-09-23 14:59:15.102609

"""

from alembic import op

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '3c88bdea3054'
down_revision = '393bf843b96'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.LIBERTY, migration.MITAKA]


def upgrade():
    op.drop_constraint('unique_nsxv_vdr_dhcp_bindings0dhcp_router_id',
                       'nsxv_vdr_dhcp_bindings', 'unique')
    op.drop_column('nsxv_vdr_dhcp_bindings', 'dhcp_router_id')
