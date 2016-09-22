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

"""Fix the availability zones default value in the router bindings table

Revision ID: 7b5ec3caa9a4
Revises: 6e6da8296c0e
Create Date: 2016-09-07 11:38:35.369938

"""

from alembic import op

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '7b5ec3caa9a4'
down_revision = '6e6da8296c0e'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.NEWTON]


def upgrade():
    #previous migration left this column empty instead of 'default'
    op.execute("UPDATE nsxv_router_bindings SET availability_zone='default' "
               "where availability_zone is NULL")
