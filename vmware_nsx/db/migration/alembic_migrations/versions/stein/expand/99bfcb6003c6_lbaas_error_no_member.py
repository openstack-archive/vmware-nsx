# Copyright 2019 VMware, Inc.
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

"""lbaas_error_no_member

Revision ID: 99bfcb6003c6
Revises: fc6308289aca
Create Date: 2019-03-07 11:27:00.000000
"""

from alembic import op

from neutron.db import migration

# revision identifiers, used by Alembic.
revision = '99bfcb6003c6'
down_revision = 'fc6308289aca'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.STEIN]


def upgrade():
    if (migration.schema_has_table('nsxv3_lbaas_loadbalancers') and
        migration.schema_has_table('lbaas_loadbalancers')):
        # Mark as ERROR loadbalancers without nsx mapping
        op.execute("UPDATE lbaas_loadbalancers "
                   "SET provisioning_status='ERROR' "
                   "WHERE id not in (SELECT loadbalancer_id FROM "
                   "nsxv3_lbaas_loadbalancers)")
