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

"""remove the foreign key constrain from nsxv3_qos_policy_mapping

Revision ID: 84ceffa27115
Revises: 8c0a81a07691
Create Date: 2017-03-15 11:47:09.450116
"""

from alembic import op
from sqlalchemy.engine import reflection

from neutron.db import migration

# revision identifiers, used by Alembic.
revision = '84ceffa27115'
down_revision = '8c0a81a07691'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.PIKE]


def upgrade():
    table_name = 'neutron_nsx_qos_policy_mappings'
    inspector = reflection.Inspector.from_engine(op.get_bind())
    fk_constraint = inspector.get_foreign_keys(table_name)[0]
    op.drop_constraint(fk_constraint.get('name'), table_name,
                       type_='foreignkey')
