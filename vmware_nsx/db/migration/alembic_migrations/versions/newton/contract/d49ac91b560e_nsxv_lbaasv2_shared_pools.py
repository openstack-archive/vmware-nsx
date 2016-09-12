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

"""Support shared pools with NSXv LBaaSv2 driver

Revision ID: d49ac91b560e
Revises: dbe29d208ac6
Create Date: 2016-07-21 05:03:35.369938

"""

from alembic import op
from sqlalchemy.engine import reflection

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = 'd49ac91b560e'
down_revision = 'dbe29d208ac6'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.NEWTON]


def upgrade():
    change_pk_constraint('nsxv_lbaas_pool_bindings', ['loadbalancer_id',
                                                      'pool_id'])
    change_pk_constraint('nsxv_lbaas_monitor_bindings', ['loadbalancer_id',
                                                         'pool_id',
                                                         'hm_id',
                                                         'edge_id'])


def change_pk_constraint(table_name, columns):
    inspector = reflection.Inspector.from_engine(op.get_bind())
    pk_constraint = inspector.get_pk_constraint(table_name)
    op.drop_constraint(pk_constraint.get('name'), table_name, type_='primary')
    op.drop_column(table_name, 'listener_id')
    op.create_primary_key(None, table_name, columns)
