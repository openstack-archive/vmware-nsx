# Copyright 2016 VMware, Inc.
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

"""lbaas foreignkeys

Revision ID: 7e46906f8997
Revises: aede17d51d0f
Create Date: 2016-04-21 10:45:32.278433

"""

from alembic import op
from neutron.db import migration

# revision identifiers, used by Alembic.
revision = '7e46906f8997'
down_revision = 'aede17d51d0f'


def upgrade():
    if (migration.schema_has_table('lbaas_loadbalancers') and
        migration.schema_has_table('nsxv_lbaas_loadbalancer_bindings')):

        op.execute('delete from nsxv_lbaas_loadbalancer_bindings '
                   'where loadbalancer_id not in '
                   '(select id from lbaas_loadbalancers)')
        op.create_foreign_key(
            'fk_lbaas_loadbalancers_id', 'nsxv_lbaas_loadbalancer_bindings',
            'lbaas_loadbalancers', ['loadbalancer_id'], ['id'],
            ondelete='CASCADE')

    if (migration.schema_has_table('lbaas_listeners') and
        migration.schema_has_table('nsxv_lbaas_listener_bindings')):

        op.execute('delete from nsxv_lbaas_listener_bindings '
                   'where listener_id  not in '
                   '(select id from lbaas_listeners)')
        op.create_foreign_key(
            'fk_lbaas_listeners_id', 'nsxv_lbaas_listener_bindings',
            'lbaas_listeners', ['listener_id'], ['id'], ondelete='CASCADE')

    if (migration.schema_has_table('lbaas_pools') and
        migration.schema_has_table('nsxv_lbaas_pool_bindings')):

        op.execute('delete from nsxv_lbaas_pool_bindings '
                   'where pool_id not in (select id from lbaas_pools)')
        op.create_foreign_key(
            'fk_lbaas_pools_id', 'nsxv_lbaas_pool_bindings',
            'lbaas_pools', ['pool_id'], ['id'], ondelete='CASCADE')

    if (migration.schema_has_table('lbaas_healthmonitors') and
        migration.schema_has_table('nsxv_lbaas_monitor_bindings')):

        op.execute('delete from nsxv_lbaas_monitor_bindings '
                   'where hm_id not in (select id from lbaas_healthmonitors)')
        op.create_foreign_key(
            'fk_lbaas_healthmonitors_id', 'nsxv_lbaas_monitor_bindings',
            'lbaas_healthmonitors', ['hm_id'], ['id'], ondelete='CASCADE')
