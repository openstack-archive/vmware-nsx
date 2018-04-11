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

"""nsxv3_secgroup_local_ip_prefix

Revision ID: 081af0e396d7
Revises: 5ed1ffbc0d2a
Create Date: 2016-03-24 07:11:30.300482

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '081af0e396d7'
down_revision = '5ed1ffbc0d2a'


def upgrade():
    op.rename_table('nsxv_extended_security_group_rule_properties',
                    'nsx_extended_security_group_rule_properties')
