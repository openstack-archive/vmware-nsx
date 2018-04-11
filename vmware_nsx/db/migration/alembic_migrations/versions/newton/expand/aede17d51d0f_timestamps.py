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

"""add timestamp

Revision ID: aede17d51d0f
Revises: 5e564e781d77
Create Date: 2016-04-21 10:45:32.278433

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'aede17d51d0f'
down_revision = '5e564e781d77'

tables = [
    'nsxv_router_bindings',
    'nsxv_edge_vnic_bindings',
    'nsxv_edge_dhcp_static_bindings',
    'nsxv_internal_networks',
    'nsxv_internal_edges',
    'nsxv_security_group_section_mappings',
    'nsxv_rule_mappings',
    'nsxv_port_vnic_mappings',
    'nsxv_router_ext_attributes',
    'nsxv_tz_network_bindings',
    'nsxv_port_index_mappings',
    'nsxv_firewall_rule_bindings',
    'nsxv_spoofguard_policy_network_mappings',
    'nsxv_vdr_dhcp_bindings',
    'nsxv_lbaas_loadbalancer_bindings',
    'nsxv_lbaas_listener_bindings',
    'nsxv_lbaas_pool_bindings',
    'nsxv_lbaas_monitor_bindings',
    'nsxv_lbaas_certificate_bindings',
    'nsxv_subnet_ext_attributes',
    'tz_network_bindings',
    'neutron_nsx_network_mappings',
    'neutron_nsx_security_group_mappings',
    'neutron_nsx_firewall_section_mappings',
    'neutron_nsx_rule_mappings',
    'neutron_nsx_port_mappings',
    'neutron_nsx_router_mappings',
    'neutron_nsx_service_bindings',
    'neutron_nsx_dhcp_bindings',
    'multi_provider_networks',
    'networkconnections',
    'networkgatewaydevicereferences',
    'networkgatewaydevices',
    'networkgateways',
    'maclearningstates',
    'lsn_port',
    'lsn',
    'qosqueues',
    'portqueuemappings',
    'networkqueuemappings',
    'nsx_l2gw_connection_mappings',
    'neutron_nsx_qos_policy_mappings',
    'vcns_router_bindings']


def upgrade():
    for table in tables:
        op.add_column(
            table,
            sa.Column(u'created_at', sa.DateTime(), nullable=True)
        )
        op.add_column(
            table,
            sa.Column(u'updated_at', sa.DateTime(), nullable=True)
        )
