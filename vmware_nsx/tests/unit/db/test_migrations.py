# Copyright 2015 VMware, Inc.
#
# All Rights Reserved.
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

from oslo_config import cfg

from neutron.db.migration.alembic_migrations import external
from neutron.db.migration import cli as migration
from neutron.tests.functional.db import test_migrations
from neutron.tests.unit import testlib_api

from vmware_nsx.db.migration import alembic_migrations
from vmware_nsx.db.migration.models import head

#TODO(abhiraut): Remove this list from here once *aaS repos forms its
#                own list.
# Add *aaS tables to EXTERNAL_TABLES since they should not be
# tested.
LBAAS_TABLES = {
    'nsxv_edge_monitor_mappings',
    'nsxv_edge_pool_mappings',
    'nsxv_edge_vip_mappings',

    # LBaaS v2 tables
    'lbaas_healthmonitors',
    'lbaas_l7policies',
    'lbaas_l7rules',
    'lbaas_listeners',
    'lbaas_loadbalancer_statistics',
    'lbaas_loadbalanceragentbindings',
    'lbaas_loadbalancers',
    'lbaas_members',
    'lbaas_pools',
    'lbaas_sessionpersistences',
    'lbaas_sni',
}

L2GW_TABLES = {
    'l2gw_alembic_version',
    'physical_locators',
    'physical_switches',
    'physical_ports',
    'logical_switches',
    'ucast_macs_locals',
    'ucast_macs_remotes',
    'vlan_bindings',
    'l2gatewayconnections',
    'l2gatewayinterfaces',
    'l2gatewaydevices',
    'l2gateways',
    'pending_ucast_macs_remotes'
}

SFC_TABLES = {
    'sfc_flow_classifier_l7_parameters',
    'sfc_flow_classifiers',
    'sfc_port_chain_parameters',
    'sfc_service_function_params',
    'sfc_port_pair_group_params',
    'sfc_chain_classifier_associations',
    'sfc_port_pairs',
    'sfc_chain_group_associations',
    'sfc_port_pair_groups',
    'sfc_port_chains',
    'sfc_uuid_intid_associations',
    'sfc_path_port_associations',
    'sfc_portpair_details',
    'sfc_path_nodes',
}

TAAS_TABLES = {
    'tap_services',
    'tap_flows',
    'tap_id_associations',
}

FWAAS_TABLES = {
    'firewall_router_associations',
    'cisco_firewall_associations',
}

# EXTERNAL_TABLES should contain all names of tables that are not related to
# current repo.
EXTERNAL_TABLES = (set(external.TABLES) | LBAAS_TABLES |
                   L2GW_TABLES | SFC_TABLES | TAAS_TABLES | FWAAS_TABLES)


class _TestModelsMigrationsFoo(test_migrations._TestModelsMigrations):

    def db_sync(self, engine):
        cfg.CONF.set_override('connection', engine.url, group='database')
        for conf in migration.get_alembic_configs():
            self.alembic_config = conf
            self.alembic_config.neutron_config = cfg.CONF
            migration.do_alembic_command(conf, 'upgrade', 'heads')

    def get_metadata(self):
        return head.get_metadata()

    def include_object(self, object_, name, type_, reflected, compare_to):
        if type_ == 'table' and (name.startswith('alembic') or
                                 name == alembic_migrations.VERSION_TABLE or
                                 name in EXTERNAL_TABLES):
            return False
        if type_ == 'index' and reflected and name.startswith("idx_autoinc_"):
            return False
        return True


class TestModelsMigrationsMysql(testlib_api.MySQLTestCaseMixin,
                                _TestModelsMigrationsFoo,
                                testlib_api.SqlTestCaseLight):
    pass


class TestModelsMigrationsPsql(testlib_api.PostgreSQLTestCaseMixin,
                               _TestModelsMigrationsFoo,
                               testlib_api.SqlTestCaseLight):
    pass
