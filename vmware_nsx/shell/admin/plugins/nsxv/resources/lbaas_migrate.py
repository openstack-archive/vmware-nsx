# Copyright 2015 VMware, Inc.  All rights reserved.
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


import logging

from neutron.callbacks import registry
from neutron.db import servicetype_db
from neutron.plugins.common import constants as neutron_const
from neutron_lbaas.db.loadbalancer import loadbalancer_db as neutron_lbaas_v1
from neutron_lbaas.db.loadbalancer import models as neutron_lbaas_v2
from neutron_lbaas.services.loadbalancer import constants as lb_const
from neutron_lbaas.services.loadbalancer.drivers.vmware import db as nsx_lb_v1

from vmware_nsx._i18n import _LI
from vmware_nsx.db import nsxv_db

from vmware_nsx.shell.admin.plugins.common import constants
import vmware_nsx.shell.admin.plugins.common.utils as admin_utils
import vmware_nsx.shell.admin.plugins.nsxv.resources.utils as utils
from vmware_nsx.shell import resources

from oslo_utils import uuidutils

LOG = logging.getLogger(__name__)
neutron_db = utils.NeutronDbClient()

# default values for new V2 fields
default_provis_status = neutron_const.ACTIVE
default_operating_status = lb_const.ONLINE


def _create_v2_healthmonitor(v1_db_instance, v1_pool_id):
    """get one of the health-monitor entries of this pool,
    create a matching V2 entry, and return it's id, and also the matching v1 id
    If no entry was found - return None.
    Please note - lbaas v1 can have multiple health-monitors per pool,
    Here we choose one of those, arbitrarily for the V2 loadbalancer
    """

    query = v1_db_instance._model_query(
        neutron_db.context,
        neutron_lbaas_v1.PoolMonitorAssociation)
    hm_association = query.filter_by(pool_id=v1_pool_id).first()
    if hm_association:
        v1_hm_id = hm_association['monitor_id']
        hm_data = v1_db_instance.get_health_monitor(
            neutron_db.context,
            v1_hm_id)
        v2_hm_id = uuidutils.generate_uuid()
        v2_hm_data = {'id': v2_hm_id,
                      'tenant_id': hm_data['tenant_id'],
                      'type': hm_data['type'],
                      'delay': hm_data['delay'],
                      'timeout': hm_data['timeout'],
                      'max_retries': hm_data['max_retries'],
                      'admin_state_up': hm_data['admin_state_up'],
                      'provisioning_status': default_provis_status,
                      'name': None
                      }
        # the existence of those attributes depends on the hm type
        for attr in ['url_path', 'http_method', 'expected_codes']:
            if attr in hm_data:
                v2_hm_data[attr] = hm_data[attr]
            else:
                v2_hm_data[attr] = None

        db_entry = neutron_lbaas_v2.HealthMonitorV2(**v2_hm_data)
        neutron_db.context.session.add(db_entry)
        return v2_hm_id, v1_hm_id
    else:
        # no matching health monitor entry was found
        return None, None


def _create_v2_lb_stats(v1_db_instance, v1_pool_id, v2_lb_id):
    query = v1_db_instance._model_query(neutron_db.context,
                                        neutron_lbaas_v1.PoolStatistics)
    pool_stats = query.filter_by(pool_id=v1_pool_id).first()
    if pool_stats:
        v2_lb_stats = {'loadbalancer_id': v2_lb_id,
                       'bytes_in': pool_stats['bytes_in'],
                       'bytes_out': pool_stats['bytes_out'],
                       'active_connections': pool_stats['active_connections'],
                       'total_connections': pool_stats['total_connections'],
                       }
    else:
        # if there is a v1 matching entry, create an empty one
        v2_lb_stats = {'loadbalancer_id': v2_lb_id,
                       'bytes_in': 0,
                       'bytes_out': 0,
                       'active_connections': 0,
                       'total_connections': 0,
                       }
    db_entry = neutron_lbaas_v2.LoadBalancerStatistics(**v2_lb_stats)
    neutron_db.context.session.add(db_entry)


def _create_v2_pool(v1_neutron_db, v1_pool_data, v2_lb_id, v2_hm_id):
    # Create the v2 pool entry, and return its id
    v2_pool_id = uuidutils.generate_uuid()
    v2_pool = {
               'id': v2_pool_id,
               'loadbalancer_id': v2_lb_id,
               'tenant_id': v1_pool_data['tenant_id'],
               'name': v1_pool_data['name'],
               'description': v1_pool_data['description'],
               'protocol': v1_pool_data['protocol'],
               'lb_algorithm': v1_pool_data['lb_method'],
               'healthmonitor_id': v2_hm_id,
               'admin_state_up': v1_pool_data['admin_state_up'],
               'provisioning_status': default_provis_status,
               'operating_status': default_operating_status
    }

    db_entry = neutron_lbaas_v2.PoolV2(**v2_pool)
    neutron_db.context.session.add(db_entry)
    return v2_pool_id


def _create_v2_listener(v1_vip_data, v2_lb_id, v2_pool_id):
    # Create the v2 listener entry and return the id
    v2_listener_id = uuidutils.generate_uuid()
    v2_listener = {'id': v2_listener_id,
                   'tenant_id': v1_vip_data['tenant_id'],
                   'name': None,
                   'description': None,
                   'protocol': v1_vip_data['protocol'],
                   'protocol_port': v1_vip_data['protocol_port'],
                   'connection_limit': v1_vip_data['connection_limit'],
                   'loadbalancer_id': v2_lb_id,
                   'default_pool_id': v2_pool_id,
                   'admin_state_up': v1_vip_data['admin_state_up'],
                   'provisioning_status': default_provis_status,
                   'operating_status': default_operating_status,
                   'default_tls_container_id': None  # Not supported by V1
                   }

    db_entry = neutron_lbaas_v2.Listener(**v2_listener)
    neutron_db.context.session.add(db_entry)
    return v2_listener_id


def _create_v2_member(v1_member_data, v2_pool_id, subnet_id):
    # create a member entry in lbaas v2
    v2_member_id = uuidutils.generate_uuid()
    v2_memeber = {'id': v2_member_id,
                  'tenant_id': v1_member_data['tenant_id'],
                  'pool_id': v2_pool_id,
                  'subnet_id': subnet_id,
                  'address': v1_member_data['address'],
                  'protocol_port': v1_member_data['protocol_port'],
                  'weight': v1_member_data['weight'],
                  'admin_state_up': v1_member_data['admin_state_up'],
                  'provisioning_status': default_provis_status,
                  'operating_status': default_operating_status,
                  'name': None
                  }
    db_entry = neutron_lbaas_v2.MemberV2(**v2_memeber)
    neutron_db.context.session.add(db_entry)


def _create_v2_sess_persistence(v1_vip_id, v2_pool_id):
    # create V2 session persistence entry if one was created in v1
    sess_qry = neutron_db.context.session.query(
        neutron_lbaas_v1.SessionPersistence)
    v1_entry = sess_qry.filter_by(vip_id=v1_vip_id).first()
    if v1_entry:
        v2_entry = {'pool_id': v2_pool_id,
                    'type': v1_entry['type'],
                    'cookie_name': v1_entry['cookie_name']
                    }
        db_entry = neutron_lbaas_v2.SessionPersistenceV2(**v2_entry)
        neutron_db.context.session.add(db_entry)


def _create_v2_nsx_mappings(v1_pool_id, v1_hm_id, v2_pool_id, v2_lb_id,
                            v2_listener_id, v2_hm_id, vip_address):
    # NSX health-monitor edge mapping
    v1_monitor_edge_mappings = nsx_lb_v1.get_nsxv_edge_monitor_mapping_all(
        neutron_db.context, v1_hm_id)
    if len(v1_monitor_edge_mappings) > 0:
        v1_hm_map = v1_monitor_edge_mappings[0]
        nsxv_db.add_nsxv_lbaas_monitor_binding(
            neutron_db.context.session,
            v2_lb_id,
            v2_pool_id,
            v2_hm_id,
            v1_hm_map['edge_id'],
            v1_hm_map['edge_monitor_id'])

    # NSX edge pool mapping
    if v2_listener_id is not None:
        v1_pool_map = nsx_lb_v1.get_nsxv_edge_pool_mapping(
            neutron_db.context, v1_pool_id)
        if v1_pool_map is not None:
            nsxv_db.add_nsxv_lbaas_pool_binding(
                neutron_db.context.session,
                v2_lb_id,
                v2_pool_id,
                v1_pool_map['edge_pool_id'])

    # NSX V1 edge vip mappings -> loadbalancer & listener binding
    v1_vip_map = nsx_lb_v1.get_nsxv_edge_vip_mapping(
        neutron_db.context, v1_pool_id)
    if v1_vip_map is not None:
        nsxv_db.add_nsxv_lbaas_loadbalancer_binding(
            neutron_db.context.session,
            v2_lb_id,
            v1_vip_map['edge_id'],
            v1_vip_map['edge_fw_rule_id'],
            vip_address)
        if v2_listener_id is not None:
            nsxv_db.add_nsxv_lbaas_listener_binding(
                neutron_db.context.session,
                v2_lb_id,
                v2_listener_id,
                v1_vip_map['edge_app_profile_id'],
                v1_vip_map['edge_vse_id'])


def _delete_v1_entries_for_pool(v1_db_instance, v1_pool_id, pool_data):
    # Delete all lbaas v1 db entries related to a specific pool id
    # delete nsx mappings of this pool
    v1_pool_map = nsx_lb_v1.get_nsxv_edge_pool_mapping(
        neutron_db.context, v1_pool_id)
    if v1_pool_map is not None:
        neutron_db.context.session.delete(v1_pool_map)

    v1_vip_map = nsx_lb_v1.get_nsxv_edge_vip_mapping(
        neutron_db.context, v1_pool_id)
    if v1_vip_map is not None:
        neutron_db.context.session.delete(v1_vip_map)

    # delete the provider-resource-association entry for this pool
    provider_resource_association = None
    query = neutron_db.context.session.query(
        servicetype_db.ProviderResourceAssociation)
    entry = query.filter_by(resource_id=v1_pool_id).first()
    if entry is not None:
        provider_resource_association = entry
        neutron_db.context.session.delete(entry)

    # delete the pool itself (which will automatically delete pool-stats,
    # pool-monitor-association & member)
    pool = v1_db_instance._get_resource(neutron_db.context,
                                        neutron_lbaas_v1.Pool,
                                        v1_pool_id)
    neutron_db.context.session.delete(pool)

    # delete vip and related entries
    if 'vip_id' in pool_data and pool_data['vip_id'] is not None:
        v1_vip_id = pool_data['vip_id']
        # delete the vip entry
        # delete of the session-persistence will be done automatically
        # when the vip is deleted
        vip = v1_db_instance._get_resource(neutron_db.context,
                                           neutron_lbaas_v1.Vip,
                                           v1_vip_id)
        if vip is not None:
            neutron_db.context.session.delete(vip)

    if provider_resource_association:
        association = servicetype_db.ProviderResourceAssociation(
            provider_name=provider_resource_association.provider_name,
            resource_id=provider_resource_association.resource_id)
        neutron_db.context.session.add(association)


def _delete_v1_healthmonitors(v1_db_instance):
    # delete all health monitor entries, and their nsxv mappings
    hms = v1_db_instance.get_health_monitors(neutron_db.context)
    for hm in hms:
        # delete the nsxv mapping
        v1_monitor_edge_mappings = nsx_lb_v1.get_nsxv_edge_monitor_mapping_all(
            neutron_db.context, hm['id'])
        for entry in v1_monitor_edge_mappings:
            neutron_db.context.session.delete(entry)
        hm_entry = v1_db_instance._get_resource(
            neutron_db.context, neutron_lbaas_v1.HealthMonitor, hm['id'])
        neutron_db.context.session.delete(hm_entry)


@admin_utils.output_header
def nsx_migrate_lbaas(resource, event, trigger, **kwargs):

    """Migrate lbaas-v1 db to lbaas-v2"""
    v1_neutron_db = neutron_lbaas_v1.LoadBalancerPluginDb()
    pools = v1_neutron_db.get_pools(neutron_db.context)

    if not len(pools):
        LOG.info(_LI("No Lbaas V1 configuration to migrate"))
        return

    props = kwargs.get('property')
    delete_v1_entries = True if props and props[0] == 'delete-v1' else False
    if delete_v1_entries:
        extra_msg = _LI("and deleting the lbaas V1 database entries")
    else:
        extra_msg = _LI("without deleting the lbaas V1 database entries")
    LOG.info(_LI("Migrating lbaas V1 db entries to lbaas V2 %s"), extra_msg)

    # the entire migration process will be done under the same transaction to
    # allow full rollback in case of error
    with neutron_db.context.session.begin(subtransactions=True):
        # Go over all lbaas V1 pools
        for pool_data in pools:
            v1_pool_id = pool_data['id']
            tenant_id = pool_data['tenant_id']
            v1_pool_with_vip = False
            # get all the values from the pool and the related vip
            # in order to create the loadbalancer object for V2
            if 'vip_id' in pool_data and pool_data['vip_id'] is not None:
                v1_pool_with_vip = True
                v1_vip_id = pool_data['vip_id']
                v1_vip_data = v1_neutron_db.get_vip(neutron_db.context,
                                                    v1_vip_id)
                # get the information from the old vip entry for
                # the new loadbalancer entry
                lb_name = v1_vip_data['name']
                lb_description = v1_vip_data['description']
                lb_vip_port_id = v1_vip_data['port_id']
                lb_vip_addr = v1_vip_data['address']
                lb_admin_state_up = v1_vip_data['admin_state_up']
            else:
                # no vip entry - default/empty values
                lb_name = None
                lb_description = None
                lb_vip_port_id = None
                lb_vip_addr = None
                lb_admin_state_up = 0

            # create the V2 load-balancer entry
            # keep the old pool id as the id of the new loadbalancer
            v2_lb_id = v1_pool_id
            v2_lb = {'id': v2_lb_id,
                     'tenant_id': tenant_id,
                     'vip_subnet_id': pool_data['subnet_id'],
                     'provisioning_status': default_provis_status,
                     'operating_status': default_operating_status,
                     'name': lb_name,
                     'description': lb_description,
                     'vip_port_id': lb_vip_port_id,
                     'vip_address': lb_vip_addr,
                     'admin_state_up': lb_admin_state_up,
                     'flavor_id': None
                     }

            db_entry = neutron_lbaas_v2.LoadBalancer(**v2_lb)
            neutron_db.context.session.add(db_entry)

            # Create the loadbalancers stats entry
            _create_v2_lb_stats(v1_neutron_db, v1_pool_id, v2_lb_id)

            # create the health monitor entry (if existed in v1)
            v2_hm_id, v1_hm_id = _create_v2_healthmonitor(v1_neutron_db,
                                                          v1_pool_id)

            # Create the v2 pool entry
            v2_pool_id = _create_v2_pool(v1_neutron_db,
                                         pool_data,
                                         v2_lb_id,
                                         v2_hm_id)

            # Create lbaas V2 members for each v1 member of the same pool
            filters = {'pool_id': [v1_pool_id]}
            v1_members = v1_neutron_db.get_members(neutron_db.context,
                                                   filters=filters)
            for member in v1_members:
                # create member in lbaas v2
                _create_v2_member(member, v2_pool_id, pool_data['subnet_id'])

            # Create lbaas V2 listener entry in V1 had vip in this pool
            v2_listener_id = None
            if v1_pool_with_vip:
                v2_listener_id = _create_v2_listener(v1_vip_data,
                                                     v2_lb_id,
                                                     v2_pool_id)
                # create V2 session-persistence entry based on the v1 entry
                _create_v2_sess_persistence(v1_vip_id, v2_pool_id)

            # Update the NSX mappings table from v1 to v2
            _create_v2_nsx_mappings(v1_pool_id, v1_hm_id,
                                    v2_pool_id, v2_lb_id,
                                    v2_listener_id, v2_hm_id,
                                    lb_vip_addr)

            if delete_v1_entries:
                _delete_v1_entries_for_pool(v1_neutron_db,
                                            v1_pool_id, pool_data)

        if delete_v1_entries:
            # Delete all health monitors,
            # because they do not belong to a specific pool
            _delete_v1_healthmonitors(v1_neutron_db)

    LOG.info(_LI("Finished migrating %d Lbaas V1 pools"), len(pools))
    return


registry.subscribe(nsx_migrate_lbaas,
                   constants.LBAAS,
                   resources.Operations.NSX_MIGRATE_V1_V2.value)
