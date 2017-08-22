# Copyright 2012 VMware, Inc.
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

import six
from sqlalchemy.orm import exc

from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils

import neutron.db.api as db

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import nsx_models

LOG = logging.getLogger(__name__)


def _apply_filters_to_query(query, model, filters, like_filters=None):
    if filters:
        for key, value in six.iteritems(filters):
            column = getattr(model, key, None)
            if column:
                query = query.filter(column.in_(value))
    if like_filters:
        for key, search_term in six.iteritems(like_filters):
            column = getattr(model, key, None)
            if column:
                query = query.filter(column.like(search_term))
    return query


def get_network_bindings(session, network_id):
    session = session or db.get_reader_session()
    return (session.query(nsx_models.TzNetworkBinding).
            filter_by(network_id=network_id).
            all())


def get_network_bindings_by_vlanid_and_physical_net(session, vlan_id,
                                                    phy_uuid):
    session = session or db.get_reader_session()
    return (session.query(nsx_models.TzNetworkBinding).
            filter_by(vlan_id=vlan_id, phy_uuid=phy_uuid).
            all())


def delete_network_bindings(session, network_id):
    return (session.query(nsx_models.TzNetworkBinding).
            filter_by(network_id=network_id).delete())


def add_network_binding(session, network_id, binding_type, phy_uuid, vlan_id):
    with session.begin(subtransactions=True):
        binding = nsx_models.TzNetworkBinding(network_id, binding_type,
                                              phy_uuid, vlan_id)
        session.add(binding)
    return binding


def add_neutron_nsx_network_mapping(session, neutron_id, nsx_switch_id,
                                    dvs_id=None):
    with session.begin(subtransactions=True):
        mapping = nsx_models.NeutronNsxNetworkMapping(
            neutron_id=neutron_id, nsx_id=nsx_switch_id,
            dvs_id=dvs_id)
        session.add(mapping)
        return mapping


def add_neutron_nsx_port_mapping(session, neutron_id,
                                 nsx_switch_id, nsx_port_id):
    session.begin(subtransactions=True)
    try:
        mapping = nsx_models.NeutronNsxPortMapping(
            neutron_id, nsx_switch_id, nsx_port_id)
        session.add(mapping)
        session.commit()
    except db_exc.DBDuplicateEntry:
        with excutils.save_and_reraise_exception() as ctxt:
            session.rollback()
            # do not complain if the same exact mapping is being added,
            # otherwise re-raise because even though it is possible for the
            # same neutron port to map to different back-end ports over time,
            # this should not occur whilst a mapping already exists
            current = get_nsx_switch_and_port_id(session, neutron_id)
            if current[1] == nsx_port_id:
                LOG.debug("Port mapping for %s already available",
                          neutron_id)
                ctxt.reraise = False
    except db_exc.DBError:
        with excutils.save_and_reraise_exception():
            # rollback for any other db error
            session.rollback()
    return mapping


def add_neutron_nsx_router_mapping(session, neutron_id, nsx_router_id):
    with session.begin(subtransactions=True):
        mapping = nsx_models.NeutronNsxRouterMapping(
            neutron_id=neutron_id, nsx_id=nsx_router_id)
        session.add(mapping)
        return mapping


def add_neutron_nsx_security_group_mapping(session, neutron_id, nsx_id):
    """Map a Neutron security group to a NSX security profile.

    :param session: a valid database session object
    :param neutron_id: a neutron security group identifier
    :param nsx_id: a nsx security profile identifier
    """
    with session.begin(subtransactions=True):
        mapping = nsx_models.NeutronNsxSecurityGroupMapping(
            neutron_id=neutron_id, nsx_id=nsx_id)
        session.add(mapping)
    return mapping


def get_nsx_service_binding(session, network_id, service_type):
    try:
        return session.query(nsx_models.NeutronNsxServiceBinding).filter_by(
            network_id=network_id, nsx_service_type=service_type).one()
    except exc.NoResultFound:
        LOG.debug("NSX %s service not enabled on network %s", service_type,
                  network_id)


def add_neutron_nsx_service_binding(session, network_id, port_id,
                                    service_type, service_id):
    """Store enabled NSX services on each Neutron network.

    :param session: database session object
    :param network_id: identifier of Neutron network enabling the service
    :param port_id: identifier of Neutron port providing the service
    :param service_type: type of NSX service
    :param service_id: identifier of NSX service
    """
    with session.begin(subtransactions=True):
        binding = nsx_models.NeutronNsxServiceBinding(
            network_id=network_id, port_id=port_id,
            nsx_service_type=service_type, nsx_service_id=service_id)
        session.add(binding)
        return binding


def delete_neutron_nsx_service_binding(session, network_id, service_type):
    return session.query(nsx_models.NeutronNsxServiceBinding).filter_by(
        network_id=network_id, nsx_service_type=service_type).delete()


def update_nsx_dhcp_bindings(session, port_id, org_ip, new_ip):
    try:
        with session.begin(subtransactions=True):
            binding = (session.query(nsx_models.NeutronNsxDhcpBinding).
                       filter_by(port_id=port_id, ip_address=org_ip).one())
            binding.ip_address = new_ip
    except exc.NoResultFound:
        LOG.debug("Binding not found for port %s", port_id)
        return


def get_nsx_dhcp_bindings(session, port_id):
    return [binding for binding in session.query(
        nsx_models.NeutronNsxDhcpBinding).filter_by(port_id=port_id)]


def get_nsx_dhcp_bindings_by_service(session, service_id):
    return [binding for binding in session.query(
        nsx_models.NeutronNsxDhcpBinding).filter_by(nsx_service_id=service_id)]


def add_neutron_nsx_dhcp_binding(session, port_id, subnet_id, ip_address,
                                 service_id, binding_id):
    """Store DHCP binding of each Neutron port.

    :param session: database session object
    :param port_id: identifier of Neutron port with DHCP binding
    :param subnet_id: identifier of Neutron subnet for the port
    :param ip_address: IP address for the port in this subnet.
    :param service_id: identifier of NSX DHCP service
    :param binding_id: identifier of NSX DHCP binding
    """
    with session.begin(subtransactions=True):
        binding = nsx_models.NeutronNsxDhcpBinding(
            port_id=port_id, subnet_id=subnet_id, ip_address=ip_address,
            nsx_service_id=service_id, nsx_binding_id=binding_id)
        session.add(binding)
        return binding


def delete_neutron_nsx_dhcp_binding(session, port_id, binding_id):
    return session.query(nsx_models.NeutronNsxDhcpBinding).filter_by(
        port_id=port_id, nsx_binding_id=binding_id).delete()


def delete_neutron_nsx_dhcp_bindings_by_service_id(session, service_id):
    return session.query(nsx_models.NeutronNsxDhcpBinding).filter_by(
        nsx_service_id=service_id).delete()


def get_nsx_switch_ids(session, neutron_id):
    # This function returns a list of NSX switch identifiers because of
    # the possibility of chained logical switches
    return [mapping['nsx_id'] for mapping in
            session.query(nsx_models.NeutronNsxNetworkMapping).filter_by(
                neutron_id=neutron_id)]


def get_nsx_network_mappings(session, neutron_id):
    # This function returns a list of NSX switch identifiers because of
    # the possibility of chained logical switches
    return session.query(nsx_models.NeutronNsxNetworkMapping).filter_by(
                neutron_id=neutron_id).all()


def get_nsx_switch_id_for_dvs(session, neutron_id, dvs_id):
    """Retrieve the NSX switch ID for a given DVS ID and neutron network."""
    try:
        mapping = (session.query(nsx_models.NeutronNsxNetworkMapping).
                   filter_by(neutron_id=neutron_id,
                             dvs_id=dvs_id).one())
        return mapping['nsx_id']
    except exc.NoResultFound:
        LOG.debug("NSX switch for dvs-id: %s not yet stored in Neutron DB",
                  dvs_id)


def get_net_ids(session, nsx_id):
    return [mapping['neutron_id'] for mapping in
            get_nsx_network_mapping_for_nsx_id(session, nsx_id)]


def get_nsx_network_mapping_for_nsx_id(session, nsx_id):
    return session.query(nsx_models.NeutronNsxNetworkMapping).filter_by(
        nsx_id=nsx_id).all()


def get_nsx_networks_mapping(session):
    return session.query(nsx_models.NeutronNsxNetworkMapping).all()


def get_nsx_switch_and_port_id(session, neutron_id):
    try:
        mapping = (session.query(nsx_models.NeutronNsxPortMapping).
                   filter_by(neutron_id=neutron_id).
                   one())
        return mapping['nsx_switch_id'], mapping['nsx_port_id']
    except exc.NoResultFound:
        LOG.debug("NSX identifiers for neutron port %s not yet "
                  "stored in Neutron DB", neutron_id)
        return None, None


def get_nsx_router_id(session, neutron_id):
    try:
        mapping = (session.query(nsx_models.NeutronNsxRouterMapping).
                   filter_by(neutron_id=neutron_id).one())
        return mapping['nsx_id']
    except exc.NoResultFound:
        LOG.debug("NSX identifiers for neutron router %s not yet "
                  "stored in Neutron DB", neutron_id)


def get_neutron_from_nsx_router_id(session, nsx_router_id):
    try:
        mapping = (session.query(nsx_models.NeutronNsxRouterMapping).
                   filter_by(nsx_id=nsx_router_id).one())
        return mapping['neutron_id']
    except exc.NoResultFound:
        LOG.debug("Couldn't find router with nsx id  %s", nsx_router_id)


def get_nsx_security_group_id(session, neutron_id):
    """Return the id of a security group in the NSX backend.

    Note: security groups are called 'security profiles' in NSX
    """
    try:
        mapping = (session.query(nsx_models.NeutronNsxSecurityGroupMapping).
                   filter_by(neutron_id=neutron_id).
                   one())
        return mapping['nsx_id']
    except exc.NoResultFound:
        LOG.debug("NSX identifiers for neutron security group %s not yet "
                  "stored in Neutron DB", neutron_id)
        return None


def get_nsx_security_group_ids(session, neutron_ids):
    """Return list of ids of a security groups in the NSX backend.
    """
    filters = {'neutron_id': neutron_ids}
    like_filters = None
    query = session.query(nsx_models.NeutronNsxSecurityGroupMapping)
    mappings = _apply_filters_to_query(
        query, nsx_models.NeutronNsxSecurityGroupMapping,
        filters, like_filters).all()
    return [mapping['nsx_id'] for mapping in mappings
            if mapping['nsx_id'] is not None]


def _delete_by_neutron_id(session, model, neutron_id):
    return session.query(model).filter_by(neutron_id=neutron_id).delete()


def delete_neutron_nsx_port_mapping(session, neutron_id):
    return _delete_by_neutron_id(
        session, nsx_models.NeutronNsxPortMapping, neutron_id)


def delete_neutron_nsx_router_mapping(session, neutron_id):
    return _delete_by_neutron_id(
        session, nsx_models.NeutronNsxRouterMapping, neutron_id)


def unset_default_network_gateways(session):
    with session.begin(subtransactions=True):
        session.query(nsx_models.NetworkGateway).update(
            {nsx_models.NetworkGateway.default: False})


def set_default_network_gateway(session, gw_id):
    with session.begin(subtransactions=True):
        gw = (session.query(nsx_models.NetworkGateway).
              filter_by(id=gw_id).one())
        gw['default'] = True


def set_multiprovider_network(session, network_id):
    with session.begin(subtransactions=True):
        multiprovider_network = nsx_models.MultiProviderNetworks(
            network_id)
        session.add(multiprovider_network)
        return multiprovider_network


def is_multiprovider_network(session, network_id):
    with session.begin(subtransactions=True):
        return bool(
            session.query(nsx_models.MultiProviderNetworks).filter_by(
                network_id=network_id).first())


# NSXv3 L2 Gateway DB methods.
def add_l2gw_connection_mapping(session, connection_id, bridge_endpoint_id,
                                port_id):
    with session.begin(subtransactions=True):
        mapping = nsx_models.NsxL2GWConnectionMapping(
            connection_id=connection_id,
            port_id=port_id,
            bridge_endpoint_id=bridge_endpoint_id)
        session.add(mapping)
        return mapping


def get_l2gw_connection_mapping(session, connection_id):
    try:
        return (session.query(nsx_models.NsxL2GWConnectionMapping).
                filter_by(connection_id=connection_id).one())
    except exc.NoResultFound:
        raise nsx_exc.NsxL2GWConnectionMappingNotFound(conn=connection_id)


# NSXv3 QoS policy id <-> switch Id mapping
def add_qos_policy_profile_mapping(session, qos_policy_id, switch_profile_id):
    with session.begin(subtransactions=True):
        mapping = nsx_models.QosPolicySwitchProfile(
            qos_policy_id=qos_policy_id,
            switch_profile_id=switch_profile_id)
        session.add(mapping)
        return mapping


def get_switch_profile_by_qos_policy(session, qos_policy_id):
    try:
        entry = (session.query(nsx_models.QosPolicySwitchProfile).
                 filter_by(qos_policy_id=qos_policy_id).one())
        return entry.switch_profile_id
    except exc.NoResultFound:
        raise nsx_exc.NsxQosPolicyMappingNotFound(policy=qos_policy_id)


def delete_qos_policy_profile_mapping(session, qos_policy_id):
    return (session.query(nsx_models.QosPolicySwitchProfile).
            filter_by(qos_policy_id=qos_policy_id).delete())


# NSXv3 Port Mirror Sessions DB methods.
def add_port_mirror_session_mapping(session, tf_id, pm_session_id):
    with session.begin(subtransactions=True):
        mapping = nsx_models.NsxPortMirrorSessionMapping(
            tap_flow_id=tf_id,
            port_mirror_session_id=pm_session_id)
        session.add(mapping)
        return mapping


def get_port_mirror_session_mapping(session, tf_id):
    try:
        return (session.query(nsx_models.NsxPortMirrorSessionMapping).
                filter_by(tap_flow_id=tf_id).one())
    except exc.NoResultFound:
        raise nsx_exc.NsxPortMirrorSessionMappingNotFound(tf=tf_id)


def delete_port_mirror_session_mapping(session, tf_id):
    return (session.query(nsx_models.NsxPortMirrorSessionMapping).
            filter_by(tap_flow_id=tf_id).delete())


@db.context_manager.writer
def save_sg_mappings(context, sg_id, nsgroup_id, section_id):
    context.session.add(
        nsx_models.NeutronNsxFirewallSectionMapping(neutron_id=sg_id,
                                                    nsx_id=section_id))
    context.session.add(
        nsx_models.NeutronNsxSecurityGroupMapping(neutron_id=sg_id,
                                                  nsx_id=nsgroup_id))


def get_sg_mappings(session, sg_id):
    nsgroup_mapping = session.query(
        nsx_models.NeutronNsxSecurityGroupMapping
    ).filter_by(neutron_id=sg_id).one()
    section_mapping = session.query(
        nsx_models.NeutronNsxFirewallSectionMapping
    ).filter_by(neutron_id=sg_id).one()
    return nsgroup_mapping.nsx_id, section_mapping.nsx_id


def get_sg_rule_mapping(session, rule_id):
    rule_mapping = session.query(
        nsx_models.NeutronNsxRuleMapping).filter_by(
        neutron_id=rule_id).one()
    return rule_mapping.nsx_id


def save_sg_rule_mappings(session, rules):
    with session.begin(subtransactions=True):
        for neutron_id, nsx_id in rules:
            mapping = nsx_models.NeutronNsxRuleMapping(
                neutron_id=neutron_id, nsx_id=nsx_id)
            session.add(mapping)


def add_nsx_ipam_subnet_pool(session, subnet_id, nsx_pool_id):
    with session.begin(subtransactions=True):
        binding = nsx_models.NsxSubnetIpam(
            subnet_id=subnet_id,
            nsx_pool_id=nsx_pool_id)
        session.add(binding)
    return binding


def get_nsx_ipam_pool_for_subnet(session, subnet_id):
    try:
        entry = session.query(
            nsx_models.NsxSubnetIpam).filter_by(
            subnet_id=subnet_id).one()
        return entry.nsx_pool_id
    except exc.NoResultFound:
        return


def del_nsx_ipam_subnet_pool(session, subnet_id, nsx_pool_id):
    return (session.query(nsx_models.NsxSubnetIpam).
            filter_by(subnet_id=subnet_id,
                      nsx_pool_id=nsx_pool_id).delete())


def get_certificate(session, purpose):
    try:
        cert_entry = session.query(
            nsx_models.NsxCertificateRepository).filter_by(
                purpose=purpose).one()
        return cert_entry.certificate, cert_entry.private_key
    except exc.NoResultFound:
        return None, None


def save_certificate(session, purpose, cert, pk):
    with session.begin(subtransactions=True):
        cert_entry = nsx_models.NsxCertificateRepository(
                purpose=purpose,
                certificate=cert,
                private_key=pk)
        session.add(cert_entry)


def delete_certificate(session, purpose):
    return (session.query(nsx_models.NsxCertificateRepository).
            filter_by(purpose=purpose).delete())


def add_nsx_lbaas_loadbalancer_binding(session, loadbalancer_id,
                                       lb_service_id, lb_router_id,
                                       vip_address):
    with session.begin(subtransactions=True):
        binding = nsx_models.NsxLbaasLoadbalancer(
            loadbalancer_id=loadbalancer_id, lb_service_id=lb_service_id,
            lb_router_id=lb_router_id, vip_address=vip_address)
        session.add(binding)
    return binding


def get_nsx_lbaas_loadbalancer_binding(session, loadbalancer_id):
    try:
        return session.query(
            nsx_models.NsxLbaasLoadbalancer).filter_by(
                loadbalancer_id=loadbalancer_id).one()
    except exc.NoResultFound:
        return


def get_nsx_lbaas_loadbalancer_binding_by_service(session, lb_service_id):
    return session.query(
        nsx_models.NsxLbaasLoadbalancer).filter_by(
            lb_service_id=lb_service_id).all()


def delete_nsx_lbaas_loadbalancer_binding(session, loadbalancer_id):
    return (session.query(nsx_models.NsxLbaasLoadbalancer).
            filter_by(loadbalancer_id=loadbalancer_id).delete())


def add_nsx_lbaas_listener_binding(session, loadbalancer_id, listener_id,
                                   app_profile_id, lb_vs_id):
    with session.begin(subtransactions=True):
        binding = nsx_models.NsxLbaasListener(
            loadbalancer_id=loadbalancer_id, listener_id=listener_id,
            app_profile_id=app_profile_id,
            lb_vs_id=lb_vs_id)
        session.add(binding)
    return binding


def get_nsx_lbaas_listener_binding(session, loadbalancer_id, listener_id):
    try:
        return session.query(
            nsx_models.NsxLbaasListener).filter_by(
                loadbalancer_id=loadbalancer_id,
                listener_id=listener_id).one()
    except exc.NoResultFound:
        return


def delete_nsx_lbaas_listener_binding(session, loadbalancer_id, listener_id):
    return (session.query(nsx_models.NsxLbaasListener).
            filter_by(loadbalancer_id=loadbalancer_id,
                      listener_id=listener_id).delete())


def add_nsx_lbaas_pool_binding(session, loadbalancer_id, pool_id, lb_pool_id,
                               lb_vs_id=None):
    with session.begin(subtransactions=True):
        binding = nsx_models.NsxLbaasPool(loadbalancer_id=loadbalancer_id,
                                          pool_id=pool_id,
                                          lb_pool_id=lb_pool_id,
                                          lb_vs_id=lb_vs_id)
        session.add(binding)
    return binding


def get_nsx_lbaas_pool_binding(session, loadbalancer_id, pool_id):
    try:
        return session.query(nsx_models.NsxLbaasPool).filter_by(
            loadbalancer_id=loadbalancer_id, pool_id=pool_id).one()
    except exc.NoResultFound:
        return


def update_nsx_lbaas_pool_binding(session, loadbalancer_id, pool_id,
                                  lb_vs_id):
    try:
        with session.begin(subtransactions=True):
            binding = (session.query(nsx_models.NsxLbaasPool).
                       filter_by(loadbalancer_id=loadbalancer_id,
                                 pool_id=pool_id).one())
            binding.lb_vs_id = lb_vs_id
    except exc.NoResultFound:
        LOG.debug("Binding not found for pool %s", pool_id)
        return


def delete_nsx_lbaas_pool_binding(session, loadbalancer_id, pool_id):
    return (session.query(nsx_models.NsxLbaasPool).
            filter_by(loadbalancer_id=loadbalancer_id,
                      pool_id=pool_id).delete())


def add_nsx_lbaas_monitor_binding(session, loadbalancer_id, pool_id, hm_id,
                                  lb_monitor_id, lb_pool_id):
    with session.begin(subtransactions=True):
        binding = nsx_models.NsxLbaasMonitor(
            loadbalancer_id=loadbalancer_id, pool_id=pool_id, hm_id=hm_id,
            lb_monitor_id=lb_monitor_id, lb_pool_id=lb_pool_id)
        session.add(binding)
    return binding


def get_nsx_lbaas_monitor_binding(session, loadbalancer_id, pool_id, hm_id):
    try:
        return session.query(nsx_models.NsxLbaasMonitor).filter_by(
            loadbalancer_id=loadbalancer_id,
            pool_id=pool_id, hm_id=hm_id).one()
    except exc.NoResultFound:
        return


def delete_nsx_lbaas_monitor_binding(session, loadbalancer_id, pool_id,
                                     hm_id):
    return (session.query(nsx_models.NsxLbaasMonitor).
            filter_by(loadbalancer_id=loadbalancer_id,
                      pool_id=pool_id, hm_id=hm_id).delete())


def add_nsx_lbaas_l7rule_binding(session, loadbalancer_id, l7policy_id,
                                 l7rule_id, lb_rule_id, lb_vs_id):
    with session.begin(subtransactions=True):
        binding = nsx_models.NsxLbaasL7Rule(
            loadbalancer_id=loadbalancer_id, l7policy_id=l7policy_id,
            l7rule_id=l7rule_id, lb_rule_id=lb_rule_id, lb_vs_id=lb_vs_id)
        session.add(binding)
    return binding


def get_nsx_lbaas_l7rule_binding(session, loadbalancer_id, l7policy_id,
                                 l7rule_id):
    try:
        return session.query(nsx_models.NsxLbaasL7Rule).filter_by(
            loadbalancer_id=loadbalancer_id, l7policy_id=l7policy_id,
            l7rule_id=l7rule_id).one()
    except exc.NoResultFound:
        return


def delete_nsx_lbaas_l7rule_binding(session, loadbalancer_id, l7policy_id,
                                    l7rule_id):
    return (session.query(nsx_models.NsxLbaasL7Rule).
            filter_by(loadbalancer_id=loadbalancer_id,
                      l7policy_id=l7policy_id,
                      l7rule_id=l7rule_id).delete())
