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

from neutron_lib.api.definitions import portbindings
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db.models import l3 as l3_db
from neutron.db import models_v2
from oslo_db.sqlalchemy import models

from vmware_nsx.common import nsxv_constants


class NsxvRouterBinding(model_base.BASEV2, model_base.HasStatusDescription,
                        models.TimestampMixin):
    """Represents the mapping between neutron router and vShield Edge."""

    __tablename__ = 'nsxv_router_bindings'

    # no ForeignKey to routers.id because for now, a router can be removed
    # from routers when delete_router is executed, but the binding is only
    # removed after the Edge is deleted
    router_id = sa.Column(sa.String(36),
                          primary_key=True)
    edge_id = sa.Column(sa.String(36),
                        nullable=True)
    lswitch_id = sa.Column(sa.String(36),
                           nullable=True)
    appliance_size = sa.Column(sa.Enum(
        nsxv_constants.COMPACT,
        nsxv_constants.LARGE,
        nsxv_constants.XLARGE,
        nsxv_constants.QUADLARGE,
        name='nsxv_router_bindings_appliance_size'))
    edge_type = sa.Column(sa.Enum(nsxv_constants.SERVICE_EDGE,
                                  nsxv_constants.VDR_EDGE,
                                  name='nsxv_router_bindings_edge_type'))
    availability_zone = sa.Column(sa.String(36),
                                  nullable=True)


class NsxvEdgeVnicBinding(model_base.BASEV2, models.TimestampMixin):
    """Represents mapping between vShield Edge vnic and neutron netowrk."""

    __tablename__ = 'nsxv_edge_vnic_bindings'

    edge_id = sa.Column(sa.String(36),
                        primary_key=True)
    vnic_index = sa.Column(sa.Integer(),
                           primary_key=True)
    tunnel_index = sa.Column(sa.Integer(),
                             primary_key=True)
    network_id = sa.Column(sa.String(36), nullable=True)


class NsxvEdgeDhcpStaticBinding(model_base.BASEV2, models.TimestampMixin):
    """Represents mapping between mac addr and bindingId."""

    __tablename__ = 'nsxv_edge_dhcp_static_bindings'

    edge_id = sa.Column(sa.String(36), primary_key=True)
    mac_address = sa.Column(sa.String(32), primary_key=True)
    binding_id = sa.Column(sa.String(36), nullable=False)


class NsxvInternalNetworks(model_base.BASEV2, models.TimestampMixin):
    """Represents internal networks between NSXV plugin elements."""
    __tablename__ = 'nsxv_internal_networks'

    network_purpose = sa.Column(
        sa.Enum(nsxv_constants.INTER_EDGE_PURPOSE,
                name='nsxv_internal_networks_purpose'),
        primary_key=True)
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("networks.id", ondelete="CASCADE"),
                           nullable=True)
    availability_zone = sa.Column(sa.String(36),
                                  primary_key=True)


class NsxvInternalEdges(model_base.BASEV2, models.TimestampMixin):
    """Represents internal Edge appliances for NSXV plugin operations."""
    __tablename__ = 'nsxv_internal_edges'

    ext_ip_address = sa.Column(sa.String(64), primary_key=True)
    router_id = sa.Column(sa.String(36), nullable=True)
    purpose = sa.Column(
        sa.Enum(nsxv_constants.INTER_EDGE_PURPOSE,
                name='nsxv_internal_edges_purpose'))


class NsxvSecurityGroupSectionMapping(model_base.BASEV2,
                                      models.TimestampMixin):
    """Backend mappings for Neutron Rule Sections.

    This class maps a neutron security group identifier to the corresponding
    NSX layer 3 section.
    """

    __tablename__ = 'nsxv_security_group_section_mappings'
    neutron_id = sa.Column(sa.String(36),
                           sa.ForeignKey('securitygroups.id',
                                         ondelete="CASCADE"),
                           primary_key=True)
    ip_section_id = sa.Column(sa.String(100))


class NsxvRuleMapping(model_base.BASEV2, models.TimestampMixin):
    """Backend mappings for Neutron Rule Sections.

    This class maps a neutron security group identifier to the corresponding
    NSX layer 3 and layer 2 sections.
    """

    __tablename__ = 'nsxv_rule_mappings'

    neutron_id = sa.Column(sa.String(36),
                           sa.ForeignKey('securitygrouprules.id',
                                         ondelete="CASCADE"),
                           primary_key=True)
    nsx_rule_id = sa.Column(sa.String(36), primary_key=True)


class NsxvPortVnicMapping(model_base.BASEV2, models.TimestampMixin):
    """Maps neutron port to NSXv VM Vnic Id."""

    __tablename__ = 'nsxv_port_vnic_mappings'

    neutron_id = sa.Column(sa.String(36),
                           sa.ForeignKey('ports.id', ondelete="CASCADE"),
                           primary_key=True)
    nsx_id = sa.Column(sa.String(42), primary_key=True)


class NsxvRouterExtAttributes(model_base.BASEV2, models.TimestampMixin):
    """Router attributes managed by NSX plugin extensions."""

    __tablename__ = 'nsxv_router_ext_attributes'

    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)
    distributed = sa.Column(sa.Boolean, default=False, nullable=False)
    router_type = sa.Column(
        sa.Enum('shared', 'exclusive',
                name='nsxv_router_type'),
        default='exclusive', nullable=False)
    service_router = sa.Column(sa.Boolean, default=False, nullable=False)
    # Add a relationship to the Router model in order to instruct
    # SQLAlchemy to eagerly load this association
    router = orm.relationship(
        l3_db.Router,
        backref=orm.backref("nsx_attributes", lazy='joined',
                            uselist=False, cascade='delete'))


class NsxvTzNetworkBinding(model_base.BASEV2, models.TimestampMixin):
    """Represents a binding of a virtual network with a transport zone.

    This model class associates a Neutron network with a transport zone;
    optionally a vlan ID might be used if the binding type is 'bridge'
    """

    __tablename__ = 'nsxv_tz_network_bindings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    binding_type = sa.Column(
        sa.Enum('flat', 'vlan', 'portgroup', 'vxlan',
                name='nsxv_tz_network_bindings_binding_type'),
        nullable=False, primary_key=True)
    phy_uuid = sa.Column(sa.String(36), primary_key=True, nullable=True)
    vlan_id = sa.Column(sa.Integer, primary_key=True, nullable=True,
                        autoincrement=False)

    def __init__(self, network_id, binding_type, phy_uuid, vlan_id):
        self.network_id = network_id
        self.binding_type = binding_type
        self.phy_uuid = phy_uuid
        self.vlan_id = vlan_id

    def __repr__(self):
        return "<NsxvTzNetworkBinding(%s,%s,%s,%s)>" % (self.network_id,
                                                        self.binding_type,
                                                        self.phy_uuid,
                                                        self.vlan_id)


class NsxvPortIndexMapping(model_base.BASEV2, models.TimestampMixin):
    """Associates attached Neutron ports with the instance VNic index."""

    __tablename__ = 'nsxv_port_index_mappings'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    device_id = sa.Column(sa.String(255), nullable=False)
    index = sa.Column(sa.Integer, nullable=False)
    __table_args__ = (sa.UniqueConstraint(device_id, index),
                      model_base.BASEV2.__table_args__)

    # Add a relationship to the Port model in order to instruct SQLAlchemy to
    # eagerly read port vnic-index
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref("vnic_index", lazy='joined',
                            uselist=False, cascade='delete'))


class NsxvEdgeFirewallRuleBinding(model_base.BASEV2, models.TimestampMixin):
    """Mapping between firewall rule and edge firewall rule_id."""

    __tablename__ = 'nsxv_firewall_rule_bindings'

    rule_id = sa.Column(sa.String(36),
                        primary_key=True)
    edge_id = sa.Column(sa.String(36), primary_key=True)
    rule_vse_id = sa.Column(sa.String(36))


class NsxvSpoofGuardPolicyNetworkMapping(model_base.BASEV2,
                                         models.TimestampMixin):
    """Mapping between SpoofGuard and neutron networks"""

    __tablename__ = 'nsxv_spoofguard_policy_network_mappings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete='CASCADE'),
                           primary_key=True,
                           nullable=False)
    policy_id = sa.Column(sa.String(36), nullable=False)


class NsxvLbaasLoadbalancerBinding(model_base.BASEV2, models.TimestampMixin):
    """Mapping between Edge LB and LBaaSv2"""

    __tablename__ = 'nsxv_lbaas_loadbalancer_bindings'

    loadbalancer_id = sa.Column(sa.String(36), primary_key=True)
    edge_id = sa.Column(sa.String(36), nullable=False)
    edge_fw_rule_id = sa.Column(sa.String(36), nullable=False)
    vip_address = sa.Column(sa.String(36), nullable=False)


class NsxvLbaasListenerBinding(model_base.BASEV2, models.TimestampMixin):
    """Mapping between Edge VSE and LBaaSv2"""

    __tablename__ = 'nsxv_lbaas_listener_bindings'

    loadbalancer_id = sa.Column(sa.String(36), primary_key=True)
    listener_id = sa.Column(sa.String(36), primary_key=True)
    app_profile_id = sa.Column(sa.String(36), nullable=False)
    vse_id = sa.Column(sa.String(36), nullable=False)


class NsxvLbaasPoolBinding(model_base.BASEV2, models.TimestampMixin):
    """Mapping between Edge Pool and LBaaSv2"""

    __tablename__ = 'nsxv_lbaas_pool_bindings'

    loadbalancer_id = sa.Column(sa.String(36), primary_key=True)
    pool_id = sa.Column(sa.String(36), primary_key=True)
    edge_pool_id = sa.Column(sa.String(36), nullable=False)


class NsxvLbaasMonitorBinding(model_base.BASEV2, models.TimestampMixin):
    """Mapping between Edge Monitor and LBaaSv2"""

    __tablename__ = 'nsxv_lbaas_monitor_bindings'

    loadbalancer_id = sa.Column(sa.String(36), primary_key=True)
    pool_id = sa.Column(sa.String(36), primary_key=True)
    hm_id = sa.Column(sa.String(36), primary_key=True)
    edge_id = sa.Column(sa.String(36), primary_key=True)
    edge_mon_id = sa.Column(sa.String(36), nullable=False)


class NsxvLbaasCertificateBinding(model_base.BASEV2, models.TimestampMixin):
    """Mapping between Edge certificate and LBaaSv2 object"""

    __tablename__ = 'nsxv_lbaas_certificate_bindings'

    cert_id = sa.Column(sa.String(128), primary_key=True)
    edge_id = sa.Column(sa.String(36), primary_key=True)
    edge_cert_id = sa.Column(sa.String(36), nullable=False)


class NsxvLbaasL7PolicyBinding(model_base.BASEV2, models.TimestampMixin):
    """Mapping between NSX Edge and LBaaSv2 L7 policy """

    __tablename__ = 'nsxv_lbaas_l7policy_bindings'

    policy_id = sa.Column(sa.String(36), primary_key=True)
    edge_id = sa.Column(sa.String(36), nullable=False)
    edge_app_rule_id = sa.Column(sa.String(36), nullable=False)


class NsxvSubnetExtAttributes(model_base.BASEV2, models.TimestampMixin):
    """Subnet attributes managed by NSX plugin extensions."""

    __tablename__ = 'nsxv_subnet_ext_attributes'

    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id', ondelete="CASCADE"),
                          primary_key=True)
    dns_search_domain = sa.Column(sa.String(255), nullable=True)
    dhcp_mtu = sa.Column(sa.Integer, nullable=True)
    # Add a relationship to the Subnet model in order to instruct
    # SQLAlchemy to eagerly load this association
    subnet = orm.relationship(
        models_v2.Subnet,
        backref=orm.backref("nsxv_subnet_attributes", lazy='joined',
                            uselist=False, cascade='delete'))


class NsxvPortExtAttributes(model_base.BASEV2, models.TimestampMixin):
    """Port attributes managed by NSX plugin extensions."""

    __tablename__ = 'nsxv_port_ext_attributes'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    vnic_type = sa.Column(sa.String(64), nullable=False,
                          default=portbindings.VNIC_NORMAL,
                          server_default=portbindings.VNIC_NORMAL)
    # Add a relationship to the port model in order to instruct
    # SQLAlchemy to eagerly load this association
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref("nsx_port_attributes", lazy='joined',
                            uselist=False, cascade='delete'))


class NsxvBgpSpeakerBinding(model_base.BASEV2, models.TimestampMixin):
    # Maps bgp_speaker_id to NSXv edge id
    __tablename__ = 'nsxv_bgp_speaker_bindings'

    edge_id = sa.Column(sa.String(36), primary_key=True)
    bgp_speaker_id = sa.Column(sa.String(36),
                               sa.ForeignKey('bgp_speakers.id',
                                             ondelete='CASCADE'),
                               nullable=False)
    # A given BGP speaker sets the value of its BGP Identifier to an IP address
    # that is assigned to that BGP speaker.
    bgp_identifier = sa.Column(sa.String(64), nullable=False)


class NsxvBgpPeerEdgeBinding(model_base.BASEV2, models.TimestampMixin):
    # Maps between bgp-peer and edges service gateway.
    __tablename__ = 'nsxv_bgp_peer_edge_bindings'
    peer_id = sa.Column(sa.String(36),
                        sa.ForeignKey('bgp_peers.id',
                                      ondelete='CASCADE'),
                        primary_key=True,
                        nullable=False)
    edge_id = sa.Column(sa.String(36), nullable=False)
