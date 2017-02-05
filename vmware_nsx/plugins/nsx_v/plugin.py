# Copyright 2014 VMware, Inc.
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

from distutils import version
import six
import uuid

import netaddr
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import excutils
from oslo_utils import uuidutils
from sqlalchemy.orm import exc as sa_exc

from neutron.api import extensions as neutron_extensions
from neutron.api.rpc.callbacks.consumer import registry as callbacks_registry
from neutron.api.rpc.callbacks import resources as callbacks_resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.api.v2 import attributes as attr
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import ipv6_utils
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as n_context
from neutron.db import agents_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import api as db_api
from neutron.db.availability_zone import router as router_az_db
from neutron.db import db_base_plugin_v2
from neutron.db import dns_db
from neutron.db import external_net_db
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db.models import securitygroup as securitygroup_model  # noqa
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import portsecurity_db
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_db
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import availability_zone as az_ext
from neutron.extensions import external_net as ext_net_extn
from neutron.extensions import flavors
from neutron.extensions import l3
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import portbindings as pbin
from neutron.extensions import portsecurity as psec
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.plugins.common import constants as plugin_const
from neutron.plugins.common import utils
from neutron.quota import resource_registry
from neutron.services.flavors import flavors_plugin
from neutron.services.qos import qos_consts
from vmware_nsx.dvs import dvs
from vmware_nsx.services.qos.common import utils as qos_com_utils
from vmware_nsx.services.qos.nsx_v import utils as qos_utils

import vmware_nsx
from vmware_nsx._i18n import _, _LE, _LI, _LW
from vmware_nsx.common import config  # noqa
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import locking
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import nsxv_constants
from vmware_nsx.common import utils as c_utils
from vmware_nsx.db import (
    extended_security_group_rule as extend_sg_rule)
from vmware_nsx.db import (
    routertype as rt_rtr)
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import extended_security_group as extended_secgroup
from vmware_nsx.db import nsxv_db
from vmware_nsx.db import vnic_index_db
from vmware_nsx.extensions import (
    advancedserviceproviders as as_providers)
from vmware_nsx.extensions import (
    vnicindex as ext_vnic_idx)
from vmware_nsx.extensions import dhcp_mtu as ext_dhcp_mtu
from vmware_nsx.extensions import dns_search_domain as ext_dns_search_domain
from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.extensions import routersize
from vmware_nsx.extensions import secgroup_rule_local_ip_prefix
from vmware_nsx.extensions import securitygrouplogging as sg_logging
from vmware_nsx.plugins.nsx_v import availability_zones as nsx_az
from vmware_nsx.plugins.nsx_v import managers
from vmware_nsx.plugins.nsx_v import md_proxy as nsx_v_md_proxy
from vmware_nsx.plugins.nsx_v.vshield.common import (
    constants as vcns_const)
from vmware_nsx.plugins.nsx_v.vshield.common import (
    exceptions as vsh_exc)
from vmware_nsx.plugins.nsx_v.vshield import edge_firewall_driver
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.plugins.nsx_v.vshield import securitygroup_utils
from vmware_nsx.plugins.nsx_v.vshield import vcns_driver
from vmware_nsx.services.flowclassifier.nsx_v import utils as fc_utils

LOG = logging.getLogger(__name__)
PORTGROUP_PREFIX = 'dvportgroup'
ROUTER_SIZE = routersize.ROUTER_SIZE
VALID_EDGE_SIZES = routersize.VALID_EDGE_SIZES


class NsxVPluginV2(addr_pair_db.AllowedAddressPairsMixin,
                   agents_db.AgentDbMixin,
                   db_base_plugin_v2.NeutronDbPluginV2,
                   rt_rtr.RouterType_mixin,
                   external_net_db.External_net_db_mixin,
                   extraroute_db.ExtraRoute_db_mixin,
                   router_az_db.RouterAvailabilityZoneMixin,
                   l3_gwmode_db.L3_NAT_db_mixin,
                   portbindings_db.PortBindingMixin,
                   portsecurity_db.PortSecurityDbMixin,
                   extend_sg_rule.ExtendedSecurityGroupRuleMixin,
                   securitygroups_db.SecurityGroupDbMixin,
                   extended_secgroup.ExtendedSecurityGroupPropertiesMixin,
                   vnic_index_db.VnicIndexDbMixin,
                   dns_db.DNSDbMixin):

    supported_extension_aliases = ["agent",
                                   "allowed-address-pairs",
                                   "binding",
                                   "dns-search-domain",
                                   "dvr",
                                   "ext-gw-mode",
                                   "multi-provider",
                                   "port-security",
                                   "provider",
                                   "quotas",
                                   "external-net",
                                   "extraroute",
                                   "router",
                                   "security-group",
                                   "secgroup-rule-local-ip-prefix",
                                   "security-group-logging",
                                   "nsxv-router-type",
                                   "nsxv-router-size",
                                   "vnic-index",
                                   "advanced-service-providers",
                                   "subnet_allocation",
                                   "availability_zone",
                                   "network_availability_zone",
                                   "router_availability_zone",
                                   "l3-flavors", "flavors"]

    supported_qos_rule_types = [qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                                qos_consts.RULE_TYPE_DSCP_MARKING]

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    @resource_registry.tracked_resources(
        network=models_v2.Network,
        port=models_v2.Port,
        subnet=models_v2.Subnet,
        subnetpool=models_v2.SubnetPool,
        security_group=securitygroup_model.SecurityGroup,
        security_group_rule=securitygroup_model.SecurityGroupRule,
        router=l3_db.Router,
        floatingip=l3_db.FloatingIP)
    def __init__(self):
        super(NsxVPluginV2, self).__init__()
        self.init_is_complete = False
        registry.subscribe(self.init_complete,
                           resources.PROCESS,
                           events.AFTER_INIT)
        self.metadata_proxy_handler = None
        config.validate_nsxv_config_options()
        neutron_extensions.append_api_extensions_path(
            [vmware_nsx.NSX_EXT_PATH])

        self.base_binding_dict = {
            pbin.VNIC_TYPE: pbin.VNIC_NORMAL,
            pbin.VIF_TYPE: nsx_constants.VIF_TYPE_DVS,
            pbin.VIF_DETAILS: {
                # TODO(rkukura): Replace with new VIF security details
                pbin.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}
        # Create the client to interface with the NSX-v
        _nsx_v_callbacks = edge_utils.NsxVCallbacks(self)
        self.nsx_v = vcns_driver.VcnsDriver(_nsx_v_callbacks)
        # Ensure that edges do concurrency
        self._ensure_lock_operations()
        # Configure aggregate publishing
        self._aggregate_publishing()
        # Configure edge reservations
        self._configure_reservations()
        self.edge_manager = edge_utils.EdgeManager(self.nsx_v, self)
        self.vdn_scope_id = cfg.CONF.nsxv.vdn_scope_id
        self.dvs_id = cfg.CONF.nsxv.dvs_id
        self.nsx_sg_utils = securitygroup_utils.NsxSecurityGroupUtils(
            self.nsx_v)
        self._availability_zones_data = nsx_az.ConfiguredAvailabilityZones()
        self._validate_config()
        self.sg_container_id = self._create_security_group_container()
        self.default_section = self._create_cluster_default_fw_section()
        self._process_security_groups_rules_logging()
        self._router_managers = managers.RouterTypeManager(self)

        if cfg.CONF.nsxv.use_dvs_features:
            self._dvs = dvs.DvsManager(dvs_id=self.dvs_id)
        else:
            self._dvs = None

        if self.edge_manager.is_dhcp_opt_enabled:
            # Only expose the extension if it is supported
            self.supported_extension_aliases.append("dhcp-mtu")

        # Bind QoS notifications
        callbacks_registry.subscribe(self._handle_qos_notification,
                                     callbacks_resources.QOS_POLICY)

        # Make sure starting rpc listeners (for QoS and other agents)
        # will happen only once
        self.start_rpc_listeners_called = False

        # Service insertion driver register
        self._si_handler = fc_utils.NsxvServiceInsertionHandler(self)
        registry.subscribe(self.add_vms_to_service_insertion,
                           fc_utils.SERVICE_INSERTION_RESOURCE,
                           events.AFTER_CREATE)

        if c_utils.is_nsxv_version_6_2(self.nsx_v.vcns.get_version()):
            self.supported_extension_aliases.append("provider-security-group")

    def init_complete(self, resource, event, trigger, **kwargs):
        has_metadata_cfg = (
            cfg.CONF.nsxv.nova_metadata_ips
            and cfg.CONF.nsxv.mgt_net_moid
            and cfg.CONF.nsxv.mgt_net_proxy_ips
            and cfg.CONF.nsxv.mgt_net_proxy_netmask)
        if has_metadata_cfg:
            self.metadata_proxy_handler = (
                nsx_v_md_proxy.NsxVMetadataProxyHandler(self))

        self.init_is_complete = True

    def add_vms_to_service_insertion(self, sg_id):
        def _add_vms_to_service_insertion(*args, **kwargs):

            """Adding existing VMs to the service insertion security group

            Adding all current compute ports with port security to the service
            insertion security group in order to classify their traffic by the
            security redirect rules
            """
            sg_id = args[0]
            context = n_context.get_admin_context()
            filters = {'device_owner': ['compute:None']}
            ports = self.get_ports(context, filters=filters)
            for port in ports:
                # Only add compute ports with device-id, vnic & port security
                if (validators.is_attr_set(port.get(ext_vnic_idx.VNIC_INDEX))
                    and validators.is_attr_set(port.get('device_id'))
                    and port[psec.PORTSECURITY]):
                    try:
                        vnic_idx = port[ext_vnic_idx.VNIC_INDEX]
                        device_id = port['device_id']
                        vnic_id = self._get_port_vnic_id(vnic_idx, device_id)
                        self._add_member_to_security_group(sg_id, vnic_id)
                    except Exception as e:
                        LOG.info(_LI('Could not add port %(port)s to service '
                                     'insertion security group. Exception '
                                     '%(err)s'),
                                 {'port': port['id'], 'err': e})

        # Doing this in a separate thread to not slow down the init process
        # in case there are many compute ports
        c_utils.spawn_n(_add_vms_to_service_insertion, sg_id)

    def start_rpc_listeners(self):
        if self.start_rpc_listeners_called:
            # If called more than once - we should not create it again
            return self.conn.consume_in_threads()

        LOG.info(_LI("NSXV plugin: starting RPC listeners"))

        self.endpoints = [agents_db.AgentExtRpcCallback()]
        self.topic = topics.PLUGIN

        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)

        # Add QoS
        qos_topic = resources_rpc.resource_type_versioned_topic(
            callbacks_resources.QOS_POLICY)
        self.conn.create_consumer(
            qos_topic, [resources_rpc.ResourcesPushRpcCallback()],
            fanout=False)

        self.start_rpc_listeners_called = True
        return self.conn.consume_in_threads()

    def _create_security_group_container(self):
        name = "OpenStack Security Group container"
        with locking.LockManager.get_lock('security-group-container-init'):
            container_id = self.nsx_v.vcns.get_security_group_id(name)
            if not container_id:
                description = ("OpenStack Security Group Container, "
                               "managed by Neutron nsx-v plugin.")
                container = {"securitygroup": {"name": name,
                                               "description": description}}
                h, container_id = (
                    self.nsx_v.vcns.create_security_group(container))
            return container_id

    def _find_router_driver(self, context, router_id):
        router_qry = context.session.query(l3_db.Router)
        router_db = router_qry.filter_by(id=router_id).one()
        return self._get_router_driver(context, router_db)

    def _get_router_driver(self, context, router_db):
        router_type_dict = {}
        self._extend_nsx_router_dict(router_type_dict, router_db)
        router_type = None
        if router_type_dict.get("distributed", False):
            router_type = "distributed"
        else:
            router_type = router_type_dict.get("router_type")
        return self._router_managers.get_tenant_router_driver(
            context, router_type)

    def _decide_router_type(self, context, r):
        router_type = None
        if (validators.is_attr_set(r.get("distributed")) and
            r.get("distributed")):
            router_type = "distributed"
            if validators.is_attr_set(r.get("router_type")):
                err_msg = _('Can not support router_type extension for '
                            'distributed router')
                raise n_exc.InvalidInput(error_message=err_msg)
        elif validators.is_attr_set(r.get("router_type")):
            router_type = r.get("router_type")

        router_type = self._router_managers.decide_tenant_router_type(
            context, router_type)
        if router_type == "distributed":
            r["distributed"] = True
            r["router_type"] = "exclusive"
        else:
            r["distributed"] = False
            r["router_type"] = router_type

    def _create_cluster_default_fw_section(self):
        section_name = 'OS Cluster Security Group section'

        # Default cluster rules
        rules = [{'name': 'Default DHCP rule for OS Security Groups',
                  'action': 'allow',
                  'services': [('17', '67', None, None),
                               ('17', '68', None, None)]},
                 {'name': 'ICMPv6 neighbor protocol for Security Groups',
                  'action': 'allow',
                  'services': [('58', None, '135', None),
                               ('58', None, '136', None)]}]

        if cfg.CONF.nsxv.cluster_moid:
            applied_to_ids = cfg.CONF.nsxv.cluster_moid
            applied_to_type = 'ClusterComputeResource'
        else:
            applied_to_ids = [self.sg_container_id]
            applied_to_type = 'SecurityGroup'

        rule_list = []
        for rule in rules:
            rule_config = self.nsx_sg_utils.get_rule_config(
                applied_to_ids, rule['name'], rule['action'],
                applied_to_type, services=rule['services'])
            rule_list.append(rule_config)

        # Default security-group rules
        block_rule = self.nsx_sg_utils.get_rule_config(
            [self.sg_container_id], 'Block All', 'deny',
            logged=cfg.CONF.nsxv.log_security_groups_blocked_traffic)
        rule_list.append(block_rule)

        with locking.LockManager.get_lock('default-section-init'):
            section_id = self.nsx_v.vcns.get_section_id(section_name)
            section = (
                self.nsx_sg_utils.get_section_with_rules(
                    section_name, rule_list, section_id))
            section_req_body = self.nsx_sg_utils.to_xml_string(section)
            if section_id:
                self.nsx_v.vcns.update_section_by_id(
                    section_id, 'ip', section_req_body)
            else:
                # cluster section does not exists. Create it above the
                # default l3 section
                l3_id = self.nsx_v.vcns.get_default_l3_id()
                h, c = self.nsx_v.vcns.create_section('ip', section_req_body,
                                                      insert_before=l3_id)
                section_id = self.nsx_sg_utils.parse_and_get_section_id(c)
        return section_id

    def _process_security_groups_rules_logging(self):

        def process_security_groups_rules_logging(*args, **kwargs):
            with locking.LockManager.get_lock('nsx-dfw-section',
                                              lock_file_prefix='dfw-section'):
                context = n_context.get_admin_context()
                log_allowed = cfg.CONF.nsxv.log_security_groups_allowed_traffic

                # If the section/sg is already logged, then no action is
                # required.
                for sg in [sg for sg in self.get_security_groups(context)
                           if sg[sg_logging.LOGGING] is False]:
                    section_uri = self._get_section_uri(context.session,
                                                        sg['id'])
                    if section_uri is None:
                        continue

                    # Section/sg is not logged, update rules logging according
                    # to the 'log_security_groups_allowed_traffic' config
                    # option.
                    try:
                        h, c = self.nsx_v.vcns.get_section(section_uri)
                        section = self.nsx_sg_utils.parse_section(c)
                        section_needs_update = (
                            self.nsx_sg_utils.set_rules_logged_option(
                                section, log_allowed))
                        if section_needs_update:
                            self.nsx_v.vcns.update_section(
                                section_uri,
                                self.nsx_sg_utils.to_xml_string(section), h)
                    except Exception as exc:
                        LOG.error(_LE('Unable to update section for logging. '
                                      '%s'), exc)

        c_utils.spawn_n(process_security_groups_rules_logging)

    def _create_dhcp_static_binding(self, context, neutron_port_db):

        network_id = neutron_port_db['network_id']
        device_owner = neutron_port_db['device_owner']
        if device_owner.startswith("compute"):
            s_bindings = self.edge_manager.create_static_binding(
                context, neutron_port_db)
            self.edge_manager.create_dhcp_bindings(
                    context, neutron_port_db['id'], network_id, s_bindings)

    def _delete_dhcp_static_binding(self, context, neutron_port_db):

        network_id = neutron_port_db['network_id']
        try:
            self.edge_manager.delete_dhcp_binding(
                context, neutron_port_db['id'], network_id,
                neutron_port_db['mac_address'])
        except Exception as e:
            LOG.error(_LE('Unable to delete static bindings for %(id)s. '
                          'Error: %(e)s'),
                      {'id': neutron_port_db['id'], 'e': e})

    def _validate_network_qos(self, network, backend_network):
        err_msg = None
        if validators.is_attr_set(network.get(qos_consts.QOS_POLICY_ID)):
            if not backend_network:
                err_msg = (_("Cannot configure QOS on external networks"))
            if not cfg.CONF.nsxv.use_dvs_features:
                err_msg = (_("Cannot configure QOS "
                             "without enabling use_dvs_features"))

        if err_msg:
            raise n_exc.InvalidInput(error_message=err_msg)

    def _validate_physical_network(self, physical_network):
        dvs_ids = self._get_dvs_ids(physical_network)
        for dvs_id in dvs_ids:
            if not self.nsx_v.vcns.validate_dvs(dvs_id):
                raise nsx_exc.NsxResourceNotFound(res_name='dvs_id',
                                                  res_id=dvs_id)

    def _validate_provider_create(self, context, network):
        if not validators.is_attr_set(network.get(mpnet.SEGMENTS)):
            return

        for segment in network[mpnet.SEGMENTS]:
            network_type = segment.get(pnet.NETWORK_TYPE)
            physical_network = segment.get(pnet.PHYSICAL_NETWORK)
            segmentation_id = segment.get(pnet.SEGMENTATION_ID)
            network_type_set = validators.is_attr_set(network_type)
            segmentation_id_set = validators.is_attr_set(segmentation_id)
            physical_network_set = validators.is_attr_set(physical_network)

            err_msg = None
            if not network_type_set:
                err_msg = _("%s required") % pnet.NETWORK_TYPE
            elif network_type == c_utils.NsxVNetworkTypes.FLAT:
                if segmentation_id_set:
                    err_msg = _("Segmentation ID cannot be specified with "
                                "flat network type")
                if physical_network_set:
                    self._validate_physical_network(physical_network)
            elif network_type == c_utils.NsxVNetworkTypes.VLAN:
                if not segmentation_id_set:
                    err_msg = _("Segmentation ID must be specified with "
                                "vlan network type")
                elif (segmentation_id_set and
                      not utils.is_valid_vlan_tag(segmentation_id)):
                    err_msg = (_("%(segmentation_id)s out of range "
                                 "(%(min_id)s through %(max_id)s)") %
                               {'segmentation_id': segmentation_id,
                                'min_id': plugin_const.MIN_VLAN_TAG,
                                'max_id': plugin_const.MAX_VLAN_TAG})
                else:
                    # Verify segment is not already allocated
                    bindings = nsxv_db.get_network_bindings_by_vlanid(
                        context.session, segmentation_id)
                    if bindings:
                        phy_uuid = (physical_network if physical_network_set
                                    else self.dvs_id)
                        for binding in bindings:
                            if binding['phy_uuid'] == phy_uuid:
                                raise n_exc.VlanIdInUse(
                                    vlan_id=segmentation_id,
                                    physical_network=phy_uuid)
                # Verify whether the DVSes exist in the backend.
                if physical_network_set:
                    self._validate_physical_network(physical_network)

            elif network_type == c_utils.NsxVNetworkTypes.VXLAN:
                # Currently unable to set the segmentation id
                if segmentation_id_set:
                    err_msg = _("Segmentation ID cannot be set with VXLAN")
            elif network_type == c_utils.NsxVNetworkTypes.PORTGROUP:
                external = network.get(ext_net_extn.EXTERNAL)
                if segmentation_id_set:
                    err_msg = _("Segmentation ID cannot be set with portgroup")
                if not physical_network_set:
                    err_msg = _("Physical network must be set!")
                elif not self.nsx_v.vcns.validate_network(physical_network):
                    err_msg = _("Physical network doesn't exist")
                # A provider network portgroup will need the network name to
                # match the portgroup name
                elif ((not validators.is_attr_set(external) or
                       validators.is_attr_set(external) and not external) and
                      not self.nsx_v.vcns.validate_network_name(
                          physical_network, network['name'])):
                    err_msg = _("Portgroup name must match network name")
            else:
                err_msg = (_("%(net_type_param)s %(net_type_value)s not "
                             "supported") %
                           {'net_type_param': pnet.NETWORK_TYPE,
                            'net_type_value': network_type})
            if err_msg:
                raise n_exc.InvalidInput(error_message=err_msg)
            # TODO(salvatore-orlando): Validate tranport zone uuid
            # which should be specified in physical_network

    def _extend_network_dict_provider(self, context, network,
                                      multiprovider=None, bindings=None):
        if not bindings:
            bindings = nsxv_db.get_network_bindings(context.session,
                                                    network['id'])
        if not multiprovider:
            multiprovider = nsx_db.is_multiprovider_network(context.session,
                                                            network['id'])
        # With NSX plugin 'normal' overlay networks will have no binding
        # TODO(salvatore-orlando) make sure users can specify a distinct
        # phy_uuid as 'provider network' for STT net type
        if bindings:
            if not multiprovider:
                # network came in through provider networks api
                network[pnet.NETWORK_TYPE] = bindings[0].binding_type
                network[pnet.PHYSICAL_NETWORK] = bindings[0].phy_uuid
                network[pnet.SEGMENTATION_ID] = bindings[0].vlan_id
            else:
                # network come in though multiprovider networks api
                network[mpnet.SEGMENTS] = [
                    {pnet.NETWORK_TYPE: binding.binding_type,
                     pnet.PHYSICAL_NETWORK: binding.phy_uuid,
                     pnet.SEGMENTATION_ID: binding.vlan_id}
                    for binding in bindings]

        # update availability zones
        network[az_ext.AVAILABILITY_ZONES] = (
            self.get_network_availability_zones(context, network))

    def _get_subnet_as_providers(self, context, subnet, nw_dict=None):
        net_id = subnet.get('network_id')
        if net_id is None:
            net_id = self.get_subnet(context, subnet['id']).get('network_id')

        if nw_dict:
            providers = nw_dict.get(net_id, [])
        else:
            as_provider_data = nsxv_db.get_edge_vnic_bindings_by_int_lswitch(
                context.session, net_id)
            providers = [asp['edge_id'] for asp in as_provider_data]
        return providers

    def get_subnet(self, context, id, fields=None):
        subnet = super(NsxVPluginV2, self).get_subnet(context, id, fields)

        if not context.is_admin:
            return subnet
        elif fields and as_providers.ADV_SERVICE_PROVIDERS in fields:
            subnet[as_providers.ADV_SERVICE_PROVIDERS] = (
                self._get_subnet_as_providers(context, subnet))
        return subnet

    def get_subnets(self, context, filters=None, fields=None, sorts=None,
                    limit=None, marker=None, page_reverse=False):
        subnets = super(NsxVPluginV2, self).get_subnets(context, filters,
                                                        fields, sorts, limit,
                                                        marker, page_reverse)

        if not context.is_admin or (not filters and not fields):
            return subnets

        new_subnets = []
        if ((fields and as_providers.ADV_SERVICE_PROVIDERS in fields)
            or (filters and filters.get(as_providers.ADV_SERVICE_PROVIDERS))):

            # This ugly mess should reduce DB calls with network_id field
            # as filter - as network_id is not indexed
            vnic_binds = nsxv_db.get_edge_vnic_bindings_with_networks(
                context.session)
            nw_dict = {}
            for vnic_bind in vnic_binds:
                if nw_dict.get(vnic_bind['network_id']):
                    nw_dict[vnic_bind['network_id']].append(
                        vnic_bind['edge_id'])
                else:
                    nw_dict[vnic_bind['network_id']] = [vnic_bind['edge_id']]

            # We only deal metadata provider field when:
            # - adv_service_provider is explicitly retrieved
            # - adv_service_provider is used in a filter
            for subnet in subnets:
                as_provider = self._get_subnet_as_providers(
                    context, subnet, nw_dict)
                md_filter = (
                    None if filters is None
                    else filters.get(as_providers.ADV_SERVICE_PROVIDERS))

                if md_filter is None or len(set(as_provider) & set(md_filter)):
                    # Include metadata_providers only if requested in results
                    if fields and as_providers.ADV_SERVICE_PROVIDERS in fields:
                        subnet[as_providers.ADV_SERVICE_PROVIDERS] = (
                            as_provider)

                    new_subnets.append(subnet)
        else:
            # No need to handle metadata providers field
            return subnets

        return new_subnets

    def _convert_to_transport_zones_dict(self, network):
        """Converts the provider request body to multiprovider.
        Returns: True if request is multiprovider False if provider
        and None if neither.
        """
        if any(validators.is_attr_set(network.get(f))
               for f in (pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                         pnet.SEGMENTATION_ID)):
            if validators.is_attr_set(network.get(mpnet.SEGMENTS)):
                raise mpnet.SegmentsSetInConjunctionWithProviders()
            # convert to transport zone list
            network[mpnet.SEGMENTS] = [
                {pnet.NETWORK_TYPE: network[pnet.NETWORK_TYPE],
                 pnet.PHYSICAL_NETWORK: network[pnet.PHYSICAL_NETWORK],
                 pnet.SEGMENTATION_ID: network[pnet.SEGMENTATION_ID]}]
            del network[pnet.NETWORK_TYPE]
            del network[pnet.PHYSICAL_NETWORK]
            del network[pnet.SEGMENTATION_ID]
            return False
        if validators.is_attr_set(network.get(mpnet.SEGMENTS)):
            return True

    def _delete_backend_network(self, moref):
        """Deletes the backend NSX network.

        This can either be a VXLAN or a VLAN network. The type is determined
        by the prefix of the moref.
        """
        if moref.startswith(PORTGROUP_PREFIX):
            self.nsx_v.delete_port_group(self.dvs_id, moref)
        else:
            self.nsx_v.delete_virtual_wire(moref)

    def _get_vlan_network_name(self, net_data, dvs_id):
        if net_data.get('name') is None:
            net_data['name'] = ''
        if net_data['name'] == '':
            # Include only the first 8 characters from the dvs-id.
            return '%s-%s' % (dvs_id[:8], net_data['id'])
        else:
            # Maximum name length is 80 characters. 'id' length is 36
            # maximum prefix for name plus dvs-id is 43
            return '%s-%s-%s' % (dvs_id[:8], net_data['name'][:35],
                                 net_data['id'])

    def _create_vlan_network_at_backend(self, net_data, dvs_id):
        network_name = self._get_vlan_network_name(net_data, dvs_id)
        segment = net_data[mpnet.SEGMENTS][0]
        vlan_tag = 0
        if (segment.get(pnet.NETWORK_TYPE) ==
            c_utils.NsxVNetworkTypes.VLAN):
            vlan_tag = segment.get(pnet.SEGMENTATION_ID, 0)
        portgroup = {'vlanId': vlan_tag,
                     'networkBindingType': 'Static',
                     'networkName': network_name,
                     'networkType': 'Isolation'}
        config_spec = {'networkSpec': portgroup}
        try:
            h, c = self.nsx_v.vcns.create_port_group(dvs_id,
                                                     config_spec)
            return c
        except Exception as e:
            error = (_("Failed to create port group on DVS: %(dvs_id)s. "
                       "Reason: %(reason)s") % {'dvs_id': dvs_id,
                                                'reason': e.response})
            raise nsx_exc.NsxPluginException(err_msg=error)

    def _get_dvs_ids(self, physical_network):
        """Extract DVS-IDs provided in the physical network field.

        If physical network attribute is not set, return the pre configured
        dvs-id from nsx.ini file, otherwise convert physical network string
        to a list of unique DVS-IDs.
        """
        if not validators.is_attr_set(physical_network):
            return [self.dvs_id]
        # Return unique DVS-IDs only and ignore duplicates
        return list(set(
            dvs.strip() for dvs in physical_network.split(',') if dvs))

    def _get_default_security_group(self, context, tenant_id):
        return self._ensure_default_security_group(context, tenant_id)

    def _add_member_to_security_group(self, sg_id, vnic_id):
        with locking.LockManager.get_lock('neutron-security-ops' + str(sg_id)):
            try:
                self.nsx_v.vcns.add_member_to_security_group(
                    sg_id, vnic_id)
                LOG.info(_LI("Added %(sg_id)s member to NSX security "
                             "group %(vnic_id)s"),
                         {'sg_id': sg_id, 'vnic_id': vnic_id})
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("NSX security group %(sg_id)s member add "
                                  "failed %(vnic_id)s."),
                              {'sg_id': sg_id,
                               'vnic_id': vnic_id})

    def _add_security_groups_port_mapping(self, session, vnic_id,
                                          added_sgids):
        if vnic_id is None or added_sgids is None:
            return
        for add_sg in added_sgids:
            nsx_sg_id = nsx_db.get_nsx_security_group_id(session, add_sg)
            if nsx_sg_id is None:
                LOG.warning(_LW("NSX security group not found for %s"), add_sg)
            else:
                self._add_member_to_security_group(nsx_sg_id, vnic_id)

    def _remove_member_from_security_group(self, sg_id, vnic_id):
        with locking.LockManager.get_lock('neutron-security-ops' + str(sg_id)):
            try:
                h, c = self.nsx_v.vcns.remove_member_from_security_group(
                    sg_id, vnic_id)
            except Exception:
                LOG.debug("NSX security group %(nsx_sg_id)s member "
                          "delete failed %(vnic_id)s",
                          {'nsx_sg_id': sg_id,
                           'vnic_id': vnic_id})

    def _delete_security_groups_port_mapping(self, session, vnic_id,
                                             deleted_sgids):
        if vnic_id is None or deleted_sgids is None:
            return
        # Remove vnic from delete security groups binding
        for del_sg in deleted_sgids:
            nsx_sg_id = nsx_db.get_nsx_security_group_id(session, del_sg)
            if nsx_sg_id is None:
                LOG.warning(_LW("NSX security group not found for %s"), del_sg)
            else:
                self._remove_member_from_security_group(nsx_sg_id, vnic_id)

    def _update_security_groups_port_mapping(self, session, port_id,
                                             vnic_id, current_sgids,
                                             new_sgids):

        new_sgids = new_sgids or []
        current_sgids = current_sgids or []
        # If no vnic binding is found, nothing can be done, so return
        if vnic_id is None:
            return
        deleted_sgids = set()
        added_sgids = set()
        # Find all delete security group from port binding
        for curr_sg in current_sgids:
            if curr_sg not in new_sgids:
                deleted_sgids.add(curr_sg)
        # Find all added security group from port binding
        for new_sg in new_sgids:
            if new_sg not in current_sgids:
                added_sgids.add(new_sg)

        self._delete_security_groups_port_mapping(session, vnic_id,
                                                  deleted_sgids)
        self._add_security_groups_port_mapping(session, vnic_id,
                                               added_sgids)

    def _get_port_vnic_id(self, port_index, device_id):
        # The vnic-id format which is expected by NSXv
        return '%s.%03d' % (device_id, port_index)

    def _list_availability_zones(self, context, filters=None):
        #TODO(asarfaty): We may need to use the filters arg, but now it
        # is here only for overriding the original api
        result = {}
        for az in self._availability_zones_data.list_availability_zones():
            # Add this availability zone as a router & network resource
            for resource in ('router', 'network'):
                result[(az, resource)] = True
        return result

    def _validate_availability_zones_in_obj(self, context, resource_type,
                                           obj_data):
        if az_ext.AZ_HINTS in obj_data:
            self.validate_availability_zones(context, resource_type,
                                             obj_data[az_ext.AZ_HINTS])

    def validate_availability_zones(self, context, resource_type,
                                    availability_zones):
        """Verify that the availability zones exist, and only 1 hint
        was set.
        """
        # For now we support only 1 hint per network/router
        # TODO(asarfaty): support multiple hints
        if len(availability_zones) > 1:
            err_msg = _("Can't use multiple availability zone hints")
            raise n_exc.InvalidInput(error_message=err_msg)

        # check that all hints appear in the predefined list of availability
        # zones
        diff = (set(availability_zones) -
                set(self._availability_zones_data.list_availability_zones()))
        if diff:
            raise az_ext.AvailabilityZoneNotFound(
                availability_zone=diff.pop())

    def get_network_or_router_az(self, object):
        if az_ext.AZ_HINTS in object:
            for hint in object[az_ext.AZ_HINTS]:
                # For now we use only the first hint
                return self.get_az_by_hint(hint)

        # return the default
        return self.get_default_az()

    def get_network_az(self, context, network_id):
        network = self.get_network(context, network_id)
        return self.get_network_or_router_az(network)

    def get_router_az(self, router):
        return self.get_network_or_router_az(router)

    def _prepare_spoofguard_policy(self, network_type, net_data, net_morefs):
        # The method will determine if a portgroup is already assigned to a
        # spoofguard policy. If so, it will return the predefined policy. If
        # not a new spoofguard policy will be created
        if network_type == c_utils.NsxVNetworkTypes.PORTGROUP:
            pcs = self.nsx_v.vcns.get_spoofguard_policies()[1].get('policies',
                                                                   [])
            for policy in pcs:
                for ep in policy['enforcementPoints']:
                    if ep['id'] == net_morefs[0]:
                        return policy['policyId'], True
        sg_policy_id = self.nsx_v.vcns.create_spoofguard_policy(
                net_morefs, net_data['id'], net_data[psec.PORTSECURITY])[1]
        return sg_policy_id, False

    def create_network(self, context, network):
        net_data = network['network']
        tenant_id = net_data['tenant_id']
        self._ensure_default_security_group(context, tenant_id)
        # Process the provider network extension
        provider_type = self._convert_to_transport_zones_dict(net_data)
        self._validate_provider_create(context, net_data)
        self._validate_availability_zones_in_obj(context, 'network', net_data)
        net_data['id'] = str(uuid.uuid4())

        external = net_data.get(ext_net_extn.EXTERNAL)
        backend_network = (not validators.is_attr_set(external) or
                           validators.is_attr_set(external) and not external)
        self._validate_network_qos(net_data, backend_network)

        network_type = None
        if backend_network:
            #NOTE(abhiraut): Consider refactoring code below to have more
            #                readable conditions.
            if provider_type is not None:
                segment = net_data[mpnet.SEGMENTS][0]
                network_type = segment.get(pnet.NETWORK_TYPE)

            if (provider_type is None or
                network_type == c_utils.NsxVNetworkTypes.VXLAN):
                virtual_wire = {"name": net_data['id'],
                                "tenantId": "virtual wire tenant"}
                config_spec = {"virtualWireCreateSpec": virtual_wire}
                vdn_scope_id = self.vdn_scope_id
                if provider_type is not None:
                    segment = net_data[mpnet.SEGMENTS][0]
                    if validators.is_attr_set(
                        segment.get(pnet.PHYSICAL_NETWORK)):
                        vdn_scope_id = segment.get(pnet.PHYSICAL_NETWORK)
                        if not (self.nsx_v.vcns.
                                validate_vdn_scope(vdn_scope_id)):
                            raise nsx_exc.NsxResourceNotFound(
                                res_name=pnet.PHYSICAL_NETWORK,
                                res_id=vdn_scope_id)
                h, c = self.nsx_v.vcns.create_virtual_wire(vdn_scope_id,
                                                           config_spec)
                net_morefs = [c]
                dvs_net_ids = [net_data['id']]
            elif network_type == c_utils.NsxVNetworkTypes.PORTGROUP:
                segment = net_data[mpnet.SEGMENTS][0]
                net_morefs = [segment.get(pnet.PHYSICAL_NETWORK)]
                dvs_net_ids = [net_data['name']]
            else:
                segment = net_data[mpnet.SEGMENTS][0]
                physical_network = segment.get(pnet.PHYSICAL_NETWORK)
                # Retrieve the list of dvs-ids from physical network.
                # If physical_network attr is not set, retrieve a list
                # consisting of a single dvs-id pre-configured in nsx.ini
                dvs_ids = self._get_dvs_ids(physical_network)
                dvs_net_ids = []
                # Save the list of netmorefs from the backend
                net_morefs = []
                dvs_pg_mappings = {}
                for dvs_id in dvs_ids:
                    try:
                        net_moref = self._create_vlan_network_at_backend(
                            dvs_id=dvs_id,
                            net_data=net_data)
                    except nsx_exc.NsxPluginException:
                        with excutils.save_and_reraise_exception():
                            # Delete VLAN networks on other DVSes if it
                            # fails to be created on one DVS and reraise
                            # the original exception.
                            for net_moref in net_morefs:
                                self._delete_backend_network(net_moref)
                    dvs_pg_mappings[dvs_id] = net_moref
                    net_morefs.append(net_moref)
                    dvs_net_ids.append(self._get_vlan_network_name(
                        net_data, dvs_id))
        try:
            net_data[psec.PORTSECURITY] = net_data.get(psec.PORTSECURITY, True)
            # Create SpoofGuard policy for network anti-spoofing
            if cfg.CONF.nsxv.spoofguard_enabled and backend_network:
                # This variable is set as the method below may result in a
                # exception and we may need to rollback
                sg_policy_id = None
                predefined = False
                sg_policy_id, predefined = self._prepare_spoofguard_policy(
                    network_type, net_data, net_morefs)
            with context.session.begin(subtransactions=True):
                new_net = super(NsxVPluginV2, self).create_network(context,
                                                                   network)
                # Process port security extension
                self._process_network_port_security_create(
                    context, net_data, new_net)

                # update the network with the availability zone hints
                if az_ext.AZ_HINTS in net_data:
                    self.validate_availability_zones(context, 'network',
                                                     net_data[az_ext.AZ_HINTS])
                    az_hints = az_ext.convert_az_list_to_string(
                                                    net_data[az_ext.AZ_HINTS])
                    super(NsxVPluginV2, self).update_network(context,
                        new_net['id'],
                        {'network': {az_ext.AZ_HINTS: az_hints}})
                    new_net[az_ext.AZ_HINTS] = az_hints
                    # still no availability zones until subnets creation
                    new_net[az_ext.AVAILABILITY_ZONES] = []

                # DB Operations for setting the network as external
                self._process_l3_create(context, new_net, net_data)
                if (net_data.get(mpnet.SEGMENTS) and
                    isinstance(provider_type, bool)):
                    net_bindings = []
                    for tz in net_data[mpnet.SEGMENTS]:
                        network_type = tz.get(pnet.NETWORK_TYPE)
                        segmentation_id = tz.get(pnet.SEGMENTATION_ID, 0)
                        segmentation_id_set = validators.is_attr_set(
                            segmentation_id)
                        if not segmentation_id_set:
                            segmentation_id = 0
                        physical_network = tz.get(pnet.PHYSICAL_NETWORK, '')
                        physical_net_set = validators.is_attr_set(
                            physical_network)
                        if not physical_net_set:
                            physical_network = self.dvs_id
                        net_bindings.append(nsxv_db.add_network_binding(
                            context.session, new_net['id'],
                            network_type,
                            physical_network,
                            segmentation_id))
                    if provider_type:
                        nsx_db.set_multiprovider_network(context.session,
                                                         new_net['id'])
                    self._extend_network_dict_provider(context, new_net,
                                                       provider_type,
                                                       net_bindings)
                if backend_network:
                    # Save moref in the DB for future access
                    if network_type == c_utils.NsxVNetworkTypes.VLAN:
                        # Save netmoref to dvs id mappings for VLAN network
                        # type for future access.
                        for dvs_id, netmoref in six.iteritems(dvs_pg_mappings):
                            nsx_db.add_neutron_nsx_network_mapping(
                                session=context.session,
                                neutron_id=new_net['id'],
                                nsx_switch_id=netmoref,
                                dvs_id=dvs_id)
                    else:
                        for net_moref in net_morefs:
                            nsx_db.add_neutron_nsx_network_mapping(
                                context.session, new_net['id'],
                                net_moref)
                    if cfg.CONF.nsxv.spoofguard_enabled:
                        nsxv_db.map_spoofguard_policy_for_network(
                            context.session, new_net['id'], sg_policy_id)

        except Exception:
            with excutils.save_and_reraise_exception():
                # Delete the backend network
                if backend_network:
                    if (cfg.CONF.nsxv.spoofguard_enabled and sg_policy_id and
                        not predefined):
                        self.nsx_v.vcns.delete_spoofguard_policy(sg_policy_id)
                    # Ensure that an predefined portgroup will not be deleted
                    if network_type != c_utils.NsxVNetworkTypes.PORTGROUP:
                        for net_moref in net_morefs:
                            self._delete_backend_network(net_moref)
                LOG.exception(_LE('Failed to create network'))

        # If init is incomplete calling _update_qos_network() will result a
        # deadlock.
        # That situation happens when metadata init is creating a network
        # on its 1st execution.
        # Therefore we skip this code during init.
        if backend_network and self.init_is_complete:
            # Update the QOS restrictions of the backend network
            self._update_network_qos(context, net_data, dvs_net_ids, net_moref)
            new_net[qos_consts.QOS_POLICY_ID] = (
                qos_com_utils.get_network_policy_id(context, new_net['id']))

        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        net_model = self._get_network(context, new_net['id'])
        self._apply_dict_extend_functions('networks', new_net, net_model)
        return new_net

    def _update_network_qos(self, context, net_data, dvs_net_ids, net_moref):
        if validators.is_attr_set(net_data.get(qos_consts.QOS_POLICY_ID)):
            # Translate the QoS rule data into Nsx values
            qos_data = qos_utils.NsxVQosRule(
                context=context,
                qos_policy_id=net_data[qos_consts.QOS_POLICY_ID])

            # update the qos data on the dvs
            for dvs_net_id in dvs_net_ids:
                self._dvs.update_port_groups_config(
                    dvs_net_id,
                    net_moref,
                    self._dvs.update_port_group_spec_qos, qos_data)

            # attach the policy to the network in the neutron DB
            qos_com_utils.update_network_policy_binding(
                context,
                net_data['id'],
                net_data[qos_consts.QOS_POLICY_ID])

    def _cleanup_dhcp_edge_before_deletion(self, context, net_id):
        if self.metadata_proxy_handler:
            # Find if this is the last network which is bound
            # to DHCP Edge. If it is - cleanup Edge metadata config
            dhcp_edge = nsxv_db.get_dhcp_edge_network_binding(
                context.session, net_id)

            if dhcp_edge:
                edge_vnics = nsxv_db.get_edge_vnic_bindings_by_edge(
                    context.session, dhcp_edge['edge_id'])

                # If the DHCP Edge is connected to two networks:
                # the delete network and the inter-edge network, we can delete
                # the inter-edge interface
                if len(edge_vnics) == 2:
                    rtr_binding = nsxv_db.get_nsxv_router_binding_by_edge(
                        context.session, dhcp_edge['edge_id'])
                    if rtr_binding:
                        rtr_id = rtr_binding['router_id']
                        self.metadata_proxy_handler.cleanup_router_edge(
                            context, rtr_id)

    def _update_dhcp_edge_service(self, context, network_id, address_groups):
        self.edge_manager.update_dhcp_edge_service(
            context, network_id, address_groups=address_groups)

    def _delete_dhcp_edge_service(self, context, id):
        self.edge_manager.delete_dhcp_edge_service(context, id)

    def _is_neutron_spoofguard_policy(self, net_id, moref, policy_id):
        # A neutron policy will have the network UUID as the name of the
        # policy
        try:
            policy = self.nsx_v.vcns.get_spoofguard_policy(policy_id)[1]
        except Exception:
            LOG.error(_LE("Policy does not exists for %s"), policy_id)
            # We will not attempt to delete a policy that does not exist
            return False
        if policy:
            for ep in policy['enforcementPoints']:
                if ep['id'] == moref and policy['name'] == net_id:
                    return True
        return False

    def delete_network(self, context, id):
        mappings = nsx_db.get_nsx_switch_ids(context.session, id)
        bindings = nsxv_db.get_network_bindings(context.session, id)
        if cfg.CONF.nsxv.spoofguard_enabled:
            sg_policy_id = nsxv_db.get_spoofguard_policy_id(
                context.session, id)

        # Update the DHCP edge for metadata and clean the vnic in DHCP edge
        # if there is only no other existing port besides DHCP port
        filters = {'network_id': [id]}
        ports = self.get_ports(context, filters=filters)
        auto_del = all(p['device_owner'] in [constants.DEVICE_OWNER_DHCP]
                       for p in ports)
        is_dhcp_backend_deleted = False
        if auto_del:
            filters = {'network_id': [id], 'enable_dhcp': [True]}
            sids = self.get_subnets(context, filters=filters, fields=['id'])
            if len(sids) > 0:
                try:
                    self._cleanup_dhcp_edge_before_deletion(context, id)
                    self._delete_dhcp_edge_service(context, id)
                    is_dhcp_backend_deleted = True
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_LE('Failed to delete network'))

        with context.session.begin(subtransactions=True):
            self._process_l3_delete(context, id)
            # We would first delete subnet db if the backend dhcp service is
            # deleted in case of entering delete_subnet logic and retrying
            # to delete backend dhcp service again.
            if is_dhcp_backend_deleted:
                subnets = self._get_subnets_by_network(context, id)
                for subnet in subnets:
                    super(NsxVPluginV2, self).delete_subnet(
                        context, subnet['id'])
            super(NsxVPluginV2, self).delete_network(context, id)

        # Do not delete a predefined port group that was attached to
        # an external network
        if (bindings and
            bindings[0].binding_type == c_utils.NsxVNetworkTypes.PORTGROUP):
            if cfg.CONF.nsxv.spoofguard_enabled and sg_policy_id:
                if self._is_neutron_spoofguard_policy(id, mappings[0],
                                                      sg_policy_id):
                    self.nsx_v.vcns.delete_spoofguard_policy(sg_policy_id)
            return

        # Delete the backend network if necessary. This is done after
        # the base operation as that may throw an exception in the case
        # that there are ports defined on the network.
        if mappings:
            if cfg.CONF.nsxv.spoofguard_enabled and sg_policy_id:
                self.nsx_v.vcns.delete_spoofguard_policy(sg_policy_id)
            edge_utils.check_network_in_use_at_backend(context, id)
            for mapping in mappings:
                self._delete_backend_network(mapping)

    def _extend_get_network_dict_provider(self, context, net):
        self._extend_network_dict_provider(context, net)
        net[qos_consts.QOS_POLICY_ID] = qos_com_utils.get_network_policy_id(
            context, net['id'])

    def get_network(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            # goto to the plugin DB and fetch the network
            network = self._get_network(context, id)
            # Don't do field selection here otherwise we won't be able
            # to add provider networks fields
            net_result = self._make_network_dict(network,
                                                 context=context)
            self._extend_get_network_dict_provider(context, net_result)
        return self._fields(net_result, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        filters = filters or {}
        with context.session.begin(subtransactions=True):
            networks = (
                super(NsxVPluginV2, self).get_networks(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            for net in networks:
                self._extend_get_network_dict_provider(context, net)
        return (networks if not fields else
                [self._fields(network, fields) for network in networks])

    def update_network(self, context, id, network):
        net_attrs = network['network']
        original_network = self.get_network(context, id)

        pnet._raise_if_updates_provider_attributes(net_attrs)
        if net_attrs.get("admin_state_up") is False:
            raise NotImplementedError(_("admin_state_up=False networks "
                                        "are not supported."))
        net_morefs = nsx_db.get_nsx_switch_ids(context.session, id)
        backend_network = True if len(net_morefs) > 0 else False
        self._validate_network_qos(net_attrs, backend_network)

        # PortSecurity validation checks
        # TODO(roeyc): enacapsulate validation in a method
        psec_update = (psec.PORTSECURITY in net_attrs and
                       original_network[psec.PORTSECURITY] !=
                       net_attrs[psec.PORTSECURITY])
        if psec_update and not net_attrs[psec.PORTSECURITY]:
            LOG.warning(_LW("Disabling port-security on network %s would "
                            "require instance in the network to have VM tools "
                            "installed in order for security-groups to "
                            "function properly."))

        with context.session.begin(subtransactions=True):
            net_res = super(NsxVPluginV2, self).update_network(context, id,
                                                               network)
            self._process_network_port_security_update(
                context, net_attrs, net_res)
            self._process_l3_update(context, net_res, net_attrs)
            self._extend_network_dict_provider(context, net_res)

        # Updating SpoofGuard policy if exists, on failure revert to network
        # old state
        if cfg.CONF.nsxv.spoofguard_enabled and psec_update:
            policy_id = nsxv_db.get_spoofguard_policy_id(context.session, id)
            try:
                self.nsx_v.vcns.update_spoofguard_policy(
                    policy_id, net_morefs, id,
                    net_attrs[psec.PORTSECURITY])
            except Exception:
                with excutils.save_and_reraise_exception():
                    revert_update = self._fields(original_network,
                                                 ['shared', psec.PORTSECURITY])
                    self._process_network_port_security_update(
                        context, revert_update, net_res)
                    super(NsxVPluginV2, self).update_network(
                        context, id, {'network': revert_update})

        # Handle QOS updates (Value can be None, meaning to delete the
        # current policy)
        if qos_consts.QOS_POLICY_ID in net_attrs:
            # update the qos data
            qos_data = qos_utils.NsxVQosRule(
                context=context,
                qos_policy_id=net_attrs[qos_consts.QOS_POLICY_ID])

            # get the network moref/s from the db
            for moref in net_morefs:
                # update the qos restrictions of the network
                self._dvs.update_port_groups_config(
                    id, moref, self._dvs.update_port_group_spec_qos, qos_data)

                # attach the policy to the network in neutron DB
                qos_com_utils.update_network_policy_binding(
                    context, id, net_attrs[qos_consts.QOS_POLICY_ID])

            net_res[qos_consts.QOS_POLICY_ID] = (
                qos_com_utils.get_network_policy_id(context, id))

        return net_res

    def _validate_address_pairs(self, attrs, db_port):
        for ap in attrs[addr_pair.ADDRESS_PAIRS]:
            # Check that the IP address is a subnet
            if len(ap['ip_address'].split('/')) > 1:
                msg = _('NSXv does not support CIDR as address pairs')
                raise n_exc.BadRequest(resource='address_pairs', msg=msg)
            # Check that the MAC address is the same as the port
            if ('mac_address' in ap and
                ap['mac_address'] != db_port['mac_address']):
                msg = _('Address pairs should have same MAC as the port')
                raise n_exc.BadRequest(resource='address_pairs', msg=msg)

    @db_api.retry_db_errors
    def base_create_port(self, context, port):
        return super(NsxVPluginV2, self).create_port(context, port)

    def create_port(self, context, port):
        port_data = port['port']
        with context.session.begin(subtransactions=True):
            # First we allocate port in neutron database
            neutron_db = super(NsxVPluginV2, self).create_port(context, port)
            # Port port-security is decided by the port-security state on the
            # network it belongs to, unless specifically specified here
            if validators.is_attr_set(port_data.get(psec.PORTSECURITY)):
                port_security = port_data[psec.PORTSECURITY]
            else:
                port_security = self._get_network_security_binding(
                    context, neutron_db['network_id'])
                port_data[psec.PORTSECURITY] = port_security

            self._process_port_port_security_create(
                context, port_data, neutron_db)
            # Update fields obtained from neutron db (eg: MAC address)
            port["port"].update(neutron_db)
            has_ip = self._ip_on_port(neutron_db)
            provider_sg_specified = (validators.is_attr_set(
                port_data.get(provider_sg.PROVIDER_SECURITYGROUPS))
                and port_data[provider_sg.PROVIDER_SECURITYGROUPS] != [])
            has_security_groups = (
                self._check_update_has_security_groups(port))

            # allowed address pair checks
            attrs = port[attr.PORT]
            if self._check_update_has_allowed_address_pairs(port):
                if not port_security:
                    raise addr_pair.AddressPairAndPortSecurityRequired()
                self._validate_address_pairs(attrs, neutron_db)
            else:
                # remove ATTR_NOT_SPECIFIED
                attrs[addr_pair.ADDRESS_PAIRS] = []

            # security group extension checks
            if has_ip:
                self._ensure_default_security_group_on_port(context, port)
            elif (has_security_groups or provider_sg_specified):
                raise psec.PortSecurityAndIPRequiredForSecurityGroups()
            else:
                port_data[provider_sg.PROVIDER_SECURITYGROUPS] = []

            sgids = self._get_security_groups_on_port(context, port)
            ssgids = self._get_provider_security_groups_on_port(context, port)
            self._process_port_create_security_group(context, port_data, sgids)
            self._process_port_create_provider_security_group(context,
                                                              port_data,
                                                              ssgids)

            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         port_data)
            neutron_db[addr_pair.ADDRESS_PAIRS] = (
                self._process_create_allowed_address_pairs(
                    context, neutron_db,
                    attrs.get(addr_pair.ADDRESS_PAIRS)))

        try:
            # Configure NSX - this should not be done in the DB transaction
            # Configure the DHCP Edge service
            self._create_dhcp_static_binding(context, neutron_db)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Failed to create port'))
                # Revert what we have created and raise the exception
                self.delete_port(context, port_data['id'])

        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        port_model = self._get_port(context, port_data['id'])
        self._apply_dict_extend_functions('ports', port_data, port_model)
        return port_data

    def _get_port_subnet_mask(self, context, port):
        if len(port['fixed_ips']) > 0 and 'subnet_id' in port['fixed_ips'][0]:
            subnet_id = port['fixed_ips'][0]['subnet_id']
            subnet = self._get_subnet(context, subnet_id)
            return str(netaddr.IPNetwork(subnet.cidr).netmask)

    def _get_port_fixed_ip_addr(self, port):
        if (len(port['fixed_ips']) > 0 and
            'ip_address' in port['fixed_ips'][0]):
            return port['fixed_ips'][0]['ip_address']

    def _count_no_sec_ports_for_device_id(self, context, device_id):
        """Find how many compute ports with this device ID and no security
        there are, so we can decide on adding / removing the device from
        the exclusion list
        """
        filters = {'device_id': [device_id],
                   'device_owner': ['compute:None']}
        ports = self.get_ports(context.elevated(), filters=filters)
        return len([p for p in ports
            if validators.is_attr_set(p.get(ext_vnic_idx.VNIC_INDEX))
            and not p[psec.PORTSECURITY]])

    def _add_vm_to_exclude_list(self, context, device_id, port_id):
        if (self._dvs and
            cfg.CONF.nsxv.use_exclude_list):
            # first time for this vm (we expect the count to be 1 already
            # because the DB was already updated)
            if (self._count_no_sec_ports_for_device_id(
                    context, device_id) <= 1):
                vm_moref = self._dvs.get_vm_moref(device_id)
                if vm_moref is not None:
                    try:
                        LOG.info(_LI("Add VM %(dev)s to exclude list on "
                                     "behalf of port %(port)s: added to "
                                     "list"),
                                 {"dev": device_id, "port": port_id})
                        self.nsx_v.vcns.add_vm_to_exclude_list(vm_moref)
                    except vsh_exc.RequestBad as e:
                        LOG.error(_LE("Failed to add vm %(device)s "
                                      "moref %(moref)s to exclude list: "
                                      "%(err)s"),
                                  {'device': device_id, 'moref': vm_moref,
                                   'err': e})
            else:
                LOG.info(_LI("Add VM %(dev)s to exclude list on behalf of "
                             "port %(port)s: already in list"),
                         {"dev": device_id, "port": port_id})

    def _remove_vm_from_exclude_list(self, context, device_id, port_id,
                                     expected_count=0):
        if (self._dvs and
            cfg.CONF.nsxv.use_exclude_list):
            # No ports left in DB (expected count is 0 or 1 depending
            # on whether the DB was already updated),
            # So we can remove it from the backend exclude list
            if (self._count_no_sec_ports_for_device_id(
                    context, device_id) <= expected_count):
                vm_moref = self._dvs.get_vm_moref(device_id)
                if vm_moref is not None:
                    try:
                        LOG.info(_LI("Remove VM %(dev)s from exclude list on "
                                     "behalf of port %(port)s: removed from "
                                     "list"),
                                 {"dev": device_id, "port": port_id})
                        self.nsx_v.vcns.delete_vm_from_exclude_list(vm_moref)
                    except vsh_exc.RequestBad as e:
                        LOG.error(_LE("Failed to delete vm %(device)s "
                                      "moref %(moref)s from exclude list: "
                                      "%(err)s"),
                                  {'device': device_id, 'moref': vm_moref,
                                   'err': e})
            else:
                LOG.info(_LI("Remove VM %(dev)s from exclude list on behalf "
                             "of port %(port)s: other ports still in list"),
                         {"dev": device_id, "port": port_id})

    def update_port(self, context, id, port):
        with locking.LockManager.get_lock('port-update-%s' % id):

            original_port = super(NsxVPluginV2, self).get_port(context, id)
            is_compute_port = self._is_compute_port(original_port)
            device_id = original_port['device_id']
            if is_compute_port and device_id:
                # Lock on the device ID to make sure we do not change/delete
                # ports of the same device at the same time
                with locking.LockManager.get_lock(
                    'port-device-%s' % device_id):
                    return self._update_port(context, id, port, original_port,
                                             is_compute_port, device_id)
            else:
                return self._update_port(context, id, port, original_port,
                                         is_compute_port, device_id)

    def _update_port(self, context, id, port, original_port, is_compute_port,
                     device_id):
        attrs = port[attr.PORT]
        port_data = port['port']
        if addr_pair.ADDRESS_PAIRS in attrs:
            self._validate_address_pairs(attrs, original_port)
        orig_has_port_security = (cfg.CONF.nsxv.spoofguard_enabled and
                                  original_port[psec.PORTSECURITY])

        port_ip_change = port_data.get('fixed_ips') is not None
        device_owner_change = port_data.get('device_owner') is not None
        # We do not support updating the port ip and device owner together
        if port_ip_change and device_owner_change:
            msg = (_('Cannot set fixed ips and device owner together for port '
                     '%s') % original_port['id'])
            raise n_exc.BadRequest(resource='port', msg=msg)

        # Check if port security has changed
        port_sec_change = False
        has_port_security = orig_has_port_security
        if (psec.PORTSECURITY in port_data and
            port_data[psec.PORTSECURITY] != original_port[psec.PORTSECURITY]):
            port_sec_change = True
            has_port_security = (cfg.CONF.nsxv.spoofguard_enabled and
                                 port_data[psec.PORTSECURITY])
            # We do not support modification of port security with other
            # parameters (only with security groups) to reduce some of
            # the complications
            if (len(port_data.keys()) > 2 or
                (ext_sg.SECURITYGROUPS not in port_data and
                 len(port_data.keys()) > 1)):
                msg = (_('Cannot set port security together with other '
                         'attributes for port %s') % original_port['id'])
                raise n_exc.BadRequest(resource='port', msg=msg)

        # TODO(roeyc): create a method '_process_vnic_index_update' from the
        # following code block
        # Process update for vnic-index
        vnic_idx = port_data.get(ext_vnic_idx.VNIC_INDEX)
        # Only set the vnic index for a compute VM
        if validators.is_attr_set(vnic_idx) and is_compute_port:
            # Update database only if vnic index was changed
            if original_port.get(ext_vnic_idx.VNIC_INDEX) != vnic_idx:
                self._set_port_vnic_index_mapping(
                    context, id, device_id, vnic_idx)
            vnic_id = self._get_port_vnic_id(vnic_idx, device_id)
            self._add_security_groups_port_mapping(
                context.session, vnic_id,
                original_port[ext_sg.SECURITYGROUPS] +
                original_port[provider_sg.PROVIDER_SECURITYGROUPS])
            if has_port_security:
                LOG.debug("Assigning vnic port fixed-ips: port %s, "
                          "vnic %s, with fixed-ips %s", id, vnic_id,
                          original_port['fixed_ips'])
                self._update_vnic_assigned_addresses(
                    context.session, original_port, vnic_id)
            elif cfg.CONF.nsxv.spoofguard_enabled:
                # Add vm to the exclusion list, since it has no port security
                self._add_vm_to_exclude_list(context, device_id, id)
            # if service insertion is enabled - add this vnic to the service
            # insertion security group
            if self._si_handler.enabled and original_port[psec.PORTSECURITY]:
                self._add_member_to_security_group(self._si_handler.sg_id,
                                                   vnic_id)

        provider_sgs_specified = validators.is_attr_set(
            port_data.get(provider_sg.PROVIDER_SECURITYGROUPS))
        delete_provider_sg = provider_sgs_specified and (
            port_data[provider_sg.PROVIDER_SECURITYGROUPS] != [])
        delete_security_groups = self._check_update_deletes_security_groups(
            port)
        has_security_groups = self._check_update_has_security_groups(port)
        comp_owner_update = ('device_owner' in port_data and
                             port_data['device_owner'].startswith('compute:'))

        with context.session.begin(subtransactions=True):
            ret_port = super(NsxVPluginV2, self).update_port(
                context, id, port)
            # copy values over - except fixed_ips as
            # they've already been processed
            updates_fixed_ips = port['port'].pop('fixed_ips', [])
            ret_port.update(port['port'])
            has_ip = self._ip_on_port(ret_port)

            # checks that if update adds/modify security groups,
            # then port has ip
            if not has_ip:
                if (has_security_groups or provider_sgs_specified):
                        raise psec.PortSecurityAndIPRequiredForSecurityGroups()
                if ((not delete_security_groups
                     and original_port[ext_sg.SECURITYGROUPS]) or
                    (not delete_provider_sg and
                     original_port[provider_sg.PROVIDER_SECURITYGROUPS])):
                        raise psec.PortSecurityAndIPRequiredForSecurityGroups()

            if delete_security_groups or has_security_groups:
                self.update_security_group_on_port(context, id, port,
                                                   original_port, ret_port)
            # NOTE(roeyc): Should call this method only after
            # update_security_group_on_port was called.
            pvd_sg_changed = self._process_port_update_provider_security_group(
                context, port, original_port, ret_port)

            LOG.debug("Updating port: %s", port)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         ret_port)

            update_assigned_addresses = False
            if addr_pair.ADDRESS_PAIRS in attrs:
                update_assigned_addresses = self.update_address_pairs_on_port(
                    context, id, port, original_port, ret_port)

        if comp_owner_update:
            # Create dhcp bindings, the port is now owned by an instance
            self._create_dhcp_static_binding(context, ret_port)
        elif port_ip_change:
            owner = original_port['device_owner']
            # If port IP has changed we should update according to device
            # owner
            if is_compute_port:
                # This is an instance port, so re-create DHCP entry
                self._delete_dhcp_static_binding(context, original_port)
                self._create_dhcp_static_binding(context, ret_port)
            elif owner == constants.DEVICE_OWNER_DHCP:
                # Update the ip of the dhcp port
                address_groups = self._create_network_dhcp_address_group(
                    context, ret_port['network_id'])
                self._update_dhcp_edge_service(
                    context, ret_port['network_id'], address_groups)
            elif (owner == constants.DEVICE_OWNER_ROUTER_GW or
                  owner == constants.DEVICE_OWNER_ROUTER_INTF):
                # This is a router port - update the edge appliance
                old_ip = self._get_port_fixed_ip_addr(original_port)
                new_ip = self._get_port_fixed_ip_addr(ret_port)
                if ((old_ip is not None or new_ip is not None) and
                    (old_ip != new_ip)):
                    if validators.is_attr_set(original_port.get('device_id')):
                        router_id = original_port['device_id']
                        router_driver = self._find_router_driver(context,
                                                                 router_id)
                        # subnet mask is needed for adding new ip to the vnic
                        sub_mask = self._get_port_subnet_mask(context,
                                                              ret_port)
                        router_driver.update_router_interface_ip(
                            context,
                            router_id,
                            original_port['id'],
                            ret_port['network_id'],
                            old_ip, new_ip, sub_mask)
            else:
                LOG.info(_LI('Not updating fixed IP on backend for '
                             'device owner [%(dev_own)s] and port %(pid)s'),
                         {'dev_own': owner, 'pid': original_port['id']})

        # Processing compute port update
        vnic_idx = original_port.get(ext_vnic_idx.VNIC_INDEX)
        if validators.is_attr_set(vnic_idx) and is_compute_port:
            vnic_id = self._get_port_vnic_id(vnic_idx, device_id)
            curr_sgids = (
                original_port[provider_sg.PROVIDER_SECURITYGROUPS] +
                original_port[ext_sg.SECURITYGROUPS])
            if ret_port['device_id'] != device_id:
                # Update change device_id - remove port-vnic association and
                # delete security-groups memberships for the vnic
                self._delete_security_groups_port_mapping(
                    context.session, vnic_id, curr_sgids)
                if cfg.CONF.nsxv.spoofguard_enabled:
                    if original_port[psec.PORTSECURITY]:
                        try:
                            self._remove_vnic_from_spoofguard_policy(
                                context.session,
                                original_port['network_id'],
                                vnic_id)
                        except Exception as e:
                            LOG.error(_LE('Could not delete the spoofguard '
                                          'policy. Exception %s'), e)
                    # remove vm from the exclusion list when it is detached
                    # from the device if it has no port security
                    if not original_port[psec.PORTSECURITY]:
                        self._remove_vm_from_exclude_list(
                            context, device_id, id)
                self._delete_port_vnic_index_mapping(context, id)
                self._delete_dhcp_static_binding(context, original_port)

                # if service insertion is enabled - remove this vnic from the
                # service insertion security group
                if (self._si_handler.enabled and
                    original_port[psec.PORTSECURITY]):
                    self._remove_member_from_security_group(
                        self._si_handler.sg_id,
                        vnic_id)
            else:
                # port security enabled / disabled
                if port_sec_change:
                    self._process_port_port_security_update(
                        context, port_data, ret_port)
                    if has_port_security:
                        LOG.debug("Assigning vnic port fixed-ips: port %s, "
                                  "vnic %s, with fixed-ips %s", id, vnic_id,
                                  original_port['fixed_ips'])
                        self._update_vnic_assigned_addresses(
                            context.session, original_port, vnic_id)
                        # Remove vm from the exclusion list, since it now has
                        # port security
                        self._remove_vm_from_exclude_list(context, device_id,
                                                          id)
                        # add the vm to the service insertion
                        if self._si_handler.enabled:
                            self._add_member_to_security_group(
                                self._si_handler.sg_id, vnic_id)
                    elif cfg.CONF.nsxv.spoofguard_enabled:
                        try:
                            self._remove_vnic_from_spoofguard_policy(
                                context.session, original_port['network_id'],
                                vnic_id)
                        except Exception as e:
                            LOG.error(_LE('Could not delete the spoofguard '
                                          'policy. Exception %s'), e)
                        # Add vm to the exclusion list, since it has no port
                        # security now
                        self._add_vm_to_exclude_list(context, device_id, id)
                        # remove the vm from the service insertion
                        if self._si_handler.enabled:
                            self._remove_member_from_security_group(
                                self._si_handler.sg_id, vnic_id)

                # Update vnic with the newest approved IP addresses
                if (has_port_security and
                    (updates_fixed_ips or update_assigned_addresses)):
                    LOG.debug("Updating vnic port fixed-ips: port %s, vnic "
                              "%s, fixed-ips %s",
                              id, vnic_id, ret_port['fixed_ips'])
                    self._update_vnic_assigned_addresses(
                        context.session, ret_port, vnic_id)
                if not has_port_security and has_security_groups:
                    LOG.warning(_LW("port-security is disabled on "
                                    "port %(id)s, "
                                    "VM tools must be installed on instance "
                                    "%(device_id)s for security-groups to "
                                    "function properly "),
                                {'id': id,
                                 'device_id': original_port['device_id']})
                if (delete_security_groups
                        or has_security_groups or pvd_sg_changed):
                    # Update security-groups,
                    # calculate differences and update vnic membership
                    # accordingly.
                    new_sgids = (
                        ret_port[provider_sg.PROVIDER_SECURITYGROUPS] +
                        ret_port[ext_sg.SECURITYGROUPS])
                    self._update_security_groups_port_mapping(
                        context.session, id, vnic_id, curr_sgids, new_sgids)

        return ret_port

    def delete_port(self, context, id, l3_port_check=True,
                    nw_gw_port_check=True):
        neutron_db_port = self.get_port(context, id)
        device_id = neutron_db_port['device_id']
        is_compute_port = self._is_compute_port(neutron_db_port)
        if is_compute_port and device_id:
            # Lock on the device ID to make sure we do not change/delete
            # ports of the same device at the same time
            with locking.LockManager.get_lock(
                'port-device-%s' % device_id):
                return self._delete_port(context, id, l3_port_check,
                                         nw_gw_port_check, neutron_db_port)
        else:
            return self._delete_port(context, id, l3_port_check,
                                     nw_gw_port_check, neutron_db_port)

    def _delete_port(self, context, id, l3_port_check,
                    nw_gw_port_check, neutron_db_port):
        """Deletes a port on a specified Virtual Network.

        If the port contains a remote interface attachment, the remote
        interface is first un-plugged and then the port is deleted.

        :returns: None
        :raises: exception.PortInUse
        :raises: exception.PortNotFound
        :raises: exception.NetworkNotFound
        """
        # if needed, check to see if this is a port owned by
        # a l3 router.  If so, we should prevent deletion here
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        if neutron_db_port['device_owner'] in [constants.DEVICE_OWNER_DHCP]:
            msg = (_('Can not delete DHCP port %s') % neutron_db_port['id'])
            raise n_exc.BadRequest(resource='port', msg=msg)
        # If this port is attached to a device, remove the corresponding vnic
        # from all NSXv Security-Groups and the spoofguard policy
        port_index = neutron_db_port.get(ext_vnic_idx.VNIC_INDEX)
        if validators.is_attr_set(port_index):
            vnic_id = self._get_port_vnic_id(port_index,
                                             neutron_db_port['device_id'])
            sgids = neutron_db_port.get(ext_sg.SECURITYGROUPS)
            self._delete_security_groups_port_mapping(
                context.session, vnic_id, sgids)

            # if service insertion is enabled - remove this vnic from the
            # service insertion security group
            if self._si_handler.enabled and neutron_db_port[psec.PORTSECURITY]:
                self._remove_member_from_security_group(self._si_handler.sg_id,
                                                        vnic_id)

            if (cfg.CONF.nsxv.spoofguard_enabled and
                neutron_db_port[psec.PORTSECURITY]):
                try:
                    self._remove_vnic_from_spoofguard_policy(
                        context.session, neutron_db_port['network_id'],
                        vnic_id)
                except Exception as e:
                    LOG.error(_LE('Could not delete the spoofguard policy. '
                                  'Exception %s'), e)

            if (cfg.CONF.nsxv.spoofguard_enabled and
                not neutron_db_port[psec.PORTSECURITY] and
                self._is_compute_port(neutron_db_port)):
                device_id = neutron_db_port['device_id']
                # Note that we expect to find 1 relevant port in the DB still
                # because this port was not yet deleted
                self._remove_vm_from_exclude_list(context, device_id, id,
                                                  expected_count=1)

        self.disassociate_floatingips(context, id)
        with context.session.begin(subtransactions=True):
            super(NsxVPluginV2, self).delete_port(context, id)

        self._delete_dhcp_static_binding(context, neutron_db_port)

    def delete_subnet(self, context, id):
        subnet = self._get_subnet(context, id)
        filters = {'fixed_ips': {'subnet_id': [id]}}
        ports = self.get_ports(context, filters=filters)

        # Add nsx-edge-pool here is because we first delete the subnet in db.
        # if the subnet overlaps with another new creating subnet, there is a
        # chance that the new creating subnet select the deleting subnet's edge
        # and send update dhcp interface rest call before deleting subnet's
        # corresponding dhcp interface rest call and lead to overlap response
        # from backend.
        with locking.LockManager.get_lock('nsx-edge-pool'):
            with context.session.begin(subtransactions=True):
                super(NsxVPluginV2, self).delete_subnet(context, id)
                if subnet['enable_dhcp']:
                    # There is only DHCP port available
                    if len(ports) == 1:
                        port = ports.pop()
                        self.ipam.delete_port(context, port['id'])

            if subnet['enable_dhcp']:
                # Delete the DHCP edge service
                network_id = subnet['network_id']
                filters = {'network_id': [network_id]}
                remaining_subnets = self.get_subnets(context,
                                                     filters=filters)
                if len(remaining_subnets) == 0:
                    self._cleanup_dhcp_edge_before_deletion(
                        context, network_id)
                    LOG.debug("Delete the DHCP service for network %s",
                              network_id)
                    self._delete_dhcp_edge_service(context, network_id)
                else:
                    # Update address group and delete the DHCP port only
                    address_groups = self._create_network_dhcp_address_group(
                        context, network_id)
                    self._update_dhcp_edge_service(context, network_id,
                                                   address_groups)

    def _is_overlapping_reserved_subnets(self, subnet):
        """Return True if the subnet overlaps with reserved subnets.

        For the V plugin we have a limitation that we should not use
        some reserved ranges like: 169.254.128.0/17 and 169.254.1.0/24
        """
        reserved_subnets = nsxv_constants.RESERVED_IPS

        # translate the given subnet to a range object
        data = subnet['subnet']

        if data['cidr'] not in (constants.ATTR_NOT_SPECIFIED, None):
            range = netaddr.IPNetwork(data['cidr'])

            # Check each reserved subnet for intersection
            for reserved_subnet in reserved_subnets:
                # translate the reserved subnet to a range object
                reserved_range = netaddr.IPNetwork(reserved_subnet)
                # check if new subnet overlaps this reserved subnet
                if (range.first <= reserved_range.last
                    and reserved_range.first <= range.last):
                    return True

        return False

    def _get_dhcp_ip_addr_from_subnet(self, context, subnet_id):
        dhcp_port_filters = {'fixed_ips': {'subnet_id': [subnet_id]},
                             'device_owner': [constants.DEVICE_OWNER_DHCP]}
        dhcp_ports = self.get_ports(context, filters=dhcp_port_filters)
        if dhcp_ports and dhcp_ports[0].get('fixed_ips'):
            return dhcp_ports[0]['fixed_ips'][0]['ip_address']

    def is_dhcp_metadata(self, context, subnet_id):
        try:
            subnet = self.get_subnet(context, subnet_id)
        except n_exc.SubnetNotFound:
            LOG.debug("subnet %s not found to determine its dhcp meta",
                      subnet_id)
            return False
        return bool(subnet['enable_dhcp'] and
                    self.metadata_proxy_handler and
                    cfg.CONF.nsxv.dhcp_force_metadata)

    def _validate_host_routes_input(self, subnet_input,
                                    orig_enable_dhcp=None,
                                    orig_host_routes=None):
        s = subnet_input['subnet']
        request_host_routes = (validators.is_attr_set(s.get('host_routes')) and
                               s['host_routes'])
        clear_host_routes = (validators.is_attr_set(s.get('host_routes')) and
                             not s['host_routes'])
        request_enable_dhcp = s.get('enable_dhcp')
        if request_enable_dhcp is False:
            if (request_host_routes or
                not clear_host_routes and orig_host_routes):
                err_msg = _("Can't disable DHCP while using host routes")
                raise n_exc.InvalidInput(error_message=err_msg)

        if request_host_routes:
            if not request_enable_dhcp and orig_enable_dhcp is False:
                err_msg = _("Host routes can only be supported when DHCP "
                            "is enabled")
                raise n_exc.InvalidInput(error_message=err_msg)
            if not self.edge_manager.is_dhcp_opt_enabled:
                err_msg = _("Host routes can only be supported at NSX version "
                            "6.2.3 or higher")
                raise n_exc.InvalidInput(error_message=err_msg)

    def create_subnet(self, context, subnet):
        """Create subnet on nsx_v provider network.

        If the subnet is created with DHCP enabled, and the network which
        the subnet is attached is not bound to an DHCP Edge, nsx_v will
        create the Edge and make sure the network is bound to the Edge
        """
        self._validate_host_routes_input(subnet)
        if subnet['subnet']['enable_dhcp']:
            filters = {'id': [subnet['subnet']['network_id']],
                       'router:external': [True]}
            nets = self.get_networks(context, filters=filters)
            if len(nets) > 0:
                err_msg = _("Can not enable DHCP on external network")
                raise n_exc.InvalidInput(error_message=err_msg)
            data = subnet['subnet']
            if (data.get('ip_version') == 6 or
                (data['cidr'] not in (constants.ATTR_NOT_SPECIFIED, None)
                 and netaddr.IPNetwork(data['cidr']).version == 6)):
                err_msg = _("No support for DHCP for IPv6")
                raise n_exc.InvalidInput(error_message=err_msg)
            if self._is_overlapping_reserved_subnets(subnet):
                err_msg = _("The requested subnet contains reserved IP's")
                raise n_exc.InvalidInput(error_message=err_msg)

        with locking.LockManager.get_lock(subnet['subnet']['network_id']):
            with locking.LockManager.get_lock('nsx-edge-pool'):
                s = super(NsxVPluginV2, self).create_subnet(context, subnet)
            if s['enable_dhcp']:
                try:
                    self._process_subnet_ext_attr_create(
                        session=context.session,
                        subnet_db=s,
                        subnet_req=data)
                    self._update_dhcp_service_with_subnet(context, s)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        self.delete_subnet(context, s['id'])
        return s

    def _process_subnet_ext_attr_create(self, session, subnet_db,
                                        subnet_req):
        # Verify if dns search domain/dhcp mtu for subnet are configured
        dns_search_domain = subnet_req.get(
            ext_dns_search_domain.DNS_SEARCH_DOMAIN)
        dhcp_mtu = subnet_req.get(
            ext_dhcp_mtu.DHCP_MTU)
        if (not validators.is_attr_set(dns_search_domain) and
            not validators.is_attr_set(dhcp_mtu)):
            return
        if not validators.is_attr_set(dns_search_domain):
            dns_search_domain = None
        if not validators.is_attr_set(dhcp_mtu):
            dhcp_mtu = None
        sub_binding = nsxv_db.get_nsxv_subnet_ext_attributes(
            session=session,
            subnet_id=subnet_db['id'])
        # Create a subnet extensions for subnet if it does not exist
        if not sub_binding:
            nsxv_db.add_nsxv_subnet_ext_attributes(
                session=session,
                subnet_id=subnet_db['id'],
                dns_search_domain=dns_search_domain,
                dhcp_mtu=dhcp_mtu)
        # Else update only if a new values for subnet extensions are provided
        elif (sub_binding.dns_search_domain != dns_search_domain or
              sub_binding.dhcp_mtu != dhcp_mtu):
            nsxv_db.update_nsxv_subnet_ext_attributes(
                session=session,
                subnet_id=subnet_db['id'],
                dns_search_domain=dns_search_domain,
                dhcp_mtu=dhcp_mtu)
        subnet_db['dns_search_domain'] = dns_search_domain
        subnet_db['dhcp_mtu'] = dhcp_mtu

    def _process_subnet_ext_attr_update(self, session, subnet_db,
                                        subnet_req):
        update_dhcp_config = False
        # Update extended attributes for subnet
        if (ext_dns_search_domain.DNS_SEARCH_DOMAIN in subnet_req or
            ext_dhcp_mtu.DHCP_MTU in subnet_req):
            self._process_subnet_ext_attr_create(session,
                                                 subnet_db,
                                                 subnet_req)
            update_dhcp_config = True
        return update_dhcp_config

    def update_subnet(self, context, id, subnet):
        s = subnet['subnet']
        orig = self._get_subnet(context, id)
        gateway_ip = orig['gateway_ip']
        enable_dhcp = orig['enable_dhcp']
        orig_host_routes = orig['routes']
        self._validate_host_routes_input(subnet,
                                         orig_enable_dhcp=enable_dhcp,
                                         orig_host_routes=orig_host_routes)
        subnet = super(NsxVPluginV2, self).update_subnet(context, id, subnet)
        update_dhcp_config = self._process_subnet_ext_attr_update(
            context.session, subnet, s)
        if (gateway_ip != subnet['gateway_ip'] or update_dhcp_config or
            set(orig['dns_nameservers']) != set(subnet['dns_nameservers']) or
            orig_host_routes != subnet['host_routes'] or
            enable_dhcp and not subnet['enable_dhcp']):
            # Need to ensure that all of the subnet attributes will be reloaded
            # when creating the edge bindings. Without adding this the original
            # subnet details are provided.
            context.session.expire_all()
            # Update the edge
            network_id = subnet['network_id']
            self.edge_manager.update_dhcp_edge_bindings(context, network_id)
        if enable_dhcp != subnet['enable_dhcp']:
            self._update_subnet_dhcp_status(subnet, context)
        return subnet

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attr.SUBNETS, ['_extend_subnet_dict_extended_attributes'])

    def _extend_subnet_dict_extended_attributes(self, subnet_res, subnet_db):
        subnet_attr = subnet_db.get('nsxv_subnet_attributes')
        if subnet_attr:
            subnet_res['dns_search_domain'] = subnet_attr.dns_search_domain
            subnet_res['dhcp_mtu'] = subnet_attr.dhcp_mtu

    def _update_subnet_dhcp_status(self, subnet, context):
        network_id = subnet['network_id']
        if subnet['enable_dhcp']:
            # Check if the network has one related dhcp edge
            resource_id = (vcns_const.DHCP_EDGE_PREFIX + network_id)[:36]
            edge_binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                           resource_id)
            if edge_binding:
                # Create DHCP port
                port_dict = {'name': '',
                             'admin_state_up': True,
                             'network_id': network_id,
                             'tenant_id': subnet['tenant_id'],
                             'fixed_ips': [{'subnet_id': subnet['id']}],
                             'device_owner': constants.DEVICE_OWNER_DHCP,
                             'device_id': '',
                             'mac_address': constants.ATTR_NOT_SPECIFIED
                             }
                self.create_port(context, {'port': port_dict})
            # First time binding network with dhcp edge
            else:
                self._update_dhcp_service_with_subnet(context, subnet)
                return
        else:
            # delete dhcp port
            filters = {'fixed_ips': {'subnet_id': [subnet['id']]}}
            ports = self.get_ports(context, filters=filters)
            for port in ports:
                if port["device_owner"] == constants.DEVICE_OWNER_DHCP:
                    self.ipam.delete_port(context, port['id'])
        address_groups = self._create_network_dhcp_address_group(context,
                                                                 network_id)
        self._update_dhcp_edge_service(context, network_id, address_groups)

    def _get_conflict_network_ids_by_overlapping(self, context, subnets):
        with locking.LockManager.get_lock('nsx-networking'):
            conflict_network_ids = []
            subnet_ids = [subnet['id'] for subnet in subnets]
            conflict_set = netaddr.IPSet(
                [subnet['cidr'] for subnet in subnets])
            subnets_qry = context.session.query(models_v2.Subnet).all()
            subnets_all = [subnet for subnet in subnets_qry
                           if subnet['id'] not in subnet_ids]
            for subnet in subnets_all:
                cidr_set = netaddr.IPSet([subnet['cidr']])
                if cidr_set & conflict_set:
                    conflict_network_ids.append(subnet['network_id'])
            return conflict_network_ids

    def _get_conflicting_networks_for_subnet(self, context, subnet):
        network_id = subnet['network_id']
        # The DHCP for network with different physical network can not be used
        # The flat network should be located in different DHCP
        conflicting_networks = []
        network_ids = self.get_networks(context.elevated(),
                                        fields=['id'])
        phy_net = nsxv_db.get_network_bindings(context.session, network_id)
        if phy_net:
            binding_type = phy_net[0]['binding_type']
            phy_uuid = phy_net[0]['phy_uuid']
            for net_id in network_ids:
                p_net = nsxv_db.get_network_bindings(context.session,
                                                    net_id['id'])
                if (p_net and binding_type == p_net[0]['binding_type']
                    and binding_type == c_utils.NsxVNetworkTypes.FLAT):
                    conflicting_networks.append(net_id['id'])
                elif (p_net and phy_uuid != p_net[0]['phy_uuid']):
                    conflicting_networks.append(net_id['id'])
        # get all of the subnets on the network, there may be more than one
        filters = {'network_id': [network_id]}
        subnets = super(NsxVPluginV2, self).get_subnets(context.elevated(),
                                                        filters=filters)
        # Query all networks with overlap subnet
        if cfg.CONF.allow_overlapping_ips:
            conflicting_networks.extend(
                self._get_conflict_network_ids_by_overlapping(
                    context, subnets))

        conflicting_networks = list(set(conflicting_networks))
        return conflicting_networks

    def _get_edge_id_by_rtr_id(self, context, rtr_id):
        binding = nsxv_db.get_nsxv_router_binding(
            context.session,
            rtr_id)

        if binding:
            return binding['edge_id']

    def _update_dhcp_service_new_edge(self, context, resource_id):
        edge_id = self._get_edge_id_by_rtr_id(context, resource_id)
        if edge_id:
            with locking.LockManager.get_lock(str(edge_id)):
                if self.metadata_proxy_handler:
                    LOG.debug('Update metadata for resource %s',
                              resource_id)
                    self.metadata_proxy_handler.configure_router_edge(
                        context, resource_id)

                self.setup_dhcp_edge_fw_rules(context, self,
                                              resource_id)

    def _update_dhcp_service_with_subnet(self, context, subnet):
        network_id = subnet['network_id']
        # Create DHCP port
        port_dict = {'name': '',
                     'admin_state_up': True,
                     'network_id': network_id,
                     'tenant_id': subnet['tenant_id'],
                     'fixed_ips': [{'subnet_id': subnet['id']}],
                     'device_owner': constants.DEVICE_OWNER_DHCP,
                     'device_id': '',
                     'mac_address': constants.ATTR_NOT_SPECIFIED
                     }
        self.create_port(context, {'port': port_dict})

        try:
            resource_id = self.edge_manager.create_dhcp_edge_service(
                context, network_id, subnet)
            # Create all dhcp ports within the network
            address_groups = self._create_network_dhcp_address_group(
                context, network_id)
            self.edge_manager.update_dhcp_edge_service(
                context, network_id, address_groups=address_groups)

            if resource_id:
                self._update_dhcp_service_new_edge(context, resource_id)

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to update DHCP for subnet %s"),
                              subnet['id'])

    def setup_dhcp_edge_fw_rules(self, context, plugin, router_id):
        rules = []
        # It would be best to configure the rule with icmp type 8 (Echo),
        # but this format is broken on Edge (should be fixed in 6.3.1)
        # TODO(annak): use icmp type when fix is available
        # Workaround: use applications, but since application ids can change,
        # need to look them up by application name
        try:
            application_ids = plugin.nsx_v.get_icmp_echo_application_ids()

            rules = [{"name": "ICMPPing",
                  "enabled": True,
                  "action": "allow",
                  "application": {
                      "applicationId": application_ids}}]

        except Exception as e:
            LOG.error(
                _LE('Could not find ICMP Echo application. Exception %s'), e)

        if plugin.metadata_proxy_handler:
            rules += nsx_v_md_proxy.get_router_fw_rules()

        try:
            edge_utils.update_firewall(plugin.nsx_v, context, router_id,
                                       {'firewall_rule_list': rules},
                                       allow_external=False)
        except Exception as e:
            # On failure, log that we couldn't configure the firewall on the
            # Edge appliance. This won't break the DHCP functionality
            LOG.error(
                _LE('Could not set up DHCP Edge firewall. Exception %s'), e)

    def _create_network_dhcp_address_group(self, context, network_id):
        """Create dhcp address group for subnets attached to the network."""

        filters = {'network_id': [network_id],
                   'device_owner': [constants.DEVICE_OWNER_DHCP]}
        ports = self.get_ports(context, filters=filters)

        filters = {'network_id': [network_id], 'enable_dhcp': [True]}
        subnets = self.get_subnets(context, filters=filters)

        address_groups = []
        for subnet in subnets:
            address_group = {}
            net = netaddr.IPNetwork(subnet['cidr'])
            address_group['subnetPrefixLength'] = str(net.prefixlen)
            for port in ports:
                fixed_ips = port['fixed_ips']
                for fip in fixed_ips:
                    s_id = fip['subnet_id']
                    ip_addr = fip['ip_address']
                    if s_id == subnet['id'] and self._is_valid_ip(ip_addr):
                        address_group['primaryAddress'] = ip_addr
                        break
            address_groups.append(address_group)
        LOG.debug("Update the DHCP address group to %s", address_groups)
        return address_groups

    def _extract_external_gw(self, context, router, is_extract=True):
        r = router['router']
        gw_info = constants.ATTR_NOT_SPECIFIED
        # First extract the gateway info in case of updating
        # gateway before edge is deployed.
        if 'external_gateway_info' in r:
            gw_info = r['external_gateway_info']
            if is_extract:
                del r['external_gateway_info']
            network_id = (gw_info.get('network_id') if gw_info
                          else None)
            if network_id:
                ext_net = self._get_network(context, network_id)
                if not ext_net.external:
                    msg = (_("Network '%s' is not a valid external network") %
                           network_id)
                    raise n_exc.BadRequest(resource='router', msg=msg)

                subnets = self._get_subnets_by_network(context, network_id)
                if not subnets:
                    msg = _("Cannot update gateway on Network '%s' "
                            "with no subnet") % network_id
                    raise n_exc.BadRequest(resource='router', msg=msg)
        return gw_info

    def _validate_router_size(self, router):
        # Check if router-size is specified. router-size can only be specified
        # for an exclusive non-distributed router; else raise a BadRequest
        # exception.
        r = router['router']
        if validators.is_attr_set(r.get(ROUTER_SIZE)):
            if r.get('router_type') == nsxv_constants.SHARED:
                msg = _("Cannot specify router-size for shared router")
                raise n_exc.BadRequest(resource="router", msg=msg)
            elif r.get('distributed') is True:
                msg = _("Cannot specify router-size for distributed router")
                raise n_exc.BadRequest(resource="router", msg=msg)
        else:
            if r.get('router_type') == nsxv_constants.EXCLUSIVE:
                r[ROUTER_SIZE] = cfg.CONF.nsxv.exclusive_router_appliance_size

    def _get_router_flavor_profile(self, context, flavor_id):
        flv_plugin = manager.NeutronManager.get_service_plugins().get(
            plugin_const.FLAVORS)
        if not flv_plugin:
            msg = _("Flavors plugin not found")
            raise n_exc.BadRequest(resource="router", msg=msg)

        # Will raise FlavorNotFound if doesn't exist
        fl_db = flavors_plugin.FlavorsPlugin.get_flavor(
            flv_plugin, context, flavor_id)

        if fl_db['service_type'] != plugin_const.L3_ROUTER_NAT:
            raise flavors.InvalidFlavorServiceType(
                service_type=fl_db['service_type'])

        if not fl_db['enabled']:
            raise flavors.FlavorDisabled()

        # get the profile (Currently only 1 is supported, so take the first)
        if not fl_db['service_profiles']:
            return
        profile_id = fl_db['service_profiles'][0]

        return flavors_plugin.FlavorsPlugin.get_service_profile(
            flv_plugin,
            context,
            profile_id)

    def _get_flavor_metainfo_from_profile(self, flavor_id, flavor_profile):
        if not flavor_profile:
            return {}
        metainfo_string = flavor_profile.get('metainfo').replace("'", "\"")
        try:
            metainfo = jsonutils.loads(metainfo_string)
            if not isinstance(metainfo, dict):
                LOG.warning(_LW("Skipping router flavor %(flavor)s metainfo "
                                "[%(metainfo)s]: expected a dictionary"),
                            {'flavor': flavor_id,
                             'metainfo': metainfo_string})
                metainfo = {}
        except ValueError as e:
            LOG.warning(_LW("Error reading router flavor %(flavor)s metainfo "
                            "[%(metainfo)s]: %(error)s"),
                        {'flavor': flavor_id,
                         'metainfo': metainfo_string,
                         'error': e})
            metainfo = {}
        return metainfo

    def _get_router_config_from_flavor(self, context, router):
        """Validate the router flavor and initialize router data

        Validate that the flavor is legit, and that contradicting configuration
        does not exist.
        Also update the router data to reflect the selected flavor.
        """
        if not validators.is_attr_set(router.get('flavor_id')):
            return
        flavor_id = router['flavor_id']
        flavor_profile = self._get_router_flavor_profile(context, flavor_id)
        metainfo = self._get_flavor_metainfo_from_profile(flavor_id,
                                                          flavor_profile)

        # Go over the attributes of the metainfo
        allowed_keys = [ROUTER_SIZE, 'router_type', 'distributed',
                        az_ext.AZ_HINTS]
        for k, v in metainfo.items():
            if k in allowed_keys:
                #special case for availability zones hints which are an array
                if k == az_ext.AZ_HINTS:
                    if not isinstance(v, list):
                        v = [v]
                    # The default az hists is an empty array
                    if (validators.is_attr_set(router.get(k)) and
                        len(router[k]) > 0):
                        msg = (_("Cannot specify %s if the flavor profile "
                                 "defines it") % k)
                        raise n_exc.BadRequest(resource="router", msg=msg)

                elif validators.is_attr_set(router.get(k)) and router[k] != v:
                    msg = _("Cannot specify %s if the flavor defines it") % k
                    raise n_exc.BadRequest(resource="router", msg=msg)
                # Legal value
                router[k] = v
            else:
                LOG.warning(_LW("Skipping router flavor metainfo [%(k)s:%(v)s]"
                                ":unsupported field"),
                            {'k': k, 'v': v})

    def create_router(self, context, router, allow_metadata=True):
        r = router['router']
        self._get_router_config_from_flavor(context, r)
        self._decide_router_type(context, r)
        self._validate_router_size(router)
        self._validate_availability_zones_in_obj(context, 'router', r)

        # First extract the gateway info in case of updating
        # gateway before edge is deployed.
        # TODO(berlin): admin_state_up and routes update
        gw_info = self._extract_external_gw(context, router)
        lrouter = super(NsxVPluginV2, self).create_router(context, router)

        with context.session.begin(subtransactions=True):
            router_db = self._get_router(context, lrouter['id'])
            self._process_extra_attr_router_create(context, router_db, r)
            self._process_nsx_router_create(context, router_db, r)
            self._process_router_flavor_create(context, router_db, r)

        lrouter = super(NsxVPluginV2, self).get_router(context,
                                                       lrouter['id'])
        try:
            router_driver = self._get_router_driver(context, router_db)
            if router_driver.get_type() == nsxv_constants.EXCLUSIVE:
                router_driver.create_router(
                    context, lrouter,
                    appliance_size=r.get(ROUTER_SIZE),
                    allow_metadata=(allow_metadata and
                                    self.metadata_proxy_handler))
            else:
                router_driver.create_router(
                    context, lrouter,
                    allow_metadata=(allow_metadata and
                                    self.metadata_proxy_handler))
            if gw_info != constants.ATTR_NOT_SPECIFIED and gw_info is not None:
                self._update_router_gw_info(
                    context, lrouter['id'], gw_info)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.delete_router(context, lrouter['id'])
        return self.get_router(context, lrouter['id'])

    def _validate_router_migration(self, context, router_id,
                                   new_router_type, router):
        if new_router_type == 'shared':
            # shared router cannot have static routes
            # verify that the original router did not have static routes
            err_msg = _('Unable to create a shared router with static routes')
            routes = self._get_extra_routes_by_router_id(context, router_id)
            if len(routes) > 0:
                raise n_exc.InvalidInput(error_message=err_msg)
            # verify that the updated router does not have static routes
            if (validators.is_attr_set(router.get("routes")) and
                len(router['routes']) > 0):
                raise n_exc.InvalidInput(error_message=err_msg)

    def update_router(self, context, router_id, router):
        # Validate that the gateway information is relevant
        self._extract_external_gw(context, router, is_extract=False)
        # Toggling the distributed flag is not supported
        if 'distributed' in router['router']:
            r = self.get_router(context, router_id)
            if r['distributed'] != router['router']['distributed']:
                err_msg = _('Unable to update distributed mode')
                raise n_exc.InvalidInput(error_message=err_msg)

        # Toggling router type is supported only for non-distributed router
        elif 'router_type' in router['router']:
            r = self.get_router(context, router_id)
            if r['router_type'] != router['router']['router_type']:
                if r["distributed"]:
                    err_msg = _('Unable to update distributed mode')
                    raise n_exc.InvalidInput(error_message=err_msg)
                else:
                    # should migrate the router because its type changed
                    new_router_type = router['router']['router_type']
                    self._validate_router_size(router)
                    self._validate_router_migration(
                        context, router_id, new_router_type, r)

                    # remove the router from the old pool, and free resources
                    old_router_driver = \
                        self._router_managers.get_tenant_router_driver(
                            context, r['router_type'])
                    old_router_driver.detach_router(context, router_id, router)

                    # update the router-type
                    with context.session.begin(subtransactions=True):
                        router_db = self._get_router(context, router_id)
                        self._process_nsx_router_create(
                            context, router_db, router['router'])

                    # add the router to the new pool
                    appliance_size = router['router'].get(ROUTER_SIZE)
                    new_router_driver = \
                        self._router_managers.get_tenant_router_driver(
                            context, new_router_type)
                    new_router_driver.attach_router(
                        context,
                        router_id,
                        router,
                        appliance_size=appliance_size)
                    # continue to update the router with the new driver
                    # but remove the router-size that was already updated
                    router['router'].pop(ROUTER_SIZE, None)

        router_driver = self._find_router_driver(context, router_id)
        return router_driver.update_router(context, router_id, router)

    def _check_router_in_use(self, context, router_id):
        with context.session.begin(subtransactions=True):
            # Ensure that the router is not used
            router_filter = {'router_id': [router_id]}
            fips = self.get_floatingips_count(context.elevated(),
                                              filters=router_filter)
            if fips:
                raise l3.RouterInUse(router_id=router_id)

            device_filter = {'device_id': [router_id],
                             'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF]}
            ports = self.get_ports_count(context.elevated(),
                                         filters=device_filter)
            if ports:
                raise l3.RouterInUse(router_id=router_id)

    def delete_router(self, context, id):
        self._check_router_in_use(context, id)
        router_driver = self._find_router_driver(context, id)
        # Clear vdr's gw relative components if the router has gw info
        if router_driver.get_type() == "distributed":
            router = self.get_router(context, id)
            if router.get(l3.EXTERNAL_GW_INFO):
                router_driver._update_router_gw_info(context, id, {})
        super(NsxVPluginV2, self).delete_router(context, id)
        router_driver.delete_router(context, id)

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attr.NETWORKS, ['_extend_availability_zone_hints'])

    def _extend_availability_zone_hints(self, net_res, net_db):
        net_res[az_ext.AZ_HINTS] = az_ext.convert_az_string_to_list(
            net_db[az_ext.AZ_HINTS])

    def _get_availability_zone_name_by_edge(self, context, edge_id):
        az_name = nsxv_db.get_edge_availability_zone(
            context.session, edge_id)
        if az_name:
            return az_name
        # fallback
        return nsx_az.DEFAULT_NAME

    def get_network_availability_zones(self, context, net_db):
        """Return availability zones which a network belongs to."""

        resource_id = (vcns_const.DHCP_EDGE_PREFIX + net_db["id"])[:36]
        dhcp_edge_binding = nsxv_db.get_nsxv_router_binding(
            context.session, resource_id)
        if dhcp_edge_binding:
            edge_id = dhcp_edge_binding['edge_id']
            return [self._get_availability_zone_name_by_edge(
                context, edge_id)]
        return []

    def get_router_availability_zones(self, router):
        """Return availability zones which a router belongs to."""
        context = n_context.get_admin_context()
        edge_id = self._get_edge_id_by_rtr_id(context, router["id"])
        if edge_id:
            return [self._get_availability_zone_name_by_edge(
                context, edge_id)]
        return []

    def _process_router_flavor_create(self, context, router_db, r):
        """Update the router DB structure with the flavor ID upon creation
        """
        if validators.is_attr_set(r.get('flavor_id')):
            router_db.flavor_id = r['flavor_id']

    def add_flavor_id(plugin, router_res, router_db):
        router_res['flavor_id'] = router_db['flavor_id']

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, [add_flavor_id])

    def get_router(self, context, id, fields=None):
        router = super(NsxVPluginV2, self).get_router(context, id, fields)
        if router.get("distributed") and 'router_type' in router:
            del router['router_type']
        if router.get("router_type") == nsxv_constants.EXCLUSIVE:
            binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                      router.get("id"))
            if binding:
                router[ROUTER_SIZE] = binding.get("appliance_size")
            else:
                LOG.error(_LE("No binding for router %s"), id)
        return router

    def _get_external_attachment_info(self, context, router):
        gw_port = router.gw_port
        ipaddress = None
        netmask = None
        nexthop = None

        if gw_port:
            # TODO(berlin): we can only support gw port with one fixed ip at
            # present.
            if gw_port.get('fixed_ips'):
                ipaddress = gw_port['fixed_ips'][0]['ip_address']
                subnet_id = gw_port['fixed_ips'][0]['subnet_id']
                subnet = self.get_subnet(context.elevated(), subnet_id)
                nexthop = subnet['gateway_ip']

            network_id = gw_port.get('network_id')
            if network_id:
                ext_net = self._get_network(context, network_id)
                if not ext_net.external:
                    msg = (_("Network '%s' is not a valid external "
                             "network") % network_id)
                    raise n_exc.BadRequest(resource='router', msg=msg)
                if ext_net.subnets:
                    netmask = set([str(ext_subnet.cidr)
                                   for ext_subnet in ext_net.subnets])

        return (ipaddress, netmask, nexthop)

    def _add_network_info_for_routes(self, context, routes, ports):
        for route in routes:
            for port in ports:
                for ip in port['fixed_ips']:
                    subnet = self.get_subnet(context.elevated(),
                                             ip['subnet_id'])
                    if netaddr.all_matching_cidrs(
                        route['nexthop'], [subnet['cidr']]):
                        net = self.get_network(context.elevated(),
                                               subnet['network_id'])
                        route['network_id'] = net['id']
                        if net.get(ext_net_extn.EXTERNAL):
                            route['external'] = True

    def _prepare_edge_extra_routes(self, context, router_id):
        routes = self._get_extra_routes_by_router_id(context, router_id)
        filters = {'device_id': [router_id]}
        ports = self.get_ports(context, filters)
        self._add_network_info_for_routes(context, routes, ports)
        return routes

    def _update_routes(self, context, router_id, nexthop):
        routes = self._prepare_edge_extra_routes(context, router_id)
        edge_utils.update_routes(self.nsx_v, context, router_id,
                                 routes, nexthop)

    def _update_current_gw_port(self, context, router_id, router, ext_ips):
        """Override this function in order not to call plugins' update_port
        since the actual backend work was already done by the router driver,
        and it may cause a deadlock.
        """
        super(NsxVPluginV2, self).update_port(context,
                                              router.gw_port['id'],
                                              {'port': {'fixed_ips': ext_ips}})
        context.session.expire(router.gw_port)

    def _update_router_gw_info(self, context, router_id, info,
                               is_routes_update=False,
                               force_update=False):
        router_driver = self._find_router_driver(context, router_id)
        if info:
            try:
                ext_ips = info.get('external_fixed_ips')
                network_id = info.get('network_id')
                router_db = self._get_router(context, router_id)

                # for multiple external subnets support, we need to set gw
                # port first on subnet which has gateway. If can't get one
                # subnet with gateway or allocate one available ip from
                # subnet, we would just enter normal logic and admin should
                # exactly know what he did.
                if (not ext_ips and network_id and
                    (not router_db.gw_port or
                     not router_db.gw_port.get('fixed_ips'))):
                    net_id_filter = {'network_id': [network_id]}
                    subnets = self.get_subnets(context, filters=net_id_filter)
                    fixed_subnet = True
                    if len(subnets) <= 1:
                        fixed_subnet = False
                    else:
                        for subnet in subnets:
                            if ipv6_utils.is_auto_address_subnet(subnet):
                                fixed_subnet = False
                    if fixed_subnet:
                        for subnet in subnets:
                            if not subnet['gateway_ip']:
                                continue
                            try:
                                info['external_fixed_ips'] = [{
                                    'subnet_id': subnet['id']}]
                                return router_driver._update_router_gw_info(
                                    context, router_id, info,
                                    is_routes_update=is_routes_update)
                            except n_exc.IpAddressGenerationFailure:
                                del info['external_fixed_ips']
                        LOG.warning(_LW("Cannot get one subnet with gateway "
                                        "to allocate one available gw ip"))
                router_driver._update_router_gw_info(
                    context, router_id, info,
                    is_routes_update=is_routes_update,
                    force_update=force_update)
            except vsh_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Failed to update gw_info %(info)s on "
                                  "router %(router_id)s"),
                              {'info': str(info),
                               'router_id': router_id})
                    router_driver._update_router_gw_info(
                        context, router_id, {},
                        is_routes_update=is_routes_update,
                        force_update=force_update)
        else:
            router_driver._update_router_gw_info(
                context, router_id, info,
                is_routes_update=is_routes_update,
                force_update=force_update)

    def _get_internal_network_ids_by_router(self, context, router_id):
        ports_qry = context.session.query(models_v2.Port)
        intf_ports = ports_qry.filter_by(
            device_id=router_id,
            device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF).all()
        intf_net_ids = list(set([port['network_id'] for port in intf_ports]))
        return intf_net_ids

    def _get_router_interface_ports_by_network(
        self, context, router_id, network_id):
        port_filters = {'device_id': [router_id],
                        'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                        'network_id': [network_id]}
        return self.get_ports(context, filters=port_filters)

    def _get_address_groups(self, context, router_id, network_id):
        address_groups = []
        ports = self._get_router_interface_ports_by_network(
            context, router_id, network_id)
        for port in ports:
            address_group = {}
            gateway_ip = port['fixed_ips'][0]['ip_address']
            subnet = self.get_subnet(context,
                                     port['fixed_ips'][0]['subnet_id'])
            prefixlen = str(netaddr.IPNetwork(subnet['cidr']).prefixlen)
            address_group['primaryAddress'] = gateway_ip
            address_group['subnetPrefixLength'] = prefixlen
            address_groups.append(address_group)
        return address_groups

    def _get_port_by_device_id(self, context, device_id, device_owner):
        """Retrieve ports associated with a specific device id.

        Used for retrieving all neutron ports attached to a given router.
        """
        port_qry = context.session.query(models_v2.Port)
        return port_qry.filter_by(
            device_id=device_id,
            device_owner=device_owner,).all()

    def _find_router_subnets_cidrs(self, context, router_id):
        """Retrieve subnets attached to the specified router."""
        ports = self._get_port_by_device_id(context, router_id,
                                            l3_db.DEVICE_OWNER_ROUTER_INTF)
        # No need to check for overlapping CIDRs
        cidrs = []
        for port in ports:
            for ip in port.get('fixed_ips', []):
                subnet_qry = context.session.query(models_v2.Subnet)
                subnet = subnet_qry.filter_by(id=ip.subnet_id).one()
                cidrs.append(subnet.cidr)
        return cidrs

    def _get_nat_rules(self, context, router):
        fip_qry = context.session.query(l3_db.FloatingIP)
        fip_db = fip_qry.filter_by(router_id=router['id']).all()

        snat = []

        dnat = [{'dst': fip.floating_ip_address,
                 'translated': fip.fixed_ip_address}
                for fip in fip_db if fip.fixed_port_id]

        gw_port = router.gw_port
        if gw_port and gw_port.get('fixed_ips') and router.enable_snat:
            snat_ip = gw_port['fixed_ips'][0]['ip_address']
            subnets = self._find_router_subnets_cidrs(context.elevated(),
                                                      router['id'])
            for subnet in subnets:
                snat.append({
                    'src': subnet,
                    'translated': snat_ip
                })
        return (snat, dnat)

    def _get_nosnat_subnets_fw_rules(self, context, router):
        """Open edge firewall holes for nosnat subnets to do static routes."""
        no_snat_fw_rules = []
        gw_port = router.gw_port
        if gw_port and not router.enable_snat:
            subnet_cidrs = self._find_router_subnets_cidrs(context.elevated(),
                                                           router['id'])
            if subnet_cidrs:
                no_snat_fw_rules.append({
                    'action': 'allow',
                    'enabled': True,
                    'source_vnic_groups': ["external"],
                    'destination_ip_address': subnet_cidrs})
        return no_snat_fw_rules

    def _update_nat_rules(self, context, router, router_id=None):
        snat, dnat = self._get_nat_rules(context, router)
        if not router_id:
            router_id = router['id']
        edge_utils.update_nat_rules(
            self.nsx_v, context, router_id, snat, dnat)

    def _check_intf_number_of_router(self, context, router_id):
        intf_ports = self._get_port_by_device_id(
            context, router_id, l3_db.DEVICE_OWNER_ROUTER_INTF)
        if len(intf_ports) >= (vcns_const.MAX_INTF_NUM):
            err_msg = _("Interfaces number on router: %(router_id)s "
                        "has reached the maximum %(number)d which NSXv can "
                        "support. Please use vdr if you want to add unlimited "
                        "interfaces") % {'router_id': router_id,
                                         'number': vcns_const.MAX_INTF_NUM}
            raise nsx_exc.ServiceOverQuota(overs="router-interface-add",
                                           err_msg=err_msg)

    def _update_router_admin_state(self, context,
                                   router_id, router_type, admin_state):
        # Collecting all router interfaces and updating the connection status
        # for each one to reflect the router admin-state-up status.
        intf_net_ids = (
            self._get_internal_network_ids_by_router(context, router_id))
        for network_id in intf_net_ids:
            address_groups = (
                self._get_address_groups(context, router_id, network_id))
            update_args = (self.nsx_v, context, router_id, network_id,
                           address_groups, admin_state)
            if router_type == 'distributed':
                edge_utils.update_vdr_internal_interface(*update_args)
            else:
                edge_utils.update_internal_interface(*update_args)

    def _get_interface_info_net_id(self, context, interface_info):
        is_port, is_sub = self._validate_interface_info(interface_info)
        if is_port:
            net_id = self.get_port(
                context, interface_info['port_id'])['network_id']
        elif is_sub:
            net_id = self.get_subnet(
                context, interface_info['subnet_id'])['network_id']
        return net_id

    def _is_external_interface_info(self, context, interface_info):
        net_id = self._get_interface_info_net_id(context, interface_info)
        network = self.get_network(context, net_id)
        if (network.get(ext_net_extn.EXTERNAL)):
            return True
        return False

    def add_router_interface(self, context, router_id, interface_info):
        # Do not support external subnet/port as a router interface
        if self._is_external_interface_info(context.elevated(),
                                            interface_info):
            msg = (_('cannot add an external subnet/port as a router '
                     'interface'))
            raise n_exc.InvalidInput(error_message=msg)

        router_driver = self._find_router_driver(context, router_id)
        try:
            return router_driver.add_router_interface(
                context, router_id, interface_info)
        except vsh_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to add interface_info %(info)s on "
                              "router %(router_id)s"),
                          {'info': str(interface_info),
                           'router_id': router_id})
                router_driver.remove_router_interface(
                    context, router_id, interface_info)

    def remove_router_interface(self, context, router_id, interface_info):
        router_driver = self._find_router_driver(context, router_id)
        return router_driver.remove_router_interface(
            context, router_id, interface_info)

    def _get_floatingips_by_router(self, context, router_id):
        fip_qry = context.session.query(l3_db.FloatingIP)
        fip_db = fip_qry.filter_by(router_id=router_id).all()
        return [fip.floating_ip_address
                for fip in fip_db if fip.fixed_port_id]

    def _update_external_interface(self, context, router, router_id=None):
        ext_net_id = router.gw_port_id and router.gw_port.network_id
        addr, mask, nexthop = self._get_external_attachment_info(
            context, router)
        secondary = self._get_floatingips_by_router(context, router['id'])
        if not router_id:
            router_id = router['id']
        edge_utils.update_external_interface(
            self.nsx_v, context, router_id, ext_net_id,
            addr, mask, secondary)

    def _set_floatingip_status(self, context, floatingip_db, status=None):
        if not status:
            status = (constants.FLOATINGIP_STATUS_ACTIVE
                      if floatingip_db.get('router_id')
                      else constants.FLOATINGIP_STATUS_DOWN)
        if floatingip_db['status'] != status:
            floatingip_db['status'] = status
            self.update_floatingip_status(context, floatingip_db['id'], status)

    def _update_edge_router(self, context, router_id):
        router_driver = self._find_router_driver(context, router_id)
        router_driver._update_edge_router(context, router_id)

    def create_floatingip(self, context, floatingip):
        fip_db = super(NsxVPluginV2, self).create_floatingip(
            context, floatingip)
        router_id = fip_db['router_id']
        if router_id:
            try:
                self._update_edge_router(context, router_id)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("Failed to update edge router"))
                    super(NsxVPluginV2, self).delete_floatingip(context,
                                                                fip_db['id'])
        self._set_floatingip_status(context, fip_db)
        return fip_db

    def update_floatingip(self, context, id, floatingip):
        old_fip = self._get_floatingip(context, id)
        old_router_id = old_fip.router_id
        old_port_id = old_fip.fixed_port_id
        fip_db = super(NsxVPluginV2, self).update_floatingip(
            context, id, floatingip)
        router_id = fip_db.get('router_id')
        try:
            # Update old router's nat rules if old_router_id is not None.
            if old_router_id:
                self._update_edge_router(context, old_router_id)
            # Update current router's nat rules if router_id is not None.
            if router_id:
                self._update_edge_router(context, router_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to update edge router"))
                super(NsxVPluginV2, self).update_floatingip(
                    context, id, {'floatingip': {'port_id': old_port_id}})
        self._set_floatingip_status(context, fip_db)
        return fip_db

    def delete_floatingip(self, context, id):
        fip_db = self._get_floatingip(context, id)
        router_id = None
        if fip_db.fixed_port_id:
            router_id = fip_db.router_id
        super(NsxVPluginV2, self).delete_floatingip(context, id)
        if router_id:
            self._update_edge_router(context, router_id)

    def disassociate_floatingips(self, context, port_id):
        router_id = None
        try:
            fip_qry = context.session.query(l3_db.FloatingIP)
            fip_db = fip_qry.filter_by(fixed_port_id=port_id)
            for fip in fip_db:
                if fip.router_id:
                    router_id = fip.router_id
                    break
        except sa_exc.NoResultFound:
            router_id = None
        super(NsxVPluginV2, self).disassociate_floatingips(context, port_id)
        if router_id:
            self._update_edge_router(context, router_id)

    def _update_subnets_and_dnat_firewall(self, context, router,
                                          router_id=None, allow_external=True):
        fake_fw_rules = []
        if not router_id:
            router_id = router['id']
        subnet_cidrs = self._find_router_subnets_cidrs(context, router['id'])
        routes = self._get_extra_routes_by_router_id(context, router_id)
        subnet_cidrs.extend([route['destination'] for route in routes])
        if subnet_cidrs:
            # Fake fw rule to open subnets firewall flows and static routes
            # relative flows
            fake_subnet_fw_rule = {
                'action': 'allow',
                'enabled': True,
                'source_ip_address': subnet_cidrs,
                'destination_ip_address': subnet_cidrs}
            fake_fw_rules.append(fake_subnet_fw_rule)
        _, dnat_rules = self._get_nat_rules(context, router)

        # If metadata service is enabled, block access to inter-edge network
        if self.metadata_proxy_handler:
            fake_fw_rules += nsx_v_md_proxy.get_router_fw_rules()

        dnat_cidrs = [rule['dst'] for rule in dnat_rules]
        if dnat_cidrs:
            # Fake fw rule to open dnat firewall flows
            fake_dnat_fw_rule = {
                'action': 'allow',
                'enabled': True,
                'destination_ip_address': dnat_cidrs}
            fake_fw_rules.append(fake_dnat_fw_rule)
        nosnat_fw_rules = self._get_nosnat_subnets_fw_rules(
            context, router)
        fake_fw_rules.extend(nosnat_fw_rules)

        # Get the load balancer rules in case they are refreshed
        edge_id = self._get_edge_id_by_rtr_id(context, router_id)
        lb_rules = nsxv_db.get_nsxv_lbaas_loadbalancer_binding_by_edge(
                context.session, edge_id)
        for rule in lb_rules:
            vsm_rule = self.nsx_v.vcns.get_firewall_rule(
                    edge_id, rule['edge_fw_rule_id'])[1]
            lb_fw_rule = {
                'action': edge_firewall_driver.FWAAS_ALLOW,
                'enabled': vsm_rule['enabled'],
                'destination_ip_address': vsm_rule['destination']['ipAddress'],
                'name': vsm_rule['name'],
                'ruleId': vsm_rule['ruleId']
            }
            fake_fw_rules.append(lb_fw_rule)

        # TODO(berlin): Add fw rules if fw service is supported
        fake_fw = {'firewall_rule_list': fake_fw_rules}
        try:
            edge_utils.update_firewall(self.nsx_v, context, router_id, fake_fw,
                                       allow_external=allow_external)
        except vsh_exc.ResourceNotFound:
            LOG.error(_LE("Failed to update firewall for router %s"),
                      router_id)

    # Security group handling section #
    def _delete_nsx_security_group(self, nsx_sg_id):
        """Helper method to delete nsx security group."""
        if nsx_sg_id is not None:
            self.nsx_v.vcns.delete_security_group(nsx_sg_id)

    def _delete_section(self, section_uri):
        """Helper method to delete nsx rule section."""
        if section_uri is not None:
            self.nsx_v.vcns.delete_section(section_uri)

    def _get_section_uri(self, session, security_group_id):
        mapping = nsxv_db.get_nsx_section(session, security_group_id)
        if mapping is not None:
            return mapping['ip_section_id']

    def _create_fw_section_for_security_group(self,
                                              context,
                                              securitygroup,
                                              nsx_sg_id):
        logging = (cfg.CONF.nsxv.log_security_groups_allowed_traffic or
                   securitygroup[sg_logging.LOGGING])
        action = 'deny' if securitygroup[provider_sg.PROVIDER] else 'allow'
        section_name = self.nsx_sg_utils.get_nsx_section_name(securitygroup)
        nsx_rules = []
        # Translate Neutron rules to NSXv fw rules and construct the fw section
        for rule in securitygroup['security_group_rules']:
            nsx_rule = self._create_nsx_rule(
                context, rule, nsx_sg_id, logged=logging, action=action)
            nsx_rules.append(nsx_rule)
        section = self.nsx_sg_utils.get_section_with_rules(
            section_name, nsx_rules)
        # Execute REST API for creating the section
        h, c = self.nsx_v.vcns.create_section(
            'ip', self.nsx_sg_utils.to_xml_string(section),
            insert_top=securitygroup[provider_sg.PROVIDER],
            insert_before=self.default_section)

        rule_pairs = self.nsx_sg_utils.get_rule_id_pair_from_section(c)
        # Add database associations for fw section and rules
        nsxv_db.add_neutron_nsx_section_mapping(
            context.session, securitygroup['id'], h['location'])
        for pair in rule_pairs:
            # Save nsx rule id in the DB for future access
            nsxv_db.add_neutron_nsx_rule_mapping(
                context.session, pair['neutron_id'], pair['nsx_id'])

    def _create_nsx_security_group(self, context, securitygroup):
        nsx_sg_name = self.nsx_sg_utils.get_nsx_sg_name(securitygroup)
        # NSX security-group config
        sg_dict = {"securitygroup":
                   {"name": nsx_sg_name,
                    "description": securitygroup['description']}}
        # Create the nsx security group
        h, nsx_sg_id = self.nsx_v.vcns.create_security_group(sg_dict)

        # Save moref in the DB for future access
        nsx_db.add_neutron_nsx_security_group_mapping(
            context.session, securitygroup['id'], nsx_sg_id)
        return nsx_sg_id

    def _process_security_group_create_backend_resources(self,
                                                         context,
                                                         securitygroup):
        nsx_sg_id = self._create_nsx_security_group(context, securitygroup)
        try:
            self._create_fw_section_for_security_group(
                context, securitygroup, nsx_sg_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._delete_nsx_security_group(nsx_sg_id)

        if not securitygroup[provider_sg.PROVIDER]:
            # Add Security Group to the Security Groups container inorder to
            # apply the default block rule. provider security-groups should not
            # have a default blocking rule.
            self._add_member_to_security_group(self.sg_container_id, nsx_sg_id)

    def create_security_group(self, context, security_group, default_sg=False):
        """Create a security group."""
        sg_data = security_group['security_group']
        sg_id = sg_data["id"] = str(uuid.uuid4())

        with context.session.begin(subtransactions=True):
            if sg_data.get(provider_sg.PROVIDER):
                new_sg = self.create_provider_security_group(
                    context, security_group)
            else:
                new_sg = super(NsxVPluginV2, self).create_security_group(
                    context, security_group, default_sg)
            self._process_security_group_properties_create(
                context, new_sg, sg_data, default_sg)
        try:
            self._process_security_group_create_backend_resources(
                context, new_sg)
        except Exception:
            # Couldn't create backend resources, rolling back neutron db
            # changes.
            with excutils.save_and_reraise_exception():
                # Delete security-group and its associations from database,
                # Only admin can delete the default security-group
                if default_sg:
                    context = context.elevated()
                super(NsxVPluginV2, self).delete_security_group(context, sg_id)
                LOG.exception(_LE('Failed to create security group'))
        return new_sg

    def update_security_group(self, context, id, security_group):
        s = security_group['security_group']
        nsx_sg_id = nsx_db.get_nsx_security_group_id(context.session, id)
        section_uri = self._get_section_uri(context.session, id)
        section_needs_update = False

        sg_data = super(NsxVPluginV2, self).update_security_group(
            context, id, security_group)

        # Reflect security-group name or description changes in the backend,
        # dfw section name needs to be updated as well.
        h, c = self.nsx_v.vcns.get_section(section_uri)
        section = self.nsx_sg_utils.parse_section(c)
        if set(['name', 'description']) & set(s.keys()):
            nsx_sg_name = self.nsx_sg_utils.get_nsx_sg_name(sg_data)
            section_name = self.nsx_sg_utils.get_nsx_section_name(sg_data)
            self.nsx_v.vcns.update_security_group(
                nsx_sg_id, nsx_sg_name, sg_data['description'])
            section.attrib['name'] = section_name
            section_needs_update = True
        # Update the dfw section if security-group logging option has changed.
        log_all_rules = cfg.CONF.nsxv.log_security_groups_allowed_traffic
        self._process_security_group_properties_update(context, sg_data, s)
        if not log_all_rules and context.is_admin:
            section_needs_update |= self.nsx_sg_utils.set_rules_logged_option(
                section, sg_data[sg_logging.LOGGING])
        if section_needs_update:
            self.nsx_v.vcns.update_section(
                section_uri, self.nsx_sg_utils.to_xml_string(section), h)
        return sg_data

    def delete_security_group(self, context, id):
        """Delete a security group."""
        self._prevent_non_admin_delete_provider_sg(context, id)
        try:
            # Find nsx rule sections
            section_uri = self._get_section_uri(context.session, id)

            # Find nsx security group
            nsx_sg_id = nsx_db.get_nsx_security_group_id(context.session, id)

            # Delete neutron security group
            super(NsxVPluginV2, self).delete_security_group(context, id)

            # Delete nsx rule sections
            self._delete_section(section_uri)

            # Delete nsx security group
            self._delete_nsx_security_group(nsx_sg_id)

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to delete security group"))

    def _create_nsx_rule(self, context, rule,
                         nsx_sg_id=None, logged=False, action='allow'):
        src = None
        dest = None
        port = None
        protocol = None
        icmptype = None
        icmpcode = None
        flags = {}

        if nsx_sg_id is None:
            # Find nsx security group for neutron security group
            nsx_sg_id = nsx_db.get_nsx_security_group_id(
                context.session, rule['security_group_id'])

        # Find the remote nsx security group id, which might be the current
        # one. In case of the default security-group, the associated
        # nsx-security-group wasn't written to the database yet.
        if rule['remote_group_id'] == rule['security_group_id']:
            remote_nsx_sg_id = nsx_sg_id
        else:
            remote_nsx_sg_id = nsx_db.get_nsx_security_group_id(
                context.session, rule['remote_group_id'])

        # Get source and destination containers from rule
        if rule['direction'] == 'ingress':
            if rule.get(secgroup_rule_local_ip_prefix.LOCAL_IP_PREFIX):
                dest = self.nsx_sg_utils.get_remote_container(
                    None, rule[secgroup_rule_local_ip_prefix.LOCAL_IP_PREFIX])
            src = self.nsx_sg_utils.get_remote_container(
                remote_nsx_sg_id, rule['remote_ip_prefix'])
            dest = dest or self.nsx_sg_utils.get_container(nsx_sg_id)
            flags['direction'] = 'in'
        else:
            dest = self.nsx_sg_utils.get_remote_container(
                remote_nsx_sg_id, rule['remote_ip_prefix'])
            src = self.nsx_sg_utils.get_container(nsx_sg_id)
            flags['direction'] = 'out'

        protocol = rule.get('protocol')
        if rule['port_range_min'] is not None:
            if protocol == '1' or protocol == 'icmp':
                icmptype = str(rule['port_range_min'])
                if rule['port_range_max'] is not None:
                    icmpcode = str(rule['port_range_max'])
            else:
                port = str(rule['port_range_min'])
                if rule['port_range_max'] != rule['port_range_min']:
                    port = port + '-' + str(rule['port_range_max'])

        # Get the neutron rule id to use as name in nsxv rule
        name = rule.get('id')
        services = [(protocol, port, icmptype, icmpcode)] if protocol else []

        flags['ethertype'] = rule.get('ethertype')
        # Add rule in nsx rule section
        nsx_rule = self.nsx_sg_utils.get_rule_config(
            applied_to_ids=[nsx_sg_id],
            name=name,
            source=src,
            destination=dest,
            services=services,
            flags=flags,
            action=action,
            logged=logged)
        return nsx_rule

    def create_security_group_rule(self, context, security_group_rule):
        """Create a single security group rule."""
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def create_security_group_rule_bulk(self, context, security_group_rules):
        """Create security group rules.

        :param security_group_rules: list of rules to create
        """
        sg_rules = security_group_rules['security_group_rules']
        sg_id = sg_rules[0]['security_group_rule']['security_group_id']
        self._prevent_non_admin_delete_provider_sg(context, sg_id)

        ruleids = set()
        nsx_rules = []

        self._validate_security_group_rules(context, security_group_rules)

        # Querying DB for associated dfw section id
        section_uri = self._get_section_uri(context.session, sg_id)
        logging = self._is_security_group_logged(context, sg_id)
        provider = self._is_provider_security_group(context, sg_id)
        log_all_rules = cfg.CONF.nsxv.log_security_groups_allowed_traffic

        # Translating Neutron rules to Nsx DFW rules
        for r in sg_rules:
            rule = r['security_group_rule']
            if not self._check_local_ip_prefix(context, rule):
                rule[secgroup_rule_local_ip_prefix.LOCAL_IP_PREFIX] = None
            rule['id'] = uuidutils.generate_uuid()
            ruleids.add(rule['id'])
            nsx_rules.append(
                self._create_nsx_rule(context, rule,
                                      logged=log_all_rules or logging,
                                      action='deny' if provider else 'allow')
            )

        _h, _c = self.nsx_v.vcns.get_section(section_uri)
        section = self.nsx_sg_utils.parse_section(_c)
        self.nsx_sg_utils.extend_section_with_rules(section, nsx_rules)
        h, c = self.nsx_v.vcns.update_section(
            section_uri, self.nsx_sg_utils.to_xml_string(section), _h)
        rule_pairs = self.nsx_sg_utils.get_rule_id_pair_from_section(c)

        try:
            # Save new rules in Database, including mappings between Nsx rules
            # and Neutron security-groups rules
            with context.session.begin(subtransactions=True):
                new_rule_list = super(
                    NsxVPluginV2, self).create_security_group_rule_bulk_native(
                        context, security_group_rules)
                for pair in rule_pairs:
                    neutron_rule_id = pair['neutron_id']
                    nsx_rule_id = pair['nsx_id']
                    if neutron_rule_id in ruleids:
                        nsxv_db.add_neutron_nsx_rule_mapping(
                            context.session, neutron_rule_id, nsx_rule_id)
                for i, r in enumerate(sg_rules):
                    self._process_security_group_rule_properties(
                        context, new_rule_list[i], r['security_group_rule'])
        except Exception:
            with excutils.save_and_reraise_exception():
                for nsx_rule_id in [p['nsx_id'] for p in rule_pairs
                                    if p['neutron_id'] in ruleids]:
                    self.nsx_v.vcns.remove_rule_from_section(
                        section_uri, nsx_rule_id)
                LOG.exception(_LE("Failed to create security group rule"))
        return new_rule_list

    def delete_security_group_rule(self, context, id):
        """Delete a security group rule."""
        rule_db = self._get_security_group_rule(context, id)
        security_group_id = rule_db['security_group_id']
        self._prevent_non_admin_delete_provider_sg(context, security_group_id)

        # Get the nsx rule from neutron DB and delete it
        nsx_rule_id = nsxv_db.get_nsx_rule_id(context.session, id)
        section_uri = self._get_section_uri(
            context.session, security_group_id)
        try:
            if nsx_rule_id and section_uri:
                self.nsx_v.vcns.remove_rule_from_section(
                    section_uri, nsx_rule_id)
        except vsh_exc.ResourceNotFound:
            LOG.debug("Security group rule %(id)s deleted, backend "
                      "nsx-rule %(nsx_rule_id)s doesn't exist.",
                      {'id': id, 'nsx_rule_id': nsx_rule_id})

        with context.session.begin(subtransactions=True):
            context.session.delete(rule_db)

    def _remove_vnic_from_spoofguard_policy(self, session, net_id, vnic_id):
        policy_id = nsxv_db.get_spoofguard_policy_id(session, net_id)
        self.nsx_v.vcns.inactivate_vnic_assigned_addresses(policy_id, vnic_id)

    def _update_vnic_assigned_addresses(self, session, port, vnic_id):
        sg_policy_id = nsxv_db.get_spoofguard_policy_id(
            session, port['network_id'])
        mac_addr = port['mac_address']
        approved_addrs = [addr['ip_address'] for addr in port['fixed_ips']]
        # add in the address pair
        approved_addrs.extend(
            addr['ip_address'] for addr in port[addr_pair.ADDRESS_PAIRS])
        self.nsx_v.vcns.approve_assigned_addresses(
            sg_policy_id, vnic_id, mac_addr, approved_addrs)
        self.nsx_v.vcns.publish_assigned_addresses(sg_policy_id, vnic_id)

    def _is_compute_port(self, port):
        try:
            if (port['device_id'] and uuidutils.is_uuid_like(port['device_id'])
                and port['device_owner'].startswith('compute:')):
                return True
        except (KeyError, AttributeError):
            pass
        return False

    def _is_valid_ip(self, ip_addr):
        return netaddr.valid_ipv4(ip_addr) or netaddr.valid_ipv6(ip_addr)

    def _ensure_lock_operations(self):
        try:
            self.nsx_v.vcns.edges_lock_operation()
        except Exception:
            LOG.info(_LI("Unable to set manager lock operation"))

    def _aggregate_publishing(self):
        try:
            self.nsx_v.vcns.configure_aggregate_publishing()
        except Exception:
            LOG.info(_LI("Unable to configure aggregate publishing"))

    def _configure_reservations(self):
        ver = self.nsx_v.vcns.get_version()
        if version.LooseVersion(ver) < version.LooseVersion('6.2.3'):
            LOG.debug("Skipping reservation configuration. "
                      "Not supported by version - %s.", ver)
            return
        try:
            self.nsx_v.vcns.configure_reservations()
        except Exception:
            LOG.info(_LI("Unable to configure edge reservations"))

    def _validate_config(self):
        if (cfg.CONF.nsxv.dvs_id and
            not self.nsx_v.vcns.validate_dvs(cfg.CONF.nsxv.dvs_id)):
            raise nsx_exc.NsxResourceNotFound(
                                res_name='dvs_id',
                                res_id=cfg.CONF.nsxv.dvs_id)

        if not self.nsx_v.vcns.validate_datacenter_moid(
                cfg.CONF.nsxv.datacenter_moid):
            raise nsx_exc.NsxResourceNotFound(
                                res_name='datacenter_moid',
                                res_id=cfg.CONF.nsxv.datacenter_moid)

        if not self.nsx_v.vcns.validate_network(
                cfg.CONF.nsxv.external_network):
            raise nsx_exc.NsxResourceNotFound(
                                res_name='external_network',
                                res_id=cfg.CONF.nsxv.external_network)

        if not self.nsx_v.vcns.validate_vdn_scope(cfg.CONF.nsxv.vdn_scope_id):
            raise nsx_exc.NsxResourceNotFound(
                                res_name='vdn_scope_id',
                                res_id=cfg.CONF.nsxv.vdn_scope_id)

        if (cfg.CONF.nsxv.mgt_net_moid
            and not self.nsx_v.vcns.validate_network(
                cfg.CONF.nsxv.mgt_net_moid)):
            raise nsx_exc.NsxResourceNotFound(
                                res_name='mgt_net_moid',
                                res_id=cfg.CONF.nsxv.mgt_net_moid)

        ver = self.nsx_v.vcns.get_version()
        if version.LooseVersion(ver) < version.LooseVersion('6.2.0'):
            LOG.warning(_LW("Skipping validations. Not supported by version."))
            return
        # Validations below only supported by 6.2.0 and above
        inventory = [(cfg.CONF.nsxv.resource_pool_id,
                      'resource_pool_id'),
                     (cfg.CONF.nsxv.datastore_id,
                      'datastore_id'),
                     (cfg.CONF.nsxv.ha_datastore_id,
                      'ha_datastore_id'),
                     ]
        # Treat the cluster list
        for cluster in cfg.CONF.nsxv.cluster_moid:
            inventory.append((cluster, 'cluster_moid'))

        # Add the availability zones resources
        az_resources = self._availability_zones_data.get_resources()
        for res in az_resources:
            inventory.append((res, 'availability_zones'))

        for moref, field in inventory:
            if moref and not self.nsx_v.vcns.validate_inventory(moref):
                error = _("Configured %s not found") % field
                raise nsx_exc.NsxPluginException(err_msg=error)

    def _handle_qos_notification(self, qos_policys, event_type):
        qos_utils.handle_qos_notification(qos_policys, event_type, self._dvs)

    def get_az_by_hint(self, hint):
        az = self._availability_zones_data.get_availability_zone(hint)
        if not az:
            raise az_ext.AvailabilityZoneNotFound(availability_zone=hint)
        return az

    def get_default_az(self):
        return self._availability_zones_data.get_default_availability_zone()


# Register the callback
def _validate_network_has_subnet(resource, event, trigger, **kwargs):
    network_id = kwargs.get('network_id')
    subnets = kwargs.get('subnets')
    if not subnets:
        msg = _('No subnet defined on network %s') % network_id
        raise n_exc.InvalidInput(error_message=msg)


def subscribe():
    registry.subscribe(_validate_network_has_subnet,
                       resources.ROUTER_GATEWAY, events.BEFORE_CREATE)


subscribe()
