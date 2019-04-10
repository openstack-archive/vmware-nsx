# Copyright 2018 VMware, Inc.
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

import time

import netaddr

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import uuidutils

from neutron.db import agents_db
from neutron.db import l3_db
from neutron.db.models import l3 as l3_db_models
from neutron.db.models import securitygroup as securitygroup_model  # noqa
from neutron.db import models_v2
from neutron.extensions import securitygroup as ext_sg
from neutron.quota import resource_registry
from neutron_lib.api.definitions import address_scope
from neutron_lib.api.definitions import agent as agent_apidef
from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api.definitions import availability_zone as az_apidef
from neutron_lib.api.definitions import dhcpagentscheduler
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import extra_dhcp_opt as ext_edo
from neutron_lib.api.definitions import extraroute
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import network_availability_zone
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings as pbin_apidef
from neutron_lib.api.definitions import provider_net as pnet_apidef
from neutron_lib.api.definitions import router_availability_zone
from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from neutron_lib.api import extensions
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from neutron_lib.services.qos import constants as qos_consts

from vmware_nsx._i18n import _
from vmware_nsx.common import config  # noqa
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import l3_rpc_agent_api
from vmware_nsx.common import locking
from vmware_nsx.common import managers
from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.extensions import maclearning as mac_ext
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.extensions import secgroup_rule_local_ip_prefix as sg_prefix
from vmware_nsx.extensions import securitygrouplogging as sg_logging
from vmware_nsx.plugins.common_v3 import plugin as nsx_plugin_common
from vmware_nsx.plugins.nsx_p import availability_zones as nsxp_az
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils
from vmware_nsx.services.fwaas.common import utils as fwaas_utils
from vmware_nsx.services.fwaas.nsx_p import fwaas_callbacks_v2
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_p.implementation import healthmonitor_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import l7policy_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import l7rule_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import listener_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import loadbalancer_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import member_mgr
from vmware_nsx.services.lbaas.nsx_p.implementation import pool_mgr
from vmware_nsx.services.lbaas.nsx_p.v2 import lb_driver_v2
from vmware_nsx.services.lbaas.octavia import octavia_listener
from vmware_nsx.services.qos.common import utils as qos_com_utils
from vmware_nsx.services.qos.nsx_v3 import driver as qos_driver
from vmware_nsx.services.qos.nsx_v3 import pol_utils as qos_utils

from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as nsxlib_consts
from vmware_nsxlib.v3.policy import constants as policy_constants
from vmware_nsxlib.v3.policy import core_defs as policy_defs
from vmware_nsxlib.v3 import security
from vmware_nsxlib.v3 import utils as nsxlib_utils

LOG = log.getLogger(__name__)
NSX_P_SECURITY_GROUP_TAG = 'os-security-group'
NSX_P_GLOBAL_DOMAIN_ID = policy_constants.DEFAULT_DOMAIN
NSX_P_DEFAULT_GROUP = 'os_default_group'
NSX_P_DEFAULT_GROUP_DESC = 'Default Group for the openstack plugin'
NSX_P_DEFAULT_SECTION = 'os_default_section'
NSX_P_DEFAULT_SECTION_DESC = ('This section is handled by OpenStack to '
                              'contain default rules on security-groups.')
NSX_P_DEFAULT_SECTION_CATEGORY = policy_constants.CATEGORY_APPLICATION
NSX_P_REGULAR_SECTION_CATEGORY = policy_constants.CATEGORY_ENVIRONMENT
NSX_P_PROVIDER_SECTION_CATEGORY = policy_constants.CATEGORY_INFRASTRUCTURE
NSX_P_PORT_RESOURCE_TYPE = 'os-neutron-port-id'
NSX_P_EXCLUDE_LIST_GROUP = 'neutron_excluded_ports_group'
NSX_P_EXCLUDE_LIST_TAG = 'Exclude-Port'

SPOOFGUARD_PROFILE_ID = 'neutron-spoofguard-profile'
NO_SPOOFGUARD_PROFILE_ID = policy_defs.SpoofguardProfileDef.DEFAULT_PROFILE
MAC_DISCOVERY_PROFILE_ID = 'neutron-mac-discovery-profile'
NO_MAC_DISCOVERY_PROFILE_ID = (
    policy_defs.MacDiscoveryProfileDef.DEFAULT_PROFILE)
NO_SEG_SECURITY_PROFILE_ID = 'neutron-no-segment-security-profile'
SEG_SECURITY_PROFILE_ID = (
    policy_defs.SegmentSecurityProfileDef.DEFAULT_PROFILE)
SLAAC_NDRA_PROFILE_ID = 'neutron-slaac-profile'
DEFAULT_NDRA_PROFILE_ID = 'default'

IPV6_RA_SERVICE = 'neutron-ipv6-ra'

# Priorities for NAT rules: (FIP specific rules should come before GW rules)
NAT_RULE_PRIORITY_FIP = 2000
NAT_RULE_PRIORITY_GW = 3000


@resource_extend.has_resource_extenders
class NsxPolicyPlugin(nsx_plugin_common.NsxPluginV3Base):

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = [addr_apidef.ALIAS,
                                   address_scope.ALIAS,
                                   "quotas",
                                   pbin_apidef.ALIAS,
                                   ext_edo.ALIAS,
                                   agent_apidef.ALIAS,
                                   dhcpagentscheduler.ALIAS,
                                   "ext-gw-mode",
                                   "security-group",
                                   sg_prefix.ALIAS,
                                   psec.ALIAS,
                                   pnet_apidef.ALIAS,
                                   external_net.ALIAS,
                                   extraroute.ALIAS,
                                   l3_apidef.ALIAS,
                                   az_apidef.ALIAS,
                                   network_availability_zone.ALIAS,
                                   router_availability_zone.ALIAS,
                                   "subnet_allocation",
                                   sg_logging.ALIAS,
                                   provider_sg.ALIAS,
                                   "port-security-groups-filtering",
                                   mac_ext.ALIAS]

    @resource_registry.tracked_resources(
        network=models_v2.Network,
        port=models_v2.Port,
        subnet=models_v2.Subnet,
        subnetpool=models_v2.SubnetPool,
        security_group=securitygroup_model.SecurityGroup,
        security_group_rule=securitygroup_model.SecurityGroupRule,
        router=l3_db_models.Router,
        floatingip=l3_db_models.FloatingIP)
    def __init__(self):
        self.fwaas_callbacks = None
        self.init_is_complete = False
        self._is_sub_plugin = False
        self.octavia_listener = None
        self.octavia_stats_collector = None
        nsxlib_utils.set_is_attr_callback(validators.is_attr_set)
        self._extend_fault_map()
        extension_drivers = cfg.CONF.nsx_extension_drivers
        self._extension_manager = managers.ExtensionManager(
            extension_drivers=extension_drivers)
        self.cfg_group = 'nsx_p'  # group name for nsx_p section in nsx.ini
        self.init_availability_zones()

        self.nsxpolicy = v3_utils.get_nsxpolicy_wrapper()
        # NOTE: This is needed for passthrough APIs, should be removed when
        # policy has full support
        self.nsxlib = None
        if cfg.CONF.nsx_p.allow_passthrough:
            self.nsxlib = v3_utils.get_nsxlib_wrapper(
                plugin_conf=cfg.CONF.nsx_p,
                allow_overwrite_header=True)

        super(NsxPolicyPlugin, self).__init__()

        # Bind the dummy L3 notifications
        self.l3_rpc_notifier = l3_rpc_agent_api.L3NotifyAPI()
        LOG.info("Starting NsxPolicyPlugin")
        self._extension_manager.initialize()
        self.supported_extension_aliases.extend(
            self._extension_manager.extension_aliases())

        # Support transparent VLANS only if the global configuration flag
        # vlan_transparent is True
        if cfg.CONF.vlan_transparent:
            self.supported_extension_aliases.append(vlan_apidef.ALIAS)

        nsxlib_utils.set_inject_headers_callback(v3_utils.inject_headers)
        self._validate_nsx_policy_version()

        self._init_default_config()
        self._prepare_default_rules()
        self._init_profiles()
        self._prepare_exclude_list()
        self._init_dhcp_metadata()
        self.lbv2_driver = self._init_lbv2_driver()

        # Init QoS
        qos_driver.register(qos_utils.PolicyQosNotificationsHandler())

        registry.subscribe(self.spawn_complete,
                           resources.PROCESS,
                           events.AFTER_SPAWN)

        # subscribe the init complete method last, so it will be called only
        # if init was successful
        registry.subscribe(self.init_complete,
                           resources.PROCESS,
                           events.AFTER_INIT)

    def _init_default_config(self):

        # Ipv6 is disabled by default in NSX
        if cfg.CONF.nsx_p.allow_passthrough:
            self.nsxlib.global_routing.enable_ipv6()
        else:
            LOG.warning("Unable to switch on Ipv6 forwarding. Ipv6 "
                        "connectivity might be broken.")
        # Default tier0/transport zones are initialized via the default AZ

        # Validate other mandatory configuration
        if cfg.CONF.nsx_p.allow_passthrough:
            if not cfg.CONF.nsx_p.dhcp_profile:
                raise cfg.RequiredOptError("dhcp_profile",
                                           group=cfg.OptGroup('nsx_p'))

            if not cfg.CONF.nsx_p.metadata_proxy:
                raise cfg.RequiredOptError("metadata_proxy",
                                           group=cfg.OptGroup('nsx_p'))

        # If using tags to find the objects, make sure tag scope is configured
        if (cfg.CONF.nsx_p.init_objects_by_tags and
            not cfg.CONF.nsx_p.search_objects_scope):
            raise cfg.RequiredOptError("search_objects_scope",
                                       group=cfg.OptGroup('nsx_p'))

        # Init AZ resources
        search_scope = (cfg.CONF.nsx_p.search_objects_scope
                        if cfg.CONF.nsx_p.init_objects_by_tags else None)
        for az in self.get_azs_list():
            az.translate_configured_names_to_uuids(
                self.nsxpolicy, nsxlib=self.nsxlib, search_scope=search_scope)

        self._waf_profile_uuid = self._init_backend_resource(
            self.nsxpolicy.waf_profile,
            cfg.CONF.nsx_p.waf_profile,
            search_scope=search_scope)

        # create or override ipv6 RA service
        unicast_ra = self.nsxpolicy.icmp_service.build_entry(
            'unicast RA', IPV6_RA_SERVICE, 'unicast',
            version=6, icmp_type=134)
        multicast_ra = self.nsxpolicy.icmp_service.build_entry(
            'multicast RA', IPV6_RA_SERVICE, 'multicast',
            version=6, icmp_type=151)

        try:
            self.nsxpolicy.mixed_service.create_or_overwrite(
                IPV6_RA_SERVICE, IPV6_RA_SERVICE,
                entries=[unicast_ra, multicast_ra])
        except nsx_lib_exc.ManagerError:
            msg = _("Failed to configure RA service for IPv6 connectivity")
            LOG.error(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def _init_backend_resource(self, resource_api, name_or_id,
                               search_scope=None):
        resource_type = resource_api.entry_def.resource_type()
        if not name_or_id:
            return None
        try:
            # Check if the configured value is the ID
            resource_api.get(name_or_id, silent=True)
            return name_or_id
        except nsx_lib_exc.ResourceNotFound:
            # Search by tags
            if search_scope:
                resource_id = self.nsxpolicy.get_id_by_resource_and_tag(
                    resource_type,
                    search_scope,
                    name_or_id)
                if resource_id:
                    return resource_id

            # Check if the configured value is the name
            resource = resource_api.get_by_name(name_or_id)
            if resource:
                return resource['id']

        msg = (_("Could not find %(type)s %(id)s") % {
            'type': resource_type, 'id': name_or_id})
        raise nsx_exc.NsxPluginException(err_msg=msg)

    def get_waf_profile_path_and_mode(self):
        if not self._waf_profile_uuid:
            return None, None
        path = self.nsxpolicy.waf_profile.get_path(
            profile_id=self._waf_profile_uuid)
        mode = (policy_constants.WAF_OPERATIONAL_MODE_PROTECTION
                if cfg.CONF.nsx_p.waf_protect
                else policy_constants.WAF_OPERATIONAL_MODE_DETECTION)
        return path, mode

    def _init_dhcp_metadata(self):
        if (cfg.CONF.dhcp_agent_notification and
            cfg.CONF.nsx_p.allow_passthrough):
            msg = _("Need to disable dhcp_agent_notification when "
                    "native DHCP & Metadata is enabled")
            raise nsx_exc.NsxPluginException(err_msg=msg)
        self._init_native_dhcp()
        self._init_native_metadata()

    def init_availability_zones(self):
        self._availability_zones_data = nsxp_az.NsxPAvailabilityZones()

    def _validate_nsx_policy_version(self):
        self._nsx_version = self.nsxpolicy.get_version()
        LOG.info("NSX Version: %s", self._nsx_version)
        if (not self.nsxpolicy.feature_supported(
                nsxlib_consts.FEATURE_NSX_POLICY_NETWORKING) or
            not utils.is_nsx_version_2_5_0(self._nsx_version)):
            msg = (_("The NSX Policy plugin requires version 2.5 "
                     "(current version %(ver)s)") % {'ver': self._nsx_version})
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def _init_profiles(self):
        """Find/Create segment profiles this plugin will use"""
        # Spoofguard profile (find it or create)
        try:
            self.nsxpolicy.spoofguard_profile.get(SPOOFGUARD_PROFILE_ID)
        except nsx_lib_exc.ResourceNotFound:
            self.nsxpolicy.spoofguard_profile.create_or_overwrite(
                SPOOFGUARD_PROFILE_ID,
                profile_id=SPOOFGUARD_PROFILE_ID,
                address_binding_whitelist=True,
                tags=self.nsxpolicy.build_v3_api_version_tag())

        # No Port security spoofguard profile
        # (default NSX profile. just verify it exists)
        try:
            self.nsxpolicy.spoofguard_profile.get(NO_SPOOFGUARD_PROFILE_ID)
        except nsx_lib_exc.ResourceNotFound:
            msg = (_("Cannot find spoofguard profile %s") %
                   NO_SPOOFGUARD_PROFILE_ID)
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # Mac discovery profile (find it or create)
        try:
            self.nsxpolicy.mac_discovery_profile.get(
                MAC_DISCOVERY_PROFILE_ID)
        except nsx_lib_exc.ResourceNotFound:
            self.nsxpolicy.mac_discovery_profile.create_or_overwrite(
                MAC_DISCOVERY_PROFILE_ID,
                profile_id=MAC_DISCOVERY_PROFILE_ID,
                mac_change_enabled=True,
                mac_learning_enabled=True,
                tags=self.nsxpolicy.build_v3_api_version_tag())

        # No Mac discovery profile profile
        # (default NSX profile. just verify it exists)
        try:
            self.nsxpolicy.mac_discovery_profile.get(
                NO_MAC_DISCOVERY_PROFILE_ID)
        except nsx_lib_exc.ResourceNotFound:
            msg = (_("Cannot find MAC discovery profile %s") %
                   NO_MAC_DISCOVERY_PROFILE_ID)
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # No Port security segment-security profile (find it or create)
        try:
            self.nsxpolicy.segment_security_profile.get(
                NO_SEG_SECURITY_PROFILE_ID)
        except nsx_lib_exc.ResourceNotFound:
            self.nsxpolicy.segment_security_profile.create_or_overwrite(
                NO_SEG_SECURITY_PROFILE_ID,
                profile_id=NO_SEG_SECURITY_PROFILE_ID,
                bpdu_filter_enable=False,
                dhcp_client_block_enabled=False,
                dhcp_client_block_v6_enabled=False,
                dhcp_server_block_enabled=False,
                dhcp_server_block_v6_enabled=False,
                non_ip_traffic_block_enabled=False,
                ra_guard_enabled=False,
                rate_limits_enabled=False,
                tags=self.nsxpolicy.build_v3_api_version_tag())

        # Port security segment-security profile
        # (default NSX profile. just verify it exists)
        try:
            self.nsxpolicy.segment_security_profile.get(
                SEG_SECURITY_PROFILE_ID)
        except nsx_lib_exc.ResourceNotFound:
            msg = (_("Cannot find segment security profile %s") %
                   SEG_SECURITY_PROFILE_ID)
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # Ipv6 NDRA profile (find it or create)
        try:
            self.nsxpolicy.ipv6_ndra_profile.get(SLAAC_NDRA_PROFILE_ID)
        except nsx_lib_exc.ResourceNotFound:
            self.nsxpolicy.ipv6_ndra_profile.create_or_overwrite(
                SLAAC_NDRA_PROFILE_ID,
                profile_id=SLAAC_NDRA_PROFILE_ID,
                ra_mode=policy_constants.IPV6_RA_MODE_SLAAC_RA,
                tags=self.nsxpolicy.build_v3_api_version_tag())

        # Verify default NDRA profile exists
        try:
            self.nsxpolicy.ipv6_ndra_profile.get(DEFAULT_NDRA_PROFILE_ID)
        except nsx_lib_exc.ResourceNotFound:
            msg = (_("Cannot find ipv6 ndra profile %s") %
                   DEFAULT_NDRA_PROFILE_ID)
            raise nsx_exc.NsxPluginException(err_msg=msg)

    @staticmethod
    def plugin_type():
        return projectpluginmap.NsxPlugins.NSX_P

    def _init_lbv2_driver(self):
        # Get LBaaSv2 driver during plugin initialization. If the platform
        # has a version that doesn't support native loadbalancing, the driver
        # will return a NotImplementedManager class.
        LOG.debug("Initializing LBaaSv2.0 nsxp driver")
        return lb_driver_v2.EdgeLoadbalancerDriverV2()

    @staticmethod
    def is_tvd_plugin():
        return False

    def _init_fwaas(self, with_rpc):
        if self.fwaas_callbacks:
            # already initialized
            return

        if fwaas_utils.is_fwaas_v2_plugin_enabled():
            LOG.info("NSXp FWaaS v2 plugin enabled")
            self.fwaas_callbacks = fwaas_callbacks_v2.NsxpFwaasCallbacksV2(
                with_rpc)

    def _get_octavia_stats_getter(self):
        return listener_mgr.stats_getter

    def spawn_complete(self, resource, event, trigger, payload=None):
        # Init the FWaaS support with RPC listeners for the original process
        self._init_fwaas(with_rpc=True)

        self.octavia_stats_collector = (
            octavia_listener.NSXOctaviaStatisticsCollector(
                self,
                self._get_octavia_stats_getter()))

    def _init_octavia(self):
        octavia_objects = self._get_octavia_objects()
        self.octavia_listener = octavia_listener.NSXOctaviaListener(
            **octavia_objects)

    def _get_octavia_objects(self):
        return {
            'loadbalancer': loadbalancer_mgr.EdgeLoadBalancerManagerFromDict(),
            'listener': listener_mgr.EdgeListenerManagerFromDict(),
            'pool': pool_mgr.EdgePoolManagerFromDict(),
            'member': member_mgr.EdgeMemberManagerFromDict(),
            'healthmonitor':
                healthmonitor_mgr.EdgeHealthMonitorManagerFromDict(),
            'l7policy': l7policy_mgr.EdgeL7PolicyManagerFromDict(),
            'l7rule': l7rule_mgr.EdgeL7RuleManagerFromDict()}

    def init_complete(self, resource, event, trigger, payload=None):
        with locking.LockManager.get_lock('plugin-init-complete'):
            if self.init_is_complete:
                # Should be called only once per worker
                return

            # reinitialize the cluster upon fork for api workers to ensure
            # each process has its own keepalive loops + state
            self.nsxpolicy.reinitialize_cluster(resource, event, trigger,
                                                payload=payload)

            if self.nsxlib:
                self.nsxlib.reinitialize_cluster(resource, event, trigger,
                                                 payload=payload)

            # Init the FWaaS support without RPC listeners
            # for the spawn workers
            self._init_fwaas(with_rpc=False)

            # Init octavia listener and endpoints
            self._init_octavia()

            self.init_is_complete = True

    def _setup_rpc(self):
        self.endpoints = [agents_db.AgentExtRpcCallback()]

    def _create_network_on_backend(self, context, net_data,
                                   transparent_vlan,
                                   provider_data):
        net_data['id'] = net_data.get('id') or uuidutils.generate_uuid()

        # update the network name to indicate the neutron id too.
        net_name = utils.get_name_and_uuid(net_data['name'] or 'network',
                                           net_data['id'])
        tags = self.nsxpolicy.build_v3_tags_payload(
            net_data, resource_type='os-neutron-net-id',
            project_name=context.tenant_name)

        admin_state = net_data.get('admin_state_up', True)
        LOG.debug('create_network: %(net_name)s, %(physical_net)s, '
                  '%(tags)s, %(admin_state)s, %(vlan_id)s',
                  {'net_name': net_name,
                   'physical_net': provider_data['physical_net'],
                   'tags': tags,
                   'admin_state': admin_state,
                   'vlan_id': provider_data['vlan_id']})
        if transparent_vlan:
            # all vlan tags are allowed for guest vlan
            vlan_ids = ["0-%s" % const.MAX_VLAN_TAG]
        elif provider_data['vlan_id']:
            vlan_ids = [provider_data['vlan_id']]
        else:
            vlan_ids = None

        self.nsxpolicy.segment.create_or_overwrite(
            net_name,
            segment_id=net_data['id'],
            description=net_data.get('description'),
            vlan_ids=vlan_ids,
            transport_zone_id=provider_data['physical_net'],
            tags=tags)

        if not admin_state and cfg.CONF.nsx_p.allow_passthrough:
            # This api uses the passthrough api
            self.nsxpolicy.segment.set_admin_state(
                net_data['id'], admin_state)

    def _tier0_validator(self, tier0_uuid):
        # Fail if the tier0 uuid was not found on the NSX
        self.nsxpolicy.tier0.get(tier0_uuid)

    def _get_nsx_net_tz_id(self, nsx_net):
        return nsx_net['transport_zone_path'].split('/')[-1]

    def _allow_ens_networks(self):
        return True

    def _ens_psec_supported(self):
        """ENS security features are always enabled on NSX versions which
        the policy plugin supports.
        """
        return True

    def _validate_ens_net_portsecurity(self, net_data):
        """ENS security features are always enabled on NSX versions which
        the policy plugin supports.
        So no validation is needed
        """
        pass

    def _assert_on_resource_admin_state_down(self, resource_data):
        """Network & port admin state is only supported with passthrough api"""
        if (not cfg.CONF.nsx_p.allow_passthrough and
            resource_data.get("admin_state_up") is False):
            err_msg = (_("admin_state_up=False is not supported when "
                         "passthrough is disabled"))
            LOG.warning(err_msg)
            raise n_exc.InvalidInput(error_message=err_msg)

    def create_network(self, context, network):
        net_data = network['network']
        external = net_data.get(external_net.EXTERNAL)
        is_external_net = validators.is_attr_set(external) and external
        tenant_id = net_data['tenant_id']

        # validate the availability zone, and get the AZ object
        az = self._validate_obj_az_on_creation(context, net_data, 'network')

        self._ensure_default_security_group(context, tenant_id)

        vlt = False
        if extensions.is_extension_supported(self, 'vlan-transparent'):
            vlt = vlan_apidef.get_vlan_transparent(net_data)

        self._validate_create_network(context, net_data)
        self._assert_on_resource_admin_state_down(net_data)

        if is_external_net:
            is_provider_net, net_type, physical_net, vlan_id = (
                self._validate_external_net_create(
                    net_data, az._default_tier0_router,
                    self._tier0_validator))
            provider_data = {'is_provider_net': is_provider_net,
                             'net_type': net_type,
                             'physical_net': physical_net,
                             'vlan_id': vlan_id}
            is_backend_network = False
        else:
            provider_data = self._validate_provider_create(
                context, net_data,
                az._default_vlan_tz_uuid,
                az._default_overlay_tz_uuid,
                self.nsxpolicy.transport_zone,
                self.nsxpolicy.segment,
                transparent_vlan=vlt)

            # Vlan range is only supported with vlan transport zone
            if (vlt and
                provider_data['net_type'] != utils.NsxV3NetworkTypes.VLAN and
                provider_data['net_type'] != utils.NsxV3NetworkTypes.FLAT):
                err_msg = (_('vlan_transparent network can be configured only '
                             'with network-type:vlan or flat'))
                raise n_exc.InvalidInput(error_message=err_msg)

            if (provider_data['is_provider_net'] and
                provider_data['net_type'] ==
                utils.NsxV3NetworkTypes.NSX_NETWORK):
                is_backend_network = False
            else:
                is_backend_network = True

        # Create the neutron network
        with db_api.CONTEXT_WRITER.using(context):
            # Create network in Neutron
            created_net = super(NsxPolicyPlugin, self).create_network(
                context, network)
            net_id = created_net['id']
            if extensions.is_extension_supported(self, 'vlan-transparent'):
                super(NsxPolicyPlugin, self).update_network(
                    context, net_id,
                    {'network': {'vlan_transparent': vlt}})
            self._extension_manager.process_create_network(
                context, net_data, created_net)
            if psec.PORTSECURITY not in net_data:
                net_data[psec.PORTSECURITY] = True
            self._process_network_port_security_create(
                context, net_data, created_net)
            self._process_l3_create(context, created_net, net_data)
            self._add_az_to_net(context, net_id, net_data)

            if provider_data['is_provider_net']:
                # Save provider network fields, needed by get_network()
                net_bindings = [nsx_db.add_network_binding(
                    context.session, net_id,
                    provider_data['net_type'],
                    provider_data['physical_net'],
                    provider_data['vlan_id'])]
                self._extend_network_dict_provider(context, created_net,
                                                   bindings=net_bindings)

        # Create the backend NSX network
        if is_backend_network:
            try:
                self._create_network_on_backend(
                    context, created_net, vlt, provider_data)
            except Exception as e:
                LOG.exception("Failed to create NSX network network: %s", e)
                with excutils.save_and_reraise_exception():
                    super(NsxPolicyPlugin, self).delete_network(
                        context, net_id)

        # MD Proxy is currently supported by the passthrough api only
        if is_backend_network and cfg.CONF.nsx_p.allow_passthrough:
            try:
                # The new segment was not realized yet. Waiting for a bit.
                time.sleep(cfg.CONF.nsx_p.realization_wait_sec)
                nsx_net_id = self._get_network_nsx_id(context, net_id)
                self._create_net_mdproxy_port(
                    context, created_net, az, nsx_net_id)
            except Exception as e:
                LOG.error("Failed to create mdproxy port for network %s: %s",
                          net_id, e)

        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        net_model = self._get_network(context, net_id)
        resource_extend.apply_funcs('networks', created_net, net_model)

        # Update the QoS policy (will affect only future compute ports)
        qos_com_utils.set_qos_policy_on_new_net(
            context, net_data, created_net)
        if net_data.get(qos_consts.QOS_POLICY_ID):
            LOG.info("QoS Policy %(qos)s will be applied to future compute "
                     "ports of network %(net)s",
                     {'qos': net_data[qos_consts.QOS_POLICY_ID],
                      'net': created_net['id']})

        return created_net

    def delete_network(self, context, network_id):
        if cfg.CONF.nsx_p.allow_passthrough:
            self._delete_network_disable_dhcp(context, network_id)

        is_nsx_net = self._network_is_nsx_net(context, network_id)
        is_external_net = self._network_is_external(context, network_id)

        # First call DB operation for delete network as it will perform
        # checks on active ports
        self._retry_delete_network(context, network_id)

        # MD Proxy is currently supported by the passthrough api only.
        # Use it to delete mdproxy ports
        if not is_external_net and cfg.CONF.nsx_p.allow_passthrough:
            self._delete_nsx_port_by_network(network_id)

        # Delete the network segment from the backend
        if not is_external_net and not is_nsx_net:
            self.nsxpolicy.segment.delete(network_id)

    def update_network(self, context, network_id, network):
        original_net = super(NsxPolicyPlugin, self).get_network(
            context, network_id)
        net_data = network['network']

        # Validate the updated parameters
        self._validate_update_network(context, network_id, original_net,
                                      net_data)
        self._assert_on_resource_admin_state_down(net_data)

        # Neutron does not support changing provider network values
        utils.raise_if_updates_provider_attributes(net_data)
        extern_net = self._network_is_external(context, network_id)
        is_nsx_net = self._network_is_nsx_net(context, network_id)

        # Update the neutron network
        updated_net = super(NsxPolicyPlugin, self).update_network(
            context, network_id, network)
        self._extension_manager.process_update_network(context, net_data,
                                                       updated_net)
        self._process_l3_update(context, updated_net, network['network'])
        self._extend_network_dict_provider(context, updated_net)

        if qos_consts.QOS_POLICY_ID in net_data:
            # attach the policy to the network in neutron DB
            #(will affect only future compute ports)
            qos_com_utils.update_network_policy_binding(
                context, network_id, net_data[qos_consts.QOS_POLICY_ID])
            updated_net[qos_consts.QOS_POLICY_ID] = net_data[
                qos_consts.QOS_POLICY_ID]
            if net_data[qos_consts.QOS_POLICY_ID]:
                LOG.info("QoS Policy %(qos)s will be applied to future "
                         "compute ports of network %(net)s",
                         {'qos': net_data[qos_consts.QOS_POLICY_ID],
                          'net': network_id})

        # Update the backend segment
        if (not extern_net and not is_nsx_net and
            ('name' in net_data or 'description' in net_data)):
            net_name = utils.get_name_and_uuid(
                updated_net['name'] or 'network', network_id)
            try:
                self.nsxpolicy.segment.update(
                    network_id,
                    name=net_name,
                    description=net_data.get('description'))
            except nsx_lib_exc.ManagerError:
                LOG.exception("Unable to update NSX backend, rolling "
                              "back changes on neutron")
                with excutils.save_and_reraise_exception():
                    super(NsxPolicyPlugin, self).update_network(
                        context, network_id, {'network': original_net})

        if (not extern_net and not is_nsx_net and
            'admin_state_up' in net_data and
            cfg.CONF.nsx_p.allow_passthrough):
            # Update admin state using the passthrough api
            self.nsxpolicy.segment.set_admin_state(
                network_id, net_data['admin_state_up'])

        return updated_net

    def create_subnet(self, context, subnet):
        return self._create_subnet(context, subnet)

    def delete_subnet(self, context, subnet_id):
        # Call common V3 code to delete the subnet
        super(NsxPolicyPlugin, self).delete_subnet(context, subnet_id)

    def update_subnet(self, context, subnet_id, subnet):
        return self._update_subnet(context, subnet_id, subnet)

    def _build_port_address_bindings(self, context, port_data):
        psec_on, has_ip = self._determine_port_security_and_has_ip(context,
                                                                   port_data)
        if not psec_on:
            return None

        address_bindings = []
        for fixed_ip in port_data['fixed_ips']:
            ip_addr = fixed_ip['ip_address']
            mac_addr = port_data['mac_address']
            binding = self.nsxpolicy.segment_port.build_address_binding(
                ip_addr, mac_addr)
            address_bindings.append(binding)

            # add address binding for link local ipv6 address, otherwise
            # neighbor discovery will be blocked by spoofguard.
            # for now only one ipv6 address is allowed
            if netaddr.IPAddress(ip_addr).version == 6:
                lladdr = netaddr.EUI(mac_addr).ipv6_link_local()
                binding = self.nsxpolicy.segment_port.build_address_binding(
                    lladdr, mac_addr)
                address_bindings.append(binding)

        for pair in port_data.get(addr_apidef.ADDRESS_PAIRS):
            binding = self.nsxpolicy.segment_port.build_address_binding(
                pair['ip_address'], pair['mac_address'])
            address_bindings.append(binding)

        return address_bindings

    def _get_network_nsx_id(self, context, network_id):
        """Return the id of this logical switch in the nsx manager

        This api waits for the segment to really be realized, and return the ID
        of the NSX logical switch.
        If it was not realized or timed out retrying, it will return None
        The nova api will use this to attach to the instance.
        """
        if not self._network_is_external(context, network_id):
            segment_id = self._get_network_nsx_segment_id(context, network_id)
            try:
                return self.nsxpolicy.segment.get_realized_logical_switch_id(
                    segment_id)
            except nsx_lib_exc.ManagerError:
                LOG.error("Network %s was not realized", network_id)

    def _get_network_nsx_segment_id(self, context, network_id):
        """Return the NSX segment ID matching the neutron network id

        Usually the NSX ID is the same as the neutron ID. The exception is
        when this is a provider NSX_NETWORK, which means the network already
        existed on the NSX backend, and it is being consumed by the plugin.
        """
        bindings = nsx_db.get_network_bindings(context.session, network_id)
        if (bindings and
            bindings[0].binding_type == utils.NsxV3NetworkTypes.NSX_NETWORK):
            # return the ID of the NSX network
            return bindings[0].phy_uuid
        return network_id

    def _build_port_tags(self, port_data):
        sec_groups = []
        sec_groups.extend(port_data.get(ext_sg.SECURITYGROUPS, []))
        sec_groups.extend(port_data.get(provider_sg.PROVIDER_SECURITYGROUPS,
                                        []))

        tags = []
        for sg in sec_groups:
            tags = nsxlib_utils.add_v3_tag(tags,
                                           NSX_P_SECURITY_GROUP_TAG,
                                           sg)

        return tags

    def _create_or_update_port_on_backend(self, context, port_data, is_psec_on,
                                          qos_policy_id, original_port=None):
        is_create = original_port is None
        is_update = not is_create

        name = self._build_port_name(context, port_data)
        address_bindings = self._build_port_address_bindings(
            context, port_data)
        device_owner = port_data.get('device_owner')
        vif_id = None
        if device_owner and device_owner != l3_db.DEVICE_OWNER_ROUTER_INTF:
            vif_id = port_data['id']

        tags = self._build_port_tags(port_data)
        if device_owner == const.DEVICE_OWNER_DHCP:
            tag_resource_type = 'os-neutron-dport-id'
        elif device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF:
            tag_resource_type = 'os-neutron-rport-id'
        else:
            tag_resource_type = NSX_P_PORT_RESOURCE_TYPE
        tags.extend(self.nsxpolicy.build_v3_tags_payload(
            port_data, resource_type=tag_resource_type,
            project_name=context.tenant_name))

        if self._is_excluded_port(device_owner, is_psec_on):
            tags.append({'scope': security.PORT_SG_SCOPE,
                         'tag': NSX_P_EXCLUDE_LIST_TAG})

        segment_id = self._get_network_nsx_segment_id(
            context, port_data['network_id'])
        self.nsxpolicy.segment_port.create_or_overwrite(
            name, segment_id,
            port_id=port_data['id'],
            description=port_data.get('description'),
            address_bindings=address_bindings,
            vif_id=vif_id,
            tags=tags)

        # add the security profiles to the port
        if is_psec_on:
            spoofguard_profile = SPOOFGUARD_PROFILE_ID
            seg_sec_profile = SEG_SECURITY_PROFILE_ID
        else:
            spoofguard_profile = NO_SPOOFGUARD_PROFILE_ID
            seg_sec_profile = NO_SEG_SECURITY_PROFILE_ID
        self.nsxpolicy.segment_port_security_profiles.create_or_overwrite(
            name, segment_id, port_data['id'],
            spoofguard_profile_id=spoofguard_profile,
            segment_security_profile_id=seg_sec_profile)

        # add the mac discovery profile to the port
        mac_disc_profile_must = False
        if is_psec_on:
            address_pairs = port_data.get(addr_apidef.ADDRESS_PAIRS)
            if validators.is_attr_set(address_pairs) and address_pairs:
                mac_disc_profile_must = True
        mac_learning_enabled = (
            validators.is_attr_set(port_data.get(mac_ext.MAC_LEARNING)) and
            port_data.get(mac_ext.MAC_LEARNING) is True)
        if mac_disc_profile_must or mac_learning_enabled:
            mac_discovery_profile = MAC_DISCOVERY_PROFILE_ID
        else:
            mac_discovery_profile = NO_MAC_DISCOVERY_PROFILE_ID
        self.nsxpolicy.segment_port_discovery_profiles.create_or_overwrite(
            name, segment_id, port_data['id'],
            mac_discovery_profile_id=mac_discovery_profile)

        # Add QoS segment profile (only if QoS is enabled)
        if directory.get_plugin(plugin_const.QOS):
            self.nsxpolicy.segment_port_qos_profiles.create_or_overwrite(
                name, segment_id, port_data['id'],
                qos_profile_id=qos_policy_id)

        # Update port admin status using passthrough api, only if it changed
        # or new port with disabled admin state
        if cfg.CONF.nsx_p.allow_passthrough and 'admin_state_up' in port_data:
            new_state = port_data['admin_state_up']
            if ((is_create and new_state is False) or
                (is_update and
                 original_port.get('admin_state_up') != new_state)):
                # This api uses the passthrough api
                self.nsxpolicy.segment_port.set_admin_state(
                    segment_id, port_data['id'], new_state)

    def base_create_port(self, context, port):
        neutron_db = super(NsxPolicyPlugin, self).create_port(context, port)
        self._extension_manager.process_create_port(
            context, port['port'], neutron_db)
        return neutron_db

    def _is_backend_port(self, context, port_data):
        is_external_net = self._network_is_external(
            context, port_data['network_id'])

        device_owner = port_data.get('device_owner')
        is_router_interface = (device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF)

        if is_external_net or is_router_interface:
            return False

        return True

    def create_port(self, context, port, l2gw_port_check=False):
        port_data = port['port']
        # validate the new port parameters
        self._validate_create_port(context, port_data)
        self._assert_on_resource_admin_state_down(port_data)

        # Validate the vnic type (the same types as for the NSX-T plugin)
        direct_vnic_type = self._validate_port_vnic_type(
            context, port_data, port_data['network_id'],
            projectpluginmap.NsxPlugins.NSX_T)

        is_external_net = self._network_is_external(
            context, port_data['network_id'])
        if is_external_net:
            self._assert_on_external_net_with_compute(port_data)

        with db_api.CONTEXT_WRITER.using(context):
            neutron_db = self.base_create_port(context, port)
            port["port"].update(neutron_db)

            self.fix_direct_vnic_port_sec(direct_vnic_type, port_data)
            (is_psec_on, has_ip, sgids, psgids) = (
                self._create_port_preprocess_security(context, port,
                                                      port_data, neutron_db,
                                                      False))
            self._process_portbindings_create_and_update(
                context, port['port'], port_data,
                vif_type=self._vif_type_by_vnic_type(direct_vnic_type))
            self._process_port_create_extra_dhcp_opts(
                context, port_data,
                port_data.get(ext_edo.EXTRADHCPOPTS))
            self._process_port_create_security_group(context, port_data, sgids)
            self._process_port_create_provider_security_group(
                context, port_data, psgids)

            # Handle port mac learning
            if validators.is_attr_set(port_data.get(mac_ext.MAC_LEARNING)):
                # Make sure mac_learning and port sec are not both enabled
                if port_data.get(mac_ext.MAC_LEARNING) and is_psec_on:
                    msg = _('Mac learning requires that port security be '
                            'disabled')
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
                # save the mac learning value in the DB
                self._create_mac_learning_state(context, port_data)
            elif mac_ext.MAC_LEARNING in port_data:
                # This is due to the fact that the default is
                # ATTR_NOT_SPECIFIED
                port_data.pop(mac_ext.MAC_LEARNING)

        qos_policy_id = self._get_port_qos_policy_id(
            context, None, port_data)

        if self._is_backend_port(context, port_data):
            # router interface port is created automatically by policy
            try:
                self._create_or_update_port_on_backend(
                    context, port_data, is_psec_on, qos_policy_id)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.error('Failed to create port %(id)s on NSX '
                              'backend. Exception: %(e)s',
                              {'id': neutron_db['id'], 'e': e})
                    super(NsxPolicyPlugin, self).delete_port(
                        context, neutron_db['id'])

        # Attach the policy to the port in the neutron DB
        if qos_policy_id:
            qos_com_utils.update_port_policy_binding(context,
                                                     neutron_db['id'],
                                                     qos_policy_id)
        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        port_model = self._get_port(context, port_data['id'])
        resource_extend.apply_funcs('ports', port_data, port_model)
        self._extend_nsx_port_dict_binding(context, port_data)
        self._remove_provider_security_groups_from_list(port_data)

        # Add Mac/IP binding to native DHCP server and neutron DB.
        if cfg.CONF.nsx_p.allow_passthrough:
            try:
                self._add_dhcp_binding(context, port_data)
            except nsx_lib_exc.ManagerError:
                # Rollback create port
                self.delete_port(context, port_data['id'],
                                 force_delete_dhcp=True)
                msg = _('Unable to create port. Please contact admin')
                LOG.exception(msg)
                raise nsx_exc.NsxPluginException(err_msg=msg)

        kwargs = {'context': context, 'port': neutron_db}
        registry.notify(resources.PORT, events.AFTER_CREATE, self, **kwargs)
        return port_data

    def _delete_port_on_backend(self, context, net_id, port_id):
        try:
            segment_id = self._get_network_nsx_segment_id(context, net_id)
            self.nsxpolicy.segment_port_security_profiles.delete(
                segment_id, port_id)
            self.nsxpolicy.segment_port_discovery_profiles.delete(
                segment_id, port_id)
            if directory.get_plugin(plugin_const.QOS):
                self.nsxpolicy.segment_port_qos_profiles.delete(
                    segment_id, port_id)
            self.nsxpolicy.segment_port.delete(segment_id, port_id)
        except Exception as ex:
            LOG.error("Failed to delete port %(id)s on NSX backend "
                      "due to %(e)s", {'id': port_id, 'e': ex})
            # Do not fail the neutron action

    def delete_port(self, context, port_id,
                    l3_port_check=True, l2gw_port_check=True,
                    force_delete_dhcp=False,
                    force_delete_vpn=False):
        # first update neutron (this will perform all types of validations)
        port_data = self.get_port(context, port_id)
        net_id = port_data['network_id']
        # if needed, check to see if this is a port owned by
        # a l3 router.  If so, we should prevent deletion here
        if l3_port_check:
            self.prevent_l3_port_deletion(context, port_id)
        port = self.get_port(context, port_id)
        # Prevent DHCP port deletion if native support is enabled
        if (cfg.CONF.nsx_p.allow_passthrough and
            not force_delete_dhcp and
            port['device_owner'] in [const.DEVICE_OWNER_DHCP]):
            msg = (_('Can not delete DHCP port %s') % port_id)
            raise n_exc.BadRequest(resource='port', msg=msg)

        if self._is_backend_port(context, port_data):
            self._delete_port_on_backend(context, net_id, port_id)

        self.disassociate_floatingips(context, port_id)

        # Remove Mac/IP binding from native DHCP server and neutron DB.
        if cfg.CONF.nsx_p.allow_passthrough:
            self._delete_dhcp_binding(context, port)

        super(NsxPolicyPlugin, self).delete_port(context, port_id)

    def _update_port_on_backend(self, context, lport_id,
                                original_port, updated_port,
                                is_psec_on, qos_policy_id):
        # For now port create and update are the same
        # Update might evolve with more features
        return self._create_or_update_port_on_backend(
            context, updated_port, is_psec_on,
            qos_policy_id, original_port=original_port)

    def update_port(self, context, port_id, port):
        with db_api.CONTEXT_WRITER.using(context):
            # get the original port, and keep it honest as it is later used
            # for notifications
            original_port = super(NsxPolicyPlugin, self).get_port(
                context, port_id)
            self._remove_provider_security_groups_from_list(original_port)
            port_data = port['port']
            self._validate_update_port(context, port_id, original_port,
                                       port_data)
            self._assert_on_resource_admin_state_down(port_data)
            validate_port_sec = self._should_validate_port_sec_on_update_port(
                port_data)
            is_external_net = self._network_is_external(
                context, original_port['network_id'])
            if is_external_net:
                self._assert_on_external_net_with_compute(port_data)
            device_owner = (port_data['device_owner']
                            if 'device_owner' in port_data
                            else original_port.get('device_owner'))
            self._validate_max_ips_per_port(context,
                                            port_data.get('fixed_ips', []),
                                            device_owner)

            direct_vnic_type = self._validate_port_vnic_type(
                context, port_data, original_port['network_id'])

            updated_port = super(NsxPolicyPlugin, self).update_port(
                context, port_id, port)

            self._extension_manager.process_update_port(context, port_data,
                                                        updated_port)
            # copy values over - except fixed_ips as
            # they've already been processed
            port_data.pop('fixed_ips', None)
            updated_port.update(port_data)

            updated_port = self._update_port_preprocess_security(
                context, port, port_id, updated_port, False,
                validate_port_sec=validate_port_sec,
                direct_vnic_type=direct_vnic_type)

            self._update_extra_dhcp_opts_on_port(context, port_id, port,
                                                 updated_port)

            sec_grp_updated = self.update_security_group_on_port(
                context, port_id, port, original_port, updated_port)

            self._process_port_update_provider_security_group(
                context, port, original_port, updated_port)

            (port_security, has_ip) = self._determine_port_security_and_has_ip(
                context, updated_port)
            self._process_portbindings_create_and_update(
                context, port_data, updated_port,
                vif_type=self._vif_type_by_vnic_type(direct_vnic_type))
            self._extend_nsx_port_dict_binding(context, updated_port)

            mac_learning_state = updated_port.get(mac_ext.MAC_LEARNING)
            if mac_learning_state is not None:
                if port_security and mac_learning_state:
                    msg = _('Mac learning requires that port security be '
                            'disabled')
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
                self._update_mac_learning_state(context, port_id,
                                                mac_learning_state)
            self._remove_provider_security_groups_from_list(updated_port)

        # Update the QoS policy
        qos_policy_id = self._get_port_qos_policy_id(
            context, original_port, updated_port)
        qos_com_utils.update_port_policy_binding(context, port_id,
                                                 qos_policy_id)

        # update the port in the backend, only if it exists in the DB
        # (i.e not external net) and is not router interface
        if self._is_backend_port(context, updated_port):
            try:
                self._update_port_on_backend(context, port_id,
                                             original_port, updated_port,
                                             port_security, qos_policy_id)
            except Exception as e:
                LOG.error('Failed to update port %(id)s on NSX '
                          'backend. Exception: %(e)s',
                          {'id': port_id, 'e': e})
                # Rollback the change
                with excutils.save_and_reraise_exception():
                    with db_api.CONTEXT_WRITER.using(context):
                        self._revert_neutron_port_update(
                            context, port_id, original_port, updated_port,
                            port_security, sec_grp_updated)
        else:
            # if this port changed ownership to router interface, it should
            # be deleted from policy, since policy handles router connectivity
            original_owner = original_port.get('device_owner')
            new_owner = port_data.get('device_owner')
            if (original_owner != new_owner and
                new_owner == const.DEVICE_OWNER_ROUTER_INTF):
                self._delete_port_on_backend(context,
                                             original_port['network_id'],
                                             port_id)

        # Update DHCP bindings.
        if cfg.CONF.nsx_p.allow_passthrough:
            self._update_dhcp_binding(context, original_port, updated_port)

        # Make sure the port revision is updated
        if 'revision_number' in updated_port:
            port_model = self._get_port(context, port_id)
            updated_port['revision_number'] = port_model.revision_number

        # Notifications must be sent after the above transaction is complete
        kwargs = {
            'context': context,
            'port': updated_port,
            'mac_address_updated': False,
            'original_port': original_port,
        }
        registry.notify(resources.PORT, events.AFTER_UPDATE, self, **kwargs)
        return updated_port

    def get_port(self, context, port_id, fields=None):
        port = super(NsxPolicyPlugin, self).get_port(
            context, port_id, fields=None)
        self._extend_nsx_port_dict_binding(context, port)
        self._extend_qos_port_dict_binding(context, port)
        self._remove_provider_security_groups_from_list(port)
        return db_utils.resource_fields(port, fields)

    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        filters = filters or {}
        self._update_filters_with_sec_group(context, filters)
        with db_api.CONTEXT_READER.using(context):
            ports = (
                super(NsxPolicyPlugin, self).get_ports(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            # Add port extensions
            for port in ports[:]:
                self._extend_nsx_port_dict_binding(context, port)
                self._extend_qos_port_dict_binding(context, port)
                self._remove_provider_security_groups_from_list(port)
        return (ports if not fields else
                [db_utils.resource_fields(port, fields) for port in ports])

    def _get_tier0_uuid_by_router(self, context, router):
        network_id = router.gw_port_id and router.gw_port.network_id
        return self._get_tier0_uuid_by_net_id(context, network_id)

    def _add_subnet_snat_rule(self, context, router_id, subnet,
                              gw_address_scope, gw_ip):
        if not self._need_router_snat_rules(context, router_id, subnet,
                                            gw_address_scope):
            return

        self.nsxpolicy.tier1_nat_rule.create_or_overwrite(
            'snat for subnet %s' % subnet['id'],
            router_id,
            nat_rule_id=self._get_snat_rule_id(subnet),
            action=policy_constants.NAT_ACTION_SNAT,
            sequence_number=NAT_RULE_PRIORITY_GW,
            translated_network=gw_ip,
            source_network=subnet['cidr'],
            firewall_match=policy_constants.NAT_FIREWALL_MATCH_INTERNAL)

    def _get_snat_rule_id(self, subnet):
        return 'S-' + subnet['id']

    def _get_no_dnat_rule_id(self, subnet):
        return 'ND-' + subnet['id']

    def _add_subnet_no_dnat_rule(self, context, router_id, subnet):
        if not self._need_router_no_dnat_rules(subnet):
            return

        # Add NO-DNAT rule to allow internal traffic between VMs, even if
        # they have floating ips (Only for routers with snat enabled)
        self.nsxpolicy.tier1_nat_rule.create_or_overwrite(
            'no-dnat for subnet %s' % subnet['id'],
            router_id,
            nat_rule_id=self._get_no_dnat_rule_id(subnet),
            action=policy_constants.NAT_ACTION_NO_DNAT,
            sequence_number=NAT_RULE_PRIORITY_GW,
            destination_network=subnet['cidr'],
            firewall_match=policy_constants.NAT_FIREWALL_MATCH_BYPASS)

    def _del_subnet_no_dnat_rule(self, router_id, subnet):
        # Delete the previously created NO-DNAT rules
        self.nsxpolicy.tier1_nat_rule.delete(
            router_id,
            nat_rule_id=self._get_no_dnat_rule_id(subnet))

    def _del_subnet_snat_rule(self, router_id, subnet):
        # Delete the previously created SNAT rules
        self.nsxpolicy.tier1_nat_rule.delete(
            router_id,
            nat_rule_id=self._get_snat_rule_id(subnet))

    def _get_edge_cluster_path(self, tier0_uuid, router):
        # Take the AZ edge cluster if configured
        az = self._get_router_az_obj(router)
        if az and az._edge_cluster_uuid:
            ec_id = az._edge_cluster_uuid
            # get the full path of the edge cluster (no backend call)
            return self.nsxpolicy.edge_cluster.get_path(ec_id)

        # Get the current tier0 edge cluster (cached call)
        return self.nsxpolicy.tier0.get_edge_cluster_path(
            tier0_uuid)

    def service_router_has_services(self, context, router_id, router=None):
        """Check if the neutron router has any services
        which require a backend service router
        currently those are: SNAT, Loadbalancer, Edge firewall
        """
        if not router:
            router = self._get_router(context, router_id)
        snat_exist = router.enable_snat
        fw_exist = self._router_has_edge_fw_rules(context, router)
        lb_exist = False
        if not (fw_exist or snat_exist):
            lb_exist = self.service_router_has_loadbalancers(router_id)
        return snat_exist or lb_exist or fw_exist

    def service_router_has_loadbalancers(self, router_id):
        tags_to_search = [{'scope': lb_const.LR_ROUTER_TYPE, 'tag': router_id}]
        router_lb_services = self.nsxpolicy.search_by_tags(
            tags_to_search,
            self.nsxpolicy.load_balancer.lb_service.entry_def.resource_type()
        )['results']
        return True if router_lb_services else False

    def verify_sr_at_backend(self, router_id):
        """Check if the backend Tier1 has a service router or not"""
        if self.nsxpolicy.tier1.get_edge_cluster_path(router_id):
            return True

    def create_service_router(self, context, router_id, router=None,
                              update_firewall=True):
        """Create a service router and enable standby relocation"""
        if not router:
            router = self._get_router(context, router_id)
        tier0_uuid = self._get_tier0_uuid_by_router(context, router)
        if not tier0_uuid:
            err_msg = (_("Cannot create service router for %s without a "
                         "gateway") % router_id)
            raise n_exc.InvalidInput(error_message=err_msg)
        edge_cluster_path = self._get_edge_cluster_path(
            tier0_uuid, router)
        if edge_cluster_path:
            self.nsxpolicy.tier1.set_edge_cluster_path(
                router_id, edge_cluster_path)
        else:
            LOG.error("Tier0 %s does not have an edge cluster",
                      tier0_uuid)

        try:
            # Enable standby relocation on this router
            self.nsxpolicy.tier1.set_standby_relocation(
                router['id'], enable_standby_relocation=True)
        except Exception as ex:
            LOG.warning("Failed to enable standby relocation for router "
                        "%s: %s", router['id'], ex)

        # update firewall rules (there might be FW group waiting for a
        # service router)
        if update_firewall:
            self.update_router_firewall(context, router_id)

    def delete_service_router(self, project_id, router_id):
        try:
            # Disable standby relocation on this router
            self.nsxpolicy.tier1.set_standby_relocation(
                router_id, enable_standby_relocation=False)
        except Exception as ex:
            LOG.warning("Failed to disable standby relocation for router "
                        "%s: %s", router_id, ex)

        # remove the edge firewall
        if self.fwaas_callbacks and self.fwaas_callbacks.fwaas_enabled:
            self.fwaas_callbacks.delete_router_gateway_policy(
                project_id, router_id)
        self.nsxpolicy.tier1.update(router_id, disable_firewall=True)

        # remove the edge cluster from the tier1 router
        self.nsxpolicy.tier1.remove_edge_cluster(router_id)

    def _update_router_gw_info(self, context, router_id, info):
        # Get the original data of the router GW
        router = self._get_router(context, router_id)
        org_tier0_uuid = self._get_tier0_uuid_by_router(context, router)
        org_enable_snat = router.enable_snat
        orgaddr, orgmask, _orgnexthop = (
            self._get_external_attachment_info(
                context, router))
        router_subnets = self._find_router_subnets(
            context.elevated(), router_id)
        self._validate_router_gw_and_tz(context, router_id, info,
                                        org_enable_snat, router_subnets)
        # Interface subnets cannot overlap with the GW external subnet
        if info and info.get('network_id'):
            self._validate_gw_overlap_interfaces(
                context, info['network_id'],
                [sub['network_id'] for sub in router_subnets])

        # First update the neutron DB
        super(NsxPolicyPlugin, self)._update_router_gw_info(
            context, router_id, info, router=router)

        # Get the new tier0 of the updated router (or None if GW was removed)
        new_tier0_uuid = self._get_tier0_uuid_by_router(context, router)
        new_enable_snat = router.enable_snat
        newaddr, newmask, _newnexthop = self._get_external_attachment_info(
            context, router)
        router_name = utils.get_name_and_uuid(router['name'] or 'router',
                                              router['id'])
        router_subnets = self._find_router_subnets(
            context.elevated(), router_id)
        sr_currently_exists = self.verify_sr_at_backend(router_id)
        lb_exist = False
        fw_exist = self._router_has_edge_fw_rules(context, router)
        actions = self._get_update_router_gw_actions(
            org_tier0_uuid, orgaddr, org_enable_snat,
            new_tier0_uuid, newaddr, new_enable_snat,
            lb_exist, fw_exist, sr_currently_exists)

        if actions['add_service_router']:
            self.create_service_router(context, router_id, router=router)

        if actions['remove_snat_rules']:
            for subnet in router_subnets:
                self._del_subnet_snat_rule(router_id, subnet)
        if actions['remove_no_dnat_rules']:
            for subnet in router_subnets:
                self._del_subnet_no_dnat_rule(router_id, subnet)

        if (actions['remove_router_link_port'] or
            actions['add_router_link_port']):
            # GW was changed
            #TODO(asarfaty): adding the router name even though it was not
            # changed because otherwise the NSX will set it to default.
            # This code should be removed once NSX supports it.
            self.nsxpolicy.tier1.update(router_id, name=router_name,
                                        tier0=new_tier0_uuid)

            # Set/Unset the router TZ to allow vlan switches traffic
            if cfg.CONF.nsx_p.allow_passthrough:
                if new_tier0_uuid:
                    tz_uuid = self.nsxpolicy.tier0.get_overlay_transport_zone(
                        new_tier0_uuid)
                else:
                    tz_uuid = None
                self.nsxpolicy.tier1.update_transport_zone(
                    router_id, tz_uuid)
            else:
                LOG.debug("Not adding transport-zone to tier1 router %s as "
                          "passthrough api is disabled", router_id)

        if actions['add_snat_rules']:
            # Add SNAT rules for all the subnets which are in different scope
            # than the GW
            gw_address_scope = self._get_network_address_scope(
                context, router.gw_port.network_id)
            for subnet in router_subnets:
                self._add_subnet_snat_rule(context, router_id,
                                           subnet, gw_address_scope, newaddr)

        if actions['add_no_dnat_rules']:
            for subnet in router_subnets:
                self._add_subnet_no_dnat_rule(context, router_id, subnet)

        self.nsxpolicy.tier1.update_route_advertisement(
            router_id,
            nat=actions['advertise_route_nat_flag'],
            subnets=actions['advertise_route_connected_flag'])

        if actions['remove_service_router']:
            self.delete_service_router(router['project_id'], router_id)

    def create_router(self, context, router):
        r = router['router']
        gw_info = self._extract_external_gw(context, router, is_extract=True)

        # validate the availability zone, and get the AZ object
        self._validate_obj_az_on_creation(context, r, 'router')

        with db_api.CONTEXT_WRITER.using(context):
            router = super(NsxPolicyPlugin, self).create_router(
                context, router)
            router_db = self._get_router(context, router['id'])
            self._process_extra_attr_router_create(context, router_db, r)

        router_name = utils.get_name_and_uuid(router['name'] or 'router',
                                              router['id'])
        tags = self.nsxpolicy.build_v3_tags_payload(
            r, resource_type='os-neutron-router-id',
            project_name=context.tenant_name)
        try:
            self.nsxpolicy.tier1.create_or_overwrite(
                router_name, router['id'],
                tier0=None,
                tags=tags)
        #TODO(annak): narrow down the exception
        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error('Failed to create router %(id)s '
                          'on NSX backend. Exception: %(e)s',
                          {'id': router['id'], 'e': ex})
                self.delete_router(context, router['id'])

        if gw_info and gw_info != const.ATTR_NOT_SPECIFIED:
            try:
                self._update_router_gw_info(context, router['id'], gw_info)
            except (db_exc.DBError, nsx_lib_exc.ManagerError):
                with excutils.save_and_reraise_exception():
                    LOG.error("Failed to set gateway info for router "
                              "being created: %s - removing router",
                              router['id'])
                    self.delete_router(context, router['id'])
                    LOG.info("Create router failed while setting external "
                             "gateway. Router:%s has been removed from "
                             "DB and backend",
                             router['id'])

        return self.get_router(context, router['id'])

    def delete_router(self, context, router_id):
        router = self.get_router(context, router_id)
        if router.get(l3_apidef.EXTERNAL_GW_INFO):
            self._update_router_gw_info(context, router_id, {})
        ret_val = super(NsxPolicyPlugin, self).delete_router(
            context, router_id)

        try:
            self.nsxpolicy.tier1.delete(router_id)
        except Exception as ex:
            LOG.error("Failed to delete NSX T1 router %(id)s: %(e)s", {
                'e': ex, 'id': router_id})

        return ret_val

    def _get_static_route_id(self, route):
        return "%s-%s" % (route['destination'].replace('/', '_'),
                          route['nexthop'])

    def _add_static_routes(self, router_id, routes):
        for route in routes:
            dest = route['destination']
            self.nsxpolicy.tier1_static_route.create_or_overwrite(
                'Static route for %s' % dest,
                router_id,
                static_route_id=self._get_static_route_id(route),
                network=dest,
                next_hop=route['nexthop'])

    def _delete_static_routes(self, router_id, routes):
        for route in routes:
            self.nsxpolicy.tier1_static_route.delete(
                router_id,
                static_route_id=self._get_static_route_id(route))

    def update_router(self, context, router_id, router):
        gw_info = self._extract_external_gw(context, router, is_extract=False)
        router_data = router['router']
        self._assert_on_router_admin_state(router_data)

        if validators.is_attr_set(gw_info):
            self._validate_update_router_gw(context, router_id, gw_info)

        routes_added = []
        routes_removed = []
        if 'routes' in router_data:
            routes_added, routes_removed = self._get_static_routes_diff(
                context, router_id, gw_info, router_data)

        # Update the neutron router
        updated_router = super(NsxPolicyPlugin, self).update_router(
            context, router_id, router)

        # Update the policy backend
        try:
            added_routes = removed_routes = False
            # Updating name & description
            if 'name' in router_data or 'description' in router_data:
                router_name = utils.get_name_and_uuid(
                    updated_router.get('name') or 'router',
                    router_id)
                self.nsxpolicy.tier1.update(
                    router_id, name=router_name,
                    description=updated_router.get('description'))
            # Updating static routes
            self._delete_static_routes(router_id, routes_removed)
            removed_routes = True
            self._add_static_routes(router_id, routes_added)
            added_routes = True

        except (nsx_lib_exc.ResourceNotFound, nsx_lib_exc.ManagerError):
            with excutils.save_and_reraise_exception():
                with db_api.CONTEXT_WRITER.using(context):
                    router_db = self._get_router(context, router_id)
                    router_db['status'] = const.NET_STATUS_ERROR
                # return the static routes to the old state
                if added_routes:
                    try:
                        self._delete_static_routes(router_id, routes_added)
                    except Exception as e:
                        LOG.error("Rollback router %s changes failed to "
                                  "delete static routes: %s", router_id, e)
                if removed_routes:
                    try:
                        self._add_static_routes(router_id, routes_removed)
                    except Exception as e:
                        LOG.error("Rollback router %s changes failed to add "
                                  "static routes: %s", router_id, e)

        return updated_router

    def _get_gateway_addr_from_subnet(self, subnet):
        cidr_prefix = int(subnet['cidr'].split('/')[1])
        return "%s/%s" % (subnet['gateway_ip'], cidr_prefix)

    def add_router_interface(self, context, router_id, interface_info):
        network_id = self._get_interface_network(context, interface_info)
        extern_net = self._network_is_external(context, network_id)
        overlay_net = self._is_overlay_network(context, network_id)
        router_db = self._get_router(context, router_id)
        gw_network_id = (router_db.gw_port.network_id if router_db.gw_port
                         else None)
        # NOTE: In dual stack case, neutron would create a separate interface
        # for each IP version
        # We only allow one subnet per IP version
        subnet = self._get_interface_subnet(context, interface_info)

        with locking.LockManager.get_lock(str(network_id)):
            # disallow more than one subnets belong to same network being
            # attached to routers
            self._validate_multiple_subnets_routers(
                context, router_id, network_id, subnet)

            # A router interface cannot be an external network
            if extern_net:
                msg = _("An external network cannot be attached as "
                        "an interface to a router")
                raise n_exc.InvalidInput(error_message=msg)

            # Non overlay networks should be configured with a centralized
            # router, which is allowed only if GW network is attached
            if not overlay_net and not gw_network_id:
                msg = _("A router attached to a VLAN backed network "
                        "must have an external network assigned")
                raise n_exc.InvalidInput(error_message=msg)

            # Interface subnets cannot overlap with the GW external subnet
            self._validate_gw_overlap_interfaces(context, gw_network_id,
                                                 [network_id])

            # Update the interface of the neutron router
            info = super(NsxPolicyPlugin, self).add_router_interface(
                 context, router_id, interface_info)

        try:
            # If it is a no-snat router, interface address scope must be the
            # same as the gateways
            self._validate_interface_address_scope(context, router_db, info)

            # Check GW & subnets TZ
            subnets = self._find_router_subnets(context.elevated(), router_id)
            tier0_uuid = self._get_tier0_uuid_by_router(
                context.elevated(), router_db)
            #TODO(asarfaty): it is enough to validate only the new subnet,
            # and not all
            self._validate_router_tz(context.elevated(), tier0_uuid, subnets)

            segment_id = self._get_network_nsx_segment_id(context, network_id)
            subnet = self.get_subnet(context, info['subnet_ids'][0])
            if overlay_net:
                # overlay interface
                #TODO(asarfaty): adding the segment name even though it was not
                # changed because otherwise the NSX will set it to default.
                # This code should be removed once NSX supports it.
                net = self._get_network(context, network_id)
                net_name = utils.get_name_and_uuid(
                    net['name'] or 'network', network_id)
                pol_subnets = []
                for rtr_subnet in subnets:
                    # For dueal stack, we allow one v4 and one v6
                    # subnet per network
                    if rtr_subnet['network_id'] == network_id:
                        gw_addr = self._get_gateway_addr_from_subnet(
                            rtr_subnet)
                        pol_subnets.append(
                            policy_defs.Subnet(gateway_address=gw_addr))

                self.nsxpolicy.segment.update(segment_id,
                                              name=net_name,
                                              tier1_id=router_id,
                                              subnets=pol_subnets)
            else:
                # Vlan interface
                pol_subnets = []
                for rtr_subnet in subnets:
                    if rtr_subnet['network_id'] == network_id:
                        prefix_len = int(rtr_subnet['cidr'].split('/')[1])
                        pol_subnets.append(policy_defs.InterfaceSubnet(
                            ip_addresses=[rtr_subnet['gateway_ip']],
                            prefix_len=prefix_len))

                self.nsxpolicy.tier1.add_segment_interface(
                    router_id, segment_id,
                    segment_id, pol_subnets)

            # add the SNAT/NO_DNAT rules for this interface
            if router_db.enable_snat and gw_network_id:
                if router_db.gw_port.get('fixed_ips'):
                    gw_ip = router_db.gw_port['fixed_ips'][0]['ip_address']
                    gw_address_scope = self._get_network_address_scope(
                        context, gw_network_id)
                    self._add_subnet_snat_rule(
                        context, router_id,
                        subnet, gw_address_scope, gw_ip)
                self._add_subnet_no_dnat_rule(context, router_id, subnet)

            # update firewall rules
            self.update_router_firewall(context, router_id, router_db)

        except Exception as ex:
            with excutils.save_and_reraise_exception():
                LOG.error('Failed to create router interface for network '
                          '%(id)s on NSX backend. Exception: %(e)s',
                          {'id': network_id, 'e': ex})
                self.remove_router_interface(
                    context, router_id, interface_info)

        return info

    def remove_router_interface(self, context, router_id, interface_info):
        LOG.info("Removing router %s interface %s", router_id, interface_info)
        # find the subnet - it is need for removing the SNAT rule
        subnet = subnet_id = None
        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
            port = self._get_port(context, port_id)
            if port.get('fixed_ips'):
                subnet_id = port['fixed_ips'][0]['subnet_id']
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
        if subnet_id:
            subnet = self.get_subnet(context, subnet_id)

        # Update the neutron router first
        info = super(NsxPolicyPlugin, self).remove_router_interface(
            context, router_id, interface_info)
        network_id = info['network_id']
        overlay_net = self._is_overlay_network(context, network_id)
        segment_id = self._get_network_nsx_segment_id(context, network_id)

        subnets = self._find_router_subnets(context.elevated(),
                                            router_id)
        try:
            if overlay_net:
                # Remove the tier1 router from this segment on the NSX
                pol_subnets = []
                for rtr_subnet in subnets:
                    # For dual stack, we allow one v4 and one v6
                    # subnet per network
                    if rtr_subnet['network_id'] == network_id:
                        gw_addr = self._get_gateway_addr_from_subnet(
                            rtr_subnet)
                        pol_subnets.append(
                            policy_defs.Subnet(gateway_address=gw_addr))

                if pol_subnets:
                    self.nsxpolicy.segment.update(segment_id,
                                                  tier1_id=router_id,
                                                  subnets=pol_subnets)
                else:
                    self.nsxpolicy.segment.remove_connectivity_and_subnets(
                        segment_id)

            else:
                # VLAN interface
                pol_subnets = []
                for rtr_subnet in subnets:
                    if rtr_subnet['network_id'] == network_id:
                        prefix_len = int(rtr_subnet['cidr'].split('/')[1])
                        pol_subnets.append(policy_defs.InterfaceSubnet(
                            ip_addresses=[rtr_subnet['gateway_ip']],
                            prefix_len=prefix_len))

                if pol_subnets:
                    # This will update segment interface
                    self.nsxpolicy.tier1.add_segment_interface(
                        router_id, segment_id,
                        segment_id, pol_subnets)
                else:
                    self.nsxpolicy.tier1.remove_segment_interface(
                        router_id, segment_id)

            # try to delete the SNAT/NO_DNAT rules of this subnet
            router_db = self._get_router(context, router_id)
            if (subnet and router_db.gw_port and router_db.enable_snat and
                subnet['ip_version'] == 4):
                self._del_subnet_snat_rule(router_id, subnet)
                self._del_subnet_no_dnat_rule(router_id, subnet)

            # update firewall rules
            self.update_router_firewall(context, router_id, router_db)

        except Exception as ex:
            # do not fail the neutron action
            LOG.error('Failed to remove router interface for network '
                      '%(id)s on NSX backend. Exception: %(e)s',
                      {'id': network_id, 'e': ex})

        return info

    def _get_fip_snat_rule_id(self, fip_id):
        return 'S-' + fip_id

    def _get_fip_dnat_rule_id(self, fip_id):
        return 'D-' + fip_id

    def _add_fip_nat_rules(self, tier1_id, fip_id, ext_ip, int_ip):
        self.nsxpolicy.tier1_nat_rule.create_or_overwrite(
            'snat for fip %s' % fip_id,
            tier1_id,
            nat_rule_id=self._get_fip_snat_rule_id(fip_id),
            action=policy_constants.NAT_ACTION_SNAT,
            translated_network=ext_ip,
            source_network=int_ip,
            sequence_number=NAT_RULE_PRIORITY_FIP,
            firewall_match=policy_constants.NAT_FIREWALL_MATCH_INTERNAL)
        self.nsxpolicy.tier1_nat_rule.create_or_overwrite(
            'dnat for fip %s' % fip_id,
            tier1_id,
            nat_rule_id=self._get_fip_dnat_rule_id(fip_id),
            action=policy_constants.NAT_ACTION_DNAT,
            translated_network=int_ip,
            destination_network=ext_ip,
            sequence_number=NAT_RULE_PRIORITY_FIP,
            firewall_match=policy_constants.NAT_FIREWALL_MATCH_INTERNAL)

    def _delete_fip_nat_rules(self, tier1_id, fip_id):
        self.nsxpolicy.tier1_nat_rule.delete(
            tier1_id,
            nat_rule_id=self._get_fip_snat_rule_id(fip_id))
        self.nsxpolicy.tier1_nat_rule.delete(
            tier1_id,
            nat_rule_id=self._get_fip_dnat_rule_id(fip_id))

    def create_floatingip(self, context, floatingip):
        new_fip = super(NsxPolicyPlugin, self).create_floatingip(
                context, floatingip, initial_status=(
                    const.FLOATINGIP_STATUS_ACTIVE
                    if floatingip['floatingip']['port_id']
                    else const.FLOATINGIP_STATUS_DOWN))
        router_id = new_fip['router_id']
        if not router_id:
            return new_fip

        try:
            self._add_fip_nat_rules(
                router_id, new_fip['id'],
                new_fip['floating_ip_address'],
                new_fip['fixed_ip_address'])
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                self.delete_floatingip(context, new_fip['id'])

        return new_fip

    def delete_floatingip(self, context, fip_id):
        fip = self.get_floatingip(context, fip_id)
        router_id = fip['router_id']
        if router_id:
            self._delete_fip_nat_rules(router_id, fip_id)

        super(NsxPolicyPlugin, self).delete_floatingip(context, fip_id)

    def update_floatingip(self, context, fip_id, floatingip):
        old_fip = self.get_floatingip(context, fip_id)
        new_status = (const.FLOATINGIP_STATUS_ACTIVE
                      if floatingip['floatingip'].get('port_id')
                      else const.FLOATINGIP_STATUS_DOWN)
        new_fip = super(NsxPolicyPlugin, self).update_floatingip(
            context, fip_id, floatingip)
        router_id = new_fip['router_id']

        if (old_fip['router_id'] and
            (not router_id or old_fip['router_id'] != router_id)):
            # Delete the old rules (if the router did not change - rewriting
            # the rules with _add_fip_nat_rules is enough)
            self._delete_fip_nat_rules(old_fip['router_id'], fip_id)

        if router_id:
            self._add_fip_nat_rules(
                router_id, new_fip['id'],
                new_fip['floating_ip_address'],
                new_fip['fixed_ip_address'])

        if new_fip['status'] != new_status:
            new_fip['status'] = new_status
            self.update_floatingip_status(context, fip_id, new_status)

        return new_fip

    def disassociate_floatingips(self, context, port_id):
        fip_qry = context.session.query(l3_db_models.FloatingIP)
        fip_dbs = fip_qry.filter_by(fixed_port_id=port_id)

        for fip_db in fip_dbs:
            if not fip_db.router_id:
                continue
            if fip_db.router_id:
                # Delete the old rules
                self._delete_fip_nat_rules(fip_db.router_id, fip_db.id)
            self.update_floatingip_status(context, fip_db.id,
                                          const.FLOATINGIP_STATUS_DOWN)

        super(NsxPolicyPlugin, self).disassociate_floatingips(
            context, port_id, do_notify=False)

    def _prepare_default_rules(self):
        """Create a default group & communication map in the default domain"""
        # Run this code only on one worker at the time
        with locking.LockManager.get_lock('nsx_p_prepare_default_rules'):
            # Return if the objects were already created
            try:
                self.nsxpolicy.comm_map.get(NSX_P_GLOBAL_DOMAIN_ID,
                                            NSX_P_DEFAULT_SECTION)
                self.nsxpolicy.group.get(NSX_P_GLOBAL_DOMAIN_ID,
                                         NSX_P_DEFAULT_GROUP)
            except nsx_lib_exc.ResourceNotFound:
                LOG.info("Going to create default group & "
                         "communication map under the default domain")
            else:
                LOG.debug("Verified default group already exist")
                return

            # Create the default group membership criteria to match all neutron
            # ports by scope (and no tag)
            scope_and_tag = "%s|" % (NSX_P_PORT_RESOURCE_TYPE)
            conditions = [self.nsxpolicy.group.build_condition(
                cond_val=scope_and_tag,
                cond_key=policy_constants.CONDITION_KEY_TAG,
                cond_member_type=policy_constants.CONDITION_MEMBER_PORT)]
            # Create the default OpenStack group
            # (This will not fail if the group already exists)
            try:
                self.nsxpolicy.group.create_or_overwrite_with_conditions(
                    name=NSX_P_DEFAULT_GROUP,
                    domain_id=NSX_P_GLOBAL_DOMAIN_ID,
                    group_id=NSX_P_DEFAULT_GROUP,
                    description=NSX_P_DEFAULT_GROUP_DESC,
                    conditions=conditions)

            except Exception as e:
                msg = (_("Failed to create NSX default group: %(e)s") % {
                    'e': e})
                raise nsx_exc.NsxPluginException(err_msg=msg)

            # create default section and rules
            logged = cfg.CONF.nsx_p.log_security_groups_blocked_traffic
            scope = [self.nsxpolicy.group.get_path(
                NSX_P_GLOBAL_DOMAIN_ID, NSX_P_DEFAULT_GROUP)]
            rule_id = 1
            dhcp_client_rule = self.nsxpolicy.comm_map.build_entry(
                'DHCP Reply', NSX_P_GLOBAL_DOMAIN_ID,
                NSX_P_DEFAULT_SECTION,
                rule_id, sequence_number=rule_id,
                service_ids=['DHCP-Client'],
                action=policy_constants.ACTION_ALLOW,
                scope=scope,
                direction=nsxlib_consts.IN,
                logged=logged)
            rule_id += 1
            dhcp_server_rule = self.nsxpolicy.comm_map.build_entry(
                'DHCP Request', NSX_P_GLOBAL_DOMAIN_ID,
                NSX_P_DEFAULT_SECTION,
                rule_id, sequence_number=rule_id,
                service_ids=['DHCP-Server'],
                action=policy_constants.ACTION_ALLOW,
                scope=scope,
                direction=nsxlib_consts.OUT,
                logged=logged)
            rule_id += 1
            nd_rule = self.nsxpolicy.comm_map.build_entry(
                'IPv6 Neighbor Discovery', NSX_P_GLOBAL_DOMAIN_ID,
                NSX_P_DEFAULT_SECTION,
                rule_id, sequence_number=rule_id,
                service_ids=['IPv6-ICMP_Neighbor_Solicitation',
                             'IPv6-ICMP_Neighbor_Advertisement',
                             IPV6_RA_SERVICE],
                action=policy_constants.ACTION_ALLOW,
                ip_protocol=nsxlib_consts.IPV6,
                scope=scope,
                direction=nsxlib_consts.IN_OUT,
                logged=logged)
            rule_id += 1
            block_rule = self.nsxpolicy.comm_map.build_entry(
                'Block All', NSX_P_GLOBAL_DOMAIN_ID,
                NSX_P_DEFAULT_SECTION,
                rule_id, sequence_number=rule_id, service_ids=None,
                action=policy_constants.ACTION_DENY,
                scope=scope,
                direction=nsxlib_consts.IN_OUT,
                logged=logged)
            rules = [dhcp_client_rule, dhcp_server_rule, nd_rule, block_rule]
            try:
                # This will not fail if the map already exists
                self.nsxpolicy.comm_map.create_with_entries(
                    name=NSX_P_DEFAULT_SECTION,
                    domain_id=NSX_P_GLOBAL_DOMAIN_ID,
                    map_id=NSX_P_DEFAULT_SECTION,
                    description=NSX_P_DEFAULT_SECTION_DESC,
                    category=NSX_P_DEFAULT_SECTION_CATEGORY,
                    entries=rules)
            except Exception as e:
                msg = (_("Failed to create NSX default communication map: "
                         "%(e)s") % {'e': e})
                raise nsx_exc.NsxPluginException(err_msg=msg)

    def _prepare_exclude_list_group(self):
        try:
            self.nsxpolicy.group.get(NSX_P_GLOBAL_DOMAIN_ID,
                                     NSX_P_EXCLUDE_LIST_GROUP)
        except nsx_lib_exc.ResourceNotFound:
            LOG.info("Going to create exclude list group")
        else:
            LOG.debug("Verified exclude list group already exists")
            return

        # Create the group membership criteria to match excluded neutron
        # ports by scope and tag
        scope_and_tag = "%s|%s" % (security.PORT_SG_SCOPE,
                                   NSX_P_EXCLUDE_LIST_TAG)
        conditions = [self.nsxpolicy.group.build_condition(
            cond_val=scope_and_tag,
            cond_key=policy_constants.CONDITION_KEY_TAG,
            cond_member_type=policy_constants.CONDITION_MEMBER_PORT)]
        # Create the exclude list group
        # (This will not fail if the group already exists)
        try:
            self.nsxpolicy.group.create_or_overwrite_with_conditions(
                name=NSX_P_EXCLUDE_LIST_GROUP,
                domain_id=NSX_P_GLOBAL_DOMAIN_ID,
                group_id=NSX_P_EXCLUDE_LIST_GROUP,
                conditions=conditions)

        except Exception as e:
            msg = (_("Failed to create NSX exclude list group: %(e)s") % {
                'e': e})
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def _add_exclude_list_group(self):
        member = self.nsxpolicy.group.get_path(
            domain_id=NSX_P_GLOBAL_DOMAIN_ID,
            group_id=NSX_P_EXCLUDE_LIST_GROUP)

        exclude_list = self.nsxpolicy.exclude_list.get()
        if member in exclude_list['members']:
            LOG.debug("Verified that group %s was already added to the "
                      "NSX exclude list", member)
            return

        LOG.info("Going to add group %s to the NSX exclude list", member)
        members = exclude_list['members']
        members.append(member)
        try:
            self.nsxpolicy.exclude_list.create_or_overwrite(members=members)
        except Exception as e:
            msg = (_("Failed to add group to the NSX exclude list: %(e)s") % {
                'e': e})
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def _prepare_exclude_list(self):
        """Create exclude list for ports without port security

        Create a group for excluded ports and add it to the NSX exclude list
        """
        # Run this code only on one worker at the time
        with locking.LockManager.get_lock('nsx_p_prepare_exclude_list'):
            self._prepare_exclude_list_group()
            self._add_exclude_list_group()

    def _create_security_group_backend_resources(self, context, secgroup,
                                                 domain_id):
        """Create communication map (=section) and group (=NS group)

        Both will have the security group id as their NSX id.
        """
        sg_id = secgroup['id']
        tags = self.nsxpolicy.build_v3_tags_payload(
            secgroup, resource_type='os-neutron-secg-id',
            project_name=secgroup.get('tenant_id'))
        nsx_name = utils.get_name_and_uuid(secgroup['name'] or 'securitygroup',
                                           sg_id)
        # Create the groups membership criteria for ports by scope & tag
        scope_and_tag = "%s|%s" % (NSX_P_SECURITY_GROUP_TAG, sg_id)
        condition = self.nsxpolicy.group.build_condition(
            cond_val=scope_and_tag,
            cond_key=policy_constants.CONDITION_KEY_TAG,
            cond_member_type=policy_constants.CONDITION_MEMBER_PORT)
        # Create the group
        try:
            self.nsxpolicy.group.create_or_overwrite_with_conditions(
                nsx_name, domain_id, group_id=sg_id,
                description=secgroup.get('description'),
                conditions=[condition], tags=tags)
        except Exception as e:
            msg = (_("Failed to create NSX group for SG %(sg)s: "
                     "%(e)s") % {'sg': sg_id, 'e': e})
            raise nsx_exc.NsxPluginException(err_msg=msg)

        category = NSX_P_REGULAR_SECTION_CATEGORY
        if secgroup.get(provider_sg.PROVIDER) is True:
            category = NSX_P_PROVIDER_SECTION_CATEGORY
        # create the communication map (=section) without and entries (=rules)
        try:
            self.nsxpolicy.comm_map.create_or_overwrite_map_only(
                nsx_name, domain_id, map_id=sg_id,
                description=secgroup.get('description'),
                tags=tags, category=category)
        except Exception as e:
            msg = (_("Failed to create NSX communication map for SG %(sg)s: "
                     "%(e)s") % {'sg': sg_id, 'e': e})
            self.nsxpolicy.group.delete(domain_id, sg_id)
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def _get_rule_ip_protocol(self, sg_rule):
        ethertype = sg_rule.get('ethertype')
        if ethertype == const.IPv4:
            return nsxlib_consts.IPV4
        if ethertype == const.IPv6:
            return nsxlib_consts.IPV6

        return nsxlib_consts.IPV4_IPV6

    def _get_rule_service_id(self, context, sg_rule, tags):
        """Return the NSX Policy service id matching the SG rule"""
        srv_id = None
        l4_protocol = nsxlib_utils.get_l4_protocol_name(sg_rule['protocol'])
        srv_name = 'Service for OS rule %s' % sg_rule['id']

        if l4_protocol in [nsxlib_consts.TCP, nsxlib_consts.UDP]:
            # If port_range_min is not specified then we assume all ports are
            # matched, relying on neutron to perform validation.
            if sg_rule['port_range_min'] is None:
                destination_ports = []
            elif sg_rule['port_range_min'] != sg_rule['port_range_max']:
                # NSX API requires a non-empty range (e.g - '22-23')
                destination_ports = ['%(port_range_min)s-%(port_range_max)s'
                                     % sg_rule]
            else:
                destination_ports = ['%(port_range_min)s' % sg_rule]

            srv_id = self.nsxpolicy.service.create_or_overwrite(
                srv_name, service_id=sg_rule['id'],
                description=sg_rule.get('description'),
                protocol=l4_protocol,
                dest_ports=destination_ports,
                tags=tags)
        elif l4_protocol in [nsxlib_consts.ICMPV4, nsxlib_consts.ICMPV6]:
            # Validate the icmp type & code
            version = 4 if l4_protocol == nsxlib_consts.ICMPV4 else 6
            icmp_type = sg_rule['port_range_min']
            icmp_code = sg_rule['port_range_max']
            nsxlib_utils.validate_icmp_params(
                icmp_type, icmp_code, icmp_version=version, strict=True)

            srv_id = self.nsxpolicy.icmp_service.create_or_overwrite(
                srv_name, service_id=sg_rule['id'],
                description=sg_rule.get('description'),
                version=version,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
                tags=tags)
        elif l4_protocol:
            srv_id = self.nsxpolicy.ip_protocol_service.create_or_overwrite(
                srv_name, service_id=sg_rule['id'],
                description=sg_rule.get('description'),
                protocol_number=l4_protocol,
                tags=tags)

        return srv_id

    def _get_sg_rule_remote_ip_group_id(self, sg_rule):
        return '%s_remote_group' % sg_rule['id']

    def _get_sg_rule_local_ip_group_id(self, sg_rule):
        return '%s_local_group' % sg_rule['id']

    def _create_security_group_backend_rule(self, context, domain_id, map_id,
                                            sg_rule, secgroup_logging,
                                            is_provider_sg=False):
        # The id of the map and group is the same as the security group id
        this_group_id = map_id
        # There is no rule name in neutron. Using ID instead
        nsx_name = sg_rule['id']
        direction = (nsxlib_consts.IN if sg_rule.get('direction') == 'ingress'
                     else nsxlib_consts.OUT)
        self._fix_sg_rule_dict_ips(sg_rule)
        source = None
        destination = this_group_id

        tags = self.nsxpolicy.build_v3_tags_payload(
            sg_rule, resource_type='os-neutron-secgr-id',
            project_name=sg_rule.get('tenant_id'))

        if sg_rule.get('remote_group_id'):
            # This is the ID of a security group that already exists,
            # so it should be known to the policy manager
            source = sg_rule.get('remote_group_id')
        elif sg_rule.get('remote_ip_prefix'):
            # Create a group for the remote IPs
            remote_ip = sg_rule['remote_ip_prefix']
            remote_group_id = self._get_sg_rule_remote_ip_group_id(sg_rule)
            expr = self.nsxpolicy.group.build_ip_address_expression(
                [remote_ip])
            self.nsxpolicy.group.create_or_overwrite_with_conditions(
                remote_group_id, domain_id, group_id=remote_group_id,
                description='%s for OS rule %s' % (remote_ip, sg_rule['id']),
                conditions=[expr], tags=tags)
            source = remote_group_id
        if sg_rule.get(sg_prefix.LOCAL_IP_PREFIX):
            # Create a group for the local ips
            local_ip = sg_rule[sg_prefix.LOCAL_IP_PREFIX]
            local_group_id = self._get_sg_rule_local_ip_group_id(sg_rule)
            expr = self.nsxpolicy.group.build_ip_address_expression(
                [local_ip])
            self.nsxpolicy.group.create_or_overwrite_with_conditions(
                local_group_id, domain_id, group_id=local_group_id,
                description='%s for OS rule %s' % (local_ip, sg_rule['id']),
                conditions=[expr], tags=tags)
            destination = local_group_id

        if direction == nsxlib_consts.OUT:
            # Swap source and destination
            source, destination = destination, source

        service = self._get_rule_service_id(context, sg_rule, tags)
        ip_protocol = self._get_rule_ip_protocol(sg_rule)
        logging = (cfg.CONF.nsx_p.log_security_groups_allowed_traffic or
                   secgroup_logging)
        scope = [self.nsxpolicy.group.get_path(domain_id, this_group_id)]
        action = (policy_constants.ACTION_DENY if is_provider_sg
                  else policy_constants.ACTION_ALLOW)
        self.nsxpolicy.comm_map.create_entry(
            nsx_name, domain_id, map_id, entry_id=sg_rule['id'],
            description=sg_rule.get('description'),
            service_ids=[service] if service else None,
            ip_protocol=ip_protocol,
            action=action,
            source_groups=[source] if source else None,
            dest_groups=[destination] if destination else None,
            scope=scope,
            direction=direction, logged=logging)

    def _create_project_domain(self, context, project_id):
        """Return the NSX domain id of a neutron project

        The ID of the created domain will be the same as the project ID
        so there is no need to keep it in the neutron DB
        """
        tags = self.nsxpolicy.build_v3_api_version_project_tag(
            context.tenant_name)
        try:
            domain_id = self.nsxpolicy.domain.create_or_overwrite(
                name=project_id,
                domain_id=project_id,
                description="Domain for OS project %s" % project_id,
                tags=tags)
        except Exception as e:
            msg = (_("Failed to create NSX domain for project %(proj)s: "
                     "%(e)s") % {'proj': project_id, 'e': e})
            raise nsx_exc.NsxPluginException(err_msg=msg)
        LOG.info("NSX Domain was created for project %s", project_id)
        return domain_id

    def create_security_group(self, context, security_group, default_sg=False):
        secgroup = security_group['security_group']
        # Make sure the ID is initialized, as it is used for the backend
        # objects too
        secgroup['id'] = secgroup.get('id') or uuidutils.generate_uuid()

        project_id = secgroup['tenant_id']
        if not default_sg:
            self._ensure_default_security_group(context, project_id)
        else:
            # create the NSX policy domain for this new project
            self._create_project_domain(context, project_id)

        # create the Neutron SG
        with db_api.CONTEXT_WRITER.using(context):
            if secgroup.get(provider_sg.PROVIDER) is True:
                secgroup_db = self.create_provider_security_group(
                    context, security_group)
            else:
                secgroup_db = (
                    super(NsxPolicyPlugin, self).create_security_group(
                        context, security_group, default_sg))

            self._process_security_group_properties_create(context,
                                                           secgroup_db,
                                                           secgroup,
                                                           default_sg)

        try:
            # Create Group & communication map on the NSX
            self._create_security_group_backend_resources(
                context, secgroup, project_id)

            # Add the security-group rules
            sg_rules = secgroup_db['security_group_rules']
            secgroup_logging = secgroup.get(sg_logging.LOGGING, False)
            for sg_rule in sg_rules:
                self._create_security_group_backend_rule(
                    context, project_id, secgroup_db['id'], sg_rule,
                    secgroup_logging)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception("Failed to create backend SG rules "
                              "for security-group %(name)s (%(id)s), "
                              "rolling back changes. Error: %(e)s",
                              {'name': secgroup_db['name'],
                               'id': secgroup_db['id'],
                               'e': e})
                # rollback SG creation (which will also delete the backend
                # objects)
                super(NsxPolicyPlugin, self).delete_security_group(
                    context, secgroup['id'])

        return secgroup_db

    def update_security_group(self, context, sg_id, security_group):
        self._prevent_non_admin_edit_provider_sg(context, sg_id)
        sg_data = security_group['security_group']

        # update the neutron security group
        with db_api.CONTEXT_WRITER.using(context):
            secgroup_res = super(NsxPolicyPlugin, self).update_security_group(
                context, sg_id, security_group)
            self._process_security_group_properties_update(
                context, secgroup_res, sg_data)

        # Update the name and description on NSX backend
        if 'name' in sg_data or 'description' in sg_data:
            nsx_name = utils.get_name_and_uuid(
                secgroup_res['name'] or 'securitygroup', sg_id)
            domain_id = secgroup_res['tenant_id']
            try:
                self.nsxpolicy.group.update(
                    domain_id, sg_id,
                    name=nsx_name,
                    description=secgroup_res.get('description'))
                self.nsxpolicy.comm_map.update(
                    domain_id, sg_id,
                    name=nsx_name,
                    description=secgroup_res.get('description'))
            except Exception as e:
                LOG.warning("Failed to update SG %s NSX resources: %s",
                            sg_id, e)
                # Go on with the update anyway (it's just the name & desc)

        # If the logging of the SG changed - update the backend rules
        if sg_logging.LOGGING in sg_data:
            logged = (sg_data[sg_logging.LOGGING] or
                      cfg.CONF.nsx_p.log_security_groups_allowed_traffic)
            self.nsxpolicy.comm_map.update_entries_logged(domain_id, sg_id,
                                                          logged)

        return secgroup_res

    def delete_security_group(self, context, sg_id):
        self._prevent_non_admin_edit_provider_sg(context, sg_id)
        sg = self.get_security_group(context, sg_id)

        super(NsxPolicyPlugin, self).delete_security_group(context, sg_id)

        domain_id = sg['tenant_id']
        try:
            self.nsxpolicy.comm_map.delete(domain_id, sg_id)
            self.nsxpolicy.group.delete(domain_id, sg_id)
            for rule in sg['security_group_rules']:
                self._delete_security_group_rule_backend_resources(
                    context, domain_id, rule)
        except Exception as e:
            LOG.warning("Failed to delete SG %s NSX resources: %s",
                        sg_id, e)
            # Go on with the deletion anyway

    def create_security_group_rule(self, context, security_group_rule):
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def create_security_group_rule_bulk(self, context, security_group_rules):
        sg_rules = security_group_rules['security_group_rules']
        for r in sg_rules:
            self._check_local_ip_prefix(context, r['security_group_rule'])

        # Tenant & security group are the same for all rules in the bulk
        example_rule = sg_rules[0]['security_group_rule']
        sg_id = example_rule['security_group_id']
        sg = self.get_security_group(context, sg_id)
        self._prevent_non_admin_edit_provider_sg(context, sg_id)

        with db_api.CONTEXT_WRITER.using(context):
            rules_db = (super(NsxPolicyPlugin,
                              self).create_security_group_rule_bulk_native(
                                  context, security_group_rules))
            for i, r in enumerate(sg_rules):
                self._process_security_group_rule_properties(
                    context, rules_db[i], r['security_group_rule'])

        domain_id = sg['tenant_id']
        is_provider_sg = sg.get(provider_sg.PROVIDER)
        secgroup_logging = self._is_security_group_logged(context, sg_id)
        for rule_data in rules_db:
            # create the NSX backend rule
            self._create_security_group_backend_rule(
                context, domain_id, sg_id, rule_data, secgroup_logging,
                is_provider_sg=is_provider_sg)

        return rules_db

    def _delete_security_group_rule_backend_resources(
        self, context, domain_id, rule_db):
        rule_id = rule_db['id']
        # try to delete the service of this rule, if exists
        if rule_db['protocol']:
            try:
                self.nsxpolicy.service.delete(rule_id)
            except nsx_lib_exc.ResourceNotFound:
                LOG.warning("Failed to delete SG rule %s service", rule_id)

        # Try to delete the remote ip prefix group, if exists
        if rule_db['remote_ip_prefix']:
            try:
                remote_group_id = self._get_sg_rule_remote_ip_group_id(rule_db)
                self.nsxpolicy.group.delete(domain_id, remote_group_id)
            except nsx_lib_exc.ResourceNotFound:
                LOG.warning("Failed to delete SG rule %s remote ip prefix "
                            "group", rule_id)

        # Try to delete the local ip prefix group, if exists
        if self._get_security_group_rule_local_ip(context, rule_id):
            try:
                local_group_id = self._get_sg_rule_local_ip_group_id(rule_db)
                self.nsxpolicy.group.delete(domain_id, local_group_id)
            except nsx_lib_exc.ResourceNotFound:
                LOG.warning("Failed to delete SG rule %s local ip prefix "
                            "group", rule_id)

    def delete_security_group_rule(self, context, rule_id):
        rule_db = self._get_security_group_rule(context, rule_id)
        sg_id = rule_db['security_group_id']
        self._prevent_non_admin_edit_provider_sg(context, sg_id)
        domain_id = rule_db['tenant_id']

        # Delete the rule itself
        try:
            self.nsxpolicy.comm_map.delete_entry(domain_id, sg_id, rule_id)
        except Exception as e:
            LOG.warning("Failed to delete SG rule %s NSX resources: %s",
                        rule_id, e)
            # Go on with the deletion anyway

        self._delete_security_group_rule_backend_resources(
            context, domain_id, rule_db)

        super(NsxPolicyPlugin, self).delete_security_group_rule(
            context, rule_id)

    def _is_overlay_network(self, context, network_id):
        """Return True if this is an overlay network

        1. No binding ("normal" overlay networks will have no binding)
        2. Geneve network
        3. nsx network where the backend network is connected to an overlay TZ
        """
        bindings = nsx_db.get_network_bindings(context.session, network_id)
        # With NSX plugin, "normal" overlay networks will have no binding
        if not bindings:
            # using the default /AZ overlay_tz
            return True

        binding = bindings[0]
        if binding.binding_type == utils.NsxV3NetworkTypes.GENEVE:
            return True
        if binding.binding_type == utils.NsxV3NetworkTypes.NSX_NETWORK:
            # check the backend network
            segment = self.nsxpolicy.segment.get(binding.phy_uuid)
            tz = self._get_nsx_net_tz_id(segment)
            if tz:
                type = self.nsxpolicy.transport_zone.get_transport_type(
                    tz)
                return type == nsxlib_consts.TRANSPORT_TYPE_OVERLAY

    def _is_ens_tz(self, tz_id):
        mode = self.nsxpolicy.transport_zone.get_host_switch_mode(tz_id)
        return mode == nsxlib_consts.HOST_SWITCH_MODE_ENS

    def _has_native_dhcp_metadata(self):
        return True

    def _get_tier0_uplink_cidrs(self, tier0_id):
        # return a list of tier0 uplink ip/prefix addresses
        return self.nsxpolicy.tier0.get_uplink_cidrs(tier0_id)

    def _is_vlan_router_interface_supported(self):
        return True

    def _get_neutron_net_ids_by_nsx_id(self, context, lswitch_id):
        return [lswitch_id]

    def _get_net_tz(self, context, net_id):
        bindings = nsx_db.get_network_bindings(context.session, net_id)
        if bindings:
            bind_type = bindings[0].binding_type
            if bind_type == utils.NsxV3NetworkTypes.NSX_NETWORK:
                # If it is an NSX network, return the TZ of the backend segment
                segment_id = bindings[0].phy_uuid
                return self.nsxpolicy.segment.get_transport_zone_id(segment_id)
            elif bind_type == utils.NetworkTypes.L3_EXT:
                # External network has tier0 as phy_uuid
                return
            else:
                return bindings[0].phy_uuid
        else:
            # Get the default one for the network AZ
            az = self.get_network_az_by_net_id(context, net_id)
            return az._default_overlay_tz_uuid

    def _validate_router_tz(self, context, tier0_uuid, subnets):
        # make sure the related GW (Tier0 router) belongs to the same TZ
        # as the subnets attached to the Tier1 router
        if not subnets or not tier0_uuid:
            return
        tier0_tzs = self.nsxpolicy.tier0.get_transport_zones(tier0_uuid)
        if not tier0_tzs:
            return
        for sub in subnets:
            tz_uuid = self._get_net_tz(context, sub['network_id'])
            if tz_uuid not in tier0_tzs:
                msg = (_("Tier0 router %(rtr)s transport zone should match "
                         "transport zone %(tz)s of the network %(net)s") % {
                    'rtr': tier0_uuid,
                    'tz': tz_uuid,
                    'net': sub['network_id']})
                raise n_exc.InvalidInput(error_message=msg)

    def _get_net_dhcp_relay(self, context, net_id):
        # No dhcp relay support yet
        return None

    def _support_vlan_router_interfaces(self):
        return True

    def update_router_firewall(self, context, router_id, router_db=None,
                               from_fw=False):
        """Rewrite all the rules in the router edge firewall

        This method should be called on FWaaS v2 updates, and on router
        interfaces changes.
        When FWaaS is disabled, there is no need to update the NSX router FW,
        as the default rule is allow-all.
        """
        if not router_db:
            router_db = self._get_router(context, router_id)

        if (self.fwaas_callbacks and
            self.fwaas_callbacks.fwaas_enabled):
            # find all the relevant ports of the router for FWaaS v2
            # TODO(asarfaty): Add vm ports as well
            ports = self._get_router_interfaces(context, router_id)

            # let the fwaas callbacks update the router FW
            return self.fwaas_callbacks.update_router_firewall(
                context, router_id, router_db, ports, called_from_fw=from_fw)
