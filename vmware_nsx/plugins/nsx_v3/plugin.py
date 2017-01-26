# Copyright 2015 VMware, Inc.
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

import netaddr
import six

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.callbacks.consumer import registry as callbacks_registry
from neutron.api.rpc.callbacks import resources as callbacks_resources
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.api.rpc.handlers import resources_rpc
from neutron.callbacks import events
from neutron.callbacks import exceptions as callback_exc
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as neutron_utils
from neutron import context as q_context
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import db_base_plugin_v2
from neutron.db import dns_db
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db.models import securitygroup as securitygroup_model  # noqa
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import portsecurity_db
from neutron.db import securitygroups_db
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import availability_zone as az_ext
from neutron.extensions import external_net as ext_net_extn
from neutron.extensions import extra_dhcp_opt as ext_edo
from neutron.extensions import l3
from neutron.extensions import portbindings as pbin
from neutron.extensions import portsecurity as psec
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as ext_sg
from neutron.plugins.common import constants as plugin_const
from neutron.plugins.common import utils as n_utils
from neutron.quota import resource_registry
from neutron.services.qos import qos_consts
from neutron_lib.api import validators
from neutron_lib import constants as const
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import uuidutils
from sqlalchemy import exc as sql_exc

from vmware_nsx._i18n import _, _LE, _LI, _LW
from vmware_nsx.api_replay import utils as api_replay_utils
from vmware_nsx.common import config  # noqa
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import locking
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import extended_security_group
from vmware_nsx.db import extended_security_group_rule as extend_sg_rule
from vmware_nsx.db import maclearning as mac_db
from vmware_nsx.dhcp_meta import rpc as nsx_rpc
from vmware_nsx.extensions import advancedserviceproviders as as_providers
from vmware_nsx.extensions import maclearning as mac_ext
from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.extensions import securitygrouplogging as sg_logging
from vmware_nsx.nsxlib import v3 as nsxlib
from vmware_nsx.nsxlib.v3 import dfw_api as firewall
from vmware_nsx.nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsx.nsxlib.v3 import native_dhcp
from vmware_nsx.nsxlib.v3 import resources as nsx_resources
from vmware_nsx.nsxlib.v3 import router
from vmware_nsx.nsxlib.v3 import security
from vmware_nsx.services.qos.common import utils as qos_com_utils
from vmware_nsx.services.qos.nsx_v3 import utils as qos_utils
from vmware_nsx.services.trunk.nsx_v3 import driver as trunk_driver


LOG = log.getLogger(__name__)
NSX_V3_PSEC_PROFILE_NAME = 'neutron_port_spoof_guard_profile'
NSX_V3_NO_PSEC_PROFILE_NAME = 'nsx-default-spoof-guard-vif-profile'
NSX_V3_DHCP_PROFILE_NAME = 'neutron_port_dhcp_profile'
NSX_V3_MAC_LEARNING_PROFILE_NAME = 'neutron_port_mac_learning_profile'
NSX_V3_EXCLUDED_PORT_NSGROUP_NAME = 'neutron_excluded_port_nsgroup'


# NOTE(asarfaty): the order of inheritance here is important. in order for the
# QoS notification to work, the AgentScheduler init must be called first
# NOTE(arosen): same is true with the ExtendedSecurityGroupPropertiesMixin
# this needs to be above securitygroups_db.SecurityGroupDbMixin.
# FIXME(arosen): we can solve this inheritance order issue by just mixining in
# the classes into a new class to handle the order correctly.
class NsxV3Plugin(agentschedulers_db.AZDhcpAgentSchedulerDbMixin,
                  extended_security_group.ExtendedSecurityGroupPropertiesMixin,
                  addr_pair_db.AllowedAddressPairsMixin,
                  db_base_plugin_v2.NeutronDbPluginV2,
                  extend_sg_rule.ExtendedSecurityGroupRuleMixin,
                  securitygroups_db.SecurityGroupDbMixin,
                  external_net_db.External_net_db_mixin,
                  extraroute_db.ExtraRoute_db_mixin,
                  l3_gwmode_db.L3_NAT_db_mixin,
                  portbindings_db.PortBindingMixin,
                  portsecurity_db.PortSecurityDbMixin,
                  extradhcpopt_db.ExtraDhcpOptMixin,
                  dns_db.DNSDbMixin,
                  mac_db.MacLearningDbMixin):

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["allowed-address-pairs",
                                   "quotas",
                                   "binding",
                                   "extra_dhcp_opt",
                                   "agent",
                                   "dhcp_agent_scheduler",
                                   "ext-gw-mode",
                                   "security-group",
                                   "secgroup-rule-local-ip-prefix",
                                   "port-security",
                                   "provider",
                                   "external-net",
                                   "extraroute",
                                   "router",
                                   "availability_zone",
                                   "network_availability_zone",
                                   "subnet_allocation",
                                   "security-group-logging",
                                   "provider-security-group"]

    supported_qos_rule_types = [qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                                qos_consts.RULE_TYPE_DSCP_MARKING]

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
        super(NsxV3Plugin, self).__init__()
        LOG.info(_LI("Starting NsxV3Plugin"))

        self.nsxlib = nsxlib.NsxLib(
            username=cfg.CONF.nsx_v3.nsx_api_user,
            password=cfg.CONF.nsx_v3.nsx_api_password,
            retries=cfg.CONF.nsx_v3.http_retries,
            insecure=cfg.CONF.nsx_v3.insecure,
            ca_file=cfg.CONF.nsx_v3.ca_file,
            concurrent_connections=cfg.CONF.nsx_v3.concurrent_connections,
            http_timeout=cfg.CONF.nsx_v3.http_timeout,
            http_read_timeout=cfg.CONF.nsx_v3.http_read_timeout,
            conn_idle_timeout=cfg.CONF.nsx_v3.conn_idle_timeout,
            http_provider=None,
            max_attempts=cfg.CONF.nsx_v3.retries)

        self._nsx_version = self.nsxlib.get_version()
        LOG.info(_LI("NSX Version: %s"), self._nsx_version)
        self._nsx_client = self.nsxlib.client

        self.cfg_group = 'nsx_v3'  # group name for nsx_v3 section in nsx.ini
        self.tier0_groups_dict = {}
        self._init_dhcp_metadata()

        self._port_client = nsx_resources.LogicalPort(self._nsx_client)
        self.default_section = self._init_default_section_rules()
        self._process_security_group_logging()
        self._router_client = nsx_resources.LogicalRouter(self._nsx_client)
        self._router_port_client = nsx_resources.LogicalRouterPort(
            self._nsx_client)
        self._routerlib = router.RouterLib(self._router_client,
                                           self._router_port_client,
                                           self.nsxlib)

        self._switching_profiles = nsx_resources.SwitchingProfile(
            self._nsx_client)

        # init profiles on nsx backend
        (self._psec_profile, self._no_psec_profile_id, self._dhcp_profile,
         self._mac_learning_profile) = self._init_nsx_profiles()

        # Include exclude NSGroup
        LOG.debug("Initializing NSX v3 Excluded Port NSGroup")
        self._excluded_port_nsgroup = None
        self._excluded_port_nsgroup = self._init_excluded_port_nsgroup()
        if not self._excluded_port_nsgroup:
            msg = _("Unable to initialize NSX v3 Excluded Port NSGroup %s"
                    ) % NSX_V3_EXCLUDED_PORT_NSGROUP_NAME
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # Bind QoS notifications
        callbacks_registry.subscribe(qos_utils.handle_qos_notification,
                                     callbacks_resources.QOS_POLICY)
        self.start_rpc_listeners_called = False

        self._unsubscribe_callback_events()
        if cfg.CONF.api_replay_mode:
            self.supported_extension_aliases.append('api-replay')

        # translate configured transport zones/rotuers names to uuid
        self._translate_configured_names_2_uuids()

        # Register NSXv3 trunk driver to support trunk extensions
        self.trunk_driver = trunk_driver.NsxV3TrunkDriver.create(self)

    def _init_nsx_profiles(self):
        LOG.debug("Initializing NSX v3 port spoofguard switching profile")
        # XXX improve logic to avoid requiring setting this to none.
        self._psec_profile = None
        self._psec_profile = self._init_port_security_profile()
        if not self._psec_profile:
            msg = _("Unable to initialize NSX v3 port spoofguard "
                    "switching profile: %s") % NSX_V3_PSEC_PROFILE_NAME
            raise nsx_exc.NsxPluginException(err_msg=msg)
        profiles = nsx_resources.SwitchingProfile
        self._no_psec_profile_id = profiles.build_switch_profile_ids(
                self._switching_profiles,
                self._switching_profiles.find_by_display_name(
                        NSX_V3_NO_PSEC_PROFILE_NAME)[0])[0]

        LOG.debug("Initializing NSX v3 DHCP switching profile")
        try:
            # XXX improve logic to avoid requiring setting this to none.
            self._dhcp_profile = None
            self._dhcp_profile = self._init_dhcp_switching_profile()
        except Exception:
            msg = _("Unable to initialize NSX v3 DHCP "
                    "switching profile: %s") % NSX_V3_DHCP_PROFILE_NAME
            raise nsx_exc.NsxPluginException(err_msg=msg)

        self._mac_learning_profile = None
        # Only create MAC Learning profile when nsxv3 version >= 1.1.0
        if utils.is_nsx_version_1_1_0(self._nsx_version):
            LOG.debug("Initializing NSX v3 Mac Learning switching profile")
            try:
                self._mac_learning_profile = self._init_mac_learning_profile()
                # Only expose the extension if it is supported
                self.supported_extension_aliases.append('mac-learning')
            except Exception as e:
                LOG.warning(_LW("Unable to initialize NSX v3 MAC Learning "
                                "profile: %(name)s. Reason: %(reason)s"),
                            {'name': NSX_V3_MAC_LEARNING_PROFILE_NAME,
                             'reason': e})
        return (self._psec_profile, self._no_psec_profile_id,
                self._dhcp_profile, self._mac_learning_profile)

    def _translate_configured_names_2_uuids(self):
        # default VLAN transport zone name / uuid
        self._default_vlan_tz_uuid = None
        if cfg.CONF.nsx_v3.default_vlan_tz:
            tz_id = self.nsxlib.get_transport_zone_id_by_name_or_id(
                cfg.CONF.nsx_v3.default_vlan_tz)
            self._default_vlan_tz_uuid = tz_id

        # default overlay transport zone name / uuid
        self._default_overlay_tz_uuid = None
        if cfg.CONF.nsx_v3.default_overlay_tz:
            tz_id = self.nsxlib.get_transport_zone_id_by_name_or_id(
                cfg.CONF.nsx_v3.default_overlay_tz)
            self._default_overlay_tz_uuid = tz_id

        # default tier0 router
        self._default_tier0_router = None
        if cfg.CONF.nsx_v3.default_tier0_router:
            rtr_id = self.nsxlib.get_logical_router_id_by_name_or_id(
                cfg.CONF.nsx_v3.default_tier0_router)
            self._default_tier0_router = rtr_id

    def _extend_port_dict_binding(self, context, port_data):
        port_data[pbin.VIF_TYPE] = pbin.VIF_TYPE_OVS
        port_data[pbin.VNIC_TYPE] = pbin.VNIC_NORMAL
        if 'network_id' in port_data:
            port_data[pbin.VIF_DETAILS] = {
                # TODO(rkukura): Replace with new VIF security details
                pbin.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases,
                'nsx-logical-switch-id':
                self._get_network_nsx_id(context, port_data['network_id'])}

    @utils.retry_upon_exception_nsxv3(Exception)
    def _init_excluded_port_nsgroup(self):
        with locking.LockManager.get_lock('nsxv3_excluded_port_nsgroup_init'):
            nsgroup = self._get_excluded_port_nsgroup()
            if not nsgroup:
                # Create a new NSGroup for excluded ports.
                membership_criteria = (
                    self.nsxlib.get_nsgroup_port_tag_expression(
                        security.PORT_SG_SCOPE, firewall.EXCLUDE_PORT))
                nsgroup = self.nsxlib.create_nsgroup(
                    NSX_V3_EXCLUDED_PORT_NSGROUP_NAME,
                    'Neutron Excluded Port NSGroup',
                    tags=utils.build_v3_api_version_tag(),
                    membership_criteria=membership_criteria)
                # Add this NSGroup to NSX Exclusion List.
                self.nsxlib.add_member_to_fw_exclude_list(
                    nsgroup['id'], firewall.NSGROUP)
            return self._get_excluded_port_nsgroup()

    def _get_excluded_port_nsgroup(self):
        if self._excluded_port_nsgroup:
            return self._excluded_port_nsgroup
        nsgroups = self.nsxlib.find_nsgroups_by_display_name(
            NSX_V3_EXCLUDED_PORT_NSGROUP_NAME)
        return nsgroups[0] if nsgroups else None

    def _unsubscribe_callback_events(self):
        # l3_db explicitly subscribes to the port delete callback. This
        # callback is unsubscribed here since l3 APIs are handled by
        # core_plugin instead of an advanced service, in case of NSXv3 plugin,
        # and the prevention logic is handled by NSXv3 plugin itself.
        registry.unsubscribe(l3_db._prevent_l3_port_delete_callback,
                             resources.PORT,
                             events.BEFORE_DELETE)

    def _validate_dhcp_profile(self, dhcp_profile_uuid):
        dhcp_profile = self._switching_profiles.get(dhcp_profile_uuid)
        if (dhcp_profile.get('resource_type') !=
            nsx_resources.SwitchingProfileTypes.SWITCH_SECURITY):
            msg = _("Invalid configuration on the backend for DHCP "
                    "switching profile %s. Switching Profile must be of type "
                    "'Switch Security'") % dhcp_profile_uuid
            raise n_exc.InvalidInput(error_message=msg)
        dhcp_filter = dhcp_profile.get('dhcp_filter')
        if (not dhcp_filter or dhcp_filter.get('client_block_enabled') or
            dhcp_filter.get('server_block_enabled')):
            msg = _("Invalid configuration on the backend for DHCP "
                    "switching profile %s. DHCP Server Block and Client Block "
                    "must be disabled") % dhcp_profile_uuid
            raise n_exc.InvalidInput(error_message=msg)

    @utils.retry_upon_exception_nsxv3(Exception)
    def _init_dhcp_switching_profile(self):
        with locking.LockManager.get_lock('nsxv3_dhcp_profile_init'):
            profile = self._get_dhcp_security_profile()
            if not profile:
                self._switching_profiles.create_dhcp_profile(
                    NSX_V3_DHCP_PROFILE_NAME, 'Neutron DHCP Security Profile',
                    tags=utils.build_v3_api_version_tag())
            return self._get_dhcp_security_profile()

    def _get_dhcp_security_profile(self):
        if self._dhcp_profile:
            return self._dhcp_profile
        profile = self._switching_profiles.find_by_display_name(
            NSX_V3_DHCP_PROFILE_NAME)
        return nsx_resources.SwitchingProfileTypeId(
            profile_type=(nsx_resources.SwitchingProfileTypes.
                          SWITCH_SECURITY),
            profile_id=profile[0]['id']) if profile else None

    def _init_mac_learning_profile(self):
        with locking.LockManager.get_lock('nsxv3_mac_learning_profile_init'):
            profile = self._get_mac_learning_profile()
            if not profile:
                self._switching_profiles.create_mac_learning_profile(
                    NSX_V3_MAC_LEARNING_PROFILE_NAME,
                    'Neutron MAC Learning Profile',
                    tags=utils.build_v3_api_version_tag())
            return self._get_mac_learning_profile()

    def _get_mac_learning_profile(self):
        if self._mac_learning_profile:
            return self._mac_learning_profile
        profile = self._switching_profiles.find_by_display_name(
            NSX_V3_MAC_LEARNING_PROFILE_NAME)
        return nsx_resources.SwitchingProfileTypeId(
            profile_type=(nsx_resources.SwitchingProfileTypes.
                          MAC_LEARNING),
            profile_id=profile[0]['id']) if profile else None

    def _get_port_security_profile_id(self):
        return nsx_resources.SwitchingProfile.build_switch_profile_ids(
            self._switching_profiles, self._get_port_security_profile())[0]

    def _get_port_security_profile(self):
        if self._psec_profile:
            return self._psec_profile
        profile = self._switching_profiles.find_by_display_name(
            NSX_V3_PSEC_PROFILE_NAME)
        return profile[0] if profile else None

    @utils.retry_upon_exception_nsxv3(Exception)
    def _init_port_security_profile(self):
        profile = self._get_port_security_profile()
        if profile:
            return profile

        with locking.LockManager.get_lock('nsxv3_psec_profile_init'):
            # NOTE(boden): double-checked locking pattern
            profile = self._get_port_security_profile()
            if profile:
                return profile

            self._switching_profiles.create_spoofguard_profile(
                NSX_V3_PSEC_PROFILE_NAME, 'Neutron Port Security Profile',
                whitelist_ports=True, whitelist_switches=False,
                tags=utils.build_v3_api_version_tag())
        return self._get_port_security_profile()

    def _process_security_group_logging(self):
        def process_security_group_logging(*args, **kwargs):
            context = q_context.get_admin_context()
            log_all_rules = cfg.CONF.nsx_v3.log_security_groups_allowed_traffic
            secgroups = self.get_security_groups(context,
                                                 fields=['id',
                                                 sg_logging.LOGGING])
            for sg in [sg for sg in secgroups
                       if sg[sg_logging.LOGGING] is False]:
                _, section_id = self.nsxlib.get_sg_mappings(context.session,
                                                            sg['id'])
                try:
                    self.nsxlib.set_firewall_rule_logging_for_section(
                        section_id, logging=log_all_rules)
                except nsx_lib_exc.ManagerError:
                    with excutils.save_and_reraise_exception():
                        LOG.error(_LE("Failed to update firewall rule logging "
                                      "for rule in section %s"), section_id)

        utils.spawn_n(process_security_group_logging)

    def _init_default_section_rules(self):
        with locking.LockManager.get_lock('nsxv3_default_section'):
            section_description = ("This section is handled by OpenStack to "
                                   "contain default rules on security-groups.")
            section_id = self.nsxlib._init_default_section(
                security.DEFAULT_SECTION, section_description, [])
            return section_id

    def _init_dhcp_metadata(self):
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            if cfg.CONF.dhcp_agent_notification:
                msg = _("Need to disable dhcp_agent_notification when "
                        "native_dhcp_metadata is enabled")
                raise nsx_exc.NsxPluginException(err_msg=msg)
            self._init_native_dhcp()
            self._init_native_metadata()
        else:
            self._setup_dhcp()
            self._start_rpc_notifiers()

    def _init_native_dhcp(self):
        if not cfg.CONF.nsx_v3.dhcp_profile_uuid:
            raise cfg.RequiredOptError("dhcp_profile_uuid")
        try:
            nsx_resources.DhcpProfile(self._nsx_client).get(
                cfg.CONF.nsx_v3.dhcp_profile_uuid)
            self._dhcp_server = nsx_resources.LogicalDhcpServer(
                self._nsx_client)
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to retrieve DHCP Profile %s, "
                              "native DHCP service is not supported"),
                          cfg.CONF.nsx_v3.dhcp_profile_uuid)

    def _init_native_metadata(self):
        if not cfg.CONF.nsx_v3.metadata_proxy_uuid:
            raise cfg.RequiredOptError("metadata_proxy_uuid")
        try:
            nsx_resources.MetaDataProxy(self._nsx_client).get(
                cfg.CONF.nsx_v3.metadata_proxy_uuid)
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to retrieve Metadata Proxy %s, "
                              "native metadata service is not supported"),
                          cfg.CONF.nsx_v3.metadata_proxy_uuid)

    def _setup_rpc(self):
        self.endpoints = [dhcp_rpc.DhcpRpcCallback(),
                          agents_db.AgentExtRpcCallback(),
                          metadata_rpc.MetadataRpcCallback()]

    def _setup_dhcp(self):
        """Initialize components to support DHCP."""
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )
        self.add_periodic_dhcp_agent_status_check()

    def _start_rpc_notifiers(self):
        """Initialize RPC notifiers for agents."""
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )

    def start_rpc_listeners(self):
        if self.start_rpc_listeners_called:
            # If called more than once - we should not create it again
            return self.conn.consume_in_threads()

        self._setup_rpc()
        self.topic = topics.PLUGIN
        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        self.conn.create_consumer(topics.REPORTS,
                                  [agents_db.AgentExtRpcCallback()],
                                  fanout=False)
        qos_topic = resources_rpc.resource_type_versioned_topic(
            callbacks_resources.QOS_POLICY)
        self.conn.create_consumer(qos_topic,
                                  [resources_rpc.ResourcesPushRpcCallback()],
                                  fanout=False)
        self.start_rpc_listeners_called = True

        return self.conn.consume_in_threads()

    def _validate_provider_create(self, context, network_data):
        is_provider_net = any(
            validators.is_attr_set(network_data.get(f))
            for f in (pnet.NETWORK_TYPE,
                      pnet.PHYSICAL_NETWORK,
                      pnet.SEGMENTATION_ID))

        physical_net = network_data.get(pnet.PHYSICAL_NETWORK)
        if not validators.is_attr_set(physical_net):
            physical_net = None

        vlan_id = network_data.get(pnet.SEGMENTATION_ID)
        if not validators.is_attr_set(vlan_id):
            vlan_id = None

        err_msg = None
        net_type = network_data.get(pnet.NETWORK_TYPE)
        if validators.is_attr_set(net_type):
            if net_type == utils.NsxV3NetworkTypes.FLAT:
                if vlan_id is not None:
                    err_msg = (_("Segmentation ID cannot be specified with "
                                 "%s network type") %
                               utils.NsxV3NetworkTypes.FLAT)
                else:
                    # Set VLAN id to 0 for flat networks
                    vlan_id = '0'
                    if physical_net is None:
                        physical_net = self._default_vlan_tz_uuid
            elif net_type == utils.NsxV3NetworkTypes.VLAN:
                # Use default VLAN transport zone if physical network not given
                if physical_net is None:
                    physical_net = self._default_vlan_tz_uuid

                # Validate VLAN id
                if not vlan_id:
                    err_msg = (_('Segmentation ID must be specified with %s '
                                 'network type') %
                               utils.NsxV3NetworkTypes.VLAN)
                elif not n_utils.is_valid_vlan_tag(vlan_id):
                    err_msg = (_('Segmentation ID %(segmentation_id)s out of '
                                 'range (%(min_id)s through %(max_id)s)') %
                               {'segmentation_id': vlan_id,
                                'min_id': plugin_const.MIN_VLAN_TAG,
                                'max_id': plugin_const.MAX_VLAN_TAG})
                else:
                    # Verify VLAN id is not already allocated
                    bindings = (
                        nsx_db.get_network_bindings_by_vlanid_and_physical_net(
                            context.session, vlan_id, physical_net)
                    )
                    if bindings:
                        raise n_exc.VlanIdInUse(
                            vlan_id=vlan_id, physical_network=physical_net)
            elif net_type == utils.NsxV3NetworkTypes.VXLAN:
                if vlan_id:
                    err_msg = (_("Segmentation ID cannot be specified with "
                                 "%s network type") %
                               utils.NsxV3NetworkTypes.VXLAN)
            else:
                err_msg = (_('%(net_type_param)s %(net_type_value)s not '
                             'supported') %
                           {'net_type_param': pnet.NETWORK_TYPE,
                            'net_type_value': net_type})
        elif is_provider_net:
            # FIXME: Ideally provider-network attributes should be checked
            # at the NSX backend. For now, the network_type is required,
            # so the plugin can do a quick check locally.
            err_msg = (_('%s is required for creating a provider network') %
                       pnet.NETWORK_TYPE)
        else:
            net_type = None

        if err_msg:
            raise n_exc.InvalidInput(error_message=err_msg)

        if physical_net is None:
            # Default to transport type overlay
            physical_net = self._default_overlay_tz_uuid

        return is_provider_net, net_type, physical_net, vlan_id

    def _get_edge_cluster(self, tier0_uuid):
        self._routerlib.validate_tier0(self.tier0_groups_dict, tier0_uuid)
        tier0_info = self.tier0_groups_dict[tier0_uuid]
        return tier0_info['edge_cluster_uuid']

    def _validate_external_net_create(self, net_data):
        is_provider_net = False
        if not validators.is_attr_set(net_data.get(pnet.PHYSICAL_NETWORK)):
            tier0_uuid = self._default_tier0_router
        else:
            tier0_uuid = net_data[pnet.PHYSICAL_NETWORK]
            is_provider_net = True
        self._routerlib.validate_tier0(self.tier0_groups_dict, tier0_uuid)
        return (is_provider_net, utils.NetworkTypes.L3_EXT, tier0_uuid, 0)

    def _create_network_at_the_backend(self, context, net_data):
        is_provider_net, net_type, physical_net, vlan_id = (
            self._validate_provider_create(context, net_data))
        neutron_net_id = net_data.get('id') or uuidutils.generate_uuid()
        # To ensure that the correct tag will be set
        net_data['id'] = neutron_net_id
        # update the network name to indicate the neutron id too.
        net_name = utils.get_name_and_uuid(net_data['name'] or 'network',
                                           neutron_net_id)
        tags = utils.build_v3_tags_payload(
            net_data, resource_type='os-neutron-net-id',
            project_name=context.tenant_name)

        admin_state = net_data.get('admin_state_up', True)

        # Create network on the backend
        LOG.debug('create_network: %(net_name)s, %(physical_net)s, '
                  '%(tags)s, %(admin_state)s, %(vlan_id)s',
                  {'net_name': net_name,
                   'physical_net': physical_net,
                   'tags': tags,
                   'admin_state': admin_state,
                   'vlan_id': vlan_id})
        nsx_result = self.nsxlib.create_logical_switch(
            net_name, physical_net, tags,
            admin_state=admin_state,
            vlan_id=vlan_id)

        return (is_provider_net,
                net_type,
                physical_net,
                vlan_id,
                nsx_result['id'])

    def _is_overlay_network(self, context, network_id):
        bindings = nsx_db.get_network_bindings(context.session, network_id)
        # With NSX plugin, "normal" overlay networks will have no binding
        return (not bindings or
                bindings[0].binding_type == utils.NsxV3NetworkTypes.VXLAN)

    def _extend_network_dict_provider(self, context, network, bindings=None):
        if not bindings:
            bindings = nsx_db.get_network_bindings(context.session,
                                                   network['id'])
        # With NSX plugin, "normal" overlay networks will have no binding
        if bindings:
            # Network came in through provider networks API
            network[pnet.NETWORK_TYPE] = bindings[0].binding_type
            network[pnet.PHYSICAL_NETWORK] = bindings[0].phy_uuid
            network[pnet.SEGMENTATION_ID] = bindings[0].vlan_id

    def _assert_on_external_net_with_qos(self, net_data):
        # Prevent creating/update external network with QoS policy
        if validators.is_attr_set(net_data.get(qos_consts.QOS_POLICY_ID)):
            err_msg = _("Cannot configure QOS on external networks")
            raise n_exc.InvalidInput(error_message=err_msg)

    def get_subnets(self, context, filters=None, fields=None, sorts=None,
                    limit=None, marker=None, page_reverse=False):
        filters = filters or {}
        lswitch_ids = filters.pop(as_providers.ADV_SERVICE_PROVIDERS, [])
        if lswitch_ids:
            # This is a request from Nova for metadata processing.
            # Find the corresponding neutron network for each logical switch.
            network_ids = filters.pop('network_id', [])
            context = context.elevated()
            for lswitch_id in lswitch_ids:
                network_ids += nsx_db.get_net_ids(context.session, lswitch_id)
            filters['network_id'] = network_ids
        return super(NsxV3Plugin, self).get_subnets(
            context, filters, fields, sorts, limit, marker, page_reverse)

    def create_network(self, context, network):
        net_data = network['network']
        external = net_data.get(ext_net_extn.EXTERNAL)
        is_backend_network = False
        tenant_id = net_data['tenant_id']

        self._ensure_default_security_group(context, tenant_id)
        if validators.is_attr_set(external) and external:
            self._assert_on_external_net_with_qos(net_data)
            is_provider_net, net_type, physical_net, vlan_id = (
                self._validate_external_net_create(net_data))
        else:
            is_provider_net, net_type, physical_net, vlan_id, nsx_net_id = (
                self._create_network_at_the_backend(context, net_data))
            is_backend_network = True
        try:
            with context.session.begin(subtransactions=True):
                # Create network in Neutron
                created_net = super(NsxV3Plugin, self).create_network(context,
                                                                      network)

                if psec.PORTSECURITY not in net_data:
                    net_data[psec.PORTSECURITY] = True
                self._process_network_port_security_create(
                    context, net_data, created_net)
                self._process_l3_create(context, created_net, net_data)

                if az_ext.AZ_HINTS in net_data:
                    self.validate_availability_zones(context, 'network',
                                                     net_data[az_ext.AZ_HINTS])
                    az_hints = az_ext.convert_az_list_to_string(
                                                    net_data[az_ext.AZ_HINTS])
                    net_id = created_net['id']
                    super(NsxV3Plugin, self).update_network(context,
                        net_id, {'network': {az_ext.AZ_HINTS: az_hints}})
                    created_net[az_ext.AZ_HINTS] = az_hints

                if is_provider_net:
                    # Save provider network fields, needed by get_network()
                    net_bindings = [nsx_db.add_network_binding(
                        context.session, created_net['id'],
                        net_type, physical_net, vlan_id)]
                    self._extend_network_dict_provider(context, created_net,
                                                       bindings=net_bindings)
                if is_backend_network:
                    # Add neutron-id <-> nsx-id mapping to the DB
                    # after the network creation is done
                    neutron_net_id = created_net['id']
                    nsx_db.add_neutron_nsx_network_mapping(
                        context.session,
                        neutron_net_id,
                        nsx_net_id)

            if is_backend_network and cfg.CONF.nsx_v3.native_dhcp_metadata:
                # Enable native metadata proxy for this network.
                tags = utils.build_v3_tags_payload(
                    net_data, resource_type='os-neutron-net-id',
                    project_name=context.tenant_name)
                name = utils.get_name_and_uuid('%s-%s' % (
                    'mdproxy', created_net['name'] or 'network'),
                                               created_net['id'])
                md_port = self._port_client.create(
                    nsx_net_id, cfg.CONF.nsx_v3.metadata_proxy_uuid,
                    tags=tags, name=name,
                    attachment_type=nsx_constants.ATTACHMENT_MDPROXY)
                LOG.debug("Created MD-Proxy logical port %(port)s "
                          "for network %(network)s",
                          {'port': md_port['id'],
                           'network': net_data['id']})
        except Exception:
            with excutils.save_and_reraise_exception():
                # Undo creation on the backend
                LOG.exception(_LE('Failed to create network %s'),
                              created_net['id'])
                if net_type != utils.NetworkTypes.L3_EXT:
                    self.nsxlib.delete_logical_switch(created_net['id'])

        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        net_model = self._get_network(context, created_net['id'])
        self._apply_dict_extend_functions('networks', created_net, net_model)

        if qos_consts.QOS_POLICY_ID in net_data:
            # attach the policy to the network in neutron DB
            #(will affect only future compute ports)
            qos_com_utils.update_network_policy_binding(
                context,
                created_net['id'],
                net_data[qos_consts.QOS_POLICY_ID])

        created_net[qos_consts.QOS_POLICY_ID] = (
            qos_com_utils.get_network_policy_id(context, created_net['id']))

        return created_net

    def _has_active_port(self, context, network_id):
        ports_in_use = context.session.query(models_v2.Port).filter_by(
            network_id=network_id).all()
        return not all([p.device_owner in
                        db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS
                        for p in ports_in_use]) if ports_in_use else False

    def _retry_delete_network(self, context, network_id):
        """This method attempts to retry the delete on a network if there are
           AUTO_DELETE_PORT_OWNERS left. This is to avoid a race condition
           between delete_network and the dhcp creating a port on the network.
        """
        first_try = True
        while True:
            try:
                with context.session.begin(subtransactions=True):
                    self._process_l3_delete(context, network_id)
                    return super(NsxV3Plugin, self).delete_network(
                        context, network_id)
                break
            except n_exc.NetworkInUse:
                # There is a race condition in delete_network() that we need
                # to work around here.  delete_network() issues a query to
                # automatically delete DHCP ports and then checks to see if any
                # ports exist on the network.  If a network is created and
                # deleted quickly, such as when running tempest, the DHCP agent
                # may be creating its port for the network around the same time
                # that the network is deleted.  This can result in the DHCP
                # port getting created in between these two queries in
                # delete_network().  To work around that, we'll call
                # delete_network() a second time if we get a NetworkInUse
                # exception but the only port(s) that exist are ones that
                # delete_network() is supposed to automatically delete.
                if not first_try:
                    # We tried once to work around the known race condition,
                    # but we still got the exception, so something else is
                    # wrong that we can't recover from.
                    raise
                first_try = False
                if self._has_active_port(context, network_id):
                    # There is a port on the network that is not going to be
                    # automatically deleted (such as a tenant created port), so
                    # we have nothing else to do but raise the exception.
                    raise

    def delete_network(self, context, network_id):
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            lock = 'nsxv3_network_' + network_id
            with locking.LockManager.get_lock(lock):
                # Disable native DHCP if there is no other existing port
                # besides DHCP port.
                if not self._has_active_port(context, network_id):
                    self._disable_native_dhcp(context, network_id)

        nsx_net_id = self._get_network_nsx_id(context, network_id)
        # First call DB operation for delete network as it will perform
        # checks on active ports
        self._retry_delete_network(context, network_id)
        if not self._network_is_external(context, network_id):
            # TODO(salv-orlando): Handle backend failure, possibly without
            # requiring us to un-delete the DB object. For instance, ignore
            # failures occurring if logical switch is not found
            self.nsxlib.delete_logical_switch(nsx_net_id)
        else:
            # TODO(berlin): delete subnets public announce on the network
            pass

    def _get_network_nsx_id(self, context, neutron_id):
        # get the nsx switch id from the DB mapping
        mappings = nsx_db.get_nsx_switch_ids(context.session, neutron_id)
        if not mappings or len(mappings) == 0:
            LOG.debug("Unable to find NSX mappings for neutron "
                      "network %s.", neutron_id)
            # fallback in case we didn't find the id in the db mapping
            # This should not happen, but added here in case the network was
            # created before this code was added.
            return neutron_id
        else:
            return mappings[0]

    def update_network(self, context, id, network):
        original_net = super(NsxV3Plugin, self).get_network(context, id)
        net_data = network['network']
        # Neutron does not support changing provider network values
        pnet._raise_if_updates_provider_attributes(net_data)
        extern_net = self._network_is_external(context, id)
        if extern_net:
            self._assert_on_external_net_with_qos(net_data)
        updated_net = super(NsxV3Plugin, self).update_network(context, id,
                                                              network)

        if psec.PORTSECURITY in network['network']:
            self._process_network_port_security_update(
                context, network['network'], updated_net)
        self._process_l3_update(context, updated_net, network['network'])
        self._extend_network_dict_provider(context, updated_net)

        if (not extern_net and
            'name' in net_data or 'admin_state_up' in net_data):
            try:
                # get the nsx switch id from the DB mapping
                nsx_id = self._get_network_nsx_id(context, id)
                self.nsxlib.update_logical_switch(
                    nsx_id,
                    name=utils.get_name_and_uuid(net_data['name'] or 'network',
                                                 id),
                    admin_state=net_data.get('admin_state_up'))
                # Backend does not update the admin state of the ports on
                # the switch when the switch's admin state changes. Do not
                # update the admin state of the ports in neutron either.
            except nsx_lib_exc.ManagerError:
                LOG.exception(_LE("Unable to update NSX backend, rolling "
                                  "back changes on neutron"))
                with excutils.save_and_reraise_exception():
                    super(NsxV3Plugin, self).update_network(
                        context, id, {'network': original_net})

        if qos_consts.QOS_POLICY_ID in net_data:
            # attach the policy to the network in neutron DB
            #(will affect only future compute ports)
            qos_com_utils.update_network_policy_binding(
                context, id, net_data[qos_consts.QOS_POLICY_ID])

        return updated_net

    def _has_no_dhcp_enabled_subnet(self, context, network):
        # Check if there is no DHCP-enabled subnet in the network.
        for subnet in network.subnets:
            if subnet.enable_dhcp:
                return False
        return True

    def _has_single_dhcp_enabled_subnet(self, context, network):
        # Check if there is only one DHCP-enabled subnet in the network.
        count = 0
        for subnet in network.subnets:
            if subnet.enable_dhcp:
                count += 1
                if count > 1:
                    return False
        return True if count == 1 else False

    def _enable_native_dhcp(self, context, network, subnet):
        # Enable native DHCP service on the backend for this network.
        # First create a Neutron DHCP port and use its assigned IP
        # address as the DHCP server address in an API call to create a
        # LogicalDhcpServer on the backend. Then create the corresponding
        # logical port for the Neutron port with DHCP attachment as the
        # LogicalDhcpServer UUID.

        # Delete obsolete settings if exist. This could happen when a
        # previous failed transaction was rolled back. But the backend
        # entries are still there.
        self._disable_native_dhcp(context, network['id'])

        # Get existing ports on subnet.
        existing_ports = super(NsxV3Plugin, self).get_ports(
            context, filters={'network_id': [network['id']],
                              'fixed_ips': {'subnet_id': [subnet['id']]}})
        port_data = {
            "name": "",
            "admin_state_up": True,
            "device_id": cfg.CONF.nsx_v3.dhcp_profile_uuid,
            "device_owner": const.DEVICE_OWNER_DHCP,
            "network_id": network['id'],
            "tenant_id": network["tenant_id"],
            "mac_address": const.ATTR_NOT_SPECIFIED,
            "fixed_ips": [{"subnet_id": subnet['id']}]
        }
        neutron_port = super(NsxV3Plugin, self).create_port(
            context, {'port': port_data})
        server_data = native_dhcp.build_dhcp_server_config(
            network, subnet, neutron_port, context.tenant_name)
        nsx_net_id = self._get_network_nsx_id(context, network['id'])
        tags = utils.build_v3_tags_payload(
            neutron_port, resource_type='os-neutron-dport-id',
            project_name=context.tenant_name)
        dhcp_server = None
        try:
            dhcp_server = self._dhcp_server.create(**server_data)
            LOG.debug("Created logical DHCP server %(server)s for network "
                      "%(network)s",
                      {'server': dhcp_server['id'], 'network': network['id']})
            name = self._get_port_name(context, port_data)
            nsx_port = self._port_client.create(
                nsx_net_id, dhcp_server['id'], tags=tags, name=name,
                attachment_type=nsx_constants.ATTACHMENT_DHCP,
                switch_profile_ids=[self._dhcp_profile])
            LOG.debug("Created DHCP logical port %(port)s for "
                      "network %(network)s",
                      {'port': nsx_port['id'], 'network': network['id']})
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to create logical DHCP server for "
                              "network %s"), network['id'])
                if dhcp_server:
                    self._dhcp_server.delete(dhcp_server['id'])
                super(NsxV3Plugin, self).delete_port(
                    context, neutron_port['id'])

        try:
            # Add neutron_port_id -> nsx_port_id mapping to the DB.
            nsx_db.add_neutron_nsx_port_mapping(
                context.session, neutron_port['id'], nsx_net_id,
                nsx_port['id'])
            # Add neutron_net_id -> dhcp_service_id mapping to the DB.
            nsx_db.add_neutron_nsx_service_binding(
                context.session, network['id'], neutron_port['id'],
                nsx_constants.SERVICE_DHCP, dhcp_server['id'])
        except (db_exc.DBError, sql_exc.TimeoutError):
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to create mapping for DHCP port %s,"
                              "deleting port and logical DHCP server"),
                          neutron_port['id'])
                self._dhcp_server.delete(dhcp_server['id'])
                self._cleanup_port(context, neutron_port['id'], nsx_port['id'])

        # Configure existing ports to work with the new DHCP server
        try:
            for port_data in existing_ports:
                self._add_dhcp_binding(context, port_data)
        except Exception:
            LOG.error(_LE('Unable to create DHCP bindings for existing ports '
                          'on subnet %s'), subnet['id'])

    def _disable_native_dhcp(self, context, network_id):
        # Disable native DHCP service on the backend for this network.
        # First delete the DHCP port in this network. Then delete the
        # corresponding LogicalDhcpServer for this network.
        dhcp_service = nsx_db.get_nsx_service_binding(
            context.session, network_id, nsx_constants.SERVICE_DHCP)
        if not dhcp_service:
            return

        if dhcp_service['port_id']:
            try:
                self.delete_port(context, dhcp_service['port_id'])
            except Exception:
                # This could happen when the port has been manually deleted.
                LOG.error(_LE("Failed to delete DHCP port %(port)s for "
                              "network %(network)s"),
                          {'port': dhcp_service['port_id'],
                           'network': network_id})
        else:
            LOG.error(_LE("DHCP port is not configured for network %s"),
                      network_id)

        try:
            self._dhcp_server.delete(dhcp_service['nsx_service_id'])
            LOG.debug("Deleted logical DHCP server %(server)s for network "
                      "%(network)s",
                      {'server': dhcp_service['nsx_service_id'],
                       'network': network_id})
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to delete logical DHCP server %(server)s"
                              "for network %(network)s"),
                          {'server': dhcp_service['nsx_service_id'],
                           'network': network_id})
        try:
            # Delete neutron_id -> dhcp_service_id mapping from the DB.
            nsx_db.delete_neutron_nsx_service_binding(
                context.session, network_id, nsx_constants.SERVICE_DHCP)
            # Delete all DHCP bindings under this DHCP server from the DB.
            nsx_db.delete_neutron_nsx_dhcp_bindings_by_service_id(
                context.session, dhcp_service['nsx_service_id'])
        except db_exc.DBError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to delete DHCP server mapping for "
                              "network %s"), network_id)

    def _validate_address_space(self, subnet):
        cidr = subnet.get('cidr')
        if (not validators.is_attr_set(cidr) or
            netaddr.IPNetwork(cidr).version != 4):
            return
        # Check if subnet overlaps with shared address space.
        # This is checked on the backend when attaching subnet to a router.
        if netaddr.IPSet([cidr]) & netaddr.IPSet(['100.64.0.0/10']):
            msg = _("Subnet overlaps with shared address space 100.64.0.0/10")
            raise n_exc.InvalidInput(error_message=msg)

    def _create_bulk_with_callback(self, resource, context, request_items,
                                   post_create_func=None, rollback_func=None):
        # This is a copy of the _create_bulk() in db_base_plugin_v2.py,
        # but extended with user-provided callback functions.
        objects = []
        collection = "%ss" % resource
        items = request_items[collection]
        context.session.begin(subtransactions=True)
        try:
            for item in items:
                obj_creator = getattr(self, 'create_%s' % resource)
                obj = obj_creator(context, item)
                objects.append(obj)
                if post_create_func:
                    # The user-provided post_create function is called
                    # after a new object is created.
                    post_create_func(obj)
            context.session.commit()
        except Exception:
            if rollback_func:
                # The user-provided rollback function is called when an
                # exception occurred.
                for obj in objects:
                    rollback_func(obj)

            # Note that the session.rollback() function is called here.
            # session.rollback() will invoke transaction.rollback() on
            # the transaction this session maintains. The latter will
            # deactive the transaction and clear the session's cache.
            #
            # But depending on where the exception occurred,
            # transaction.rollback() may have already been called
            # internally before reaching here.
            #
            # For example, if the exception happened under a
            # "with session.begin(subtransactions=True):" statement
            # anywhere in the middle of processing obj_creator(),
            # transaction.__exit__() will invoke transaction.rollback().
            # Thus when the exception reaches here, the session's cache
            # is already empty.
            context.session.rollback()
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("An exception occurred while creating "
                              "the %(resource)s:%(item)s"),
                          {'resource': resource, 'item': item})
        return objects

    def _post_create_subnet(self, context, subnet):
        LOG.debug("Collect native DHCP entries for network %s",
                  subnet['network_id'])
        dhcp_service = nsx_db.get_nsx_service_binding(
            context.session, subnet['network_id'], nsx_constants.SERVICE_DHCP)
        if dhcp_service:
            _net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, dhcp_service['port_id'])
            return {'nsx_port_id': nsx_port_id,
                    'nsx_service_id': dhcp_service['nsx_service_id']}

    def _rollback_subnet(self, subnet, dhcp_info):
        LOG.debug("Rollback native DHCP entries for network %s",
                  subnet['network_id'])
        if dhcp_info:
            try:
                self._port_client.delete(dhcp_info['nsx_port_id'])
            except Exception as e:
                LOG.error(_LE("Failed to delete logical port %(id)s "
                              "during rollback. Exception: %(e)s"),
                          {'id': dhcp_info['nsx_port_id'], 'e': e})
            try:
                self._dhcp_server.delete(dhcp_info['nsx_service_id'])
            except Exception as e:
                LOG.error(_LE("Failed to delete logical DHCP server %(id)s "
                              "during rollback. Exception: %(e)s"),
                          {'id': dhcp_info['nsx_service_id'], 'e': e})

    def create_subnet_bulk(self, context, subnets):
        # Maintain a local cache here because when the rollback function
        # is called, the cache in the session may have already been cleared.
        _subnet_dhcp_info = {}

        def _post_create(subnet):
            if subnet['enable_dhcp']:
                _subnet_dhcp_info[subnet['id']] = self._post_create_subnet(
                    context, subnet)

        def _rollback(subnet):
            if subnet['enable_dhcp'] and subnet['id'] in _subnet_dhcp_info:
                self._rollback_subnet(subnet, _subnet_dhcp_info[subnet['id']])
                del _subnet_dhcp_info[subnet['id']]

        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            return self._create_bulk_with_callback('subnet', context, subnets,
                                                   _post_create, _rollback)
        else:
            return self._create_bulk('subnet', context, subnets)

    def create_subnet(self, context, subnet):
        self._validate_address_space(subnet['subnet'])

        # TODO(berlin): public external subnet announcement
        if (cfg.CONF.nsx_v3.native_dhcp_metadata and
            subnet['subnet'].get('enable_dhcp', False)):
            lock = 'nsxv3_network_' + subnet['subnet']['network_id']
            with locking.LockManager.get_lock(lock):
                # Check if it is on an overlay network and is the first
                # DHCP-enabled subnet to create.
                if self._is_overlay_network(
                    context, subnet['subnet']['network_id']):
                    network = self._get_network(
                        context, subnet['subnet']['network_id'])
                    if self._has_no_dhcp_enabled_subnet(context, network):
                        created_subnet = super(
                            NsxV3Plugin, self).create_subnet(context, subnet)
                        self._enable_native_dhcp(context, network,
                                                 created_subnet)
                        msg = None
                    else:
                        msg = (_("Can not create more than one DHCP-enabled "
                                "subnet in network %s") %
                               subnet['subnet']['network_id'])
                else:
                    msg = _("Native DHCP is not supported for non-overlay "
                            "network %s") % subnet['subnet']['network_id']
                if msg:
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
        else:
            created_subnet = super(NsxV3Plugin, self).create_subnet(
                context, subnet)
        return created_subnet

    def delete_subnet(self, context, subnet_id):
        # TODO(berlin): cancel public external subnet announcement
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            subnet = self.get_subnet(context, subnet_id)
            if subnet['enable_dhcp']:
                lock = 'nsxv3_network_' + subnet['network_id']
                with locking.LockManager.get_lock(lock):
                    # Check if it is the last DHCP-enabled subnet to delete.
                    network = self._get_network(context, subnet['network_id'])
                    if self._has_single_dhcp_enabled_subnet(context, network):
                        try:
                            self._disable_native_dhcp(context, network['id'])
                        except Exception as e:
                            LOG.error(_LE("Failed to disable native DHCP for"
                                          "network %(id)s. Exception: %(e)s"),
                                      {'id': network['id'], 'e': e})
                        super(NsxV3Plugin, self).delete_subnet(
                            context, subnet_id)
                        return
        super(NsxV3Plugin, self).delete_subnet(context, subnet_id)

    def update_subnet(self, context, subnet_id, subnet):
        updated_subnet = None
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            orig_subnet = self.get_subnet(context, subnet_id)
            enable_dhcp = subnet['subnet'].get('enable_dhcp')
            if (enable_dhcp is not None and
                enable_dhcp != orig_subnet['enable_dhcp']):
                lock = 'nsxv3_network_' + orig_subnet['network_id']
                with locking.LockManager.get_lock(lock):
                    network = self._get_network(
                        context, orig_subnet['network_id'])
                    if enable_dhcp:
                        if self._is_overlay_network(
                            context, orig_subnet['network_id']):
                            if self._has_no_dhcp_enabled_subnet(
                                context, network):
                                updated_subnet = super(
                                    NsxV3Plugin, self).update_subnet(
                                    context, subnet_id, subnet)
                                self._enable_native_dhcp(context, network,
                                                         updated_subnet)
                                msg = None
                            else:
                                msg = (_("Multiple DHCP-enabled subnets is "
                                         "not allowed in network %s") %
                                       orig_subnet['network_id'])
                        else:
                            msg = (_("Native DHCP is not supported for "
                                     "non-overlay network %s") %
                                   orig_subnet['network_id'])
                        if msg:
                            LOG.error(msg)
                            raise n_exc.InvalidInput(error_message=msg)
                    elif self._has_single_dhcp_enabled_subnet(context,
                                                              network):
                        self._disable_native_dhcp(context, network['id'])
                        updated_subnet = super(
                            NsxV3Plugin, self).update_subnet(
                            context, subnet_id, subnet)

        if not updated_subnet:
            updated_subnet = super(NsxV3Plugin, self).update_subnet(
                context, subnet_id, subnet)

        # Check if needs to update logical DHCP server for native DHCP.
        if (cfg.CONF.nsx_v3.native_dhcp_metadata and
            updated_subnet['enable_dhcp']):
            kwargs = {}
            for key in ('dns_nameservers', 'gateway_ip'):
                if key in subnet['subnet']:
                    value = subnet['subnet'][key]
                    if value != orig_subnet[key]:
                        kwargs[key] = value
            if kwargs:
                dhcp_service = nsx_db.get_nsx_service_binding(
                    context.session, orig_subnet['network_id'],
                    nsx_constants.SERVICE_DHCP)
                if dhcp_service:
                    try:
                        self._dhcp_server.update(
                            dhcp_service['nsx_service_id'], **kwargs)
                    except nsx_lib_exc.ManagerError:
                        with excutils.save_and_reraise_exception():
                            LOG.error(
                                _LE("Unable to update logical DHCP server "
                                    "%(server)s for network %(network)s"),
                                {'server': dhcp_service['nsx_service_id'],
                                 'network': orig_subnet['network_id']})
                    if 'gateway_ip' in kwargs:
                        # Need to update the static binding of every VM in
                        # this logical DHCP server.
                        bindings = nsx_db.get_nsx_dhcp_bindings_by_service(
                            context.session, dhcp_service['nsx_service_id'])
                        for binding in bindings:
                            port = self._get_port(context, binding['port_id'])
                            self._update_dhcp_binding_on_server(
                                context, binding, port['mac_address'],
                                binding['ip_address'], kwargs['gateway_ip'])

        if (cfg.CONF.nsx_v3.metadata_on_demand and
            not cfg.CONF.nsx_v3.native_dhcp_metadata):
            # If enable_dhcp is changed on a subnet attached to a router,
            # update internal metadata network accordingly.
            if 'enable_dhcp' in subnet['subnet']:
                port_filters = {'device_owner': const.ROUTER_INTERFACE_OWNERS,
                                'fixed_ips': {'subnet_id': [subnet_id]}}
                ports = self.get_ports(context, filters=port_filters)
                for port in ports:
                    nsx_rpc.handle_router_metadata_access(
                        self, context, port['device_id'],
                        interface=not updated_subnet['enable_dhcp'])
        return updated_subnet

    def _build_address_bindings(self, port):
        address_bindings = []
        for fixed_ip in port['fixed_ips']:
            # NOTE(arosen): nsx-v3 doesn't seem to handle ipv6 addresses
            # currently so for now we remove them here and do not pass
            # them to the backend which would raise an error.
            if netaddr.IPNetwork(fixed_ip['ip_address']).version == 6:
                continue
            address_bindings.append(nsx_resources.PacketAddressClassifier(
                fixed_ip['ip_address'], port['mac_address'], None))

        for pair in port.get(addr_pair.ADDRESS_PAIRS):
            address_bindings.append(nsx_resources.PacketAddressClassifier(
                pair['ip_address'], pair['mac_address'], None))

        return address_bindings

    def _extend_get_network_dict_provider(self, context, network):
        self._extend_network_dict_provider(context, network)
        network[qos_consts.QOS_POLICY_ID] = (qos_com_utils.
            get_network_policy_id(context, network['id']))

    def get_network(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            # Get network from Neutron database
            network = self._get_network(context, id)
            # Don't do field selection here otherwise we won't be able to add
            # provider networks fields
            net = self._make_network_dict(network, context=context)
            self._extend_get_network_dict_provider(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        # Get networks from Neutron database
        filters = filters or {}
        with context.session.begin(subtransactions=True):
            networks = (
                super(NsxV3Plugin, self).get_networks(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            # Add provider network fields
            for net in networks:
                self._extend_get_network_dict_provider(context, net)
        return (networks if not fields else
                [self._fields(network, fields) for network in networks])

    def _get_data_from_binding_profile(self, context, port):
        if (pbin.PROFILE not in port or
                not validators.is_attr_set(port[pbin.PROFILE])):
            return None, None

        parent_name = (
            port[pbin.PROFILE].get('parent_name'))
        tag = port[pbin.PROFILE].get('tag')
        if not any((parent_name, tag)):
            # An empty profile is fine.
            return None, None
        if not all((parent_name, tag)):
            # If one is set, they both must be set.
            msg = _('Invalid binding:profile. parent_name and tag are '
                    'both required.')
            raise n_exc.InvalidInput(error_message=msg)
        if not isinstance(parent_name, six.string_types):
            msg = _('Invalid binding:profile. parent_name "%s" must be '
                    'a string.') % parent_name
            raise n_exc.InvalidInput(error_message=msg)
        if not n_utils.is_valid_vlan_tag(tag):
            msg = _('Invalid binding:profile. tag "%s" must be '
                    'an int between 1 and 4096, inclusive.') % tag
            raise n_exc.InvalidInput(error_message=msg)
        # Make sure we can successfully look up the port indicated by
        # parent_name.  Just let it raise the right exception if there is a
        # problem.
        # NOTE(arosen): For demo reasons the parent_port might not be a
        # a neutron managed port so for now do not perform this check.
        # self.get_port(context, parent_name)
        return parent_name, tag

    def _get_port_name(self, context, port_data):
        device_owner = port_data.get('device_owner')
        device_id = port_data.get('device_id')
        if device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF and device_id:
            router = self._get_router(context, device_id)
            name = utils.get_name_and_uuid(
                router['name'] or 'router', port_data['id'], tag='port')
        elif device_owner == const.DEVICE_OWNER_DHCP:
            network = self.get_network(context, port_data['network_id'])
            name = utils.get_name_and_uuid('%s-%s' % (
                                           'dhcp',
                                           network['name'] or 'network'),
                                           network['id'])
        elif device_owner.startswith(const.DEVICE_OWNER_COMPUTE_PREFIX):
            name = utils.get_name_and_uuid(
                port_data['name'] or 'instance-port', port_data['id'])
        else:
            name = port_data['name']
        return name

    def _get_qos_profile_id(self, context, policy_id):
        switch_profile_id = nsx_db.get_switch_profile_by_qos_policy(
            context.session, policy_id)
        qos_profile = self.nsxlib.get_qos_switching_profile(switch_profile_id)
        if qos_profile:
            profile_ids = self._switching_profiles.build_switch_profile_ids(
                self._switching_profiles, qos_profile)
            if profile_ids and len(profile_ids) > 0:
                # We have only 1 QoS profile, so this array is of size 1
                return profile_ids[0]
        # Didn't find it
        err_msg = _("Could not find QoS switching profile for policy "
                    "%s") % policy_id
        raise n_exc.InvalidInput(error_message=err_msg)

    def _create_port_at_the_backend(self, context, port_data,
                                    l2gw_port_check, psec_is_on):
        device_owner = port_data.get('device_owner')
        device_id = port_data.get('device_id')
        if device_owner == const.DEVICE_OWNER_DHCP:
            resource_type = 'os-neutron-dport-id'
        elif device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF:
            resource_type = 'os-neutron-rport-id'
        else:
            resource_type = 'os-neutron-port-id'
        tags = utils.build_v3_tags_payload(
            port_data, resource_type=resource_type,
            project_name=context.tenant_name)
        resource_type = self._get_resource_type_for_device_id(
            device_owner, device_id)
        if resource_type:
            tags = utils.add_v3_tag(tags, resource_type, device_id)

        if device_owner != l3_db.DEVICE_OWNER_ROUTER_INTF:
            if ((device_owner == const.DEVICE_OWNER_DHCP and
                 not cfg.CONF.nsx_v3.native_dhcp_metadata) or
                (device_owner != const.DEVICE_OWNER_DHCP and
                 not psec_is_on)):
                    tags.append({'scope': security.PORT_SG_SCOPE,
                                 'tag': firewall.EXCLUDE_PORT})

        if utils.is_nsx_version_1_1_0(self._nsx_version):
            # If port has no security-groups then we don't need to add any
            # security criteria tag.
            if port_data[ext_sg.SECURITYGROUPS]:
                tags += self.nsxlib.get_lport_tags_for_security_groups(
                    port_data[ext_sg.SECURITYGROUPS] +
                    port_data[provider_sg.PROVIDER_SECURITYGROUPS])

        parent_name, tag = self._get_data_from_binding_profile(
            context, port_data)
        address_bindings = (self._build_address_bindings(port_data)
                            if psec_is_on else [])

        if not device_owner:
            # no attachment
            attachment_type = None
            vif_uuid = None
        elif l2gw_port_check:
            # Change the attachment type for L2 gateway owned ports.
            # NSX backend requires the vif id be set to bridge endpoint id
            # for ports plugged into a Bridge Endpoint.
            # Also set port security to False, since L2GW port does not have
            # an IP address.
            vif_uuid = device_id
            attachment_type = device_owner
            psec_is_on = False
        elif device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF:
            # no attachment change
            attachment_type = False
            vif_uuid = False
        else:
            # default attachment
            attachment_type = nsx_constants.ATTACHMENT_VIF
            vif_uuid = port_data['id']

        profiles = []
        mac_learning_profile_set = False
        if psec_is_on:
            address_pairs = port_data.get(addr_pair.ADDRESS_PAIRS)
            if validators.is_attr_set(address_pairs) and address_pairs:
                mac_learning_profile_set = True
            profiles.append(self._get_port_security_profile_id())
        if device_owner == const.DEVICE_OWNER_DHCP:
            profiles.append(self._dhcp_profile)

        # Add QoS switching profile, if exists
        qos_policy_id = None
        if validators.is_attr_set(port_data.get(qos_consts.QOS_POLICY_ID)):
            qos_policy_id = port_data[qos_consts.QOS_POLICY_ID]
        elif device_owner.startswith(const.DEVICE_OWNER_COMPUTE_PREFIX):
            # check if the network of this port has a policy
            qos_policy_id = qos_com_utils.get_network_policy_id(
                context, port_data['network_id'])
        if qos_policy_id:
            qos_profile_id = self._get_qos_profile_id(context, qos_policy_id)
            profiles.append(qos_profile_id)

        # Add mac_learning profile if it exists and is configured
        if (self._mac_learning_profile and
            (mac_learning_profile_set or
             (validators.is_attr_set(port_data.get(mac_ext.MAC_LEARNING)) and
              port_data.get(mac_ext.MAC_LEARNING) is True))):
            profiles.append(self._mac_learning_profile)

        name = self._get_port_name(context, port_data)

        nsx_net_id = port_data[pbin.VIF_DETAILS]['nsx-logical-switch-id']

        try:
            result = self._port_client.create(
                nsx_net_id, vif_uuid,
                tags=tags,
                name=name,
                admin_state=port_data['admin_state_up'],
                address_bindings=address_bindings,
                attachment_type=attachment_type,
                parent_vif_id=parent_name, parent_tag=tag,
                switch_profile_ids=profiles)
        except nsx_lib_exc.ManagerError as inst:
            # we may fail if the QoS is not supported for this port
            # (for example - transport zone with KVM)
            LOG.exception(_LE("Unable to create port on the backend: %s"),
                          inst)
            msg = _("Unable to create port on the backend")
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # Attach the policy to the port in the neutron DB
        if qos_policy_id:
            qos_com_utils.update_port_policy_binding(context,
                                                     port_data['id'],
                                                     qos_policy_id)
        return result

    def _validate_address_pairs(self, address_pairs):
        for pair in address_pairs:
            ip = pair.get('ip_address')
            if not utils.is_ipv4_ip_address(ip):
                raise nsx_exc.InvalidIPAddress(ip_address=ip)

    def _create_port_preprocess_security(
            self, context, port, port_data, neutron_db):
        (port_security, has_ip) = self._determine_port_security_and_has_ip(
            context, port_data)
        port_data[psec.PORTSECURITY] = port_security
        self._process_port_port_security_create(
                context, port_data, neutron_db)
        # allowed address pair checks
        address_pairs = port_data.get(addr_pair.ADDRESS_PAIRS)
        if validators.is_attr_set(address_pairs):
            if not port_security:
                raise addr_pair.AddressPairAndPortSecurityRequired()
            else:
                self._validate_address_pairs(address_pairs)
                self._process_create_allowed_address_pairs(
                    context, neutron_db,
                    address_pairs)
        else:
            # remove ATTR_NOT_SPECIFIED
            port_data[addr_pair.ADDRESS_PAIRS] = []

        if port_security and has_ip:
            self._ensure_default_security_group_on_port(context, port)
        elif self._check_update_has_security_groups(
                {'port': port_data}):
            raise psec.PortSecurityAndIPRequiredForSecurityGroups()
        port_data[ext_sg.SECURITYGROUPS] = (
            self._get_security_groups_on_port(context, port))
        return port_security, has_ip

    def _assert_on_external_net_with_compute(self, port_data):
        # Prevent creating port with device owner prefix 'compute'
        # on external networks.
        device_owner = port_data.get('device_owner')
        if (device_owner is not None and
                device_owner.startswith(const.DEVICE_OWNER_COMPUTE_PREFIX)):
            err_msg = _("Unable to update/create a port with an external "
                        "network")
            LOG.warning(err_msg)
            raise n_exc.InvalidInput(error_message=err_msg)

    def _cleanup_port(self, context, port_id, lport_id):
        super(NsxV3Plugin, self).delete_port(context, port_id)
        if lport_id:
            self._port_client.delete(lport_id)

    def _assert_on_external_net_port_with_qos(self, port_data):
        # Prevent creating/update port with QoS policy
        # on external networks.
        if validators.is_attr_set(port_data.get(qos_consts.QOS_POLICY_ID)):
            err_msg = _("Unable to update/create a port with an external "
                        "network and a QoS policy")
            LOG.warning(err_msg)
            raise n_exc.InvalidInput(error_message=err_msg)

    def _assert_on_router_port_with_qos(self, port_data, device_owner):
        # Prevent creating/update port with QoS policy
        # on router-interface ports.
        if (device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF and
            validators.is_attr_set(port_data.get(qos_consts.QOS_POLICY_ID))):
            err_msg = _("Unable to update/create a router port with a QoS "
                        "policy")
            LOG.warning(err_msg)
            raise n_exc.InvalidInput(error_message=err_msg)

    def _filter_ipv4_dhcp_fixed_ips(self, context, fixed_ips):
        ips = []
        for fixed_ip in fixed_ips:
            if netaddr.IPNetwork(fixed_ip['ip_address']).version != 4:
                continue
            subnet = self.get_subnet(context, fixed_ip['subnet_id'])
            if subnet['enable_dhcp']:
                ips.append(fixed_ip)
        return ips

    def _add_dhcp_binding(self, context, port):
        if not utils.is_port_dhcp_configurable(port):
            return
        dhcp_service = nsx_db.get_nsx_service_binding(
            context.session, port['network_id'], nsx_constants.SERVICE_DHCP)
        if not dhcp_service:
            return
        for fixed_ip in self._filter_ipv4_dhcp_fixed_ips(
            context, port['fixed_ips']):
            binding = self._add_dhcp_binding_on_server(
                context, dhcp_service['nsx_service_id'], fixed_ip['subnet_id'],
                fixed_ip['ip_address'], port)
            try:
                nsx_db.add_neutron_nsx_dhcp_binding(
                    context.session, port['id'], fixed_ip['subnet_id'],
                    fixed_ip['ip_address'], dhcp_service['nsx_service_id'],
                    binding['id'])
            except (db_exc.DBError, sql_exc.TimeoutError):
                LOG.error(_LE("Failed to add mapping of DHCP binding "
                              "%(binding)s for port %(port)s, deleting"
                              "DHCP binding on server"),
                          {'binding': binding['id'], 'port': port['id']})
                self._delete_dhcp_binding_on_server(context, binding)

    def _add_dhcp_binding_on_server(self, context, dhcp_service_id, subnet_id,
                                    ip, port):
        try:
            hostname = 'host-%s' % ip.replace('.', '-')
            gateway_ip = self.get_subnet(
                context, subnet_id).get('gateway_ip')
            options = {'option121': {'static_routes': [
                {'network': '%s' % cfg.CONF.nsx_v3.native_metadata_route,
                 'next_hop': ip}]}}
            binding = self._dhcp_server.create_binding(
                dhcp_service_id, port['mac_address'], ip, hostname,
                cfg.CONF.nsx_v3.dhcp_lease_time, options, gateway_ip)
            LOG.debug("Created static binding (mac: %(mac)s, ip: %(ip)s, "
                      "gateway: %(gateway)s) for port %(port)s on "
                      "logical DHCP server %(server)s",
                      {'mac': port['mac_address'], 'ip': ip,
                       'gateway': gateway_ip, 'port': port['id'],
                       'server': dhcp_service_id})
            return binding
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to create static binding (mac: %(mac)s, "
                              "ip: %(ip)s, gateway: %(gateway)s) for port "
                              "%(port)s on logical DHCP server %(server)s"),
                          {'mac': port['mac_address'], 'ip': ip,
                           'gateway': gateway_ip, 'port': port['id'],
                           'server': dhcp_service_id})

    def _delete_dhcp_binding(self, context, port):
        # Do not check device_owner here because Nova may have already
        # deleted that before Neutron's port deletion.
        bindings = nsx_db.get_nsx_dhcp_bindings(context.session, port['id'])
        for binding in bindings:
            self._delete_dhcp_binding_on_server(context, binding)
            try:
                nsx_db.delete_neutron_nsx_dhcp_binding(
                    context.session, binding['port_id'],
                    binding['nsx_binding_id'])
            except db_exc.DBError:
                LOG.error(_LE("Unable to delete mapping of DHCP binding "
                              "%(binding)s for port %(port)s"),
                          {'binding': binding['nsx_binding_id'],
                           'port': binding['port_id']})

    def _delete_dhcp_binding_on_server(self, context, binding):
        try:
            self._dhcp_server.delete_binding(
                binding['nsx_service_id'], binding['nsx_binding_id'])
            LOG.debug("Deleted static binding for port %(port)s) on "
                      "logical DHCP server %(server)s",
                      {'port': binding['port_id'],
                       'server': binding['nsx_service_id']})
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to delete static binding for port "
                              "%(port)s) on logical DHCP server %(server)s"),
                          {'port': binding['port_id'],
                           'server': binding['nsx_service_id']})

    def _find_dhcp_binding(self, subnet_id, ip_address, bindings):
        for binding in bindings:
            if (subnet_id == binding['subnet_id'] and
                ip_address == binding['ip_address']):
                return binding

    def _update_dhcp_binding(self, context, old_port, new_port):
        # First check if any IPv4 address in fixed_ips is changed.
        # Then update DHCP server setting or DHCP static binding
        # depending on the port type.
        # Note that Neutron allows a port with multiple IPs in the
        # same subnet. But backend DHCP server may not support that.

        if (utils.is_port_dhcp_configurable(old_port) !=
            utils.is_port_dhcp_configurable(new_port)):
            # Note that the device_owner could be changed,
            # but still needs DHCP binding.
            if utils.is_port_dhcp_configurable(old_port):
                self._delete_dhcp_binding(context, old_port)
            else:
                self._add_dhcp_binding(context, new_port)
            return

        # Collect IPv4 DHCP addresses from original and updated fixed_ips
        # in the form of [(subnet_id, ip_address)].
        old_fixed_ips = set([(fixed_ip['subnet_id'], fixed_ip['ip_address'])
                             for fixed_ip in self._filter_ipv4_dhcp_fixed_ips(
                                 context, old_port['fixed_ips'])])
        new_fixed_ips = set([(fixed_ip['subnet_id'], fixed_ip['ip_address'])
                             for fixed_ip in self._filter_ipv4_dhcp_fixed_ips(
                                 context, new_port['fixed_ips'])])
        # Find out the subnet/IP differences before and after the update.
        ips_to_add = list(new_fixed_ips - old_fixed_ips)
        ips_to_delete = list(old_fixed_ips - new_fixed_ips)
        ip_change = (ips_to_add or ips_to_delete)

        if old_port["device_owner"] == const.DEVICE_OWNER_DHCP and ip_change:
            # Update backend DHCP server address if the IP address of a DHCP
            # port is changed.
            if len(new_fixed_ips) != 1:
                msg = _("Can only configure one IP address on a DHCP server")
                raise n_exc.InvalidInput(error_message=msg)
            # Locate the backend DHCP server for this DHCP port.
            dhcp_service = nsx_db.get_nsx_service_binding(
                context.session, old_port['network_id'],
                nsx_constants.SERVICE_DHCP)
            if dhcp_service:
                new_ip = ips_to_add[0][1]
                try:
                    self._dhcp_server.update(dhcp_service['nsx_service_id'],
                                             server_ip=new_ip)
                    LOG.debug("Updated IP %(ip)s for logical DHCP server "
                              "%(server)s",
                              {'ip': new_ip,
                               'server': dhcp_service['nsx_service_id']})
                except nsx_lib_exc.ManagerError:
                    with excutils.save_and_reraise_exception():
                        LOG.error(_LE("Unable to update IP %(ip)s for logical "
                                      "DHCP server %(server)s"),
                                  {'ip': new_ip,
                                   'server': dhcp_service['nsx_service_id']})
        elif utils.is_port_dhcp_configurable(old_port):
            # Update static DHCP bindings for a compute port.
            bindings = nsx_db.get_nsx_dhcp_bindings(context.session,
                                                    old_port['id'])
            if ip_change:
                # If IP address is changed, update associated DHCP bindings,
                # metadata route, and default hostname.
                # Mac address (if changed) will be updated at the same time.
                if ([subnet_id for (subnet_id, ip) in ips_to_add] ==
                    [subnet_id for (subnet_id, ip) in ips_to_delete]):
                    # No change on subnet_id, just update corresponding IPs.
                    for i, (subnet_id, ip) in enumerate(ips_to_delete):
                        binding = self._find_dhcp_binding(subnet_id, ip,
                                                          bindings)
                        if binding:
                            self._update_dhcp_binding_on_server(
                                context, binding, new_port['mac_address'],
                                ips_to_add[i][1])
                else:
                    for (subnet_id, ip) in ips_to_delete:
                        binding = self._find_dhcp_binding(subnet_id, ip,
                                                          bindings)
                        if binding:
                            self._delete_dhcp_binding_on_server(context,
                                                                binding)
                    if ips_to_add:
                        dhcp_service = nsx_db.get_nsx_service_binding(
                            context.session, new_port['network_id'],
                            nsx_constants.SERVICE_DHCP)
                        if dhcp_service:
                            for (subnet_id, ip) in ips_to_add:
                                self._add_dhcp_binding_on_server(
                                    context, dhcp_service['nsx_service_id'],
                                    subnet_id, ip, new_port)
            elif old_port['mac_address'] != new_port['mac_address']:
                # If only Mac address is changed, update the Mac address in
                # all associated DHCP bindings.
                for binding in bindings:
                    self._update_dhcp_binding_on_server(
                        context, binding, new_port['mac_address'],
                        binding['ip_address'])

    def _update_dhcp_binding_on_server(self, context, binding, mac, ip,
                                       gateway_ip=False):
        try:
            data = {'mac_address': mac, 'ip_address': ip}
            if ip != binding['ip_address']:
                data['host_name'] = 'host-%s' % ip.replace('.', '-')
                data['options'] = {'option121': {'static_routes': [
                    {'network': '%s' % cfg.CONF.nsx_v3.native_metadata_route,
                     'next_hop': ip}]}}
            if gateway_ip is not False:
                # Note that None is valid for gateway_ip, means deleting it.
                data['gateway_ip'] = gateway_ip
            self._dhcp_server.update_binding(
                binding['nsx_service_id'], binding['nsx_binding_id'], **data)
            LOG.debug("Updated static binding (mac: %(mac)s, ip: %(ip)s, "
                      "gateway: %(gateway)s) for port %(port)s on "
                      "logical DHCP server %(server)s",
                      {'mac': mac, 'ip': ip, 'gateway': gateway_ip,
                       'port': binding['port_id'],
                       'server': binding['nsx_service_id']})
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to update static binding (mac: %(mac)s, "
                              "ip: %(ip)s, gateway: %(gateway)s) for port "
                              "%(port)s on logical DHCP server %(server)s"),
                          {'mac': mac, 'ip': ip, 'gateway': gateway_ip,
                           'port': binding['port_id'],
                           'server': binding['nsx_service_id']})

    def create_port(self, context, port, l2gw_port_check=False):
        port_data = port['port']
        dhcp_opts = port_data.get(ext_edo.EXTRADHCPOPTS, [])

        # TODO(salv-orlando): Undo logical switch creation on failure
        with context.session.begin(subtransactions=True):
            is_external_net = self._network_is_external(
                context, port_data['network_id'])
            if is_external_net:
                self._assert_on_external_net_with_compute(port_data)
                self._assert_on_external_net_port_with_qos(port_data)

            self._assert_on_router_port_with_qos(
                port_data, port_data.get('device_owner'))

            neutron_db = super(NsxV3Plugin, self).create_port(context, port)
            port["port"].update(neutron_db)

            (is_psec_on, has_ip) = self._create_port_preprocess_security(
                context, port, port_data, neutron_db)
            self._process_portbindings_create_and_update(
                context, port['port'], port_data)
            self._process_port_create_extra_dhcp_opts(
                context, port_data, dhcp_opts)

            # handle adding security groups to port
            sgids = self._get_security_groups_on_port(context, port)
            self._process_port_create_security_group(
                context, port_data, sgids)

            # handling adding provider security group to port if there are any
            provider_groups = self._get_provider_security_groups_on_port(
                context, port)
            self._process_port_create_provider_security_group(
                context, port_data, provider_groups)
            # add provider groups to other security groups list.
            # sgids is a set() so we need to | it in.
            if provider_groups:
                sgids |= set(provider_groups)
            self._extend_port_dict_binding(context, port_data)
            if validators.is_attr_set(port_data.get(mac_ext.MAC_LEARNING)):
                if is_psec_on:
                    msg = _('Mac learning requires that port security be '
                            'disabled')
                    raise n_exc.InvalidInput(error_message=msg)
                self._create_mac_learning_state(context, port_data)
            elif mac_ext.MAC_LEARNING in port_data:
                # This is due to the fact that the default is
                # ATTR_NOT_SPECIFIED
                port_data.pop(mac_ext.MAC_LEARNING)

        # Operations to backend should be done outside of DB transaction.
        # NOTE(arosen): ports on external networks are nat rules and do
        # not result in ports on the backend.
        if not is_external_net:
            try:
                lport = self._create_port_at_the_backend(
                    context, port_data, l2gw_port_check, is_psec_on)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE('Failed to create port %(id)s on NSX '
                                  'backend. Exception: %(e)s'),
                              {'id': neutron_db['id'], 'e': e})
                    self._cleanup_port(context, neutron_db['id'], None)

            if not utils.is_nsx_version_1_1_0(self._nsx_version):
                try:
                    self.nsxlib.update_lport_with_security_groups(
                        context, lport['id'], [], sgids or [])
                except Exception as e:
                    with excutils.save_and_reraise_exception(reraise=False):
                        LOG.debug("Couldn't associate port %s with "
                                  "one or more security-groups, reverting "
                                  "logical-port creation (%s).",
                                  port_data['id'], lport['id'])
                        self._cleanup_port(
                            context, neutron_db['id'], lport['id'])

                    # NOTE(arosen): this is to translate between nsxlib
                    # exceptions and the plugin exceptions. This should be
                    # later refactored.
                    if (e.__class__ is
                            nsx_lib_exc.SecurityGroupMaximumCapacityReached):
                        raise nsx_exc.SecurityGroupMaximumCapacityReached(
                            err_msg=e.msg)
                    else:
                        raise e
            try:
                net_id = port_data[pbin.VIF_DETAILS]['nsx-logical-switch-id']
                nsx_db.add_neutron_nsx_port_mapping(
                    context.session, neutron_db['id'],
                    net_id, lport['id'])
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.debug('Failed to update mapping %s on NSX '
                              'backend. Reverting port creation. '
                              'Exception: %s', neutron_db['id'], e)
                    self._cleanup_port(context, neutron_db['id'], lport['id'])

        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        port_model = self._get_port(context, port_data['id'])
        self._apply_dict_extend_functions('ports', port_data, port_model)

        # Add Mac/IP binding to native DHCP server and neutron DB.
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            self._add_dhcp_binding(context, port_data)

        if not cfg.CONF.nsx_v3.native_dhcp_metadata:
            nsx_rpc.handle_port_metadata_access(self, context, neutron_db)
        return port_data

    def _pre_delete_port_check(self, context, port_id, l2gw_port_check):
        """Perform checks prior to deleting a port."""
        try:
            kwargs = {
                'context': context,
                'port_check': l2gw_port_check,
                'port_id': port_id,
            }
            # Send delete port notification to any interested service plugin
            registry.notify(
                resources.PORT, events.BEFORE_DELETE, self, **kwargs)
        except callback_exc.CallbackFailure as e:
            if len(e.errors) == 1:
                raise e.errors[0].error
            raise n_exc.ServicePortInUse(port_id=port_id, reason=e)

    def delete_port(self, context, port_id,
                    l3_port_check=True, l2gw_port_check=True):
        # if needed, check to see if this is a port owned by
        # a l2 gateway.  If so, we should prevent deletion here
        self._pre_delete_port_check(context, port_id, l2gw_port_check)
        # if needed, check to see if this is a port owned by
        # a l3 router.  If so, we should prevent deletion here
        if l3_port_check:
            self.prevent_l3_port_deletion(context, port_id)
        port = self.get_port(context, port_id)
        if not self._network_is_external(context, port['network_id']):
            _net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port_id)
            self._port_client.delete(nsx_port_id)
            if not utils.is_nsx_version_1_1_0(self._nsx_version):
                self.nsxlib.update_lport_with_security_groups(
                    context, nsx_port_id,
                    port.get(ext_sg.SECURITYGROUPS, []), [])
        self.disassociate_floatingips(context, port_id)

        # Remove Mac/IP binding from native DHCP server and neutron DB.
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            self._delete_dhcp_binding(context, port)
        else:
            nsx_rpc.handle_port_metadata_access(self, context, port,
                                                is_delete=True)
        super(NsxV3Plugin, self).delete_port(context, port_id)

    def _update_port_preprocess_security(
            self, context, port, id, updated_port):
        delete_addr_pairs = self._check_update_deletes_allowed_address_pairs(
            port)
        has_addr_pairs = self._check_update_has_allowed_address_pairs(port)
        has_security_groups = self._check_update_has_security_groups(port)
        delete_security_groups = self._check_update_deletes_security_groups(
            port)

        # populate port_security setting
        if psec.PORTSECURITY not in port['port']:
            updated_port[psec.PORTSECURITY] = \
                self._get_port_security_binding(context, id)
        has_ip = self._ip_on_port(updated_port)
        # validate port security and allowed address pairs
        if not updated_port[psec.PORTSECURITY]:
            #  has address pairs in request
            if has_addr_pairs:
                raise addr_pair.AddressPairAndPortSecurityRequired()
            elif not delete_addr_pairs:
                # check if address pairs are in db
                updated_port[addr_pair.ADDRESS_PAIRS] = (
                    self.get_allowed_address_pairs(context, id))
                if updated_port[addr_pair.ADDRESS_PAIRS]:
                    raise addr_pair.AddressPairAndPortSecurityRequired()

        if delete_addr_pairs or has_addr_pairs:
            self._validate_address_pairs(
                updated_port[addr_pair.ADDRESS_PAIRS])
            # delete address pairs and read them in
            self._delete_allowed_address_pairs(context, id)
            self._process_create_allowed_address_pairs(
                context, updated_port,
                updated_port[addr_pair.ADDRESS_PAIRS])

        # checks if security groups were updated adding/modifying
        # security groups, port security is set and port has ip
        if not (has_ip and updated_port[psec.PORTSECURITY]):
            if has_security_groups:
                raise psec.PortSecurityAndIPRequiredForSecurityGroups()
            # Update did not have security groups passed in. Check
            # that port does not have any security groups already on it.
            filters = {'port_id': [id]}
            security_groups = (
                super(NsxV3Plugin, self)._get_port_security_group_bindings(
                    context, filters)
            )
            if security_groups and not delete_security_groups:
                raise psec.PortSecurityPortHasSecurityGroup()

        if delete_security_groups or has_security_groups:
            # delete the port binding and read it with the new rules.
            self._delete_port_security_group_bindings(context, id)
            sgids = self._get_security_groups_on_port(context, port)
            self._process_port_create_security_group(context, updated_port,
                                                     sgids)

        if psec.PORTSECURITY in port['port']:
            self._process_port_port_security_update(
                context, port['port'], updated_port)

        return updated_port

    def _get_resource_type_for_device_id(self, device_owner, device_id):
        if device_owner in const.ROUTER_INTERFACE_OWNERS:
            return 'os-router-uuid'
        elif device_owner.startswith(const.DEVICE_OWNER_COMPUTE_PREFIX):
            return 'os-instance-uuid'

    def _update_port_on_backend(self, context, lport_id,
                                original_port, updated_port,
                                address_bindings,
                                switch_profile_ids):
        original_device_owner = original_port.get('device_owner')
        original_device_id = original_port.get('device_id')
        updated_device_owner = updated_port.get('device_owner')
        updated_device_id = updated_port.get('device_id')
        tags_update = []
        if original_device_id != updated_device_id:
            # Determine if we need to update or drop the tag. If the
            # updated_device_id exists then the tag will be updated. This
            # is done using the updated port. If the updated_device_id does
            # not exist then we need to get the original resource type
            # from original_device_owner. This enables us to drop the tag.
            if updated_device_id:
                resource_type = self._get_resource_type_for_device_id(
                    updated_device_owner, updated_device_id)
            else:
                resource_type = self._get_resource_type_for_device_id(
                    original_device_owner, updated_device_id)
            if resource_type:
                tags_update = utils.add_v3_tag(tags_update, resource_type,
                                               updated_device_id)

        parent_vif_id, tag = self._get_data_from_binding_profile(
            context, updated_port)

        if updated_device_owner in (original_device_owner,
                                    l3_db.DEVICE_OWNER_ROUTER_INTF,
                                    nsx_constants.BRIDGE_ENDPOINT):
            # no attachment change
            attachment_type = False
            vif_uuid = False
        elif updated_device_owner:
            # default attachment
            attachment_type = nsx_constants.ATTACHMENT_VIF
            vif_uuid = updated_port['id']
        else:
            # no attachment
            attachment_type = None
            vif_uuid = None

        name = self._get_port_name(context, updated_port)

        updated_ps = updated_port.get('port_security_enabled')
        if not updated_ps:
            tags_update.append({'scope': security.PORT_SG_SCOPE,
                                'tag': firewall.EXCLUDE_PORT})

        if utils.is_nsx_version_1_1_0(self._nsx_version):
            tags_update += self.nsxlib.get_lport_tags_for_security_groups(
                updated_port.get(ext_sg.SECURITYGROUPS, []) +
                updated_port.get(provider_sg.PROVIDER_SECURITYGROUPS, []))
        else:
            self.nsxlib.update_lport_with_security_groups(
                context, lport_id,
                original_port.get(ext_sg.SECURITYGROUPS, []) +
                original_port.get(provider_sg.PROVIDER_SECURITYGROUPS, []),
                updated_port.get(ext_sg.SECURITYGROUPS, []) +
                updated_port.get(provider_sg.PROVIDER_SECURITYGROUPS, []))

        # Update the DHCP profile
        if updated_device_owner == const.DEVICE_OWNER_DHCP:
            switch_profile_ids.append(self._dhcp_profile)

        # Update QoS switch profile
        orig_compute = original_device_owner.startswith(
            const.DEVICE_OWNER_COMPUTE_PREFIX)
        updated_compute = updated_device_owner.startswith(
            const.DEVICE_OWNER_COMPUTE_PREFIX)
        is_new_compute = updated_compute and not orig_compute
        qos_policy_id, qos_profile_id = self._get_port_qos_ids(context,
                                                               updated_port,
                                                               is_new_compute)
        if qos_profile_id is not None:
            switch_profile_ids.append(qos_profile_id)

        address_pairs = updated_port.get(addr_pair.ADDRESS_PAIRS)
        mac_learning_profile_set = (
            validators.is_attr_set(address_pairs) and address_pairs and
            self._get_port_security_profile_id() in switch_profile_ids)
        # Add mac_learning profile if it exists and is configured
        if (self._mac_learning_profile and
            (mac_learning_profile_set or
             updated_port.get(mac_ext.MAC_LEARNING) is True)):
            switch_profile_ids.append(self._mac_learning_profile)

        try:
            self._port_client.update(
                lport_id, vif_uuid, name=name,
                attachment_type=attachment_type,
                admin_state=updated_port.get('admin_state_up'),
                address_bindings=address_bindings,
                switch_profile_ids=switch_profile_ids,
                tags_update=tags_update,
                parent_vif_id=parent_vif_id,
                parent_tag=tag)
        except nsx_lib_exc.ManagerError as inst:
            # we may fail if the QoS is not supported for this port
            # (for example - transport zone with KVM)
            LOG.exception(_LE("Unable to update port on the backend: %s"),
                          inst)
            msg = _("Unable to update port on the backend")
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # Attach/Detach the QoS policies to the port in the neutron DB
        qos_com_utils.update_port_policy_binding(context,
                                                 updated_port['id'],
                                                 qos_policy_id)

    def _get_port_qos_ids(self, context, updated_port, is_new_compute):
        # when a port is updated, get the current QoS policy/profile ids
        policy_id = None
        profile_id = None
        if (qos_consts.QOS_POLICY_ID in updated_port):
            policy_id = updated_port[qos_consts.QOS_POLICY_ID]
        else:
            # Look for the previous QoS policy
            policy_id = qos_com_utils.get_port_policy_id(
                context, updated_port['id'])
        # If the port is now a 'compute' port (attached to a vm) and
        # Qos policy was not configured on the port directly,
        # try to take it from the ports network
        if policy_id is None and is_new_compute:
            # check if the network of this port has a policy
            policy_id = qos_com_utils.get_network_policy_id(
                context, updated_port.get('network_id'))

        if policy_id is not None:
            profile_id = self._get_qos_profile_id(context, policy_id)

        return policy_id, profile_id

    def update_port(self, context, id, port):
        switch_profile_ids = None

        with context.session.begin(subtransactions=True):
            original_port = super(NsxV3Plugin, self).get_port(context, id)
            nsx_lswitch_id, nsx_lport_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, id)
            is_external_net = self._network_is_external(
                context, original_port['network_id'])
            if is_external_net:
                self._assert_on_external_net_with_compute(port['port'])
                self._assert_on_external_net_port_with_qos(port['port'])

            device_owner = (port['port']['device_owner']
                            if 'device_owner' in port['port']
                            else original_port.get('device_owner'))
            self._assert_on_router_port_with_qos(
                port['port'], device_owner)

            updated_port = super(NsxV3Plugin, self).update_port(context,
                                                                id, port)

            # copy values over - except fixed_ips as
            # they've already been processed
            port['port'].pop('fixed_ips', None)
            updated_port.update(port['port'])
            self._update_extra_dhcp_opts_on_port(
                context, id, port, updated_port)

            updated_port = self._update_port_preprocess_security(
                context, port, id, updated_port)

            self._update_extra_dhcp_opts_on_port(context, id, port,
                                                 updated_port)
            sec_grp_updated = self.update_security_group_on_port(
                context, id, port, original_port, updated_port)

            self._process_port_update_provider_security_group(
                context, port, original_port, updated_port)

            (port_security, has_ip) = self._determine_port_security_and_has_ip(
                context, updated_port)
            self._process_portbindings_create_and_update(
                context, port['port'], updated_port)
            self._extend_port_dict_binding(context, updated_port)
            mac_learning_state = updated_port.get(mac_ext.MAC_LEARNING)
            if mac_learning_state is not None:
                if port_security and mac_learning_state:
                    msg = _('Mac learning requires that port security be '
                            'disabled')
                    raise n_exc.InvalidInput(error_message=msg)
                self._update_mac_learning_state(context, id,
                                                mac_learning_state)

        address_bindings = self._build_address_bindings(updated_port)
        if port_security and address_bindings:
            switch_profile_ids = [self._get_port_security_profile_id()]
        else:
            switch_profile_ids = [self._no_psec_profile_id]
            address_bindings = []

        # update the port in the backend, only if it exists in the DB
        # (i.e not external net)
        if nsx_lport_id is not None:
            try:
                self._update_port_on_backend(context, nsx_lport_id,
                                             original_port, updated_port,
                                             address_bindings,
                                             switch_profile_ids)
            except (nsx_lib_exc.ManagerError,
                    nsx_lib_exc.SecurityGroupMaximumCapacityReached) as e:
                # In case if there is a failure on NSX-v3 backend, rollback the
                # previous update operation on neutron side.
                LOG.exception(_LE("Unable to update NSX backend, rolling back "
                                  "changes on neutron"))
                with excutils.save_and_reraise_exception(reraise=False):
                    with context.session.begin(subtransactions=True):
                        super(NsxV3Plugin, self).update_port(
                            context, id, {'port': original_port})

                        # revert allowed address pairs
                        if port_security:
                            orig_pair = original_port.get(
                                addr_pair.ADDRESS_PAIRS)
                            updated_pair = updated_port.get(
                                addr_pair.ADDRESS_PAIRS)
                            if orig_pair != updated_pair:
                                self._delete_allowed_address_pairs(context, id)
                            if orig_pair:
                                self._process_create_allowed_address_pairs(
                                    context, original_port, orig_pair)

                        if sec_grp_updated:
                            self.update_security_group_on_port(
                                context, id, {'port': original_port},
                                updated_port, original_port)
                    # NOTE(arosen): this is to translate between nsxlib
                    # exceptions and the plugin exceptions. This should be
                    # later refactored.
                    if (e.__class__ is
                            nsx_lib_exc.SecurityGroupMaximumCapacityReached):
                        raise nsx_exc.SecurityGroupMaximumCapacityReached(
                            err_msg=e.msg)
                    else:
                        raise e

        # Update DHCP bindings.
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            self._update_dhcp_binding(context, original_port, updated_port)

        return updated_port

    def _extend_get_port_dict_binding(self, context, port):
        self._extend_port_dict_binding(context, port)

        # add the qos policy id from the DB
        if 'id' in port:
            port[qos_consts.QOS_POLICY_ID] = qos_com_utils.get_port_policy_id(
                context, port['id'])

    def get_port(self, context, id, fields=None):
        port = super(NsxV3Plugin, self).get_port(context, id, fields=None)
        self._extend_get_port_dict_binding(context, port)

        return self._fields(port, fields)

    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        filters = filters or {}
        with context.session.begin(subtransactions=True):
            ports = (
                super(NsxV3Plugin, self).get_ports(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            # Add port extensions
            for port in ports:
                self._extend_get_port_dict_binding(context, port)
        return (ports if not fields else
                [self._fields(port, fields) for port in ports])

    def _extract_external_gw(self, context, router, is_extract=True):
        r = router['router']
        gw_info = const.ATTR_NOT_SPECIFIED
        # First extract the gateway info in case of updating
        # gateway before edge is deployed.
        if 'external_gateway_info' in r:
            gw_info = r.get('external_gateway_info', {})
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
        return gw_info

    def _get_external_attachment_info(self, context, router):
        gw_port = router.gw_port
        ipaddress = None
        netmask = None
        nexthop = None

        if gw_port:
            # gw_port may have multiple IPs, only configure the first one
            if gw_port.get('fixed_ips'):
                ipaddress = gw_port['fixed_ips'][0]['ip_address']

            network_id = gw_port.get('network_id')
            if network_id:
                ext_net = self._get_network(context, network_id)
                if not ext_net.external:
                    msg = (_("Network '%s' is not a valid external "
                             "network") % network_id)
                    raise n_exc.BadRequest(resource='router', msg=msg)
                if ext_net.subnets:
                    ext_subnet = ext_net.subnets[0]
                    netmask = str(netaddr.IPNetwork(ext_subnet.cidr).netmask)
                    nexthop = ext_subnet.gateway_ip

        return (ipaddress, netmask, nexthop)

    def _get_tier0_uuid_by_net(self, context, network_id):
        if not network_id:
            return
        network = self.get_network(context, network_id)
        if not network.get(pnet.PHYSICAL_NETWORK):
            return self._default_tier0_router
        else:
            return network.get(pnet.PHYSICAL_NETWORK)

    def _update_router_gw_info(self, context, router_id, info):
        router = self._get_router(context, router_id)
        org_ext_net_id = router.gw_port_id and router.gw_port.network_id
        org_tier0_uuid = self._get_tier0_uuid_by_net(context, org_ext_net_id)
        org_enable_snat = router.enable_snat
        new_ext_net_id = info and info.get('network_id')
        orgaddr, orgmask, _orgnexthop = (
            self._get_external_attachment_info(
                context, router))

        # TODO(berlin): For nonat use case, we actually don't need a gw port
        # which consumes one external ip. But after looking at the DB logic
        # and we need to make a big change so don't touch it at present.
        super(NsxV3Plugin, self)._update_router_gw_info(
            context, router_id, info, router=router)

        new_ext_net_id = router.gw_port_id and router.gw_port.network_id
        new_tier0_uuid = self._get_tier0_uuid_by_net(context, new_ext_net_id)
        new_enable_snat = router.enable_snat
        newaddr, newmask, _newnexthop = (
            self._get_external_attachment_info(
                context, router))
        nsx_router_id = nsx_db.get_nsx_router_id(context.session, router_id)

        # Remove router link port between tier1 and tier0 if tier0 router link
        # is removed or changed
        remove_router_link_port = (org_tier0_uuid and
                                   (not new_tier0_uuid or
                                    org_tier0_uuid != new_tier0_uuid))

        # Remove SNAT rules for gw ip if gw ip is deleted/changed or
        # enable_snat is updated from True to False
        remove_snat_rules = (org_enable_snat and orgaddr and
                             (newaddr != orgaddr or
                              not new_enable_snat))

        # Revocate bgp announce for nonat subnets if tier0 router link is
        # changed or enable_snat is updated from False to True
        revocate_bgp_announce = (not org_enable_snat and org_tier0_uuid and
                                 (new_tier0_uuid != org_tier0_uuid or
                                  new_enable_snat))

        # Add router link port between tier1 and tier0 if tier0 router link is
        # added or changed to a new one
        add_router_link_port = (new_tier0_uuid and
                                (not org_tier0_uuid or
                                 org_tier0_uuid != new_tier0_uuid))

        # Add SNAT rules for gw ip if gw ip is add/changed or
        # enable_snat is updated from False to True
        add_snat_rules = (new_enable_snat and newaddr and
                          (newaddr != orgaddr or
                           not org_enable_snat))

        # Bgp announce for nonat subnets if tier0 router link is changed or
        # enable_snat is updated from True to False
        bgp_announce = (not new_enable_snat and new_tier0_uuid and
                        (new_tier0_uuid != org_tier0_uuid or
                         not org_enable_snat))

        # Advertise NAT routes if enable SNAT to support FIP. In the NoNAT
        # use case, only NSX connected routes need to be advertised.
        advertise_route_nat_flag = True if new_enable_snat else False
        advertise_route_connected_flag = True if not new_enable_snat else False

        if revocate_bgp_announce:
            # TODO(berlin): revocate bgp announce on org tier0 router
            pass
        if remove_snat_rules:
            self._routerlib.delete_gw_snat_rule(nsx_router_id, orgaddr)
        if remove_router_link_port:
            self._routerlib.remove_router_link_port(
                nsx_router_id, org_tier0_uuid)
        if add_router_link_port:
            # First update edge cluster info for router
            edge_cluster_uuid = self._get_edge_cluster(new_tier0_uuid)
            self._routerlib.update_router_edge_cluster(
                nsx_router_id, edge_cluster_uuid)
            tags = utils.build_v3_tags_payload(
                   router, resource_type='os-neutron-rport',
                   project_name=context.tenant_name)
            self._routerlib.add_router_link_port(nsx_router_id, new_tier0_uuid,
                                                 tags=tags)
        if add_snat_rules:
            self._routerlib.add_gw_snat_rule(nsx_router_id, newaddr)
        if bgp_announce:
            # TODO(berlin): bgp announce on new tier0 router
            pass

        self._routerlib.update_advertisement(nsx_router_id,
                                       advertise_route_nat_flag,
                                       advertise_route_connected_flag)

    def create_router(self, context, router):
        # TODO(berlin): admin_state_up support
        gw_info = self._extract_external_gw(context, router, is_extract=True)
        router['router']['id'] = (router['router'].get('id') or
                                  uuidutils.generate_uuid())
        tags = utils.build_v3_tags_payload(
            router['router'], resource_type='os-neutron-router-id',
            project_name=context.tenant_name)

        with context.session.begin():
            router = super(NsxV3Plugin, self).create_router(
                context, router)

        # Create backend entries here in case neutron DB exception
        # occurred during super.create_router(), which will cause
        # API retry and leaves dangling backend entries.
        try:
            result = self._router_client.create(
                display_name=utils.get_name_and_uuid(
                    router['name'] or 'router', router['id']), tags=tags)
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to create logical router for "
                              "neutron router %s"), router['id'])
                self.delete_router(context, router['id'])

        try:
            nsx_db.add_neutron_nsx_router_mapping(
                context.session, router['id'], result['id'])
        except db_exc.DBError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to create router mapping for "
                              "router %s"), router['id'])
                self.delete_router(context, router['id'])

        if gw_info != const.ATTR_NOT_SPECIFIED:
            try:
                self._update_router_gw_info(context, router['id'], gw_info)
            except (db_exc.DBError, nsx_lib_exc.ManagerError):
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Failed to set gateway info for router "
                                  "being created: %s - removing router"),
                              router['id'])
                    self.delete_router(context, router['id'])
                    LOG.info(_LI("Create router failed while setting external "
                                 "gateway. Router:%s has been removed from "
                                 "DB and backend"),
                             router['id'])

        return self.get_router(context, router['id'])

    def delete_router(self, context, router_id):
        if not cfg.CONF.nsx_v3.native_dhcp_metadata:
            nsx_rpc.handle_router_metadata_access(self, context, router_id,
                                                  interface=None)
        router = self.get_router(context, router_id)
        if router.get(l3.EXTERNAL_GW_INFO):
            self._update_router_gw_info(context, router_id, {})
        nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                 router_id)
        ret_val = super(NsxV3Plugin, self).delete_router(context,
                                                         router_id)
        # Remove logical router from the NSX backend
        # It is safe to do now as db-level checks for resource deletion were
        # passed (and indeed the resource was removed from the Neutron DB
        try:
            self._router_client.delete(nsx_router_id)
        except nsx_lib_exc.ResourceNotFound:
            # If the logical router was not found on the backend do not worry
            # about it. The conditions has already been logged, so there is no
            # need to do further logging
            pass
        except nsx_lib_exc.ManagerError:
            # if there is a failure in deleting the router do not fail the
            # operation, especially since the router object has already been
            # removed from the neutron DB. Take corrective steps to ensure the
            # resulting zombie object does not forward any traffic and is
            # eventually removed.
            LOG.warning(_LW("Backend router deletion for neutron router %s "
                            "failed. The object was however removed from the "
                            "Neutron database"), router_id)

        return ret_val

    def _validate_ext_routes(self, context, router_id, gw_info, new_routes):
        ext_net_id = (gw_info['network_id']
                      if validators.is_attr_set(gw_info) and gw_info else None)
        if not ext_net_id:
            port_filters = {'device_id': [router_id],
                            'device_owner': [l3_db.DEVICE_OWNER_ROUTER_GW]}
            gw_ports = self.get_ports(context, filters=port_filters)
            if gw_ports:
                ext_net_id = gw_ports[0]['network_id']
        if ext_net_id:
            subnets = self._get_subnets_by_network(context, ext_net_id)
            ext_cidrs = [subnet['cidr'] for subnet in subnets]
            for route in new_routes:
                if netaddr.all_matching_cidrs(
                    route['nexthop'], ext_cidrs):
                    error_message = (_("route with destination %(dest)s have "
                                       "an external nexthop %(nexthop)s which "
                                       "can't be supported") %
                                     {'dest': route['destination'],
                                      'nexthop': route['nexthop']})
                    raise n_exc.InvalidInput(error_message=error_message)

    def _update_router_wrapper(self, context, router_id, router):
        if cfg.CONF.api_replay_mode:
            # Only import mock if the reply mode is used
            import mock
            # NOTE(arosen): the mock.patch here is needed for api_replay_mode
            with mock.patch("neutron.plugins.common.utils._fixup_res_dict",
                            side_effect=api_replay_utils._fixup_res_dict):
                return super(NsxV3Plugin, self).update_router(
                    context, router_id, router)
        else:
            return super(NsxV3Plugin, self).update_router(
                context, router_id, router)

    def update_router(self, context, router_id, router):
        # TODO(berlin): admin_state_up support
        gw_info = self._extract_external_gw(context, router, is_extract=False)
        router_data = router['router']
        nsx_router_id = None
        routes_added = []
        routes_removed = []
        try:
            if 'routes' in router_data:
                new_routes = router_data['routes']
                self._validate_ext_routes(context, router_id, gw_info,
                                          new_routes)
                self._validate_routes(context, router_id, new_routes)
                old_routes, routes_dict = (
                    self._get_extra_routes_dict_by_router_id(
                        context, router_id))
                routes_added, routes_removed = neutron_utils.diff_list_of_dict(
                    old_routes, new_routes)
                nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                         router_id)
                for route in routes_removed:
                    self._routerlib.delete_static_routes(nsx_router_id, route)
                for route in routes_added:
                    self._routerlib.add_static_routes(nsx_router_id, route)
            if 'name' in router_data:
                # Update the name of logical router.
                router_name = router_data['name'] or 'router'
                display_name = utils.get_name_and_uuid(router_name, router_id)
                nsx_router_id = nsx_router_id or nsx_db.get_nsx_router_id(
                    context.session, router_id)
                self._router_client.update(nsx_router_id,
                                           display_name=display_name)
                # Update the name of associated logical ports.
                filters = {'device_id': [router_id],
                           'device_owner': const.ROUTER_INTERFACE_OWNERS}
                ports = self.get_ports(context, filters=filters)
                for port in ports:
                    nsx_s_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                        context.session, port['id'])
                    if nsx_port_id:
                        name = utils.get_name_and_uuid(
                            router_name, port['id'], tag='port')
                        try:
                            self._port_client.update(nsx_port_id, None,
                                                     name=name)
                        except Exception as e:
                            LOG.error(_LE("Unable to update port %(port_id)s. "
                                          "Reason: %(e)s"),
                                      {'port_id': nsx_port_id,
                                       'e': e})
            return self._update_router_wrapper(context, router_id, router)
        except nsx_lib_exc.ResourceNotFound:
            with context.session.begin(subtransactions=True):
                router_db = self._get_router(context, router_id)
                router_db['status'] = const.NET_STATUS_ERROR
            raise nsx_exc.NsxPluginException(
                err_msg=(_("logical router %s not found at the backend")
                         % router_id))
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                router_db = self._get_router(context, router_id)
                curr_status = router_db['status']
                router_db['status'] = const.NET_STATUS_ERROR
                if nsx_router_id:
                    for route in routes_added:
                        self._routerlib.delete_static_routes(
                            nsx_router_id, route)
                    for route in routes_removed:
                        self._routerlib.add_static_routes(nsx_router_id, route)
                router_db['status'] = curr_status

    def _get_router_interface_ports_by_network(
        self, context, router_id, network_id):
        port_filters = {'device_id': [router_id],
                        'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                        'network_id': [network_id]}
        return self.get_ports(context, filters=port_filters)

    def _get_ports_and_address_groups(self, context, router_id, network_id,
                                      exclude_sub_ids=None):
        exclude_sub_ids = [] if not exclude_sub_ids else exclude_sub_ids
        address_groups = []
        ports = self._get_router_interface_ports_by_network(
            context, router_id, network_id)
        ports = [port for port in ports
                 if port['fixed_ips'] and
                 port['fixed_ips'][0]['subnet_id'] not in exclude_sub_ids]
        for port in ports:
            address_group = {}
            gateway_ip = port['fixed_ips'][0]['ip_address']
            subnet = self.get_subnet(context,
                                     port['fixed_ips'][0]['subnet_id'])
            prefixlen = str(netaddr.IPNetwork(subnet['cidr']).prefixlen)
            address_group['ip_addresses'] = [gateway_ip]
            address_group['prefix_length'] = prefixlen
            address_groups.append(address_group)
        return (ports, address_groups)

    def _get_interface_network(self, context, interface_info):
        is_port, is_sub = self._validate_interface_info(interface_info)
        if is_port:
            net_id = self.get_port(context,
                                   interface_info['port_id'])['network_id']
        elif is_sub:
            net_id = self.get_subnet(context,
                                     interface_info['subnet_id'])['network_id']
        return net_id

    def _validate_multiple_subnets_routers(self, context, router_id, net_id):
        network = self.get_network(context, net_id)
        net_type = network.get(pnet.NETWORK_TYPE)
        if (net_type and net_type != utils.NsxV3NetworkTypes.VXLAN):
            err_msg = (_("Only overlay networks can be attached to a logical "
                         "router. Network %(net_id)s is a %(net_type)s based "
                         "network") % {'net_id': net_id, 'net_type': net_type})
            raise n_exc.InvalidInput(error_message=err_msg)

        port_filters = {'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                        'network_id': [net_id]}
        intf_ports = self.get_ports(context.elevated(), filters=port_filters)
        router_ids = [port['device_id']
                      for port in intf_ports if port['device_id']]
        if len(router_ids) > 0:
            err_msg = _("Only one subnet of network %(net_id)s can be "
                        "attached to router, one subnet is already attached "
                        "to router %(router_id)s") % {
                'net_id': net_id,
                'router_id': router_ids[0]}
            LOG.error(err_msg)
            if router_id in router_ids:
                # attach to the same router again
                raise n_exc.InvalidInput(error_message=err_msg)
            else:
                # attach to multiple routers
                raise l3.RouterInterfaceAttachmentConflict(reason=err_msg)

    def _add_router_interface_wrapper(self, context, router_id,
                                      interface_info):
        if cfg.CONF.api_replay_mode:
            # Only import mock if the reply mode is used
            import mock
            # NOTE(arosen): the mock.patch here is needed for api_replay_mode
            with mock.patch("neutron.plugins.common.utils._fixup_res_dict",
                            side_effect=api_replay_utils._fixup_res_dict):
                return super(NsxV3Plugin, self).add_router_interface(
                    context, router_id, interface_info)
        else:
            return super(NsxV3Plugin, self).add_router_interface(
                 context, router_id, interface_info)

    def add_router_interface(self, context, router_id, interface_info):
        net_id = self._get_interface_network(context, interface_info)
        with locking.LockManager.get_lock(str(net_id)):
            # disallow more than one subnets belong to same network being
            # attached to routers
            self._validate_multiple_subnets_routers(context, router_id, net_id)
            info = self._add_router_interface_wrapper(context, router_id,
                                                      interface_info)
        try:
            subnet = self.get_subnet(context, info['subnet_ids'][0])
            port = self.get_port(context, info['port_id'])
            network_id = subnet['network_id']
            nsx_net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port['id'])

            nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                     router_id)
            _ports, address_groups = self._get_ports_and_address_groups(
                context, router_id, network_id)
            display_name = utils.get_name_and_uuid(
                subnet['name'] or 'subnet', subnet['id'])
            tags = utils.build_v3_tags_payload(
                port, resource_type='os-neutron-rport-id',
                project_name=context.tenant_name)
            tags.append({'scope': 'os-subnet-id', 'tag': subnet['id']})
            self._routerlib.create_logical_router_intf_port_by_ls_id(
                logical_router_id=nsx_router_id,
                display_name=display_name,
                tags=tags,
                ls_id=nsx_net_id,
                logical_switch_port_id=nsx_port_id,
                address_groups=address_groups)

            router_db = self._get_router(context, router_id)
            if router_db.gw_port and not router_db.enable_snat:
                # TODO(berlin): Announce the subnet on tier0 if enable_snat
                # is False
                pass
            if not cfg.CONF.nsx_v3.native_dhcp_metadata:
                # Ensure the NSX logical router has a connection to a
                # 'metadata access' network (with a proxy listening on
                # its DHCP port), by creating it if needed.
                nsx_rpc.handle_router_metadata_access(self, context, router_id,
                                                      interface=info)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Neutron failed to add_router_interface on "
                              "router %s, and would try to rollback."),
                          router_id)
                self.remove_router_interface(
                    context, router_id, interface_info)
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        subnet = None
        subnet_id = None
        port_id = None
        self._validate_interface_info(interface_info, for_removal=True)
        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
            # find subnet_id - it is need for removing the SNAT rule
            port = self._get_port(context, port_id)
            if port.get('fixed_ips'):
                subnet_id = port['fixed_ips'][0]['subnet_id']
                self._confirm_router_interface_not_in_use(
                    context, router_id, subnet_id)
            if not (port['device_owner'] in const.ROUTER_INTERFACE_OWNERS
                    and port['device_id'] == router_id):
                raise l3.RouterInterfaceNotFound(router_id=router_id,
                                                 port_id=port_id)
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            self._confirm_router_interface_not_in_use(
                context, router_id, subnet_id)
            subnet = self._get_subnet(context, subnet_id)
            rport_qry = context.session.query(models_v2.Port)
            ports = rport_qry.filter_by(
                device_id=router_id,
                device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF,
                network_id=subnet['network_id'])
            for p in ports:
                if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                    port_id = p['id']
                    break
            else:
                raise l3.RouterInterfaceNotFoundForSubnet(router_id=router_id,
                                                          subnet_id=subnet_id)
        try:
            # TODO(berlin): Revocate announce the subnet on tier0 if
            # enable_snat is False
            router_db = self._get_router(context, router_id)
            if router_db.gw_port and not router_db.enable_snat:
                pass

            nsx_net_id, _nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port_id)
            subnet = self.get_subnet(context, subnet_id)
            ports, address_groups = self._get_ports_and_address_groups(
                context, router_id, subnet['network_id'],
                exclude_sub_ids=[subnet['id']])
            nsx_router_id = nsx_db.get_nsx_router_id(
                context.session, router_id)
            if len(ports) >= 1:
                new_using_port_id = ports[0]['id']
                _net_id, new_nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                    context.session, new_using_port_id)
                self._router_port_client.update_by_lswitch_id(
                    nsx_router_id, nsx_net_id,
                    linked_logical_switch_port_id={
                        'target_id': new_nsx_port_id},
                    subnets=address_groups)
            else:
                self._router_port_client.delete_by_lswitch_id(nsx_net_id)
        except nsx_lib_exc.ResourceNotFound:
            LOG.error(_LE("router port on router %(router_id)s for net "
                          "%(net_id)s not found at the backend"),
                      {'router_id': router_id,
                       'net_id': subnet['network_id']})
        info = super(NsxV3Plugin, self).remove_router_interface(
            context, router_id, interface_info)
        if not cfg.CONF.nsx_v3.native_dhcp_metadata:
            # Ensure the connection to the 'metadata access network' is removed
            # (with the network) if this is the last DHCP-disabled subnet on
            # the router.
            nsx_rpc.handle_router_metadata_access(self, context, router_id)
        return info

    def _create_floating_ip_wrapper(self, context, floatingip):
        if cfg.CONF.api_replay_mode:
            # Only import mock if the reply mode is used
            import mock
            # NOTE(arosen): the mock.patch here is needed for api_replay_mode
            with mock.patch("neutron.plugins.common.utils._fixup_res_dict",
                            side_effect=api_replay_utils._fixup_res_dict):
                return super(NsxV3Plugin, self).create_floatingip(
                    context, floatingip, initial_status=(
                        const.FLOATINGIP_STATUS_ACTIVE
                        if floatingip['floatingip']['port_id']
                        else const.FLOATINGIP_STATUS_DOWN))
        else:
            return super(NsxV3Plugin, self).create_floatingip(
                context, floatingip, initial_status=(
                    const.FLOATINGIP_STATUS_ACTIVE
                    if floatingip['floatingip']['port_id']
                    else const.FLOATINGIP_STATUS_DOWN))

    def create_floatingip(self, context, floatingip):
        new_fip = self._create_floating_ip_wrapper(context, floatingip)
        router_id = new_fip['router_id']
        if not router_id:
            return new_fip
        try:
            nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                     router_id)
            self._routerlib.add_fip_nat_rules(
                nsx_router_id, new_fip['floating_ip_address'],
                new_fip['fixed_ip_address'])
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                self.delete_floatingip(context, new_fip['id'])
        return new_fip

    def delete_floatingip(self, context, fip_id):
        fip = self.get_floatingip(context, fip_id)
        router_id = fip['router_id']
        if router_id:
            try:
                nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                         router_id)
                self._routerlib.delete_fip_nat_rules(
                    nsx_router_id, fip['floating_ip_address'],
                    fip['fixed_ip_address'])
            except nsx_lib_exc.ResourceNotFound:
                LOG.warning(_LW("Backend NAT rules for fip: %(fip_id)s "
                                "(ext_ip: %(ext_ip)s int_ip: %(int_ip)s) "
                                "not found"),
                            {'fip_id': fip_id,
                             'ext_ip': fip['floating_ip_address'],
                             'int_ip': fip['fixed_ip_address']})
        super(NsxV3Plugin, self).delete_floatingip(context, fip_id)

    def update_floatingip(self, context, fip_id, floatingip):
        old_fip = self.get_floatingip(context, fip_id)
        old_port_id = old_fip['port_id']
        new_status = (const.FLOATINGIP_STATUS_ACTIVE
                      if floatingip['floatingip']['port_id']
                      else const.FLOATINGIP_STATUS_DOWN)
        new_fip = super(NsxV3Plugin, self).update_floatingip(
            context, fip_id, floatingip)
        router_id = new_fip['router_id']
        try:
            # Delete old router's fip rules if old_router_id is not None.
            if old_fip['router_id']:

                try:
                    old_nsx_router_id = nsx_db.get_nsx_router_id(
                        context.session, old_fip['router_id'])
                    self._routerlib.delete_fip_nat_rules(
                        old_nsx_router_id, old_fip['floating_ip_address'],
                        old_fip['fixed_ip_address'])
                except nsx_lib_exc.ResourceNotFound:
                    LOG.warning(_LW("Backend NAT rules for fip: %(fip_id)s "
                                    "(ext_ip: %(ext_ip)s int_ip: %(int_ip)s) "
                                    "not found"),
                                {'fip_id': old_fip['id'],
                                 'ext_ip': old_fip['floating_ip_address'],
                                 'int_ip': old_fip['fixed_ip_address']})

            # TODO(berlin): Associating same FIP to different internal IPs
            # would lead to creating multiple times of FIP nat rules at the
            # backend. Let's see how to fix the problem latter.

            # Update current router's nat rules if router_id is not None.
            if router_id:
                nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                         router_id)
                self._routerlib.add_fip_nat_rules(
                    nsx_router_id, new_fip['floating_ip_address'],
                    new_fip['fixed_ip_address'])
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                super(NsxV3Plugin, self).update_floatingip(
                    context, fip_id, {'floatingip': {'port_id': old_port_id}})
                self.update_floatingip_status(context, fip_id,
                                              const.FLOATINGIP_STATUS_ERROR)
        if new_fip['status'] != new_status:
            new_fip['status'] = new_status
            self.update_floatingip_status(context, fip_id, new_status)
        return new_fip

    def disassociate_floatingips(self, context, port_id):
        fip_qry = context.session.query(l3_db.FloatingIP)
        fip_dbs = fip_qry.filter_by(fixed_port_id=port_id)

        for fip_db in fip_dbs:
            if not fip_db.router_id:
                continue
            try:
                nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                         fip_db.router_id)
                self._routerlib.delete_fip_nat_rules(
                    nsx_router_id, fip_db.floating_ip_address,
                    fip_db.fixed_ip_address)
            except nsx_lib_exc.ResourceNotFound:
                LOG.warning(_LW("Backend NAT rules for fip: %(fip_id)s "
                                "(ext_ip: %(ext_ip)s int_ip: %(int_ip)s) "
                                "not found"),
                            {'fip_id': fip_db.id,
                             'ext_ip': fip_db.floating_ip_address,
                             'int_ip': fip_db.fixed_ip_address})
            self.update_floatingip_status(context, fip_db.id,
                                          const.FLOATINGIP_STATUS_DOWN)

        super(NsxV3Plugin, self).disassociate_floatingips(
            context, port_id, do_notify=False)

    def _ensure_default_security_group(self, context, tenant_id):
        # NOTE(arosen): if in replay mode we'll create all the default
        # security groups for the user with their data so we don't
        # want this to be called.
        if (cfg.CONF.api_replay_mode is False):
            return super(NsxV3Plugin, self)._ensure_default_security_group(
                context, tenant_id)

    def get_security_groups(self, context, filters=None, fields=None,
                            sorts=None, limit=None,
                            marker=None, page_reverse=False, default_sg=False):
        return super(NsxV3Plugin, self).get_security_groups(
                context, filters=filters, fields=fields,
                sorts=sorts, limit=limit,
                marker=marker, page_reverse=page_reverse,
                default_sg=default_sg)

    def _create_fw_section_for_secgroup(self, nsgroup, is_provider):
        # NOTE(arosen): if a security group is provider we want to
        # insert our rules at the top.
        operation = (firewall.INSERT_TOP
                     if is_provider
                     else firewall.INSERT_BEFORE)

        # security-group rules are located in a dedicated firewall section.
        firewall_section = (
            self.nsxlib.create_empty_section(
                nsgroup.get('display_name'), nsgroup.get('description'),
                [nsgroup.get('id')], nsgroup.get('tags'),
                operation=operation,
                other_section=self.default_section))
        return firewall_section

    def _create_security_group_backend_resources(self, secgroup):
        tags = utils.build_v3_tags_payload(
            secgroup, resource_type='os-neutron-secgr-id',
            project_name=secgroup['tenant_id'])
        name = self.nsxlib.get_nsgroup_name(secgroup)

        if utils.is_nsx_version_1_1_0(self._nsx_version):
                tag_expression = (
                    self.nsxlib.get_nsgroup_port_tag_expression(
                        security.PORT_SG_SCOPE, secgroup['id']))
        else:
            tag_expression = None

        ns_group = self.nsxlib.create_nsgroup(
            name, secgroup['description'], tags, tag_expression)
        # security-group rules are located in a dedicated firewall section.
        firewall_section = self._create_fw_section_for_secgroup(
            ns_group, secgroup.get(provider_sg.PROVIDER))
        return ns_group, firewall_section

    def create_security_group(self, context, security_group, default_sg=False):
        secgroup = security_group['security_group']
        secgroup['id'] = secgroup.get('id') or uuidutils.generate_uuid()
        ns_group = {}
        firewall_section = {}

        if not default_sg:
            tenant_id = secgroup['tenant_id']
            self._ensure_default_security_group(context, tenant_id)
        try:
            ns_group, firewall_section = (
                self._create_security_group_backend_resources(secgroup))
            # REVISIT(roeyc): Ideally, at this point we need not be under an
            # open db transactions, however, unittests fail if omitting
            # subtransactions=True.
            with context.session.begin(subtransactions=True):
                # NOTE(arosen): a neutron security group be default adds rules
                # that allow egress traffic. We do not want this behavior for
                # provider security_groups
                if secgroup.get(provider_sg.PROVIDER) is True:
                    secgroup_db = self.create_provider_security_group(
                        context, security_group)
                else:
                    secgroup_db = (
                        super(NsxV3Plugin, self).create_security_group(
                            context, security_group, default_sg))

                nsx_db.save_sg_mappings(context.session,
                                        secgroup_db['id'],
                                        ns_group['id'],
                                        firewall_section['id'])

                self._process_security_group_properties_create(context,
                                                               secgroup_db,
                                                               secgroup,
                                                               default_sg)
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Unable to create security-group on the "
                                  "backend."))
                if ns_group:
                    self.nsxlib.delete_nsgroup(ns_group['id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                section_id = firewall_section.get('id')
                nsgroup_id = ns_group.get('id')
                LOG.debug("Neutron failed to create security-group, "
                          "deleting backend resources: "
                          "section %s, ns-group %s.",
                          section_id, nsgroup_id)
                if nsgroup_id:
                    self.nsxlib.delete_nsgroup(nsgroup_id)
                if section_id:
                    self.nsxlib.delete_section(section_id)
        try:
            sg_rules = secgroup_db['security_group_rules']
            # skip if there are no rules in group. i.e provider case
            if sg_rules:
                # translate and creates firewall rules.
                logging = (cfg.CONF.nsx_v3.log_security_groups_allowed_traffic
                           or secgroup.get(sg_logging.LOGGING, False))
                action = (firewall.DROP
                          if secgroup.get(provider_sg.PROVIDER)
                          else firewall.ALLOW)
                rules = self.nsxlib.create_firewall_rules(
                    context, firewall_section['id'], ns_group['id'],
                    logging, action, sg_rules)
                self.nsxlib.save_sg_rule_mappings(context.session,
                                                  rules['rules'])
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to create backend firewall rules "
                                  "for security-group %(name)s (%(id)s), "
                                  "rolling back changes."), secgroup_db)
                # default security group deletion requires admin context
                if default_sg:
                    context = context.elevated()
                super(NsxV3Plugin, self).delete_security_group(
                    context, secgroup_db['id'])
                self.nsxlib.delete_nsgroup(ns_group['id'])
                self.nsxlib.delete_section(firewall_section['id'])

        return secgroup_db

    def update_security_group(self, context, id, security_group):
        orig_secgroup = self.get_security_group(
            context, id, fields=['id', 'name', 'description'])
        with context.session.begin(subtransactions=True):
            secgroup_res = (
                super(NsxV3Plugin, self).update_security_group(context, id,
                                                               security_group))
            self._process_security_group_properties_update(
                context, secgroup_res, security_group['security_group'])
        try:
            self.nsxlib.update_security_group_on_backend(context, secgroup_res)
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to update security-group %(name)s "
                                  "(%(id)s), rolling back changes in "
                                  "Neutron."), orig_secgroup)
                super(NsxV3Plugin, self).update_security_group(
                    context, id, {'security_group': orig_secgroup})

        return secgroup_res

    def delete_security_group(self, context, id):
        self._prevent_non_admin_delete_provider_sg(context, id)
        nsgroup_id, section_id = self.nsxlib.get_sg_mappings(
            context.session, id)
        super(NsxV3Plugin, self).delete_security_group(context, id)
        self.nsxlib.delete_section(section_id)
        self.nsxlib.delete_nsgroup(nsgroup_id)

    def create_security_group_rule(self, context, security_group_rule):
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def create_security_group_rule_bulk(self, context, security_group_rules):
        sg_rules = security_group_rules['security_group_rules']
        for r in sg_rules:
            self._check_local_ip_prefix(context, r['security_group_rule'])
            # Generate id for security group rule or use one sepecified,
            # if specified we are running in api-replay as server doesn't
            # allow id to be specified by default
            r['security_group_rule']['id'] = (
                r['security_group_rule'].get('id') or
                uuidutils.generate_uuid())

        with context.session.begin(subtransactions=True):

            rules_db = (super(NsxV3Plugin,
                              self).create_security_group_rule_bulk_native(
                                  context, security_group_rules))
            for i, r in enumerate(sg_rules):
                self._process_security_group_rule_properties(
                    context, rules_db[i], r['security_group_rule'])

            # NOTE(arosen): here are are assuming that all of the security
            # group rules being added are part of the same security
            # group. We should be validating that this is the case though...
            sg_id = sg_rules[0]['security_group_rule']['security_group_id']
            self._prevent_non_admin_delete_provider_sg(context, sg_id)

            security_group = self.get_security_group(
                context, sg_id)
            action = firewall.ALLOW
            if security_group.get(provider_sg.PROVIDER) is True:
                # provider security groups are drop rules.
                action = firewall.DROP

        sg_id = rules_db[0]['security_group_id']
        nsgroup_id, section_id = self.nsxlib.get_sg_mappings(context.session,
                                                             sg_id)
        logging_enabled = (cfg.CONF.nsx_v3.log_security_groups_allowed_traffic
                           or self._is_security_group_logged(context, sg_id))
        try:
            rules = self.nsxlib.create_firewall_rules(
                context, section_id, nsgroup_id,
                logging_enabled, action, rules_db)
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                for rule in rules_db:
                    super(NsxV3Plugin, self).delete_security_group_rule(
                        context, rule['id'])
        self.nsxlib.save_sg_rule_mappings(context.session, rules['rules'])
        return rules_db

    def delete_security_group_rule(self, context, id):
        rule_db = self._get_security_group_rule(context, id)
        sg_id = rule_db['security_group_id']
        self._prevent_non_admin_delete_provider_sg(context, sg_id)
        _, section_id = self.nsxlib.get_sg_mappings(context.session, sg_id)
        fw_rule_id = nsx_db.get_sg_rule_mapping(context.session, id)
        self.nsxlib.delete_rule(section_id, fw_rule_id)
        super(NsxV3Plugin, self).delete_security_group_rule(context, id)
