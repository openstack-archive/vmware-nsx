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

import netaddr

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import uuidutils
import webob.exc

from neutron.db import _resource_extend as resource_extend
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import dns_db
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
from neutron.db import l3_attrs_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db.models import l3 as l3_db_models
from neutron.db.models import securitygroup as securitygroup_model  # noqa
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import portsecurity_db
from neutron.db import securitygroups_db
from neutron.db import vlantransparent_db
from neutron.extensions import providernet
from neutron.extensions import securitygroup as ext_sg
from neutron.quota import resource_registry
from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from neutron_lib.api import faults
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib.db import api as db_api
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc

from vmware_nsx._i18n import _
from vmware_nsx.common import config  # noqa
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import l3_rpc_agent_api
from vmware_nsx.common import locking
from vmware_nsx.common import managers
from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import extended_security_group_rule as extend_sg_rule
from vmware_nsx.db import maclearning as mac_db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.extensions import secgroup_rule_local_ip_prefix as sg_prefix
from vmware_nsx.extensions import securitygrouplogging as sg_logging
from vmware_nsx.plugins.common_v3 import plugin as nsx_plugin_common
from vmware_nsx.plugins.nsx_p import availability_zones as nsxp_az
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils

from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as nsxlib_consts
from vmware_nsxlib.v3 import policy_constants
from vmware_nsxlib.v3 import policy_defs
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

SPOOFGUARD_PROFILE_UUID = 'neutron-spoofguard-profile'
NO_SPOOFGUARD_PROFILE_UUID = policy_defs.SpoofguardProfileDef.DEFAULT_PROFILE
MAC_DISCOVERY_PROFILE_UUID = 'neutron-mac-discovery-profile'
NO_SEG_SECURITY_PROFILE_UUID = (
    policy_defs.SegmentSecurityProfileDef.DEFAULT_PROFILE)


@resource_extend.has_resource_extenders
class NsxPolicyPlugin(agentschedulers_db.AZDhcpAgentSchedulerDbMixin,
                      addr_pair_db.AllowedAddressPairsMixin,
                      nsx_plugin_common.NsxPluginV3Base,
                      extend_sg_rule.ExtendedSecurityGroupRuleMixin,
                      securitygroups_db.SecurityGroupDbMixin,
                      external_net_db.External_net_db_mixin,
                      extraroute_db.ExtraRoute_db_mixin,
                      l3_gwmode_db.L3_NAT_db_mixin,
                      portbindings_db.PortBindingMixin,
                      portsecurity_db.PortSecurityDbMixin,
                      extradhcpopt_db.ExtraDhcpOptMixin,
                      dns_db.DNSDbMixin,
                      vlantransparent_db.Vlantransparent_db_mixin,
                      mac_db.MacLearningDbMixin,
                      l3_attrs_db.ExtraAttributesMixin):

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["allowed-address-pairs",
                                   "address-scope",
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
                                   "subnet_allocation",
                                   "security-group-logging",
                                   "provider-security-group",
                                   "port-security-groups-filtering",
                                   "vlan-transparent"]

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
        nsxlib_utils.set_is_attr_callback(validators.is_attr_set)
        self._extend_fault_map()
        extension_drivers = cfg.CONF.nsx_extension_drivers
        self._extension_manager = managers.ExtensionManager(
            extension_drivers=extension_drivers)
        self.cfg_group = 'nsx_p'  # group name for nsx_p section in nsx.ini
        self.init_availability_zones()

        super(NsxPolicyPlugin, self).__init__()
        # Bind the dummy L3 notifications
        self.l3_rpc_notifier = l3_rpc_agent_api.L3NotifyAPI()
        LOG.info("Starting NsxPolicyPlugin (Experimental only!)")
        self._extension_manager.initialize()
        self.supported_extension_aliases.extend(
            self._extension_manager.extension_aliases())

        self.nsxpolicy = v3_utils.get_nsxpolicy_wrapper()
        nsxlib_utils.set_inject_headers_callback(v3_utils.inject_headers)
        self._validate_nsx_policy_version()

        self._init_default_config()
        self._prepare_default_rules()
        self._init_segment_profiles()

        # subscribe the init complete method last, so it will be called only
        # if init was successful
        registry.subscribe(self.init_complete,
                           resources.PROCESS,
                           events.AFTER_INIT)

    # NOTE(annak): we may need to generalize this for API calls
    # requiring path ids
    def _init_default_resource(self, resource_api, name_or_id,
                               filter_list_results=None):
        if not name_or_id:
            # If not specified, the system will auto-configure
            # in case only single resource is present
            resources = resource_api.list()
            if filter_list_results:
                resources = filter_list_results(resources)
            if len(resources) == 1:
                return resources[0]['id']
            else:
                return None

        try:
            resource_api.get(name_or_id, silent=True)
            return name_or_id
        except nsx_lib_exc.ResourceNotFound:
            try:
                resource = resource_api.get_by_name(name_or_id)
                if resource:
                    return resource['id']
            except nsx_lib_exc.ResourceNotFound:
                return None

    def _init_default_config(self):
        # Default Tier0 router
        self.default_tier0_router = self._init_default_resource(
            self.nsxpolicy.tier0,
            cfg.CONF.nsx_p.default_tier0_router)

        if not self.default_tier0_router:
            raise cfg.RequiredOptError("default_tier0_router",
                                       group=cfg.OptGroup('nsx_p'))

        # Default overlay transport zone
        self.default_overlay_tz = self._init_default_resource(
            self.nsxpolicy.transport_zone,
            cfg.CONF.nsx_p.default_overlay_tz,
            filter_list_results=lambda tzs: [
                tz for tz in tzs if tz['tz_type'].startswith('OVERLAY')])

        if not self.default_overlay_tz:
            raise cfg.RequiredOptError("default_overlay_tz",
                                       group=cfg.OptGroup('nsx_p'))

        # Default VLAN transport zone (not mandatory)
        self.default_vlan_tz = self._init_default_resource(
            self.nsxpolicy.transport_zone,
            cfg.CONF.nsx_p.default_vlan_tz,
            filter_list_results=lambda tzs: [
                tz for tz in tzs if tz['tz_type'].startswith('VLAN')])

    def init_availability_zones(self):
        self._availability_zones_data = nsxp_az.NsxPAvailabilityZones()

    def _validate_nsx_policy_version(self):
        self._nsx_version = self.nsxpolicy.get_version()
        LOG.info("NSX Version: %s", self._nsx_version)
        if not self.nsxpolicy.feature_supported(
            nsxlib_consts.FEATURE_NSX_POLICY_NETWORKING):
            msg = (_("The NSX Policy plugin cannot be used with NSX version "
                     "%(ver)s") % {'ver': self._nsx_version})
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def _init_segment_profiles(self):
        """Find/Create segment profiles this plugin will use"""
        # Spoofguard profile (find it or create)
        try:
            self.nsxpolicy.spoofguard_profile.get(SPOOFGUARD_PROFILE_UUID)
        except nsx_lib_exc.ResourceNotFound:
            self.nsxpolicy.spoofguard_profile.create_or_overwrite(
                SPOOFGUARD_PROFILE_UUID,
                profile_id=SPOOFGUARD_PROFILE_UUID,
                address_binding_whitelist=True,
                tags=self.nsxpolicy.build_v3_api_version_tag())

        # No Port security spoofguard profile
        # (default NSX profile. just verify it exists)
        try:
            self.nsxpolicy.spoofguard_profile.get(NO_SPOOFGUARD_PROFILE_UUID)
        except nsx_lib_exc.ResourceNotFound:
            msg = (_("Cannot find spoofguard profile %s") %
                   NO_SPOOFGUARD_PROFILE_UUID)
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # Mac discovery profile (find it or create)
        try:
            self.nsxpolicy.mac_discovery_profile.get(
                MAC_DISCOVERY_PROFILE_UUID)
        except nsx_lib_exc.ResourceNotFound:
            self.nsxpolicy.mac_discovery_profile.create_or_overwrite(
                MAC_DISCOVERY_PROFILE_UUID,
                profile_id=MAC_DISCOVERY_PROFILE_UUID,
                mac_learning_enabled=True,
                tags=self.nsxpolicy.build_v3_api_version_tag())

        # No Port security segment-security profile
        # (default NSX profile. just verify it exists)
        try:
            self.nsxpolicy.segment_security_profile.get(
                NO_SEG_SECURITY_PROFILE_UUID)
        except nsx_lib_exc.ResourceNotFound:
            msg = (_("Cannot find segment security profile %s") %
                   NO_SEG_SECURITY_PROFILE_UUID)
            raise nsx_exc.NsxPluginException(err_msg=msg)

    @staticmethod
    def plugin_type():
        return projectpluginmap.NsxPlugins.NSX_P

    @staticmethod
    def is_tvd_plugin():
        return False

    def init_complete(self, resource, event, trigger, payload=None):
        with locking.LockManager.get_lock('plugin-init-complete'):
            if self.init_is_complete:
                # Should be called only once per worker
                return

            # reinitialize the cluster upon fork for api workers to ensure
            # each process has its own keepalive loops + state
            self.nsxpolicy.reinitialize_cluster(resource, event, trigger,
                                             payload=payload)

            self.init_is_complete = True

    def _extend_fault_map(self):
        """Extends the Neutron Fault Map.

        Exceptions specific to the NSX Plugin are mapped to standard
        HTTP Exceptions.
        """
        #TODO(asarfaty): consider reusing the nsx-t code here
        faults.FAULT_MAP.update({nsx_lib_exc.ManagerError:
                                 webob.exc.HTTPBadRequest,
                                 nsx_lib_exc.ServiceClusterUnavailable:
                                 webob.exc.HTTPServiceUnavailable,
                                 nsx_lib_exc.ClientCertificateNotTrusted:
                                 webob.exc.HTTPBadRequest,
                                 nsx_exc.SecurityGroupMaximumCapacityReached:
                                 webob.exc.HTTPBadRequest,
                                 nsx_lib_exc.NsxLibInvalidInput:
                                 webob.exc.HTTPBadRequest,
                                 })

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

        # TODO(annak): admin state config is missing on policy
        # should we not create networks that are down?
        # alternative - configure status on manager for time being
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

    def _tier0_validator(self, tier0_uuid):
        # Fail of the tier0 uuid was not found on the BSX
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

    def create_network(self, context, network):
        net_data = network['network']

        #TODO(asarfaty): add ENS support
        external = net_data.get(external_net.EXTERNAL)
        is_external_net = validators.is_attr_set(external) and external
        tenant_id = net_data['tenant_id']

        self._ensure_default_security_group(context, tenant_id)
        vlt = vlan_apidef.get_vlan_transparent(net_data)

        self._validate_create_network(context, net_data)

        if is_external_net:
            is_provider_net, net_type, physical_net, vlan_id = (
                self._validate_external_net_create(
                    net_data, self.default_tier0_router,
                    self._tier0_validator))
            provider_data = {'is_provider_net': is_provider_net,
                             'net_type': net_type,
                             'physical_net': physical_net,
                             'vlan_id': vlan_id}
            is_backend_network = False
        else:
            provider_data = self._validate_provider_create(
                context, net_data,
                self.default_vlan_tz,
                self.default_overlay_tz,
                self.nsxpolicy.transport_zone,
                self.nsxpolicy.segment,
                transparent_vlan=vlt)
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
            super(NsxPolicyPlugin, self).update_network(context,
                created_net['id'],
                {'network': {'vlan_transparent': vlt}})
            self._extension_manager.process_create_network(
                context, net_data, created_net)
            if psec.PORTSECURITY not in net_data:
                net_data[psec.PORTSECURITY] = True
            self._process_network_port_security_create(
                context, net_data, created_net)
            self._process_l3_create(context, created_net, net_data)

            if provider_data['is_provider_net']:
                # Save provider network fields, needed by get_network()
                net_bindings = [nsx_db.add_network_binding(
                    context.session, created_net['id'],
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
                        context, created_net['id'])

        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        net_model = self._get_network(context, created_net['id'])
        resource_extend.apply_funcs('networks', created_net, net_model)
        return created_net

    def delete_network(self, context, network_id):
        is_nsx_net = self._network_is_nsx_net(context, network_id)
        is_external_net = self._network_is_external(context, network_id)
        with db_api.CONTEXT_WRITER.using(context):
            self._process_l3_delete(context, network_id)
            super(NsxPolicyPlugin, self).delete_network(
                context, network_id)
        if not is_external_net and not is_nsx_net:
            self.nsxpolicy.segment.delete(network_id)
        else:
            # TODO(asarfaty): for NSX network we may need to delete DHCP conf
            pass

    def update_network(self, context, network_id, network):
        original_net = super(NsxPolicyPlugin, self).get_network(
            context, network_id)
        net_data = network['network']

        # Neutron does not support changing provider network values
        providernet._raise_if_updates_provider_attributes(net_data)
        extern_net = self._network_is_external(context, network_id)
        is_nsx_net = self._network_is_nsx_net(context, network_id)

        # Do not support changing external/non-external networks
        if (external_net.EXTERNAL in net_data and
            net_data[external_net.EXTERNAL] != extern_net):
            err_msg = _("Cannot change the router:external flag of a network")
            raise n_exc.InvalidInput(error_message=err_msg)

        # Update the neutron network
        updated_net = super(NsxPolicyPlugin, self).update_network(
            context, network_id, network)
        self._extension_manager.process_update_network(context, net_data,
                                                       updated_net)
        self._process_l3_update(context, updated_net, network['network'])
        self._extend_network_dict_provider(context, updated_net)

        # Update the backend segment
        if (not extern_net and not is_nsx_net and
            ('name' in net_data or 'description' in net_data)):
            # TODO(asarfaty): handle admin state changes as well
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

        return updated_net

    def create_subnet(self, context, subnet):
        self._validate_host_routes_input(subnet)
        created_subnet = super(
            NsxPolicyPlugin, self).create_subnet(context, subnet)
        # TODO(asarfaty): Handle dhcp on the policy manager
        return created_subnet

    def delete_subnet(self, context, subnet_id):
        # TODO(asarfaty): cleanup dhcp on the policy manager
        super(NsxPolicyPlugin, self).delete_subnet(context, subnet_id)

    def update_subnet(self, context, subnet_id, subnet):
        updated_subnet = None
        orig = self._get_subnet(context, subnet_id)
        self._validate_host_routes_input(subnet,
                                         orig_enable_dhcp=orig['enable_dhcp'],
                                         orig_host_routes=orig['routes'])
        # TODO(asarfaty): Handle dhcp updates on the policy manager
        updated_subnet = super(NsxPolicyPlugin, self).update_subnet(
            context, subnet_id, subnet)
        self._extension_manager.process_update_subnet(
            context, subnet['subnet'], updated_subnet)

        return updated_subnet

    def _build_port_address_bindings(self, context, port_data):
        psec_on, has_ip = self._determine_port_security_and_has_ip(context,
                                                                   port_data)
        if not psec_on:
            return None

        address_bindings = []
        for fixed_ip in port_data['fixed_ips']:
            if netaddr.IPNetwork(fixed_ip['ip_address']).version != 4:
                #TODO(annak): enable when IPv6 is supported
                continue
            binding = self.nsxpolicy.segment_port.build_address_binding(
                fixed_ip['ip_address'], port_data['mac_address'])
            address_bindings.append(binding)

        for pair in port_data.get(addr_apidef.ADDRESS_PAIRS):
            binding = self.nsxpolicy.segment_port.build_address_binding(
                pair['ip_address'], pair['mac_address'])
            address_bindings.append(binding)

        return address_bindings

    def _get_network_nsx_id(self, context, network_id):
        """Return the id of this logical switch in the nsx manager

        (Not the segment in the policy manager)
        The nova api will use this to attach to the instance
        """
        #TODO(asarfaty): This is a backend call that will be called for
        # each get_port/s. We should consider caching the results or adding
        # to DB
        if not self._network_is_external(context, network_id):
            segment_id = self._get_network_nsx_segment_id(context, network_id)
            return self.nsxpolicy.segment.get_realized_id(segment_id)

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
        sec_groups = port_data.get(ext_sg.SECURITYGROUPS, [])
        sec_groups += port_data.get(provider_sg.PROVIDER_SECURITYGROUPS, [])

        tags = []
        for sg in sec_groups:
            tags = nsxlib_utils.add_v3_tag(tags,
                                           NSX_P_SECURITY_GROUP_TAG,
                                           sg)

        return tags

    def _create_port_on_backend(self, context, port_data):
        # TODO(annak): admin_state not supported by policy
        # TODO(annak): handle exclude list
        # TODO(annak): switching profiles when supported
        name = self._build_port_name(context, port_data)
        address_bindings = self._build_port_address_bindings(
            context, port_data)
        device_owner = port_data.get('device_owner')
        attachment_type = vif_id = None
        if device_owner and device_owner != l3_db.DEVICE_OWNER_ROUTER_INTF:
            vif_id = port_data['id']
            attachment_type = nsxlib_consts.ATTACHMENT_VIF
        tags = self.nsxpolicy.build_v3_api_version_project_tag(
            context.tenant_name)

        tags = self._build_port_tags(port_data)
        tags.extend(self.nsxpolicy.build_v3_api_version_project_tag(
            context.tenant_name))

        segment_id = self._get_network_nsx_segment_id(
            context, port_data['network_id'])
        self.nsxpolicy.segment_port.create_or_overwrite(
            name, segment_id,
            port_id=port_data['id'],
            description=port_data.get('description'),
            address_bindings=address_bindings,
            vif_id=vif_id,
            attachment_type=attachment_type,
            tags=tags)

    def base_create_port(self, context, port):
        neutron_db = super(NsxPolicyPlugin, self).create_port(context, port)
        self._extension_manager.process_create_port(
            context, port['port'], neutron_db)
        return neutron_db

    def create_port(self, context, port, l2gw_port_check=False):
        port_data = port['port']
        self._validate_max_ips_per_port(port_data.get('fixed_ips', []),
                                        port_data.get('device_owner'))

        # Validate the vnic type (the same types as for the NSX-T plugin)
        direct_vnic_type = self._validate_port_vnic_type(
            context, port_data, port_data['network_id'],
            projectpluginmap.NsxPlugins.NSX_T)

        with db_api.CONTEXT_WRITER.using(context):
            is_external_net = self._network_is_external(
                context, port_data['network_id'])
            if is_external_net:
                self._assert_on_external_net_with_compute(port_data)

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

            self._process_port_create_security_group(context, port_data, sgids)
            self._process_port_create_provider_security_group(
                context, port_data, psgids)
            #TODO(asarfaty): Handle mac learning

        if not is_external_net:
            try:
                self._create_port_on_backend(context, port_data)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.error('Failed to create port %(id)s on NSX '
                              'backend. Exception: %(e)s',
                              {'id': neutron_db['id'], 'e': e})
                    super(NsxPolicyPlugin, self).delete_port(
                        context, neutron_db['id'])

        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        port_model = self._get_port(context, port_data['id'])
        resource_extend.apply_funcs('ports', port_data, port_model)
        self._extend_nsx_port_dict_binding(context, port_data)
        self._remove_provider_security_groups_from_list(port_data)

        kwargs = {'context': context, 'port': neutron_db}
        registry.notify(resources.PORT, events.AFTER_CREATE, self, **kwargs)
        return port_data

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
        self.disassociate_floatingips(context, port_id)
        super(NsxPolicyPlugin, self).delete_port(context, port_id)

        if not self._network_is_external(context, net_id):
            try:
                segment_id = self._get_network_nsx_segment_id(context, net_id)
                self.nsxpolicy.segment_port.delete(segment_id, port_data['id'])
            except Exception as ex:
                LOG.error("Failed to delete port %(id)s on NSX backend "
                          "due to %(e)s", {'id': port_id, 'e': ex})
                # Do not fail the neutron action

    def _update_port_on_backend(self, context, lport_id,
                                original_port, updated_port):
        # For now port create and update are the same
        # Update might evolve with more features
        return self._create_port_on_backend(context, updated_port)

    def update_port(self, context, port_id, port):
        with db_api.CONTEXT_WRITER.using(context):
            # get the original port, and keep it honest as it is later used
            # for notifications
            original_port = super(NsxPolicyPlugin, self).get_port(
                context, port_id)
            port_data = port['port']
            validate_port_sec = self._should_validate_port_sec_on_update_port(
                port_data)
            is_external_net = self._network_is_external(
                context, original_port['network_id'])
            if is_external_net:
                self._assert_on_external_net_with_compute(port_data)
            device_owner = (port_data['device_owner']
                            if 'device_owner' in port_data
                            else original_port.get('device_owner'))
            self._validate_max_ips_per_port(
                port_data.get('fixed_ips', []), device_owner)

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

            sec_grp_updated = self.update_security_group_on_port(
                context, port_id, port, original_port, updated_port)

            self._process_port_update_provider_security_group(
                context, port, original_port, updated_port)

            (port_security, has_ip) = self._determine_port_security_and_has_ip(
                context, updated_port)
            self._remove_provider_security_groups_from_list(updated_port)
            self._process_portbindings_create_and_update(
                context, port_data, updated_port,
                vif_type=self._vif_type_by_vnic_type(direct_vnic_type))
            self._extend_nsx_port_dict_binding(context, updated_port)

            #TODO(asarfaty): Handle mac learning

        # update the port in the backend, only if it exists in the DB
        # (i.e not external net)
        if not is_external_net:
            try:
                self._update_port_on_backend(context, port_id,
                                             original_port, updated_port)
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
        if 'id' in port:
            port_model = self._get_port(context, port['id'])
            resource_extend.apply_funcs('ports', port, port_model)
        self._extend_nsx_port_dict_binding(context, port)
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
                if 'id' in port:
                    try:
                        port_model = self._get_port(context, port['id'])
                        resource_extend.apply_funcs('ports', port, port_model)
                    except n_exc.PortNotFound:
                        # Port might have been deleted by now
                        LOG.debug("Port %s was deleted during the get_ports "
                                  "process, and is being skipped", port['id'])
                        ports.remove(port)
                        continue
                self._extend_nsx_port_dict_binding(context, port)
                self._remove_provider_security_groups_from_list(port)
        return (ports if not fields else
                [db_utils.resource_fields(port, fields) for port in ports])

    def _get_tier0_uuid_by_net_id(self, context, network_id):
        if not network_id:
            return
        network = self.get_network(context, network_id)
        if not network.get(pnet.PHYSICAL_NETWORK):
            return self.default_tier0_router
        else:
            return network.get(pnet.PHYSICAL_NETWORK)

    def _get_tier0_uuid_by_router(self, context, router):
        network_id = router.gw_port_id and router.gw_port.network_id
        return self._get_tier0_uuid_by_net_id(context, network_id)

    def _add_subnet_snat_rule(self, context, router_id, subnet,
                              gw_address_scope, gw_ip):
        # if the subnets address scope is the same as the gateways:
        # no need for SNAT
        #TODO(asarfaty): move to common code
        if gw_address_scope:
            subnet_address_scope = self._get_subnetpool_address_scope(
                context, subnet['subnetpool_id'])
            if (gw_address_scope == subnet_address_scope):
                LOG.info("No need for SNAT rule for router %(router)s "
                         "and subnet %(subnet)s because they use the "
                         "same address scope %(addr_scope)s.",
                         {'router': router_id,
                          'subnet': subnet['id'],
                          'addr_scope': gw_address_scope})
                return

        self.nsxpolicy.tier1_nat_rule.create_or_overwrite(
            'snat for subnet %s' % subnet['id'],
            router_id,
            nat_rule_id=self._get_snat_rule_id(subnet),
            action=policy_constants.NAT_ACTION_SNAT,
            #sequence_number=GW_NAT_PRI # TODO(asarfaty) handle priorities
            translated_network=gw_ip,
            source_network=subnet['cidr'],
            firewall_match=policy_constants.NAT_FIREWALL_MATCH_INTERNAL)

    def _get_snat_rule_id(self, subnet):
        return 'S-' + subnet['id']

    def _get_no_dnat_rule_id(self, subnet):
        return 'ND-' + subnet['id']

    def _add_subnet_no_dnat_rule(self, context, router_id, subnet):
        # Add NO-DNAT rule to allow internal traffic between VMs, even if
        # they have floating ips (Only for routers with snat enabled)
        self.nsxpolicy.tier1_nat_rule.create_or_overwrite(
            'no-dnat for subnet %s' % subnet['id'],
            router_id,
            nat_rule_id=self._get_no_dnat_rule_id(subnet),
            action=policy_constants.NAT_ACTION_NO_DNAT,
            #sequence_number=GW_NAT_PRI # TODO(asarfaty) handle priorities
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

    def _update_router_gw_info(self, context, router_id, info):
        # Get the original data of the router GW
        router = self._get_router(context, router_id)
        org_tier0_uuid = self._get_tier0_uuid_by_router(context, router)
        org_enable_snat = router.enable_snat
        orgaddr, orgmask, _orgnexthop = (
            self._get_external_attachment_info(
                context, router))
        self._validate_router_gw(context, router_id, info, org_enable_snat)

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
        actions = self._get_update_router_gw_actions(
            org_tier0_uuid, orgaddr, org_enable_snat,
            new_tier0_uuid, newaddr, new_enable_snat, fw_exist=False,
            lb_exist=False)

        if actions['add_service_router']:
            edge_cluster = self.nsxpolicy.tier0.get_edge_cluster_path(
                new_tier0_uuid)
            if edge_cluster:
                self.nsxpolicy.tier1.set_edge_cluster_path(
                    router_id, edge_cluster)
            else:
                LOG.error("Tier0 %s does not have an edge cluster",
                          new_tier0_uuid)

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
            #TODO(asarfaty) no api for this yet

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

        #self.nsxpolicy.tier1.update_route_advertisement(
        #    router_id,
        #    actions['advertise_route_nat_flag'],
        #    actions['advertise_route_connected_flag'])

        # TODO(asarfaty): handle enable/disable snat, router adv flags, etc.

        if actions['remove_service_router']:
            # disable edge firewall before removing  the service router
            #TODO(asarfaty) no api for this yet

            # remove the edge cluster
            self.nsxpolicy.tier1.remove_edge_cluster(router_id)

    def create_router(self, context, router):
        r = router['router']
        gw_info = self._extract_external_gw(context, router, is_extract=True)
        with db_api.CONTEXT_WRITER.using(context):
            router = super(NsxPolicyPlugin, self).create_router(
                context, router)
            router_db = self._get_router(context, router['id'])
            self._process_extra_attr_router_create(context, router_db, r)

        router_name = utils.get_name_and_uuid(router['name'] or 'router',
                                              router['id'])
        tags = self.nsxpolicy.build_v3_api_version_project_tag(
            context.tenant_name)
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

    def update_router(self, context, router_id, router):
        gw_info = self._extract_external_gw(context, router, is_extract=False)
        router_data = router['router']
        LOG.debug("Updating router %s: %s. GW info %s",
                  router_id, router_data, gw_info)
        #TODO(asarfaty) update the NSX logical router & interfaces

        return super(NsxPolicyPlugin, self).update_router(
            context, router_id, router)

    def add_router_interface(self, context, router_id, interface_info):
        LOG.info("Adding router %s interface %s", router_id, interface_info)
        network_id = self._get_interface_network(context, interface_info)
        extern_net = self._network_is_external(context, network_id)
        router_db = self._get_router(context, router_id)
        gw_network_id = (router_db.gw_port.network_id if router_db.gw_port
                         else None)

        # A router interface cannot be an external network
        if extern_net:
            msg = _("An external network cannot be attached as "
                    "an interface to a router")
            raise n_exc.InvalidInput(error_message=msg)

        # Update the interface of the neutron router
        info = super(NsxPolicyPlugin, self).add_router_interface(
             context, router_id, interface_info)

        self._validate_interface_address_scope(context, router_db, info)

        # TODO(annak): Validate TZ
        try:
            #TODO(asarfaty): adding the segment name even though it was not
            # changed because otherwise the NSX will set it to default.
            # This code should be removed once NSX supports it.
            net = self._get_network(context, network_id)
            net_name = utils.get_name_and_uuid(
                net['name'] or 'network', network_id)
            segment_id = self._get_network_nsx_segment_id(context, network_id)
            subnet = self.get_subnet(context, info['subnet_ids'][0])
            cidr_prefix = int(subnet['cidr'].split('/')[1])
            gw_addr = "%s/%s" % (subnet['gateway_ip'], cidr_prefix)
            pol_subnet = policy_defs.Subnet(
                gateway_address=gw_addr)
            self.nsxpolicy.segment.update(segment_id,
                                          name=net_name,
                                          tier1_id=router_id,
                                          subnets=[pol_subnet])

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

        # Remove the tier1 router from this segment on the nSX
        try:
            #TODO(asarfaty): adding the segment name even though it was not
            # changed because otherwise the NSX will set it to default.
            # This code should be removed once NSX supports it.
            net = self._get_network(context, network_id)
            net_name = utils.get_name_and_uuid(
                net['name'] or 'network', network_id)
            segment_id = self._get_network_nsx_segment_id(context, network_id)
            self.nsxpolicy.segment.update(segment_id, name=net_name,
                                          tier1_id=None)

            # try to delete the SNAT/NO_DNAT rules of this subnet
            router_db = self._get_router(context, router_id)
            if subnet and router_db.gw_port and router_db.enable_snat:
                self._del_subnet_snat_rule(router_id, subnet)
                self._del_subnet_no_dnat_rule(router_id, subnet)

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
            firewall_match=policy_constants.NAT_FIREWALL_MATCH_INTERNAL)
        self.nsxpolicy.tier1_nat_rule.create_or_overwrite(
            'dnat for fip %s' % fip_id,
            tier1_id,
            nat_rule_id=self._get_fip_dnat_rule_id(fip_id),
            action=policy_constants.NAT_ACTION_DNAT,
            translated_network=int_ip,
            destination_network=ext_ip,
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
                return

            # Create the default group membership criteria to match all neutron
            # ports by scope & tag
            scope_and_tag = "%s:%s" % (NSX_P_SECURITY_GROUP_TAG,
                                       NSX_P_DEFAULT_SECTION)
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
            rule_id = 1
            dhcp_client_rule = self.nsxpolicy.comm_map.build_entry(
                'DHCP Reply', NSX_P_GLOBAL_DOMAIN_ID,
                NSX_P_DEFAULT_SECTION,
                rule_id, sequence_number=rule_id,
                service_ids=['DHCP-Client'],
                action=policy_constants.ACTION_ALLOW,
                source_groups=None,
                dest_groups=[NSX_P_DEFAULT_GROUP],
                direction=nsxlib_consts.IN,
                logged=logged)
            rule_id += 1
            dhcp_server_rule = self.nsxpolicy.comm_map.build_entry(
                'DHCP Request', NSX_P_GLOBAL_DOMAIN_ID,
                NSX_P_DEFAULT_SECTION,
                rule_id, sequence_number=rule_id,
                service_ids=['DHCP-Server'],
                action=policy_constants.ACTION_ALLOW,
                source_groups=[NSX_P_DEFAULT_GROUP],
                dest_groups=None,
                direction=nsxlib_consts.OUT,
                logged=logged)
            rule_id += 1
            block_rule = self.nsxpolicy.comm_map.build_entry(
                'Block All', NSX_P_GLOBAL_DOMAIN_ID,
                NSX_P_DEFAULT_SECTION,
                rule_id, sequence_number=rule_id, service_ids=None,
                action=policy_constants.ACTION_DENY,
                source_groups=None,
                dest_groups=[NSX_P_DEFAULT_GROUP],
                direction=nsxlib_consts.IN_OUT,
                logged=logged)
            rules = [dhcp_client_rule, dhcp_server_rule, block_rule]
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

            # create exclude port group
            # TODO(asarfaty): add this while handling port security disabled

    def _create_security_group_backend_resources(self, context, secgroup,
                                                 domain_id):
        """Create communication map (=section) and group (=NS group)

        Both will have the security group id as their NSX id.
        """
        sg_id = secgroup['id']
        tags = self.nsxpolicy.build_v3_api_version_project_tag(
            context.tenant_name)
        nsx_name = utils.get_name_and_uuid(secgroup['name'] or 'securitygroup',
                                           sg_id)
        # Create the groups membership criteria for ports by scope & tag
        scope_and_tag = "%s:%s" % (NSX_P_SECURITY_GROUP_TAG, sg_id)
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

    def _get_rule_service_id(self, context, sg_rule):
        """Return the NSX Policy service id matching the SG rule"""
        srv_id = None
        l4_protocol = nsxlib_utils.get_l4_protocol_name(sg_rule['protocol'])
        srv_name = 'Service for OS rule %s' % sg_rule['id']
        tags = self.nsxpolicy.build_v3_api_version_project_tag(
            context.tenant_name)

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
                                            sg_rule, secgroup_logging):
        # The id of the map and group is the same as the security group id
        this_group_id = map_id
        # There is no rule name in neutron. Using ID instead
        nsx_name = sg_rule['id']
        direction = (nsxlib_consts.IN if sg_rule.get('direction') == 'ingress'
                     else nsxlib_consts.OUT)
        self._fix_sg_rule_dict_ips(sg_rule)
        source = None
        destination = this_group_id
        tags = self.nsxpolicy.build_v3_api_version_project_tag(
            context.tenant_name)
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

        service = self._get_rule_service_id(context, sg_rule)
        logging = (cfg.CONF.nsx_p.log_security_groups_allowed_traffic or
                   secgroup_logging)
        self.nsxpolicy.comm_map.create_entry(
            nsx_name, domain_id, map_id, entry_id=sg_rule['id'],
            description=sg_rule.get('description'),
            service_ids=[service] if service else None,
            action=policy_constants.ACTION_ALLOW,
            source_groups=[source] if source else None,
            dest_groups=[destination] if destination else None,
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
                self.nsxpolicy.group.create_or_overwrite(
                    nsx_name, domain_id, sg_id,
                    description=secgroup_res.get('description'))
                self.nsxpolicy.comm_map.create_or_overwrite_map_only(
                    nsx_name, domain_id, sg_id,
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
        self._prevent_non_admin_edit_provider_sg(context, sg_id)

        with db_api.CONTEXT_WRITER.using(context):
            rules_db = (super(NsxPolicyPlugin,
                              self).create_security_group_rule_bulk_native(
                                  context, security_group_rules))
            for i, r in enumerate(sg_rules):
                self._process_security_group_rule_properties(
                    context, rules_db[i], r['security_group_rule'])

        domain_id = example_rule['tenant_id']
        secgroup_logging = self._is_security_group_logged(context, sg_id)
        for sg_rule in sg_rules:
            # create the NSX rule
            rule_data = sg_rule['security_group_rule']
            rule_data['id'] = rule_data.get('id') or uuidutils.generate_uuid()
            self._create_security_group_backend_rule(
                context, domain_id, sg_id, rule_data, secgroup_logging)

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
