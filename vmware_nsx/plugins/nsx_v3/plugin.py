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
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.api.v2 import attributes
from neutron.callbacks import events
from neutron.callbacks import exceptions as callback_exc
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import constants as const
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as neutron_utils
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import portsecurity_db
from neutron.db import securitygroups_db
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import external_net as ext_net_extn
from neutron.extensions import extra_dhcp_opt as ext_edo
from neutron.extensions import l3
from neutron.extensions import portbindings as pbin
from neutron.extensions import portsecurity as psec
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as ext_sg
from neutron.plugins.common import constants as plugin_const
from neutron.plugins.common import utils as n_utils
from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import uuidutils

from vmware_nsx._i18n import _LE, _LI, _LW
from vmware_nsx.common import config  # noqa
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import locking
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.nsxlib import v3 as nsxlib
from vmware_nsx.nsxlib.v3 import client as nsx_client
from vmware_nsx.nsxlib.v3 import dfw_api as firewall
from vmware_nsx.nsxlib.v3 import resources as nsx_resources
from vmware_nsx.nsxlib.v3 import router
from vmware_nsx.nsxlib.v3 import security


LOG = log.getLogger(__name__)
NSX_V3_PSEC_PROFILE_NAME = 'neutron_port_spoof_guard_profile'
NSX_V3_DHCP_PROFILE_NAME = 'neutron_port_dhcp_profile'


class NsxV3Plugin(addr_pair_db.AllowedAddressPairsMixin,
                  db_base_plugin_v2.NeutronDbPluginV2,
                  securitygroups_db.SecurityGroupDbMixin,
                  external_net_db.External_net_db_mixin,
                  extraroute_db.ExtraRoute_db_mixin,
                  l3_gwmode_db.L3_NAT_db_mixin,
                  portbindings_db.PortBindingMixin,
                  portsecurity_db.PortSecurityDbMixin,
                  agentschedulers_db.DhcpAgentSchedulerDbMixin,
                  extradhcpopt_db.ExtraDhcpOptMixin):

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
                                   "port-security",
                                   "provider",
                                   "external-net",
                                   "extraroute",
                                   "router"]

    def __init__(self):
        super(NsxV3Plugin, self).__init__()
        LOG.info(_("Starting NsxV3Plugin"))

        self.base_binding_dict = {
            pbin.VIF_TYPE: pbin.VIF_TYPE_OVS,
            pbin.VIF_DETAILS: {
                # TODO(rkukura): Replace with new VIF security details
                pbin.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}
        self.tier0_groups_dict = {}
        self._setup_dhcp()
        self._start_rpc_notifiers()
        self._nsx_client = nsx_client.NSX3Client()
        self._port_client = nsx_resources.LogicalPort(self._nsx_client)
        self.nsgroup_container, self.default_section = (
            security.init_nsgroup_container_and_default_section_rules())
        self._router_client = nsx_resources.LogicalRouter(self._nsx_client)
        self._router_port_client = nsx_resources.LogicalRouterPort(
            self._nsx_client)
        self._routerlib = router.RouterLib(self._router_client,
                                           self._router_port_client)

        LOG.debug("Initializing NSX v3 port spoofguard switching profile")
        self._switching_profiles = nsx_resources.SwitchingProfile(
            self._nsx_client)
        self._psec_profile = None
        self._psec_profile = self._init_port_security_profile()
        if not self._psec_profile:
            msg = _("Unable to initialize NSX v3 port spoofguard "
                    "switching profile: %s") % NSX_V3_PSEC_PROFILE_NAME
            raise nsx_exc.NsxPluginException(msg)
        LOG.debug("Initializing NSX v3 DHCP switching profile")
        self._dhcp_profile = None
        self._dhcp_profile = self._init_dhcp_switching_profile()
        if not self._dhcp_profile:
            msg = _("Unable to initialize NSX v3 DHCP "
                    "switching profile: %s") % NSX_V3_DHCP_PROFILE_NAME
            raise nsx_exc.NsxPluginException(msg)
        self._unsubscribe_callback_events()

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
                    tags=utils.build_v3_tags_payload({
                        'id': NSX_V3_DHCP_PROFILE_NAME,
                        'tenant_id': 'neutron-nsx-plugin'}))
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
                tags=utils.build_v3_tags_payload({
                    'id': NSX_V3_PSEC_PROFILE_NAME,
                    'tenant_id': 'neutron-nsx-plugin'}))

        return self._get_port_security_profile()

    def _setup_rpc(self):
        self.endpoints = [dhcp_rpc.DhcpRpcCallback(),
                          agents_db.AgentExtRpcCallback(),
                          metadata_rpc.MetadataRpcCallback()]

    def _setup_dhcp(self):
        """Initialize components to support DHCP."""
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )
        self.start_periodic_dhcp_agent_status_check()

    def _start_rpc_notifiers(self):
        """Initialize RPC notifiers for agents."""
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )

    def start_rpc_listeners(self):
        self._setup_rpc()
        self.topic = topics.PLUGIN
        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        self.conn.create_consumer(topics.REPORTS,
                                  [agents_db.AgentExtRpcCallback()],
                                  fanout=False)
        return self.conn.consume_in_threads()

    def _validate_provider_create(self, context, network_data):
        physical_net = network_data.get(pnet.PHYSICAL_NETWORK)
        if not attributes.is_attr_set(physical_net):
            physical_net = None

        vlan_id = network_data.get(pnet.SEGMENTATION_ID)
        if not attributes.is_attr_set(vlan_id):
            vlan_id = None

        err_msg = None
        net_type = network_data.get(pnet.NETWORK_TYPE)
        if attributes.is_attr_set(net_type):
            if net_type == utils.NsxV3NetworkTypes.FLAT:
                if vlan_id is not None:
                    err_msg = (_("Segmentation ID cannot be specified with "
                                 "%s network type") %
                               utils.NsxV3NetworkTypes.FLAT)
                else:
                    # Set VLAN id to 0 for flat networks
                    vlan_id = '0'
                    if physical_net is None:
                        physical_net = cfg.CONF.nsx_v3.default_vlan_tz_uuid
            elif net_type == utils.NsxV3NetworkTypes.VLAN:
                # Use default VLAN transport zone if physical network not given
                if physical_net is None:
                    physical_net = cfg.CONF.nsx_v3.default_vlan_tz_uuid

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
        else:
            net_type = None

        if err_msg:
            raise n_exc.InvalidInput(error_message=err_msg)

        if physical_net is None:
            # Default to transport type overlay
            physical_net = cfg.CONF.nsx_v3.default_overlay_tz_uuid

        return net_type, physical_net, vlan_id

    def _get_edge_cluster_and_members(self, tier0_uuid):
        self._routerlib.validate_tier0(self.tier0_groups_dict, tier0_uuid)
        tier0_info = self.tier0_groups_dict[tier0_uuid]
        return (tier0_info['edge_cluster_uuid'],
                tier0_info['member_index_list'])

    def _validate_external_net_create(self, net_data):
        is_provider_net = False
        if not attributes.is_attr_set(net_data.get(pnet.PHYSICAL_NETWORK)):
            tier0_uuid = cfg.CONF.nsx_v3.default_tier0_router_uuid
        else:
            tier0_uuid = net_data[pnet.PHYSICAL_NETWORK]
            is_provider_net = True
        self._routerlib.validate_tier0(self.tier0_groups_dict, tier0_uuid)
        return (is_provider_net, utils.NetworkTypes.L3_EXT, tier0_uuid, 0)

    def _create_network_at_the_backend(self, context, net_data):
        is_provider_net = any(
            attributes.is_attr_set(net_data.get(f))
            for f in (pnet.NETWORK_TYPE,
                      pnet.PHYSICAL_NETWORK,
                      pnet.SEGMENTATION_ID))
        net_type, physical_net, vlan_id = self._validate_provider_create(
            context, net_data)
        net_name = net_data['name']
        tags = utils.build_v3_tags_payload(net_data)
        admin_state = net_data.get('admin_state_up', True)

        # Create network on the backend
        LOG.debug('create_network: %(net_name)s, %(physical_net)s, '
                  '%(tags)s, %(admin_state)s, %(vlan_id)s',
                  {'net_name': net_name,
                   'physical_net': physical_net,
                   'tags': tags,
                   'admin_state': admin_state,
                   'vlan_id': vlan_id})
        result = nsxlib.create_logical_switch(net_name, physical_net, tags,
                                              admin_state=admin_state,
                                              vlan_id=vlan_id)
        network_id = result['id']
        net_data['id'] = network_id
        return (is_provider_net, net_type, physical_net, vlan_id)

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

    def create_network(self, context, network):
        net_data = network['network']
        external = net_data.get(ext_net_extn.EXTERNAL)
        if attributes.is_attr_set(external) and external:
            is_provider_net, net_type, physical_net, vlan_id = (
                self._validate_external_net_create(net_data))
        else:
            is_provider_net, net_type, physical_net, vlan_id = (
                self._create_network_at_the_backend(context, net_data))
        tenant_id = self._get_tenant_id_for_create(
            context, net_data)

        self._ensure_default_security_group(context, tenant_id)
        with context.session.begin(subtransactions=True):
            # Create network in Neutron
            try:
                created_net = super(NsxV3Plugin, self).create_network(context,
                                                                      network)

                if psec.PORTSECURITY not in net_data:
                    net_data[psec.PORTSECURITY] = True
                self._process_network_port_security_create(
                    context, net_data, created_net)
                self._process_l3_create(context, created_net, net_data)
            except Exception:
                with excutils.save_and_reraise_exception():
                    # Undo creation on the backend
                    LOG.exception(_LE('Failed to create network %s'),
                                  created_net['id'])
                    if net_type != utils.NetworkTypes.L3_EXT:
                        nsxlib.delete_logical_switch(created_net['id'])

            if is_provider_net:
                # Save provider network fields, needed by get_network()
                net_bindings = [nsx_db.add_network_binding(
                    context.session, created_net['id'],
                    net_type, physical_net, vlan_id)]
                self._extend_network_dict_provider(context, created_net,
                                                   bindings=net_bindings)

        return created_net

    def delete_network(self, context, network_id):
        # First call DB operation for delete network as it will perform
        # checks on active ports
        with context.session.begin(subtransactions=True):
            self._process_l3_delete(context, network_id)
            ret_val = super(NsxV3Plugin, self).delete_network(
                context, network_id)
        if not self._network_is_external(context, network_id):
            # TODO(salv-orlando): Handle backend failure, possibly without
            # requiring us to un-delete the DB object. For instance, ignore
            # failures occurring if logical switch is not found
            nsxlib.delete_logical_switch(network_id)
        else:
            # TODO(berlin): delete subnets public announce on the network
            pass
        return ret_val

    def update_network(self, context, id, network):
        original_net = super(NsxV3Plugin, self).get_network(context, id)
        net_data = network['network']
        # Neutron does not support changing provider network values
        pnet._raise_if_updates_provider_attributes(net_data)
        updated_net = super(NsxV3Plugin, self).update_network(context, id,
                                                              network)

        if psec.PORTSECURITY in network['network']:
            self._process_network_port_security_update(
                context, network['network'], updated_net)
        self._process_l3_update(context, updated_net, network['network'])
        self._extend_network_dict_provider(context, updated_net)

        if (not self._network_is_external(context, id) and
            'name' in net_data or 'admin_state_up' in net_data):
            try:
                nsxlib.update_logical_switch(
                    id, name=net_data.get('name'),
                    admin_state=net_data.get('admin_state_up'))
                # Backend does not update the admin state of the ports on
                # the switch when the switch's admin state changes. Do not
                # update the admin state of the ports in neutron either.
            except nsx_exc.ManagerError:
                LOG.exception(_LE("Unable to update NSX backend, rolling "
                                  "back changes on neutron"))
                with excutils.save_and_reraise_exception():
                    super(NsxV3Plugin, self).update_network(
                        context, id, {'network': original_net})

        return updated_net

    def create_subnet(self, context, subnet):
        # TODO(berlin): public external subnet announcement
        return super(NsxV3Plugin, self).create_subnet(context, subnet)

    def delete_subnet(self, context, subnet_id):
        # TODO(berlin): cancel public external subnet announcement
        return super(NsxV3Plugin, self).delete_subnet(context, subnet_id)

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

    def get_network(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            # Get network from Neutron database
            network = self._get_network(context, id)
            # Don't do field selection here otherwise we won't be able to add
            # provider networks fields
            net = self._make_network_dict(network, context=context)
            self._extend_network_dict_provider(context, net)
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
                self._extend_network_dict_provider(context, net)
        return [self._fields(network, fields) for network in networks]

    def _get_data_from_binding_profile(self, context, port):
        if (pbin.PROFILE not in port or
                not attributes.is_attr_set(port[pbin.PROFILE])):
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

    def _create_port_at_the_backend(self, context, neutron_db,
                                    port_data, l2gw_port_check,
                                    psec_is_on):
        tags = utils.build_v3_tags_payload(port_data)
        parent_name, tag = self._get_data_from_binding_profile(
            context, port_data)
        address_bindings = self._build_address_bindings(port_data)
        # FIXME(arosen): we might need to pull this out of the
        # transaction here later.
        vif_uuid = port_data['id']
        attachment_type = nsx_constants.ATTACHMENT_VIF
        if port_data.get('device_owner') == l3_db.DEVICE_OWNER_ROUTER_INTF:
            attachment_type = None
            vif_uuid = None
        # Change the attachment type for L2 gateway owned ports.
        if l2gw_port_check:
            # NSX backend requires the vif id be set to bridge endpoint id
            # for ports plugged into a Bridge Endpoint.
            vif_uuid = port_data.get('device_id')
            attachment_type = port_data.get('device_owner')

        profiles = []
        if psec_is_on and address_bindings:
            profiles = [self._get_port_security_profile_id()]
        if port_data.get('device_owner') == const.DEVICE_OWNER_DHCP:
            if self._dhcp_profile:
                profiles.append(self._dhcp_profile)
            else:
                LOG.warning(_LW("No DHCP switching profile configured in the "
                                "config file. DHCP port: %s configured with "
                                "default profile on the backend"),
                            port_data['id'])

        result = self._port_client.create(
            port_data['network_id'], vif_uuid,
            tags=tags,
            name=port_data['name'],
            admin_state=port_data['admin_state_up'],
            address_bindings=address_bindings,
            attachment_type=attachment_type,
            parent_name=parent_name, parent_tag=tag,
            switch_profile_ids=profiles)

        # TODO(salv-orlando): The logical switch identifier in the
        # mapping object is not necessary anymore.
        nsx_db.add_neutron_nsx_port_mapping(
            context.session, neutron_db['id'],
            neutron_db['network_id'], result['id'])
        return result

    def _create_port_preprocess_security(
            self, context, port, port_data, neutron_db):
        (port_security, has_ip) = self._determine_port_security_and_has_ip(
            context, port_data)
        port_data[psec.PORTSECURITY] = port_security
        self._process_port_port_security_create(
                context, port_data, neutron_db)
        # allowed address pair checks
        if attributes.is_attr_set(port_data.get(addr_pair.ADDRESS_PAIRS)):
            if not port_security:
                raise addr_pair.AddressPairAndPortSecurityRequired()
            else:
                self._process_create_allowed_address_pairs(
                    context, neutron_db,
                    port_data[addr_pair.ADDRESS_PAIRS])
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

    def create_port(self, context, port, l2gw_port_check=False):
        port_data = port['port']
        dhcp_opts = port_data.get(ext_edo.EXTRADHCPOPTS, [])

        # TODO(salv-orlando): Undo logical switch creation on failure
        with context.session.begin(subtransactions=True):
            neutron_db = super(NsxV3Plugin, self).create_port(context, port)
            port["port"].update(neutron_db)

            (is_psec_on, has_ip) = self._create_port_preprocess_security(
                context, port, port_data, neutron_db)
            self._process_portbindings_create_and_update(
                context, port['port'], port_data)
            self._process_port_create_extra_dhcp_opts(
                context, port_data, dhcp_opts)

            if not self._network_is_external(context, port_data['network_id']):
                lport = self._create_port_at_the_backend(
                    context, neutron_db, port_data,
                    l2gw_port_check, is_psec_on)

            # For some reason the port bindings DB mixin does not handle
            # the VNIC_TYPE attribute, which is required by nova for
            # setting up VIFs.
            port_data[pbin.VNIC_TYPE] = pbin.VNIC_NORMAL

            sgids = self._get_security_groups_on_port(context, port)
            self._process_port_create_security_group(
                context, port_data, sgids)
            if sgids:
                security.update_lport_with_security_groups(
                    context, lport['id'], [], sgids)
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
            # Update port to remove security group bindings from the
            # backend and change it's admin state to DOWN
            updated_port = {'port': {ext_sg.SECURITYGROUPS: [],
                                     'admin_state_up': False}}
            _, nsx_lport_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port_id)
            self._update_port_on_backend(context, nsx_lport_id,
                                         port, updated_port,
                                         [], [])
            self._port_client.delete(nsx_port_id)
        self.disassociate_floatingips(context, port_id)
        ret_val = super(NsxV3Plugin, self).delete_port(context, port_id)

        return ret_val

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

    def _update_port_on_backend(self, context, lport_id,
                                original_port, updated_port,
                                address_bindings,
                                switch_profile_ids):
        self._port_client.update(
            lport_id, name=updated_port.get('name'),
            admin_state=updated_port.get('admin_state_up'),
            address_bindings=address_bindings,
            switch_profile_ids=switch_profile_ids)

        security.update_lport_with_security_groups(
            context, lport_id,
            original_port.get(ext_sg.SECURITYGROUPS, []),
            updated_port.get(ext_sg.SECURITYGROUPS, []))

    def update_port(self, context, id, port):
        original_port = super(NsxV3Plugin, self).get_port(context, id)
        _, nsx_lport_id = nsx_db.get_nsx_switch_and_port_id(
            context.session, id)
        switch_profile_ids = None

        with context.session.begin(subtransactions=True):
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
            (port_security, has_ip) = self._determine_port_security_and_has_ip(
                context, updated_port)

        address_bindings = self._build_address_bindings(updated_port)
        if port_security and address_bindings:
            switch_profile_ids = [self._get_port_security_profile_id()]

        try:
            self._update_port_on_backend(context, nsx_lport_id,
                                         original_port, updated_port,
                                         address_bindings,
                                         switch_profile_ids)
        except nsx_exc.ManagerError:
            # In case if there is a failure on NSX-v3 backend, rollback the
            # previous update operation on neutron side.
            LOG.exception(_LE("Unable to update NSX backend, rolling back "
                              "changes on neutron"))
            with excutils.save_and_reraise_exception():
                with context.session.begin(subtransactions=True):
                    super(NsxV3Plugin, self).update_port(
                        context, id, {'port': original_port})
                    if sec_grp_updated:
                        self.update_security_group_on_port(
                            context, id, {'port': original_port}, updated_port,
                            original_port)

        return updated_port

    def _extract_external_gw(self, context, router, is_extract=True):
        r = router['router']
        gw_info = attributes.ATTR_NOT_SPECIFIED
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
            return cfg.CONF.nsx_v3.default_tier0_router_uuid
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

        # TODO(berlin): For nonat user case, we actually don't need a gw port
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
            edge_cluster_uuid, members = self._get_edge_cluster_and_members(
                new_tier0_uuid)
            self._routerlib.update_router_edge_cluster(
                nsx_router_id, edge_cluster_uuid)
            self._routerlib.add_router_link_port(nsx_router_id, new_tier0_uuid,
                                           members)
        if add_snat_rules:
            self._routerlib.add_gw_snat_rule(nsx_router_id, newaddr)
        if bgp_announce:
            # TODO(berlin): bgp announce on new tier0 router
            pass

        if remove_snat_rules or add_snat_rules:
            self._routerlib.update_advertisement(nsx_router_id,
                                           advertise_route_nat_flag,
                                           advertise_route_connected_flag)

    def create_router(self, context, router):
        # TODO(berlin): admin_state_up support
        gw_info = self._extract_external_gw(context, router, is_extract=True)
        tags = utils.build_v3_tags_payload(router['router'])
        result = self._router_client.create(
            display_name=router['router'].get('name'),
            tags=tags)

        with context.session.begin():
            router = super(NsxV3Plugin, self).create_router(
                context, router)
            nsx_db.add_neutron_nsx_router_mapping(
                context.session, router['id'], result['id'])

        if gw_info != attributes.ATTR_NOT_SPECIFIED:
            try:
                self._update_router_gw_info(context, router['id'], gw_info)
            except nsx_exc.ManagerError:
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
        except nsx_exc.ResourceNotFound:
            # If the logical router was not found on the backend do not worry
            # about it. The conditions has already been logged, so there is no
            # need to do further logging
            pass
        except nsx_exc.ManagerError:
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
                      if attributes.is_attr_set(gw_info) and gw_info else None)
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

    def update_router(self, context, router_id, router):
        # TODO(berlin): admin_state_up support
        gw_info = self._extract_external_gw(context, router, is_extract=False)
        router_data = router['router']
        nsx_router_id = None
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
            return super(NsxV3Plugin, self).update_router(
                context, router_id, router)
        except nsx_exc.ResourceNotFound:
            with context.session.begin(subtransactions=True):
                router_db = self._get_router(context, router_id)
                router_db['status'] = const.NET_STATUS_ERROR
            raise nsx_exc.NsxPluginException(
                err_msg=(_("logical router %s not found at the backend")
                         % router_id))
        except nsx_exc.ManagerError:
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

    def _validate_multiple_subnets_diff_routers(self, context, network_id):
        port_filters = {'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                        'network_id': [network_id]}
        intf_ports = self.get_ports(context.elevated(), filters=port_filters)
        router_ids = [port['device_id'] for port in intf_ports]
        router_id_set = set(router_ids)
        if len(router_id_set) >= 2:
            err_msg = _("Subnets on network %s cannot be attached to "
                        "different routers") % network_id
            raise n_exc.InvalidInput(error_message=err_msg)

    def add_router_interface(self, context, router_id, interface_info):

        info = super(NsxV3Plugin, self).add_router_interface(
            context, router_id, interface_info)
        try:
            subnet = self.get_subnet(context, info['subnet_ids'][0])
            port = self.get_port(context, info['port_id'])
            network_id = subnet['network_id']
            # disallow multiple subnets belong to same network being attached
            # to different routers
            self._validate_multiple_subnets_diff_routers(context, network_id)
            nsx_net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port['id'])

            nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                     router_id)
            _ports, address_groups = self._get_ports_and_address_groups(
                context, router_id, network_id)
            self._routerlib.create_logical_router_intf_port_by_ls_id(
                logical_router_id=nsx_router_id,
                ls_id=nsx_net_id,
                logical_switch_port_id=nsx_port_id,
                address_groups=address_groups)

            router_db = self._get_router(context, router_id)
            if router_db.gw_port and not router_db.enable_snat:
                # TODO(berlin): Announce the subnet on tier0 if enable_snat
                # is False
                pass
        except n_exc.InvalidInput:
            with excutils.save_and_reraise_exception():
                super(NsxV3Plugin, self).remove_router_interface(
                    context, router_id, interface_info)
        except nsx_exc.ManagerError:
            with excutils.save_and_reraise_exception():
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
            if not (port['device_owner'] in const.ROUTER_INTERFACE_OWNERS
                    and port['device_id'] == router_id):
                raise l3.RouterInterfaceNotFound(router_id=router_id,
                                                 port_id=port_id)
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
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
                    linked_logical_switch_port_id=new_nsx_port_id,
                    subnets=address_groups)
            else:
                self._router_port_client.delete_by_lswitch_id(nsx_net_id)
        except nsx_exc.ResourceNotFound:
            LOG.error(_LE("router port on router %(router_id)s for net "
                          "%(net_id)s not found at the backend"),
                      {'router_id': router_id,
                       'net_id': subnet['network_id']})
        return super(NsxV3Plugin, self).remove_router_interface(
            context, router_id, interface_info)

    def create_floatingip(self, context, floatingip):
        new_fip = super(NsxV3Plugin, self).create_floatingip(
            context, floatingip)
        router_id = new_fip['router_id']
        if not router_id:
            return new_fip
        try:
            nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                     router_id)
            self._routerlib.add_fip_nat_rules(
                nsx_router_id, new_fip['floating_ip_address'],
                new_fip['fixed_ip_address'])
        except nsx_exc.ManagerError:
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
            except nsx_exc.ResourceNotFound:
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
                except nsx_exc.ResourceNotFound:
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
        except nsx_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                super(NsxV3Plugin, self).update_floatingip(
                    context, fip_id, {'floatingip': {'port_id': old_port_id}})
                self._set_floatingip_status(
                    context, const.FLOATINGIP_STATUS_ERROR)
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
            except nsx_exc.ResourceNotFound:
                LOG.warning(_LW("Backend NAT rules for fip: %(fip_id)s "
                                "(ext_ip: %(ext_ip)s int_ip: %(int_ip)s) "
                                "not found"),
                            {'fip_id': fip_db.id,
                             'ext_ip': fip_db.floating_ip_address,
                             'int_ip': fip_db.fixed_ip_address})

        super(NsxV3Plugin, self).disassociate_floatingips(
            context, port_id, do_notify=False)

    def extend_port_dict_binding(self, port_res, port_db):
        super(NsxV3Plugin, self).extend_port_dict_binding(port_res, port_db)
        port_res[pbin.VNIC_TYPE] = pbin.VNIC_NORMAL

    def create_security_group(self, context, security_group, default_sg=False):
        secgroup = security_group['security_group']
        secgroup['id'] = uuidutils.generate_uuid()

        tags = utils.build_v3_tags_payload(secgroup)
        name = security.get_nsgroup_name(secgroup)
        ns_group = None
        firewall_section = None

        try:
            # NOTE(roeyc): We first create the nsgroup so that once the sg is
            # saved into db its already backed up by an nsx resource.
            ns_group = firewall.create_nsgroup(
                name, secgroup['description'], tags)
            # security-group rules are located in a dedicated firewall section.
            firewall_section = (
                firewall.create_empty_section(
                    name, secgroup.get('description', ''), [ns_group['id']],
                    tags, operation=firewall.INSERT_BEFORE,
                    other_section=self.default_section))

            # REVISIT(roeyc): Ideally, at this point we need not be under an
            # open db transactions, however, unittests fail if omitting
            # subtransactions=True.
            with context.session.begin(subtransactions=True):
                secgroup_db = (
                    super(NsxV3Plugin, self).create_security_group(
                        context, security_group, default_sg))

                security.save_sg_mappings(context.session,
                                          secgroup_db['id'],
                                          ns_group['id'],
                                          firewall_section['id'])
        except nsx_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Unable to create security-group on the "
                                  "backend."))
                if ns_group:
                    firewall.delete_nsgroup(ns_group['id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.debug("Neutron failed to create security-group, "
                          "deleting backend resources: "
                          "section %s, ns-group %s.",
                          firewall_section['id'], ns_group['id'])
                firewall.delete_nsgroup(ns_group['id'])
                firewall.delete_section(firewall_section['id'])
        try:
            sg_rules = secgroup_db['security_group_rules']
            # translate and creates firewall rules.
            rules = security.create_firewall_rules(
                context, firewall_section['id'], ns_group['id'], sg_rules)
            security.save_sg_rule_mappings(context.session, rules['rules'])

            firewall.add_nsgroup_member(self.nsgroup_container,
                                        firewall.NSGROUP, ns_group['id'])
        except nsx_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to create backend firewall rules "
                                  "for security-group %(name)s (%(id)s), "
                                  "rolling back changes."), secgroup_db)
                # default security group deletion requires admin context
                if default_sg:
                    context = context.elevated()
                super(NsxV3Plugin, self).delete_security_group(
                    context, secgroup_db['id'])
                firewall.delete_nsgroup(ns_group['id'])
                firewall.delete_section(firewall_section['id'])

        return secgroup_db

    def update_security_group(self, context, id, security_group):
        nsgroup_id, section_id = security.get_sg_mappings(context.session, id)
        original_security_group = self.get_security_group(
            context, id, fields=['id', 'name', 'description'])
        updated_security_group = (
            super(NsxV3Plugin, self).update_security_group(context, id,
                                                           security_group))
        name = security.get_nsgroup_name(updated_security_group)
        description = updated_security_group['description']
        try:
            firewall.update_nsgroup(nsgroup_id, name, description)
            firewall.update_section(section_id, name, description)
        except nsx_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to update security-group %(name)s "
                                  "(%(id)s), rolling back changes in "
                                  "Neutron."), original_security_group)
                super(NsxV3Plugin, self).update_security_group(
                    context, id, {'security_group': original_security_group})

        return updated_security_group

    def delete_security_group(self, context, id):
        nsgroup_id, section_id = security.get_sg_mappings(context.session, id)
        super(NsxV3Plugin, self).delete_security_group(context, id)
        firewall.delete_section(section_id)
        firewall.remove_nsgroup_member(self.nsgroup_container, nsgroup_id)
        firewall.delete_nsgroup(nsgroup_id)

    def create_security_group_rule(self, context, security_group_rule):
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def create_security_group_rule_bulk(self, context, security_group_rules):
        security_group_rules_db = (
            super(NsxV3Plugin, self).create_security_group_rule_bulk_native(
                context, security_group_rules))
        sg_id = security_group_rules_db[0]['security_group_id']
        nsgroup_id, section_id = security.get_sg_mappings(context.session,
                                                          sg_id)
        try:
            rules = security.create_firewall_rules(
                context, section_id, nsgroup_id, security_group_rules_db)
        except nsx_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                for rule in security_group_rules_db:
                    super(NsxV3Plugin, self).delete_security_group_rule(
                        context, rule['id'])
        security.save_sg_rule_mappings(context.session, rules['rules'])
        return security_group_rules_db

    def delete_security_group_rule(self, context, id):
        rule_db = self._get_security_group_rule(context, id)
        sg_id = rule_db['security_group_id']
        _, section_id = security.get_sg_mappings(context.session, sg_id)
        fw_rule_id = security.get_sg_rule_mapping(context.session, id)
        super(NsxV3Plugin, self).delete_security_group_rule(context, id)
        firewall.delete_rule(section_id, fw_rule_id)
