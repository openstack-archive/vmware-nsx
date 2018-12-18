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
from oslo_log import log as logging
from six import moves

from neutron.db import l3_db
from neutron.extensions import securitygroup as ext_sg
from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings as pbin
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import allowedaddresspairs as addr_exc
from neutron_lib.exceptions import port_security as psec_exc
from neutron_lib.plugins import utils as plugin_utils
from neutron_lib.services.qos import constants as qos_consts
from neutron_lib.utils import net as nl_net_utils

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import extended_security_group as extended_sec
from vmware_nsx.db import nsx_portbindings_db as pbin_db
from vmware_nsx.extensions import maclearning as mac_ext
from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.extensions import secgroup_rule_local_ip_prefix as sg_prefix
from vmware_nsx.plugins.common import plugin
from vmware_nsx.services.qos.common import utils as qos_com_utils
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_utils

from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as nsxlib_consts

LOG = logging.getLogger(__name__)


class NsxPluginV3Base(plugin.NsxPluginBase,
                      extended_sec.ExtendedSecurityGroupPropertiesMixin,
                      pbin_db.NsxPortBindingMixin):
    """Common methods for NSX-V3 plugins (NSX-V3 & Policy)"""

    def __init__(self):
        super(NsxPluginV3Base, self).__init__()
        plugin_cfg = getattr(cfg.CONF, self.cfg_group)
        self._network_vlans = plugin_utils.parse_network_vlan_ranges(
            plugin_cfg.network_vlan_ranges)

    def _get_interface_network(self, context, interface_info):
        is_port, is_sub = self._validate_interface_info(interface_info)
        if is_port:
            net_id = self.get_port(context,
                                   interface_info['port_id'])['network_id']
        elif is_sub:
            net_id = self.get_subnet(context,
                                     interface_info['subnet_id'])['network_id']
        return net_id

    def _fix_sg_rule_dict_ips(self, sg_rule):
        # 0.0.0.0/# is not a valid entry for local and remote so we need
        # to change this to None
        if (sg_rule.get('remote_ip_prefix') and
            sg_rule['remote_ip_prefix'].startswith('0.0.0.0/')):
            sg_rule['remote_ip_prefix'] = None
        if (sg_rule.get(sg_prefix.LOCAL_IP_PREFIX) and
            validators.is_attr_set(sg_rule[sg_prefix.LOCAL_IP_PREFIX]) and
            sg_rule[sg_prefix.LOCAL_IP_PREFIX].startswith('0.0.0.0/')):
            sg_rule[sg_prefix.LOCAL_IP_PREFIX] = None

    def _validate_interface_address_scope(self, context,
                                          router_db, interface_info):
        gw_network_id = (router_db.gw_port.network_id if router_db.gw_port
                         else None)

        subnet = self.get_subnet(context, interface_info['subnet_ids'][0])
        if not router_db.enable_snat and gw_network_id:
            self._validate_address_scope_for_router_interface(
                context.elevated(), router_db.id, gw_network_id, subnet['id'])

    def _validate_ipv4_address_pairs(self, address_pairs):
        for pair in address_pairs:
            ip = pair.get('ip_address')
            if not utils.is_ipv4_ip_address(ip):
                raise nsx_exc.InvalidIPAddress(ip_address=ip)

    def _create_port_address_pairs(self, context, port_data):
        (port_security, has_ip) = self._determine_port_security_and_has_ip(
            context, port_data)

        address_pairs = port_data.get(addr_apidef.ADDRESS_PAIRS)
        if validators.is_attr_set(address_pairs):
            if not port_security:
                raise addr_exc.AddressPairAndPortSecurityRequired()
            else:
                self._validate_ipv4_address_pairs(address_pairs)
                self._process_create_allowed_address_pairs(context, port_data,
                                                           address_pairs)
        else:
            port_data[addr_apidef.ADDRESS_PAIRS] = []

    def _provider_sgs_specified(self, port_data):
        # checks if security groups were updated adding/modifying
        # security groups, port security is set and port has ip
        provider_sgs_specified = (validators.is_attr_set(
            port_data.get(provider_sg.PROVIDER_SECURITYGROUPS)) and
            port_data.get(provider_sg.PROVIDER_SECURITYGROUPS) != [])
        return provider_sgs_specified

    def _create_port_preprocess_security(
            self, context, port, port_data, neutron_db, is_ens_tz_port):
        (port_security, has_ip) = self._determine_port_security_and_has_ip(
            context, port_data)
        port_data[psec.PORTSECURITY] = port_security
        # No port security is allowed if the port belongs to an ENS TZ
        if (port_security and is_ens_tz_port and
            not self._ens_psec_supported()):
            raise nsx_exc.NsxENSPortSecurity()
        self._process_port_port_security_create(
                context, port_data, neutron_db)

        # allowed address pair checks
        self._create_port_address_pairs(context, port_data)

        if port_security and has_ip:
            self._ensure_default_security_group_on_port(context, port)
            (sgids, psgids) = self._get_port_security_groups_lists(
                context, port)
        elif (self._check_update_has_security_groups({'port': port_data}) or
              self._provider_sgs_specified(port_data) or
              self._get_provider_security_groups_on_port(context, port)):
            LOG.error("Port has conflicting port security status and "
                      "security groups")
            raise psec_exc.PortSecurityAndIPRequiredForSecurityGroups()
        else:
            sgids = psgids = []
        port_data[ext_sg.SECURITYGROUPS] = (
            self._get_security_groups_on_port(context, port))
        return port_security, has_ip, sgids, psgids

    def _should_validate_port_sec_on_update_port(self, port_data):
        # Need to determine if we skip validations for port security.
        # This is the edge case when the subnet is deleted.
        # This should be called prior to deleting the fixed ip from the
        # port data
        for fixed_ip in port_data.get('fixed_ips', []):
            if 'delete_subnet' in fixed_ip:
                return False
        return True

    def _update_port_preprocess_security(
            self, context, port, id, updated_port, is_ens_tz_port,
            validate_port_sec=True, direct_vnic_type=False):
        delete_addr_pairs = self._check_update_deletes_allowed_address_pairs(
            port)
        has_addr_pairs = self._check_update_has_allowed_address_pairs(port)
        has_security_groups = self._check_update_has_security_groups(port)
        delete_security_groups = self._check_update_deletes_security_groups(
            port)

        # populate port_security setting
        port_data = port['port']
        if psec.PORTSECURITY not in port_data:
            updated_port[psec.PORTSECURITY] = \
                self._get_port_security_binding(context, id)
        has_ip = self._ip_on_port(updated_port)
        # validate port security and allowed address pairs
        if not updated_port[psec.PORTSECURITY]:
            #  has address pairs in request
            if has_addr_pairs:
                raise addr_exc.AddressPairAndPortSecurityRequired()
            elif not delete_addr_pairs:
                # check if address pairs are in db
                updated_port[addr_apidef.ADDRESS_PAIRS] = (
                    self.get_allowed_address_pairs(context, id))
                if updated_port[addr_apidef.ADDRESS_PAIRS]:
                    raise addr_exc.AddressPairAndPortSecurityRequired()

        if delete_addr_pairs or has_addr_pairs:
            self._validate_ipv4_address_pairs(
                updated_port[addr_apidef.ADDRESS_PAIRS])
            # delete address pairs and read them in
            self._delete_allowed_address_pairs(context, id)
            self._process_create_allowed_address_pairs(
                context, updated_port,
                updated_port[addr_apidef.ADDRESS_PAIRS])

        if updated_port[psec.PORTSECURITY] and psec.PORTSECURITY in port_data:
            # No port security is allowed if the port belongs to an ENS TZ
            if is_ens_tz_port and not self._ens_psec_supported():
                raise nsx_exc.NsxENSPortSecurity()

            # No port security is allowed if the port has a direct vnic type
            if direct_vnic_type:
                err_msg = _("Security features are not supported for "
                            "ports with direct/direct-physical VNIC type")
                raise n_exc.InvalidInput(error_message=err_msg)

        # checks if security groups were updated adding/modifying
        # security groups, port security is set and port has ip
        provider_sgs_specified = self._provider_sgs_specified(updated_port)
        if (validate_port_sec and
            not (has_ip and updated_port[psec.PORTSECURITY])):
            if has_security_groups or provider_sgs_specified:
                LOG.error("Port has conflicting port security status and "
                          "security groups")
                raise psec_exc.PortSecurityAndIPRequiredForSecurityGroups()
            # Update did not have security groups passed in. Check
            # that port does not have any security groups already on it.
            filters = {'port_id': [id]}
            security_groups = (
                super(NsxPluginV3Base, self)._get_port_security_group_bindings(
                    context, filters)
            )
            if security_groups and not delete_security_groups:
                raise psec_exc.PortSecurityPortHasSecurityGroup()

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

    def _validate_create_network(self, context, net_data):
        """Validate the parameters of the new network to be created

        This method includes general validations that does not depend on
        provider attributes, or plugin specific configurations
        """
        external = net_data.get(extnet_apidef.EXTERNAL)
        is_external_net = validators.is_attr_set(external) and external
        with_qos = validators.is_attr_set(
            net_data.get(qos_consts.QOS_POLICY_ID))

        if with_qos:
            self._validate_qos_policy_id(
                context, net_data.get(qos_consts.QOS_POLICY_ID))
            if is_external_net:
                raise nsx_exc.QoSOnExternalNet()

    def _validate_update_network(self, context, id, original_net, net_data):
        """Validate the updated parameters of a network

        This method includes general validations that does not depend on
        provider attributes, or plugin specific configurations
        """
        extern_net = self._network_is_external(context, id)
        with_qos = validators.is_attr_set(
            net_data.get(qos_consts.QOS_POLICY_ID))

        # Do not allow QoS on external networks
        if with_qos and extern_net:
            raise nsx_exc.QoSOnExternalNet()

        # Do not support changing external/non-external networks
        if (extnet_apidef.EXTERNAL in net_data and
            net_data[extnet_apidef.EXTERNAL] != extern_net):
            err_msg = _("Cannot change the router:external flag of a network")
            raise n_exc.InvalidInput(error_message=err_msg)

    def _assert_on_illegal_port_with_qos(self, device_owner):
        # Prevent creating/update port with QoS policy
        # on router-interface/network-dhcp ports.
        if ((device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF or
             device_owner == constants.DEVICE_OWNER_DHCP)):
            err_msg = _("Unable to create or update %s port with a QoS "
                        "policy") % device_owner
            LOG.warning(err_msg)
            raise n_exc.InvalidInput(error_message=err_msg)

    def _assert_on_external_net_with_compute(self, port_data):
        # Prevent creating port with device owner prefix 'compute'
        # on external networks.
        device_owner = port_data.get('device_owner')
        if (device_owner is not None and
            device_owner.startswith(constants.DEVICE_OWNER_COMPUTE_PREFIX)):
            err_msg = _("Unable to update/create a port with an external "
                        "network")
            LOG.warning(err_msg)
            raise n_exc.InvalidInput(error_message=err_msg)

    def _validate_create_port(self, context, port_data):
        self._validate_max_ips_per_port(port_data.get('fixed_ips', []),
                                        port_data.get('device_owner'))

        is_external_net = self._network_is_external(
            context, port_data['network_id'])
        qos_selected = validators.is_attr_set(port_data.get(
            qos_consts.QOS_POLICY_ID))
        device_owner = port_data.get('device_owner')

        # QoS validations
        if qos_selected:
            self._validate_qos_policy_id(
                context, port_data.get(qos_consts.QOS_POLICY_ID))
            self._assert_on_illegal_port_with_qos(device_owner)
            if is_external_net:
                raise nsx_exc.QoSOnExternalNet()

        # External network validations:
        if is_external_net:
            self._assert_on_external_net_with_compute(port_data)

        self._assert_on_port_admin_state(port_data, device_owner)

    def _assert_on_vpn_port_change(self, port_data):
        if port_data['device_owner'] == ipsec_utils.VPN_PORT_OWNER:
            msg = _('Can not update/delete VPNaaS port %s') % port_data['id']
            raise n_exc.InvalidInput(error_message=msg)

    def _assert_on_lb_port_fixed_ip_change(self, port_data, orig_dev_own):
        if orig_dev_own == constants.DEVICE_OWNER_LOADBALANCERV2:
            if "fixed_ips" in port_data and port_data["fixed_ips"]:
                msg = _('Can not update Loadbalancer port with fixed IP')
                raise n_exc.InvalidInput(error_message=msg)

    def _assert_on_device_owner_change(self, port_data, orig_dev_own):
        """Prevent illegal device owner modifications
        """
        if orig_dev_own == constants.DEVICE_OWNER_LOADBALANCERV2:
            if ("allowed_address_pairs" in port_data and
                    port_data["allowed_address_pairs"]):
                msg = _('Loadbalancer port can not be updated '
                        'with address pairs')
                raise n_exc.InvalidInput(error_message=msg)

        if 'device_owner' not in port_data:
            return
        new_dev_own = port_data['device_owner']
        if new_dev_own == orig_dev_own:
            return

        err_msg = (_("Changing port device owner '%(orig)s' to '%(new)s' is "
                     "not allowed") % {'orig': orig_dev_own,
                                       'new': new_dev_own})

        # Do not allow changing nova <-> neutron device owners
        if ((orig_dev_own.startswith(constants.DEVICE_OWNER_COMPUTE_PREFIX) and
             new_dev_own.startswith(constants.DEVICE_OWNER_NETWORK_PREFIX)) or
            (orig_dev_own.startswith(constants.DEVICE_OWNER_NETWORK_PREFIX) and
             new_dev_own.startswith(constants.DEVICE_OWNER_COMPUTE_PREFIX))):
            raise n_exc.InvalidInput(error_message=err_msg)

        # Do not allow removing the device owner in some cases
        if orig_dev_own == constants.DEVICE_OWNER_DHCP:
            raise n_exc.InvalidInput(error_message=err_msg)

    def _assert_on_port_sec_change(self, port_data, device_owner):
        """Do not allow enabling port security/mac learning of some ports

        Trusted ports are created with port security and mac learning disabled
        in neutron, and it should not change.
        """
        if nl_net_utils.is_port_trusted({'device_owner': device_owner}):
            if port_data.get(psec.PORTSECURITY) is True:
                err_msg = _("port_security_enabled=True is not supported for "
                            "trusted ports")
                LOG.warning(err_msg)
                raise n_exc.InvalidInput(error_message=err_msg)

            mac_learning = port_data.get(mac_ext.MAC_LEARNING)
            if (validators.is_attr_set(mac_learning) and mac_learning is True):
                err_msg = _("mac_learning_enabled=True is not supported for "
                            "trusted ports")
                LOG.warning(err_msg)
                raise n_exc.InvalidInput(error_message=err_msg)

    def _validate_update_port(self, context, id, original_port, port_data):
        qos_selected = validators.is_attr_set(port_data.get
                                              (qos_consts.QOS_POLICY_ID))
        is_external_net = self._network_is_external(
            context, original_port['network_id'])
        device_owner = (port_data['device_owner']
                        if 'device_owner' in port_data
                        else original_port.get('device_owner'))

        # QoS validations
        if qos_selected:
            self._validate_qos_policy_id(
                context, port_data.get(qos_consts.QOS_POLICY_ID))
            if is_external_net:
                raise nsx_exc.QoSOnExternalNet()
            self._assert_on_illegal_port_with_qos(device_owner)

        # External networks validations:
        if is_external_net:
            self._assert_on_external_net_with_compute(port_data)

        # Device owner validations:
        orig_dev_owner = original_port.get('device_owner')
        self._assert_on_device_owner_change(port_data, orig_dev_owner)
        self._assert_on_port_admin_state(port_data, device_owner)
        self._assert_on_port_sec_change(port_data, device_owner)
        self._validate_max_ips_per_port(
            port_data.get('fixed_ips', []), device_owner)
        self._assert_on_vpn_port_change(original_port)
        self._assert_on_lb_port_fixed_ip_change(port_data, orig_dev_owner)

    def _get_dhcp_port_name(self, net_name, net_id):
        return utils.get_name_and_uuid('%s-%s' % ('dhcp',
                                                  net_name or 'network'),
                                       net_id)

    def _build_port_name(self, context, port_data):
        device_owner = port_data.get('device_owner')
        device_id = port_data.get('device_id')
        if device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF and device_id:
            router = self._get_router(context, device_id)
            name = utils.get_name_and_uuid(
                router['name'] or 'router', port_data['id'], tag='port')
        elif device_owner == constants.DEVICE_OWNER_DHCP:
            network = self.get_network(context, port_data['network_id'])
            name = self._get_dhcp_port_name(network['name'],
                                            network['id'])
        elif device_owner.startswith(constants.DEVICE_OWNER_COMPUTE_PREFIX):
            name = utils.get_name_and_uuid(
                port_data['name'] or 'instance-port', port_data['id'])
        else:
            name = port_data['name']
        return name

    def _validate_external_net_create(self, net_data, default_tier0_router,
                                      tier0_validator=None):
        """Validate external network configuration

        Returns a tuple of:
        - Boolean is provider network (always True)
        - Network type (always L3_EXT)
        - tier 0 router id
        - vlan id
        """
        if not validators.is_attr_set(net_data.get(pnet.PHYSICAL_NETWORK)):
            tier0_uuid = default_tier0_router
        else:
            tier0_uuid = net_data[pnet.PHYSICAL_NETWORK]
        if ((validators.is_attr_set(net_data.get(pnet.NETWORK_TYPE)) and
             net_data.get(pnet.NETWORK_TYPE) != utils.NetworkTypes.L3_EXT and
             net_data.get(pnet.NETWORK_TYPE) != utils.NetworkTypes.LOCAL) or
            validators.is_attr_set(net_data.get(pnet.SEGMENTATION_ID))):
            msg = (_("External network cannot be created with %s provider "
                     "network or segmentation id") %
                   net_data.get(pnet.NETWORK_TYPE))
            raise n_exc.InvalidInput(error_message=msg)
        if tier0_validator:
            tier0_validator(tier0_uuid)
        return (True, utils.NetworkTypes.L3_EXT, tier0_uuid, 0)

    def _extend_network_dict_provider(self, context, network, bindings=None):
        """Add network provider fields to the network dict from the DB"""
        if 'id' not in network:
            return
        if not bindings:
            bindings = nsx_db.get_network_bindings(context.session,
                                                   network['id'])

        # With NSX plugin, "normal" overlay networks will have no binding
        if bindings:
            # Network came in through provider networks API
            network[pnet.NETWORK_TYPE] = bindings[0].binding_type
            network[pnet.PHYSICAL_NETWORK] = bindings[0].phy_uuid
            network[pnet.SEGMENTATION_ID] = bindings[0].vlan_id

    def _extend_get_network_dict_provider(self, context, network):
        self._extend_network_dict_provider(context, network)
        network[qos_consts.QOS_POLICY_ID] = (qos_com_utils.
            get_network_policy_id(context, network['id']))

    def get_network(self, context, id, fields=None):
        with db_api.CONTEXT_READER.using(context):
            # Get network from Neutron database
            network = self._get_network(context, id)
            # Don't do field selection here otherwise we won't be able to add
            # provider networks fields
            net = self._make_network_dict(network, context=context)
            self._extend_get_network_dict_provider(context, net)
        return db_utils.resource_fields(net, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        # Get networks from Neutron database
        filters = filters or {}
        with db_api.CONTEXT_READER.using(context):
            networks = super(NsxPluginV3Base, self).get_networks(
                context, filters, fields, sorts,
                limit, marker, page_reverse)
            # Add provider network fields
            for net in networks:
                self._extend_get_network_dict_provider(context, net)
        return (networks if not fields else
                [db_utils.resource_fields(network,
                                          fields) for network in networks])

    def _assert_on_ens_with_qos(self, net_data):
        qos_id = net_data.get(qos_consts.QOS_POLICY_ID)
        if validators.is_attr_set(qos_id):
            err_msg = _("Cannot configure QOS on ENS networks")
            raise n_exc.InvalidInput(error_message=err_msg)

    def _ens_psec_supported(self):
        """Should be implemented by each plugin"""
        pass

    def _get_nsx_net_tz_id(self, nsx_net):
        """Should be implemented by each plugin"""
        pass

    def _validate_ens_net_portsecurity(self, net_data):
        """Validate/Update the port security of the new network for ENS TZ
        Should be implemented by the plugin if necessary
        """
        pass

    def _generate_segment_id(self, context, physical_network, net_data):
        bindings = nsx_db.get_network_bindings_by_phy_uuid(
            context.session, physical_network)
        vlan_ranges = self._network_vlans.get(physical_network, [])
        if vlan_ranges:
            vlan_ids = set()
            for vlan_min, vlan_max in vlan_ranges:
                vlan_ids |= set(moves.range(vlan_min, vlan_max + 1))
        else:
            vlan_min = constants.MIN_VLAN_TAG
            vlan_max = constants.MAX_VLAN_TAG
            vlan_ids = set(moves.range(vlan_min, vlan_max + 1))
        used_ids_in_range = set([binding.vlan_id for binding in bindings
                                 if binding.vlan_id in vlan_ids])
        free_ids = list(vlan_ids ^ used_ids_in_range)
        if len(free_ids) == 0:
            raise n_exc.NoNetworkAvailable()
        net_data[pnet.SEGMENTATION_ID] = free_ids[0]
        return net_data[pnet.SEGMENTATION_ID]

    def _validate_provider_create(self, context, network_data,
                                  default_vlan_tz_uuid,
                                  default_overlay_tz_uuid,
                                  nsxlib_tz, nsxlib_network,
                                  transparent_vlan=False):
        """Validate the parameters of a new provider network

        raises an error if illegal
        returns a dictionary with the relevant processed data:
        - is_provider_net: boolean
        - net_type: provider network type or None
        - physical_net: the uuid of the relevant transport zone or None
        - vlan_id: vlan tag, 0 or None
        - switch_mode: standard ot ENS
        """
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

        if vlan_id and transparent_vlan:
            err_msg = (_("Segmentation ID cannot be set with transparent "
                         "vlan!"))
            raise n_exc.InvalidInput(error_message=err_msg)

        err_msg = None
        net_type = network_data.get(pnet.NETWORK_TYPE)
        tz_type = nsxlib_consts.TRANSPORT_TYPE_VLAN
        switch_mode = nsxlib_consts.HOST_SWITCH_MODE_STANDARD
        if validators.is_attr_set(net_type):
            if net_type == utils.NsxV3NetworkTypes.FLAT:
                if vlan_id is not None:
                    err_msg = (_("Segmentation ID cannot be specified with "
                                 "%s network type") %
                               utils.NsxV3NetworkTypes.FLAT)
                else:
                    if not transparent_vlan:
                        # Set VLAN id to 0 for flat networks
                        vlan_id = '0'
                    if physical_net is None:
                        physical_net = default_vlan_tz_uuid
            elif net_type == utils.NsxV3NetworkTypes.VLAN:
                # Use default VLAN transport zone if physical network not given
                if physical_net is None:
                    physical_net = default_vlan_tz_uuid

                if not transparent_vlan:
                    # Validate VLAN id
                    if not vlan_id:
                        vlan_id = self._generate_segment_id(context,
                                                            physical_net,
                                                            network_data)
                    elif not plugin_utils.is_valid_vlan_tag(vlan_id):
                        err_msg = (_('Segmentation ID %(seg_id)s out of '
                                     'range (%(min_id)s through %(max_id)s)') %
                                   {'seg_id': vlan_id,
                                    'min_id': constants.MIN_VLAN_TAG,
                                    'max_id': constants.MAX_VLAN_TAG})
                    else:
                        # Verify VLAN id is not already allocated
                        bindings = nsx_db.\
                            get_network_bindings_by_vlanid_and_physical_net(
                                context.session, vlan_id, physical_net)
                        if bindings:
                            raise n_exc.VlanIdInUse(
                                vlan_id=vlan_id, physical_network=physical_net)
            elif net_type == utils.NsxV3NetworkTypes.GENEVE:
                if vlan_id:
                    err_msg = (_("Segmentation ID cannot be specified with "
                                 "%s network type") %
                               utils.NsxV3NetworkTypes.GENEVE)
                tz_type = nsxlib_consts.TRANSPORT_TYPE_OVERLAY
            elif net_type == utils.NsxV3NetworkTypes.NSX_NETWORK:
                # Linking neutron networks to an existing NSX logical switch
                if not physical_net:
                    err_msg = (_("Physical network must be specified with "
                                 "%s network type") % net_type)
                # Validate the logical switch existence
                else:
                    try:
                        nsx_net = nsxlib_network.get(physical_net)
                        tz_id = self._get_nsx_net_tz_id(nsx_net)
                        switch_mode = nsxlib_tz.get_host_switch_mode(tz_id)
                    except nsx_lib_exc.ResourceNotFound:
                        err_msg = (_('Logical switch %s does not exist') %
                                   physical_net)
                    # make sure no other neutron network is using it
                    bindings = (
                        nsx_db.get_network_bindings_by_vlanid_and_physical_net(
                            context.elevated().session, 0, physical_net))
                    if bindings:
                        err_msg = (_('Logical switch %s is already used by '
                                     'another network') % physical_net)
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

        if physical_net is None:
            # Default to transport type overlay
            physical_net = default_overlay_tz_uuid

        # validate the transport zone existence and type
        if (not err_msg and physical_net and
            net_type != utils.NsxV3NetworkTypes.NSX_NETWORK):
            if is_provider_net:
                try:
                    backend_type = nsxlib_tz.get_transport_type(
                        physical_net)
                except nsx_lib_exc.ResourceNotFound:
                    err_msg = (_('Transport zone %s does not exist') %
                               physical_net)
                else:
                    if backend_type != tz_type:
                        err_msg = (_('%(tz)s transport zone is required for '
                                     'creating a %(net)s provider network') %
                                   {'tz': tz_type, 'net': net_type})
            if not err_msg:
                switch_mode = nsxlib_tz.get_host_switch_mode(physical_net)

        if err_msg:
            raise n_exc.InvalidInput(error_message=err_msg)

        if (switch_mode == nsxlib_consts.HOST_SWITCH_MODE_ENS):
            if not self._allow_ens_networks():
                raise NotImplementedError(_("ENS support is disabled"))
            self._assert_on_ens_with_qos(network_data)
            self._validate_ens_net_portsecurity(network_data)

        return {'is_provider_net': is_provider_net,
                'net_type': net_type,
                'physical_net': physical_net,
                'vlan_id': vlan_id,
                'switch_mode': switch_mode}

    def _network_is_nsx_net(self, context, network_id):
        bindings = nsx_db.get_network_bindings(context.session, network_id)
        if not bindings:
            return False
        return (bindings[0].binding_type ==
                utils.NsxV3NetworkTypes.NSX_NETWORK)

    def _vif_type_by_vnic_type(self, direct_vnic_type):
        return (nsx_constants.VIF_TYPE_DVS if direct_vnic_type
            else pbin.VIF_TYPE_OVS)

    def _get_network_segmentation_id(self, context, neutron_id):
        bindings = nsx_db.get_network_bindings(context.session, neutron_id)
        if bindings:
            return bindings[0].vlan_id

    def _extend_nsx_port_dict_binding(self, context, port_data):
        # Not using the register api for this because we need the context
        # Some attributes were already initialized by _extend_port_portbinding
        if pbin.VIF_TYPE not in port_data:
            port_data[pbin.VIF_TYPE] = pbin.VIF_TYPE_OVS
        if pbin.VNIC_TYPE not in port_data:
            port_data[pbin.VNIC_TYPE] = pbin.VNIC_NORMAL
        if 'network_id' in port_data:
            net_id = port_data['network_id']
            if pbin.VIF_DETAILS not in port_data:
                port_data[pbin.VIF_DETAILS] = {}
            port_data[pbin.VIF_DETAILS][pbin.OVS_HYBRID_PLUG] = False
            if (port_data.get('device_owner') ==
                constants.DEVICE_OWNER_FLOATINGIP):
                # floatingip belongs to an external net without nsx-id
                port_data[pbin.VIF_DETAILS]['nsx-logical-switch-id'] = None
            else:
                port_data[pbin.VIF_DETAILS]['nsx-logical-switch-id'] = (
                    self._get_network_nsx_id(context, net_id))
            if port_data[pbin.VNIC_TYPE] != pbin.VNIC_NORMAL:
                port_data[pbin.VIF_DETAILS]['segmentation-id'] = (
                    self._get_network_segmentation_id(context, net_id))

    def fix_direct_vnic_port_sec(self, direct_vnic_type, port_data):
        if direct_vnic_type:
            if validators.is_attr_set(port_data.get(psec.PORTSECURITY)):
                # 'direct' and 'direct-physical' vnic types ports requires
                # port-security to be disabled.
                if port_data[psec.PORTSECURITY]:
                    err_msg = _("Security features are not supported for "
                                "ports with direct/direct-physical VNIC "
                                "type")
                    raise n_exc.InvalidInput(error_message=err_msg)
            else:
                # Implicitly disable port-security for direct vnic types.
                port_data[psec.PORTSECURITY] = False

    def _validate_network_type(self, context, network_id, net_types):
        net = self.get_network(context, network_id)
        if net.get(pnet.NETWORK_TYPE) in net_types:
            return True
        return False

    def _revert_neutron_port_update(self, context, port_id,
                                    original_port, updated_port,
                                    port_security, sec_grp_updated):
        # revert the neutron port update
        super(NsxPluginV3Base, self).update_port(context, port_id,
                                                 {'port': original_port})
        # revert allowed address pairs
        if port_security:
            orig_pair = original_port.get(addr_apidef.ADDRESS_PAIRS)
            updated_pair = updated_port.get(addr_apidef.ADDRESS_PAIRS)
            if orig_pair != updated_pair:
                self._delete_allowed_address_pairs(context, port_id)
            if orig_pair:
                self._process_create_allowed_address_pairs(
                    context, original_port, orig_pair)
        # revert the security groups modifications
        if sec_grp_updated:
            self.update_security_group_on_port(
                context, port_id, {'port': original_port},
                updated_port, original_port)

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

    def _validate_router_gw(self, context, router_id, info, org_enable_snat):
        # Ensure that a router cannot have SNAT disabled if there are
        # floating IP's assigned
        if (info and 'enable_snat' in info and
            org_enable_snat != info.get('enable_snat') and
            info.get('enable_snat') is False and
            self.router_gw_port_has_floating_ips(context, router_id)):
            msg = _("Unable to set SNAT disabled. Floating IPs assigned")
            raise n_exc.InvalidInput(error_message=msg)

    def _get_update_router_gw_actions(
        self,
        org_tier0_uuid, orgaddr, org_enable_snat,
        new_tier0_uuid, newaddr, new_enable_snat, lb_exist, fw_exist):
        """Return a dictionary of flags indicating which actions should be
           performed on this router GW update.
        """
        actions = {}
        # Remove router link port between tier1 and tier0 if tier0 router link
        # is removed or changed
        actions['remove_router_link_port'] = (
            org_tier0_uuid and
            (not new_tier0_uuid or org_tier0_uuid != new_tier0_uuid))

        # Remove SNAT rules for gw ip if gw ip is deleted/changed or
        # enable_snat is updated from True to False
        actions['remove_snat_rules'] = (
            org_enable_snat and orgaddr and
            (newaddr != orgaddr or not new_enable_snat))

        # Remove No-DNAT rules if GW was removed or snat was disabled
        actions['remove_no_dnat_rules'] = (
            orgaddr and org_enable_snat and
            (not newaddr or not new_enable_snat))

        # Revocate bgp announce for nonat subnets if tier0 router link is
        # changed or enable_snat is updated from False to True
        actions['revocate_bgp_announce'] = (
            not org_enable_snat and org_tier0_uuid and
            (new_tier0_uuid != org_tier0_uuid or new_enable_snat))

        # Add router link port between tier1 and tier0 if tier0 router link is
        # added or changed to a new one
        actions['add_router_link_port'] = (
            new_tier0_uuid and
            (not org_tier0_uuid or org_tier0_uuid != new_tier0_uuid))

        # Add SNAT rules for gw ip if gw ip is add/changed or
        # enable_snat is updated from False to True
        actions['add_snat_rules'] = (
            new_enable_snat and newaddr and
            (newaddr != orgaddr or not org_enable_snat))

        # Add No-DNAT rules if GW was added, and the router has SNAT enabled,
        # or if SNAT was enabled
        actions['add_no_dnat_rules'] = (
            new_enable_snat and newaddr and
            (not orgaddr or not org_enable_snat))

        # Bgp announce for nonat subnets if tier0 router link is changed or
        # enable_snat is updated from True to False
        actions['bgp_announce'] = (
            not new_enable_snat and new_tier0_uuid and
            (new_tier0_uuid != org_tier0_uuid or not org_enable_snat))

        # Advertise NAT routes if enable SNAT to support FIP. In the NoNAT
        # use case, only NSX connected routes need to be advertised.
        actions['advertise_route_nat_flag'] = (
            True if new_enable_snat else False)
        actions['advertise_route_connected_flag'] = (
            True if not new_enable_snat else False)

        # the purpose of the two vars is to be able to differ between
        # adding a gateway w/o snat and adding snat (when adding/removing gw
        # the snat option is on by default.

        real_new_enable_snat = new_enable_snat and newaddr
        real_org_enable_snat = org_enable_snat and orgaddr

        actions['add_service_router'] = ((real_new_enable_snat and
                                          not real_org_enable_snat) or
                                         (real_new_enable_snat and not
                                         orgaddr and newaddr)
                                         ) and not (fw_exist or lb_exist)
        actions['remove_service_router'] = ((not real_new_enable_snat and
                                             real_org_enable_snat) or (
                orgaddr and not newaddr)) and not (fw_exist or lb_exist)

        return actions
