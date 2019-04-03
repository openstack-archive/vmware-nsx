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
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy import exc as sql_exc
import webob.exc

from six import moves
from six import string_types

from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db.availability_zone import router as router_az_db
from neutron.db import db_base_plugin_v2
from neutron.db import dns_db
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
from neutron.db import l3_attrs_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import portsecurity_db
from neutron.db import securitygroups_db
from neutron.db import vlantransparent_db
from neutron.extensions import securitygroup as ext_sg
from neutron_lib.agent import topics
from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import extra_dhcp_opt as ext_edo
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings as pbin
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api import faults
from neutron_lib.api import validators
from neutron_lib.api.validators import availability_zone as az_validator
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import allowedaddresspairs as addr_exc
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.exceptions import port_security as psec_exc
from neutron_lib.plugins import utils as plugin_utils
from neutron_lib import rpc as n_rpc
from neutron_lib.services.qos import constants as qos_consts
from neutron_lib.utils import helpers
from neutron_lib.utils import net as nl_net_utils

from vmware_nsx.common import availability_zones as nsx_com_az
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import locking
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import extended_security_group as extended_sec
from vmware_nsx.db import extended_security_group_rule as extend_sg_rule
from vmware_nsx.db import maclearning as mac_db
from vmware_nsx.db import nsx_portbindings_db as pbin_db
from vmware_nsx.extensions import advancedserviceproviders as as_providers
from vmware_nsx.extensions import maclearning as mac_ext
from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.extensions import secgroup_rule_local_ip_prefix as sg_prefix
from vmware_nsx.plugins.common import plugin
from vmware_nsx.services.qos.common import utils as qos_com_utils
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_utils

from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as nsxlib_consts
from vmware_nsxlib.v3 import utils as nsxlib_utils

LOG = logging.getLogger(__name__)


# NOTE(asarfaty): the order of inheritance here is important. in order for the
# QoS notification to work, the AgentScheduler init must be called first
# NOTE(arosen): same is true with the ExtendedSecurityGroupPropertiesMixin
# this needs to be above securitygroups_db.SecurityGroupDbMixin.
# FIXME(arosen): we can solve this inheritance order issue by just mixining in
# the classes into a new class to handle the order correctly.
class NsxPluginV3Base(agentschedulers_db.AZDhcpAgentSchedulerDbMixin,
                      addr_pair_db.AllowedAddressPairsMixin,
                      plugin.NsxPluginBase,
                      extended_sec.ExtendedSecurityGroupPropertiesMixin,
                      pbin_db.NsxPortBindingMixin,
                      extend_sg_rule.ExtendedSecurityGroupRuleMixin,
                      securitygroups_db.SecurityGroupDbMixin,
                      external_net_db.External_net_db_mixin,
                      extraroute_db.ExtraRoute_db_mixin,
                      router_az_db.RouterAvailabilityZoneMixin,
                      l3_gwmode_db.L3_NAT_db_mixin,
                      portbindings_db.PortBindingMixin,
                      portsecurity_db.PortSecurityDbMixin,
                      extradhcpopt_db.ExtraDhcpOptMixin,
                      dns_db.DNSDbMixin,
                      vlantransparent_db.Vlantransparent_db_mixin,
                      mac_db.MacLearningDbMixin,
                      l3_attrs_db.ExtraAttributesMixin,
                      nsx_com_az.NSXAvailabilityZonesPluginCommon):
    """Common methods for NSX-V3 plugins (NSX-V3 & Policy)"""

    def __init__(self):

        super(NsxPluginV3Base, self).__init__()
        self._network_vlans = plugin_utils.parse_network_vlan_ranges(
            self._get_conf_attr('network_vlan_ranges'))
        self._native_dhcp_enabled = False
        self.start_rpc_listeners_called = False

    def _init_native_dhcp(self):
        if not self.nsxlib:
            self._native_dhcp_enabled = False
            return

        self._native_dhcp_enabled = True
        for az in self.get_azs_list():
            if not az._native_dhcp_profile_uuid:
                LOG.error("Unable to retrieve DHCP Profile %s for "
                          "availability zone %s, "
                          "native DHCP service is not supported",
                          az.name, az.dhcp_profile)
                self._native_dhcp_enabled = False

    def _init_native_metadata(self):
        if not self.nsxlib:
            return

        for az in self.get_azs_list():
            if not az._native_md_proxy_uuid:
                LOG.error("Unable to retrieve Metadata Proxy %s for "
                          "availability zone %s, "
                          "native metadata service is not supported",
                          az.name, az.metadata_proxy)

    def _extend_fault_map(self):
        """Extends the Neutron Fault Map.

        Exceptions specific to the NSX Plugin are mapped to standard
        HTTP Exceptions.
        """
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
                                 nsx_exc.NsxENSPortSecurity:
                                 webob.exc.HTTPBadRequest,
                                 nsx_exc.NsxPluginTemporaryError:
                                 webob.exc.HTTPServiceUnavailable
                                 })

    def _get_conf_attr(self, attr):
        plugin_cfg = getattr(cfg.CONF, self.cfg_group)
        return getattr(plugin_cfg, attr)

    def _setup_rpc(self):
        """Should be implemented by each plugin"""
        pass

    def start_rpc_listeners(self):
        if self.start_rpc_listeners_called:
            # If called more than once - we should not create it again
            return self.conn.consume_in_threads()

        self._setup_rpc()
        self.topic = topics.PLUGIN
        self.conn = n_rpc.Connection()
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        self.conn.create_consumer(topics.REPORTS,
                                  [agents_db.AgentExtRpcCallback()],
                                  fanout=False)
        self.start_rpc_listeners_called = True

        return self.conn.consume_in_threads()

    def _get_interface_subnet(self, context, interface_info):
        is_port, is_sub = self._validate_interface_info(interface_info)

        subnet_id = None
        if is_sub:
            subnet_id = interface_info.get('subnet_id')

        if not subnet_id:
            port_id = interface_info['port_id']
            port = self.get_port(context, port_id)
            if 'fixed_ips' in port and port['fixed_ips']:
                if len(port['fixed_ips'][0]) > 1:
                    # This should never happen since router interface is per
                    # IP version, and we allow single fixed ip per ip version
                    return
                subnet_id = port['fixed_ips'][0]['subnet_id']

        if subnet_id:
            return self.get_subnet(context, subnet_id)

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

    def _validate_address_pairs(self, address_pairs):
        for pair in address_pairs:
            ip = pair.get('ip_address')
            if len(ip.split('/')) > 1:
                LOG.error("cidr is not supported in allowed address pairs")
                raise nsx_exc.InvalidIPAddress(ip_address=ip)

    def _validate_number_of_address_pairs(self, port):
        address_pairs = port.get(addr_apidef.ADDRESS_PAIRS)
        num_allowed_on_backend = nsxlib_consts.NUM_ALLOWED_IP_ADDRESSES
        # Counting existing ports to take into account. If no fixed ips
        # are defined - we set it to 3 in order to reserve 2 fixed and another
        # for DHCP.

        existing_fixed_ips = len(port.get('fixed_ips', []))
        if existing_fixed_ips == 0:
            existing_fixed_ips = 3
        else:
            existing_fixed_ips += 1
        if address_pairs:
            if (len(address_pairs) + existing_fixed_ips >=
                    num_allowed_on_backend):
                err_msg = (_(
                    "Number of Address pairs is limited at the backend to %("
                    "backend)s. Existing and requested %("
                    "existing_and_requested)s") %
                           {'backend': nsxlib_consts.NUM_ALLOWED_IP_ADDRESSES,
                            'existing_and_requested': existing_fixed_ips +
                            len(address_pairs)})
                raise n_exc.InvalidInput(error_message=err_msg)

    def _create_port_address_pairs(self, context, port_data):
        (port_security, has_ip) = self._determine_port_security_and_has_ip(
            context, port_data)

        address_pairs = port_data.get(addr_apidef.ADDRESS_PAIRS)
        if validators.is_attr_set(address_pairs):
            if not port_security:
                raise addr_exc.AddressPairAndPortSecurityRequired()
            else:
                self._validate_address_pairs(address_pairs)
                self._validate_number_of_address_pairs(port_data)
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
            self._validate_address_pairs(
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

    def _validate_update_network(self, context, net_id, original_net,
                                 net_data):
        """Validate the updated parameters of a network

        This method includes general validations that does not depend on
        provider attributes, or plugin specific configurations
        """
        extern_net = self._network_is_external(context, net_id)
        with_qos = validators.is_attr_set(
            net_data.get(qos_consts.QOS_POLICY_ID))

        # Do not allow QoS on external networks
        if with_qos:
            if extern_net:
                raise nsx_exc.QoSOnExternalNet()
            self._validate_qos_policy_id(
                context, net_data.get(qos_consts.QOS_POLICY_ID))

        # Do not support changing external/non-external networks
        if (extnet_apidef.EXTERNAL in net_data and
            net_data[extnet_apidef.EXTERNAL] != extern_net):
            err_msg = _("Cannot change the router:external flag of a network")
            raise n_exc.InvalidInput(error_message=err_msg)

        is_ens_net = self._is_ens_tz_net(context, net_id)
        if is_ens_net:
            self._assert_on_ens_with_qos(net_data)

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

    def _validate_ens_create_port(self, context, port_data):
        qos_selected = validators.is_attr_set(port_data.get(
            qos_consts.QOS_POLICY_ID))
        if qos_selected:
            err_msg = _("Cannot configure QOS on ENS networks")
            raise n_exc.InvalidInput(error_message=err_msg)

    def _assert_on_port_admin_state(self, port_data, device_owner):
        """Do not allow changing the admin state of some ports"""
        if (device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF or
            device_owner == l3_db.DEVICE_OWNER_ROUTER_GW):
            if port_data.get("admin_state_up") is False:
                err_msg = _("admin_state_up=False router ports are not "
                            "supported")
                LOG.warning(err_msg)
                raise n_exc.InvalidInput(error_message=err_msg)

    def _validate_max_ips_per_port(self, context, fixed_ip_list, device_owner):
        """Validate the number of fixed ips on a port

        Do not allow multiple ip addresses on a port since the nsx backend
        cannot add multiple static dhcp bindings with the same port
        """
        if (device_owner and
            nl_net_utils.is_port_trusted({'device_owner': device_owner})):
            return

        if not validators.is_attr_set(fixed_ip_list):
            return

        msg = _('Exceeded maximum amount of fixed ips per port and ip version')
        if len(fixed_ip_list) > 2:
            raise n_exc.InvalidInput(error_message=msg)

        if len(fixed_ip_list) < 2:
            return

        def get_fixed_ip_version(i):
            if 'ip_address' in fixed_ip_list[i]:
                return netaddr.IPAddress(
                    fixed_ip_list[i]['ip_address']).version
            if 'subnet_id' in fixed_ip_list[i]:
                subnet = self.get_subnet(context.elevated(),
                                         fixed_ip_list[i]['subnet_id'])
                return subnet['ip_version']

        ipver1 = get_fixed_ip_version(0)
        ipver2 = get_fixed_ip_version(1)
        if ipver1 and ipver2 and ipver1 != ipver2:
            # One fixed IP is allowed for each IP version
            return

        raise n_exc.InvalidInput(error_message=msg)

    def _get_subnets_for_fixed_ips_on_port(self, context, port_data):
        # get the subnet id from the fixed ips of the port
        if 'fixed_ips' in port_data and port_data['fixed_ips']:
            subnet_ids = (fixed_ip['subnet_id']
                          for fixed_ip in port_data['fixed_ips'])

        # check only dhcp enabled subnets
        return (self.get_subnet(context.elevated(), subnet_id)
                for subnet_id in subnet_ids)

    def _validate_create_port(self, context, port_data):
        self._validate_max_ips_per_port(context,
                                        port_data.get('fixed_ips', []),
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

            is_ens_tz_port = self._is_ens_tz_port(context, port_data)
            if is_ens_tz_port:
                self._validate_ens_create_port(context, port_data)

        # External network validations:
        if is_external_net:
            self._assert_on_external_net_with_compute(port_data)

        self._assert_on_port_admin_state(port_data, device_owner)
        self._validate_extra_dhcp_options(port_data.get(ext_edo.EXTRADHCPOPTS))

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
            is_ens_tz_port = self._is_ens_tz_port(context, original_port)
            if is_ens_tz_port:
                err_msg = _("Cannot configure QOS on ENS networks")
                raise n_exc.InvalidInput(error_message=err_msg)

        # External networks validations:
        if is_external_net:
            self._assert_on_external_net_with_compute(port_data)

        # Device owner validations:
        orig_dev_owner = original_port.get('device_owner')
        self._assert_on_device_owner_change(port_data, orig_dev_owner)
        self._assert_on_port_admin_state(port_data, device_owner)
        self._assert_on_port_sec_change(port_data, device_owner)
        self._validate_max_ips_per_port(context,
                                        port_data.get('fixed_ips', []),
                                        device_owner)
        self._validate_number_of_address_pairs(port_data)
        self._assert_on_vpn_port_change(original_port)
        self._assert_on_lb_port_fixed_ip_change(port_data, orig_dev_owner)
        self._validate_extra_dhcp_options(port_data.get(ext_edo.EXTRADHCPOPTS))

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

    def _get_port_qos_policy_id(self, context, original_port,
                                updated_port):
        """Return the QoS policy Id of a port that is being created/updated

        Return the QoS policy assigned directly to the port (after update or
        originally), or the policy of the network, if it is a compute port that
        should inherit it.
        original_port: the neutron port data before this update
                       (or None in a case of a new port creation)
        updated_ports: the modified fields of this port
                       (or all th attributes of the new port)
        """
        orig_compute = False
        if original_port:
            orig_compute = original_port.get('device_owner', '').startswith(
                constants.DEVICE_OWNER_COMPUTE_PREFIX)
        updated_compute = updated_port.get('device_owner', '').startswith(
            constants.DEVICE_OWNER_COMPUTE_PREFIX)
        is_new_compute = updated_compute and not orig_compute

        qos_policy_id = None
        if qos_consts.QOS_POLICY_ID in updated_port:
            qos_policy_id = updated_port[qos_consts.QOS_POLICY_ID]
        elif original_port:
            # Look for the original QoS policy of this port
            qos_policy_id = qos_com_utils.get_port_policy_id(
                context, original_port['id'])
        # If the port is now a 'compute' port (attached to a vm) and
        # Qos policy was not configured on the port directly,
        # try to take it from the ports network
        if qos_policy_id is None and is_new_compute:
            # check if the network of this port has a policy
            net_id = (original_port.get('network_id') if original_port
                      else updated_port.get('network_id'))
            qos_policy_id = qos_com_utils.get_network_policy_id(
                context, net_id)
        return qos_policy_id

    def _ens_psec_supported(self):
        """Should be implemented by each plugin"""
        pass

    def _has_native_dhcp_metadata(self):
        """Should be implemented by each plugin"""
        pass

    def _get_nsx_net_tz_id(self, nsx_net):
        """Should be implemented by each plugin"""
        pass

    def _get_network_nsx_id(self, context, neutron_id):
        """Should be implemented by each plugin"""
        pass

    def _get_tier0_uplink_cidrs(self, tier0_id):
        """Should be implemented by each plugin"""
        pass

    def _validate_ens_net_portsecurity(self, net_data):
        """Validate/Update the port security of the new network for ENS TZ
        Should be implemented by the plugin if necessary
        """
        pass

    def _is_ens_tz_net(self, context, net_id):
        """Return True if the network is based on an END transport zone"""
        tz_id = self._get_net_tz(context, net_id)
        if tz_id:
            # Check the mode of this TZ
            return self._is_ens_tz(tz_id)
        return False

    def _is_ens_tz_port(self, context, port_data):
        # Check the host-switch-mode of the TZ connected to the ports network
        return self._is_ens_tz_net(context, port_data['network_id'])

    def _is_overlay_network(self, network_id):
        """Should be implemented by each plugin"""
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

    def _default_physical_net(self, physical_net):
        return physical_net is None or physical_net == 'default'

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
        - switch_mode: standard or ENS
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
                    if self._default_physical_net(physical_net):
                        physical_net = default_vlan_tz_uuid
            elif net_type == utils.NsxV3NetworkTypes.VLAN:
                # Use default VLAN transport zone if physical network not given
                if self._default_physical_net(physical_net):
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

    def _extend_qos_port_dict_binding(self, context, port):
        # add the qos policy id from the DB
        if 'id' in port:
            port[qos_consts.QOS_POLICY_ID] = qos_com_utils.get_port_policy_id(
                context, port['id'])

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

    def _get_tier0_uuid_by_net_id(self, context, network_id):
        if not network_id:
            return
        network = self.get_network(context, network_id)
        if not network.get(pnet.PHYSICAL_NETWORK):
            az = self.get_network_az(network)
            return az._default_tier0_router
        else:
            return network.get(pnet.PHYSICAL_NETWORK)

    def _validate_router_tz(self, context, tier0_uuid, subnets):
        """Ensure the related GW (Tier0 router) belongs to the same TZ
        as the subnets attached to the Tier1 router
        Should be implemented by each plugin.
        """
        pass

    def _validate_router_gw_and_tz(self, context, router_id, info,
                                   org_enable_snat, router_subnets):
        # Ensure that a router cannot have SNAT disabled if there are
        # floating IP's assigned
        if (info and 'enable_snat' in info and
            org_enable_snat != info.get('enable_snat') and
            info.get('enable_snat') is False and
            self.router_gw_port_has_floating_ips(context, router_id)):
            msg = _("Unable to set SNAT disabled. Floating IPs assigned")
            raise n_exc.InvalidInput(error_message=msg)

        # Ensure that the router GW tier0 belongs to the same TZ as the
        # subnets of its interfaces
        if info and info.get('network_id'):
            new_tier0_uuid = self._get_tier0_uuid_by_net_id(context.elevated(),
                                                            info['network_id'])
            if new_tier0_uuid:
                self._validate_router_tz(context, new_tier0_uuid,
                                         router_subnets)

    def _validate_gw_overlap_interfaces(self, context, gateway_net,
                                        interfaces_networks):
        # Ensure that interface subnets cannot overlap with the GW subnet
        gw_subnets = self._get_subnets_by_network(
            context.elevated(), gateway_net)
        gw_cidrs = [subnet['cidr'] for subnet in gw_subnets]
        gw_ip_set = netaddr.IPSet(gw_cidrs)

        if_subnets = []
        for net in interfaces_networks:
            if_subnets.extend(self._get_subnets_by_network(
                context.elevated(), net))
        if_cidrs = [subnet['cidr'] for subnet in if_subnets]
        if_ip_set = netaddr.IPSet(if_cidrs)

        if gw_ip_set & if_ip_set:
            msg = _("Interface network cannot overlap with router GW network")
            LOG.error(msg)
            raise n_exc.InvalidInput(error_message=msg)

    def _get_update_router_gw_actions(
        self,
        org_tier0_uuid, orgaddr, org_enable_snat,
        new_tier0_uuid, newaddr, new_enable_snat,
        lb_exist, fw_exist, sr_currently_exists):
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

        # the purpose of this var is to be able to differ between
        # adding a gateway w/o snat and adding snat (when adding/removing gw
        # the snat option is on by default).
        new_with_snat = True if (new_enable_snat and newaddr) else False
        has_gw = True if newaddr else False

        if sr_currently_exists:
            # currently there is a service router on the backend
            actions['add_service_router'] = False
            # Should remove the service router if the GW was removed,
            # or no service needs it: SNAT, LBaaS or FWaaS
            actions['remove_service_router'] = (
                not has_gw or not (fw_exist or lb_exist or new_with_snat))
            if actions['remove_service_router']:
                LOG.info("Removing service router [has GW: %s, FW %s, LB %s, "
                         "SNAT %s]",
                         has_gw, fw_exist, lb_exist, new_with_snat)
        else:
            # currently there is no service router on the backend
            actions['remove_service_router'] = False
            # Should add service router if there is a GW
            # and there is a service that needs it: SNAT, LB or FWaaS
            actions['add_service_router'] = (
                has_gw is not None and (new_with_snat or fw_exist or lb_exist))
            if actions['add_service_router']:
                LOG.info("Adding service router [has GW: %s, FW %s, LB %s, "
                         "SNAT %s]",
                         has_gw, fw_exist, lb_exist, new_with_snat)

        return actions

    def _validate_update_router_gw(self, context, router_id, gw_info):
        router_ports = self._get_router_interfaces(context, router_id)
        for port in router_ports:
            # if setting this router as no-snat, make sure gw address scope
            # match those of the subnets
            if not gw_info.get('enable_snat',
                               cfg.CONF.enable_snat_by_default):
                for fip in port['fixed_ips']:
                    self._validate_address_scope_for_router_interface(
                        context.elevated(), router_id,
                        gw_info['network_id'], fip['subnet_id'])
            # If the network attached to a router is a VLAN backed network
            # then it must be attached to an edge cluster
            if (not gw_info and
                not self._is_overlay_network(context, port['network_id'])):
                msg = _("A router attached to a VLAN backed network "
                        "must have an external network assigned")
                raise n_exc.InvalidInput(error_message=msg)

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
                    LOG.error(error_message)
                    raise n_exc.InvalidInput(error_message=error_message)

    def _get_static_routes_diff(self, context, router_id, gw_info,
                                router_data):
        new_routes = router_data['routes']
        self._validate_ext_routes(context, router_id, gw_info,
                                  new_routes)
        self._validate_routes(context, router_id, new_routes)
        old_routes = self._get_extra_routes_by_router_id(
            context, router_id)
        routes_added, routes_removed = helpers.diff_list_of_dict(
            old_routes, new_routes)
        return routes_added, routes_removed

    def _assert_on_router_admin_state(self, router_data):
        if router_data.get("admin_state_up") is False:
            err_msg = _("admin_state_up=False routers are not supported")
            LOG.warning(err_msg)
            raise n_exc.InvalidInput(error_message=err_msg)

    def _build_dhcp_server_config(self, context, network, subnet, port, az):

        name = self.nsxlib.native_dhcp.build_server_name(
            network['name'], network['id'])

        net_tags = self.nsxlib.build_v3_tags_payload(
            network, resource_type='os-neutron-net-id',
            project_name=context.tenant_name)

        dns_domain = None
        if network.get('dns_domain'):
            net_dns = network['dns_domain']
            if isinstance(net_dns, string_types):
                dns_domain = net_dns
            elif hasattr(net_dns, "dns_domain"):
                dns_domain = net_dns.dns_domain
        if not dns_domain or not validators.is_attr_set(dns_domain):
            dns_domain = az.dns_domain

        dns_nameservers = subnet['dns_nameservers']
        if not dns_nameservers or not validators.is_attr_set(dns_nameservers):
            dns_nameservers = az.nameservers

        return self.nsxlib.native_dhcp.build_server(
            name,
            ip_address=port['fixed_ips'][0]['ip_address'],
            cidr=subnet['cidr'],
            gateway_ip=subnet['gateway_ip'],
            host_routes=subnet['host_routes'],
            dns_domain=dns_domain,
            dns_nameservers=dns_nameservers,
            dhcp_profile_id=az._native_dhcp_profile_uuid,
            tags=net_tags)

    def _enable_native_dhcp(self, context, network, subnet):
        # Enable native DHCP service on the backend for this network.
        # First create a Neutron DHCP port and use its assigned IP
        # address as the DHCP server address in an API call to create a
        # LogicalDhcpServer on the backend. Then create the corresponding
        # logical port for the Neutron port with DHCP attachment as the
        # LogicalDhcpServer UUID.

        # TODO(annak):
        # This function temporarily serves both nsx_v3 and nsx_p plugins.
        # In future, when platform supports native dhcp in policy for infra
        # segments, this function should move back to nsx_v3 plugin

        # Delete obsolete settings if exist. This could happen when a
        # previous failed transaction was rolled back. But the backend
        # entries are still there.
        self._disable_native_dhcp(context, network['id'])

        # Get existing ports on subnet.
        existing_ports = super(NsxPluginV3Base, self).get_ports(
            context, filters={'network_id': [network['id']],
                              'fixed_ips': {'subnet_id': [subnet['id']]}})
        nsx_net_id = self._get_network_nsx_id(context, network['id'])
        if not nsx_net_id:
            msg = ("Unable to obtain backend network id for logical DHCP "
                   "server for network %s" % network['id'])
            LOG.error(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)

        az = self.get_network_az_by_net_id(context, network['id'])
        port_data = {
            "name": "",
            "admin_state_up": True,
            "device_id": az._native_dhcp_profile_uuid,
            "device_owner": constants.DEVICE_OWNER_DHCP,
            "network_id": network['id'],
            "tenant_id": network["tenant_id"],
            "mac_address": constants.ATTR_NOT_SPECIFIED,
            "fixed_ips": [{"subnet_id": subnet['id']}],
            psec.PORTSECURITY: False
        }
        # Create the DHCP port (on neutron only) and update its port security
        port = {'port': port_data}
        neutron_port = super(NsxPluginV3Base, self).create_port(context, port)
        is_ens_tz_port = self._is_ens_tz_port(context, port_data)
        self._create_port_preprocess_security(context, port, port_data,
                                              neutron_port, is_ens_tz_port)
        self._process_portbindings_create_and_update(
            context, port_data, neutron_port)

        server_data = self._build_dhcp_server_config(
            context, network, subnet, neutron_port, az)
        port_tags = self.nsxlib.build_v3_tags_payload(
            neutron_port, resource_type='os-neutron-dport-id',
            project_name=context.tenant_name)
        dhcp_server = None
        dhcp_port_profiles = []
        if (not self._has_native_dhcp_metadata() and
            not self._is_ens_tz_net(context, network['id'])):
            dhcp_port_profiles.append(self._dhcp_profile)
        try:
            dhcp_server = self.nsxlib.dhcp_server.create(**server_data)
            LOG.debug("Created logical DHCP server %(server)s for network "
                      "%(network)s",
                      {'server': dhcp_server['id'], 'network': network['id']})
            name = self._build_port_name(context, port_data)
            nsx_port = self.nsxlib.logical_port.create(
                nsx_net_id, dhcp_server['id'], tags=port_tags, name=name,
                attachment_type=nsxlib_consts.ATTACHMENT_DHCP,
                switch_profile_ids=dhcp_port_profiles)
            LOG.debug("Created DHCP logical port %(port)s for "
                      "network %(network)s",
                      {'port': nsx_port['id'], 'network': network['id']})
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to create logical DHCP server for "
                          "network %s", network['id'])
                if dhcp_server:
                    self.nsxlib.dhcp_server.delete(dhcp_server['id'])
                super(NsxPluginV3Base, self).delete_port(
                    context, neutron_port['id'])

        try:
            # Add neutron_port_id -> nsx_port_id mapping to the DB.
            nsx_db.add_neutron_nsx_port_mapping(
                context.session, neutron_port['id'], nsx_net_id,
                nsx_port['id'])
            # Add neutron_net_id -> dhcp_service_id mapping to the DB.
            nsx_db.add_neutron_nsx_service_binding(
                context.session, network['id'], neutron_port['id'],
                nsxlib_consts.SERVICE_DHCP, dhcp_server['id'])
        except (db_exc.DBError, sql_exc.TimeoutError):
            with excutils.save_and_reraise_exception():
                LOG.error("Failed to create mapping for DHCP port %s,"
                          "deleting port and logical DHCP server",
                          neutron_port['id'])
                self.nsxlib.dhcp_server.delete(dhcp_server['id'])
                self._cleanup_port(context, neutron_port['id'], nsx_port['id'])

        # Configure existing ports to work with the new DHCP server
        try:
            for port_data in existing_ports:
                self._add_dhcp_binding(context, port_data)
        except Exception:
            LOG.error('Unable to create DHCP bindings for existing ports '
                      'on subnet %s', subnet['id'])

    def _disable_native_dhcp(self, context, network_id):
        # Disable native DHCP service on the backend for this network.
        # First delete the DHCP port in this network. Then delete the
        # corresponding LogicalDhcpServer for this network.
        self._ensure_native_dhcp()
        dhcp_service = nsx_db.get_nsx_service_binding(
            context.session, network_id, nsxlib_consts.SERVICE_DHCP)
        if not dhcp_service:
            return

        if dhcp_service['port_id']:
            try:
                _net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                    context.session, dhcp_service['port_id'])
                self._cleanup_port(context, dhcp_service['port_id'],
                                   nsx_port_id)
            except nsx_lib_exc.ResourceNotFound:
                # This could happen when the port has been manually deleted.
                LOG.error("Failed to delete DHCP port %(port)s for "
                          "network %(network)s",
                          {'port': dhcp_service['port_id'],
                           'network': network_id})
        else:
            LOG.error("DHCP port is not configured for network %s",
                      network_id)

        try:
            self.nsxlib.dhcp_server.delete(dhcp_service['nsx_service_id'])
            LOG.debug("Deleted logical DHCP server %(server)s for network "
                      "%(network)s",
                      {'server': dhcp_service['nsx_service_id'],
                       'network': network_id})
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to delete logical DHCP server %(server)s "
                          "for network %(network)s",
                          {'server': dhcp_service['nsx_service_id'],
                           'network': network_id})
        try:
            # Delete neutron_id -> dhcp_service_id mapping from the DB.
            nsx_db.delete_neutron_nsx_service_binding(
                context.session, network_id, nsxlib_consts.SERVICE_DHCP)
            # Delete all DHCP bindings under this DHCP server from the DB.
            nsx_db.delete_neutron_nsx_dhcp_bindings_by_service_id(
                context.session, dhcp_service['nsx_service_id'])
        except db_exc.DBError:
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to delete DHCP server mapping for "
                          "network %s", network_id)

    def _filter_ipv4_dhcp_fixed_ips(self, context, fixed_ips):
        ips = []
        for fixed_ip in fixed_ips:
            if netaddr.IPNetwork(fixed_ip['ip_address']).version != 4:
                continue
            with db_api.CONTEXT_READER.using(context):
                subnet = self.get_subnet(context, fixed_ip['subnet_id'])
            if subnet['enable_dhcp']:
                ips.append(fixed_ip)
        return ips

    def _add_dhcp_binding(self, context, port):
        if not utils.is_port_dhcp_configurable(port):
            return
        dhcp_service = nsx_db.get_nsx_service_binding(
            context.session, port['network_id'], nsxlib_consts.SERVICE_DHCP)
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
                LOG.error("Failed to add mapping of DHCP binding "
                          "%(binding)s for port %(port)s, deleting "
                          "DHCP binding on server",
                          {'binding': binding['id'], 'port': port['id']})
                fake_db_binding = {
                    'port_id': port['id'],
                    'nsx_service_id': dhcp_service['nsx_service_id'],
                    'nsx_binding_id': binding['id']}
                self._delete_dhcp_binding_on_server(context, fake_db_binding)

    def _add_dhcp_binding_on_server(self, context, dhcp_service_id, subnet_id,
                                    ip, port):
        try:
            hostname = 'host-%s' % ip.replace('.', '-')
            subnet = self.get_subnet(context, subnet_id)
            gateway_ip = subnet.get('gateway_ip')
            options = self._get_dhcp_options(
                context, ip, port.get(ext_edo.EXTRADHCPOPTS),
                port['network_id'], subnet)
            binding = self.nsxlib.dhcp_server.create_binding(
                dhcp_service_id, port['mac_address'], ip, hostname,
                self._get_conf_attr('dhcp_lease_time'), options, gateway_ip)
            LOG.debug("Created static binding (mac: %(mac)s, ip: %(ip)s, "
                      "gateway: %(gateway)s, options: %(options)s) for port "
                      "%(port)s on logical DHCP server %(server)s",
                      {'mac': port['mac_address'], 'ip': ip,
                       'gateway': gateway_ip, 'options': options,
                       'port': port['id'],
                       'server': dhcp_service_id})
            return binding
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to create static binding (mac: %(mac)s, "
                          "ip: %(ip)s, gateway: %(gateway)s, options: "
                          "%(options)s) for port %(port)s on logical DHCP "
                          "server %(server)s",
                          {'mac': port['mac_address'], 'ip': ip,
                           'gateway': gateway_ip, 'options': options,
                           'port': port['id'],
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
                LOG.error("Unable to delete mapping of DHCP binding "
                          "%(binding)s for port %(port)s",
                          {'binding': binding['nsx_binding_id'],
                           'port': binding['port_id']})

    def _delete_dhcp_binding_on_server(self, context, binding):
        try:
            self.nsxlib.dhcp_server.delete_binding(
                binding['nsx_service_id'], binding['nsx_binding_id'])
            LOG.debug("Deleted static binding for port %(port)s) on "
                      "logical DHCP server %(server)s",
                      {'port': binding['port_id'],
                       'server': binding['nsx_service_id']})
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to delete static binding for port "
                          "%(port)s) on logical DHCP server %(server)s",
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

        if (old_port["device_owner"] == constants.DEVICE_OWNER_DHCP and
            ip_change):
            # Update backend DHCP server address if the IP address of a DHCP
            # port is changed.
            if len(new_fixed_ips) != 1:
                msg = _("Can only configure one IP address on a DHCP server")
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)
            # Locate the backend DHCP server for this DHCP port.
            dhcp_service = nsx_db.get_nsx_service_binding(
                context.session, old_port['network_id'],
                nsxlib_consts.SERVICE_DHCP)
            if dhcp_service:
                new_ip = ips_to_add[0][1]
                try:
                    self.nsxlib.dhcp_server.update(
                        dhcp_service['nsx_service_id'],
                        server_ip=new_ip)
                    LOG.debug("Updated IP %(ip)s for logical DHCP server "
                              "%(server)s",
                              {'ip': new_ip,
                               'server': dhcp_service['nsx_service_id']})
                except nsx_lib_exc.ManagerError:
                    with excutils.save_and_reraise_exception():
                        LOG.error("Unable to update IP %(ip)s for logical "
                                  "DHCP server %(server)s",
                                  {'ip': new_ip,
                                   'server': dhcp_service['nsx_service_id']})
        elif utils.is_port_dhcp_configurable(old_port):
            # Update static DHCP bindings for a compute port.
            bindings = nsx_db.get_nsx_dhcp_bindings(context.session,
                                                    old_port['id'])
            dhcp_opts = new_port.get(ext_edo.EXTRADHCPOPTS)
            dhcp_opts_changed = (old_port[ext_edo.EXTRADHCPOPTS] !=
                                 new_port[ext_edo.EXTRADHCPOPTS])
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
                            subnet = self.get_subnet(context,
                                                     binding['subnet_id'])
                            self._update_dhcp_binding_on_server(
                                context, binding, new_port['mac_address'],
                                ips_to_add[i][1], old_port['network_id'],
                                dhcp_opts=dhcp_opts, subnet=subnet)
                            # Update DB IP
                            nsx_db.update_nsx_dhcp_bindings(context.session,
                                                            old_port['id'],
                                                            ip,
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
                            nsxlib_consts.SERVICE_DHCP)
                        if dhcp_service:
                            for (subnet_id, ip) in ips_to_add:
                                self._add_dhcp_binding_on_server(
                                    context, dhcp_service['nsx_service_id'],
                                    subnet_id, ip, new_port)
            elif (old_port['mac_address'] != new_port['mac_address'] or
                  dhcp_opts_changed):
                # If only Mac address/dhcp opts is changed,
                # update it in all associated DHCP bindings.
                for binding in bindings:
                    subnet = self.get_subnet(context, binding['subnet_id'])
                    self._update_dhcp_binding_on_server(
                        context, binding, new_port['mac_address'],
                        binding['ip_address'], old_port['network_id'],
                        dhcp_opts=dhcp_opts, subnet=subnet)

    def _cleanup_port(self, context, port_id, nsx_port_id=None):
        # Clean up neutron port and nsx manager port if provided
        # Does not handle cleanup of policy port
        super(NsxPluginV3Base, self).delete_port(context, port_id)
        if nsx_port_id and self.nsxlib:
            self.nsxlib.logical_port.delete(nsx_port_id)

    def _is_excluded_port(self, device_owner, port_security):
        if device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF:
            return False
        if device_owner == constants.DEVICE_OWNER_DHCP:
            if not self._has_native_dhcp_metadata():
                return True
        elif not port_security:
            return True
        return False

    def _validate_obj_az_on_creation(self, context, obj_data, obj_type):
        # validate the availability zone, and get the AZ object
        if az_def.AZ_HINTS in obj_data:
            self._validate_availability_zones_forced(
                context, obj_type, obj_data[az_def.AZ_HINTS])
        return self.get_obj_az_by_hints(obj_data)

    def _add_az_to_net(self, context, net_id, net_data):
        if az_def.AZ_HINTS in net_data:
            # Update the AZ hints in the neutron object
            az_hints = az_validator.convert_az_list_to_string(
                net_data[az_def.AZ_HINTS])
            super(NsxPluginV3Base, self).update_network(
                context, net_id,
                {'network': {az_def.AZ_HINTS: az_hints}})

    def _add_az_to_router(self, context, router_id, router_data):
        if az_def.AZ_HINTS in router_data:
            # Update the AZ hints in the neutron object
            az_hints = az_validator.convert_az_list_to_string(
                router_data[az_def.AZ_HINTS])
            super(NsxPluginV3Base, self).update_router(
                context, router_id,
                {'router': {az_def.AZ_HINTS: az_hints}})

    def get_network_availability_zones(self, net_db):
        if self._has_native_dhcp_metadata():
            hints = az_validator.convert_az_string_to_list(
                net_db[az_def.AZ_HINTS])
            # When using the configured AZs, the az will always be the same
            # as the hint (or default if none)
            if hints:
                az_name = hints[0]
            else:
                az_name = self.get_default_az().name
            return [az_name]
        else:
            return []

    def _get_router_az_obj(self, router):
        l3_attrs_db.ExtraAttributesMixin._extend_extra_router_dict(
            router, router)
        return self.get_router_az(router)

    def get_router_availability_zones(self, router):
        """Return availability zones which a router belongs to."""
        return [self._get_router_az_obj(router).name]

    def _validate_availability_zones_forced(self, context, resource_type,
                                            availability_zones):
        return self.validate_availability_zones(context, resource_type,
                                                availability_zones,
                                                force=True)

    def _list_availability_zones(self, context, filters=None):
        # If no native_dhcp_metadata - use neutron AZs
        if not self._has_native_dhcp_metadata():
            return super(NsxPluginV3Base, self)._list_availability_zones(
                context, filters=filters)

        result = {}
        for az in self._availability_zones_data.list_availability_zones():
            # Add this availability zone as a network & router resource
            if filters:
                if 'name' in filters and az not in filters['name']:
                    continue
            for res in ['network', 'router']:
                if 'resource' not in filters or res in filters['resource']:
                    result[(az, res)] = True
        return result

    def validate_availability_zones(self, context, resource_type,
                                    availability_zones, force=False):
        # This method is called directly from this plugin but also from
        # registered callbacks
        if self._is_sub_plugin and not force:
            # validation should be done together for both plugins
            return
        # If no native_dhcp_metadata - use neutron AZs
        if not self._has_native_dhcp_metadata():
            return super(NsxPluginV3Base, self).validate_availability_zones(
                context, resource_type, availability_zones)
        # Validate against the configured AZs
        return self.validate_obj_azs(availability_zones)

    def _ensure_nsxlib(self, feature):
        if not self.nsxlib:
            msg = (_("%s is not supported since passthough API is disabled") %
                   feature)
            LOG.error(msg)
            raise n_exc.InvalidInput(error_message=msg)

    def _ensure_native_dhcp(self):
        self._ensure_nsxlib("Native DHCP")
        if not self._native_dhcp_enabled:
            msg = (_("Native DHCP is not supported since dhcp_profile is not"
                     " provided in plugin configuration"))
            LOG.error(msg)
            raise n_exc.InvalidInput(error_message=msg)

    def _get_net_dhcp_relay(self, context, net_id):
        """Should be implemented by each plugin"""
        pass

    def _get_ipv6_subnet(self, context, network):
        for subnet in network.subnets:
            if subnet.ip_version == 6:
                return subnet

    def _validate_single_ipv6_subnet(self, context, network, subnet):
        if subnet.get('ip_version') == 6:
            if self._get_ipv6_subnet(context, network):
                msg = (_("Only one ipv6 subnet per network is supported"))
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)

    def _create_subnet(self, context, subnet):
        self._validate_number_of_subnet_static_routes(subnet)
        self._validate_host_routes_input(subnet)

        network = self._get_network(
            context, subnet['subnet']['network_id'])
        self._validate_single_ipv6_subnet(context, network, subnet['subnet'])

        # TODO(berlin): public external subnet announcement
        native_metadata = self._has_native_dhcp_metadata()
        if (native_metadata and subnet['subnet'].get('enable_dhcp', False)):
            self._validate_external_subnet(context,
                                           subnet['subnet']['network_id'])
            self._ensure_native_dhcp()
            lock = 'nsxv3_network_' + subnet['subnet']['network_id']
            ddi_support, ddi_type = self._is_ddi_supported_on_net_with_type(
                context, subnet['subnet']['network_id'])
            with locking.LockManager.get_lock(lock):
                # Check if it is on an overlay network and is the first
                # DHCP-enabled subnet to create.
                if ddi_support:
                    if self._has_no_dhcp_enabled_subnet(context, network):
                        created_subnet = super(
                            NsxPluginV3Base, self).create_subnet(context,
                                                                 subnet)
                        try:
                            # This can be called only after the super create
                            # since we need the subnet pool to be translated
                            # to allocation pools
                            self._validate_address_space(
                                context, created_subnet)
                        except n_exc.InvalidInput:
                            # revert the subnet creation
                            with excutils.save_and_reraise_exception():
                                super(NsxPluginV3Base, self).delete_subnet(
                                    context, created_subnet['id'])
                        self._extension_manager.process_create_subnet(context,
                            subnet['subnet'], created_subnet)
                        dhcp_relay = self._get_net_dhcp_relay(
                            context, subnet['subnet']['network_id'])
                        if not dhcp_relay:
                            if self.nsxlib:
                                try:
                                    self._enable_native_dhcp(context, network,
                                                             created_subnet)
                                except nsx_lib_exc.ManagerError:
                                    with excutils.save_and_reraise_exception():
                                        super(NsxPluginV3Base,
                                              self).delete_subnet(
                                            context, created_subnet['id'])
                            else:
                                msg = (_("Native DHCP is not supported since "
                                         "passthough API is disabled"))
                            self._enable_native_dhcp(context, network,
                                                     created_subnet)
                        msg = None
                    else:
                        msg = (_("Can not create more than one DHCP-enabled "
                                "subnet in network %s") %
                               subnet['subnet']['network_id'])
                else:
                    msg = _("Native DHCP is not supported for %(type)s "
                            "network %(id)s") % {
                          'id': subnet['subnet']['network_id'],
                          'type': ddi_type}
                if msg:
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
        else:
            created_subnet = super(NsxPluginV3Base, self).create_subnet(
                context, subnet)
            try:
                # This can be called only after the super create
                # since we need the subnet pool to be translated
                # to allocation pools
                self._validate_address_space(context, created_subnet)
            except n_exc.InvalidInput:
                # revert the subnet creation
                with excutils.save_and_reraise_exception():
                    super(NsxPluginV3Base, self).delete_subnet(
                        context, created_subnet['id'])
        return created_subnet

    def _create_bulk_with_callback(self, resource, context, request_items,
                                   post_create_func=None, rollback_func=None):
        # This is a copy of the _create_bulk() in db_base_plugin_v2.py,
        # but extended with user-provided callback functions.
        objects = []
        collection = "%ss" % resource
        items = request_items[collection]
        try:
            with db_api.CONTEXT_WRITER.using(context):
                for item in items:
                    obj_creator = getattr(self, 'create_%s' % resource)
                    obj = obj_creator(context, item)
                    objects.append(obj)
                    if post_create_func:
                        # The user-provided post_create function is called
                        # after a new object is created.
                        post_create_func(obj)
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
                LOG.error("An exception occurred while creating "
                          "the %(resource)s:%(item)s",
                          {'resource': resource, 'item': item})
        return objects

    def _post_create_subnet(self, context, subnet):
        LOG.debug("Collect native DHCP entries for network %s",
                  subnet['network_id'])
        dhcp_service = nsx_db.get_nsx_service_binding(
            context.session, subnet['network_id'], nsxlib_consts.SERVICE_DHCP)
        if dhcp_service:
            _net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, dhcp_service['port_id'])
            return {'nsx_port_id': nsx_port_id,
                    'nsx_service_id': dhcp_service['nsx_service_id']}

    def _rollback_subnet(self, subnet, dhcp_info):
        LOG.debug("Rollback native DHCP entries for network %s",
                  subnet['network_id'])
        if dhcp_info and self.nsxlib:
            try:
                self.nsxlib.logical_port.delete(dhcp_info['nsx_port_id'])
            except Exception as e:
                LOG.error("Failed to delete logical port %(id)s "
                          "during rollback. Exception: %(e)s",
                          {'id': dhcp_info['nsx_port_id'], 'e': e})
            try:
                self.nsxlib.dhcp_server.delete(dhcp_info['nsx_service_id'])
            except Exception as e:
                LOG.error("Failed to delete logical DHCP server %(id)s "
                          "during rollback. Exception: %(e)s",
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

        if self._has_native_dhcp_metadata():
            return self._create_bulk_with_callback('subnet', context, subnets,
                                                   _post_create, _rollback)
        else:
            return self._create_bulk('subnet', context, subnets)

    def _get_neutron_net_ids_by_nsx_id(self, context, nsx_id):
        """Should be implemented by each plugin"""
        pass

    def _validate_number_of_subnet_static_routes(self, subnet_input):
        s = subnet_input['subnet']
        request_host_routes = (validators.is_attr_set(s.get('host_routes')) and
                               s['host_routes'])
        num_allowed_on_backend = nsxlib_consts.MAX_STATIC_ROUTES
        if request_host_routes:
            if len(request_host_routes) > num_allowed_on_backend:
                err_msg = (_(
                    "Number of static routes is limited at the backend to %("
                    "backend)s. Requested %(requested)s") %
                           {'backend': nsxlib_consts.MAX_STATIC_ROUTES,
                            'requested': len(request_host_routes)})
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
                network_ids += self._get_neutron_net_ids_by_nsx_id(
                    context, lswitch_id)
            filters['network_id'] = network_ids
        return super(NsxPluginV3Base, self).get_subnets(
            context, filters, fields, sorts, limit, marker, page_reverse)

    def delete_subnet(self, context, subnet_id):
        # TODO(berlin): cancel public external subnet announcement
        if self._has_native_dhcp_metadata():
            # Ensure that subnet is not deleted if attached to router.
            self._subnet_check_ip_allocations_internal_router_ports(
                context, subnet_id)
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
                            LOG.error("Failed to disable native DHCP for "
                                      "network %(id)s. Exception: %(e)s",
                                      {'id': network['id'], 'e': e})
                        super(NsxPluginV3Base, self).delete_subnet(
                            context, subnet_id)
                        return
        super(NsxPluginV3Base, self).delete_subnet(context, subnet_id)

    def _update_subnet(self, context, subnet_id, subnet):
        updated_subnet = None
        orig_subnet = self.get_subnet(context, subnet_id)
        self._validate_number_of_subnet_static_routes(subnet)
        self._validate_host_routes_input(
            subnet,
            orig_enable_dhcp=orig_subnet['enable_dhcp'],
            orig_host_routes=orig_subnet['host_routes'])

        network = self._get_network(context, orig_subnet['network_id'])
        if (subnet['subnet'].get('ip_version') !=
            orig_subnet.get('ip_version')):
            self._validate_single_ipv6_subnet(
                context, network, subnet['subnet'])

        if self._has_native_dhcp_metadata():
            enable_dhcp = subnet['subnet'].get('enable_dhcp')
            if (enable_dhcp is not None and
                enable_dhcp != orig_subnet['enable_dhcp']):
                self._ensure_native_dhcp()
                lock = 'nsxv3_network_' + orig_subnet['network_id']
                with locking.LockManager.get_lock(lock):
                    if enable_dhcp:
                        (ddi_support,
                         ddi_type) = self._is_ddi_supported_on_net_with_type(
                            context, orig_subnet['network_id'])
                        if ddi_support:
                            if self._has_no_dhcp_enabled_subnet(
                                context, network):
                                updated_subnet = super(
                                    NsxPluginV3Base, self).update_subnet(
                                    context, subnet_id, subnet)
                                self._extension_manager.process_update_subnet(
                                    context, subnet['subnet'], updated_subnet)
                                self._enable_native_dhcp(context, network,
                                                         updated_subnet)
                                msg = None
                            else:
                                msg = (_("Multiple DHCP-enabled subnets is "
                                         "not allowed in network %s") %
                                       orig_subnet['network_id'])
                        else:
                            msg = (_("Native DHCP is not supported for "
                                     "%(type)s network %(id)s") %
                                   {'id': orig_subnet['network_id'],
                                    'type': ddi_type})
                        if msg:
                            LOG.error(msg)
                            raise n_exc.InvalidInput(error_message=msg)
                    elif self._has_single_dhcp_enabled_subnet(context,
                                                              network):
                        self._disable_native_dhcp(context, network['id'])
                        updated_subnet = super(
                            NsxPluginV3Base, self).update_subnet(
                            context, subnet_id, subnet)
                        self._extension_manager.process_update_subnet(
                            context, subnet['subnet'], updated_subnet)

        if not updated_subnet:
            updated_subnet = super(NsxPluginV3Base, self).update_subnet(
                context, subnet_id, subnet)
            self._extension_manager.process_update_subnet(
                context, subnet['subnet'], updated_subnet)

        # Check if needs to update logical DHCP server for native DHCP.
        if (self._has_native_dhcp_metadata() and
            updated_subnet['enable_dhcp']):
            self._ensure_native_dhcp()
            kwargs = {}
            for key in ('dns_nameservers', 'gateway_ip', 'host_routes'):
                if key in subnet['subnet']:
                    value = subnet['subnet'][key]
                    if value != orig_subnet[key]:
                        kwargs[key] = value
                        if key != 'dns_nameservers':
                            kwargs['options'] = None
            if 'options' in kwargs:
                sr, gw_ip = self.nsxlib.native_dhcp.build_static_routes(
                    updated_subnet.get('gateway_ip'),
                    updated_subnet.get('cidr'),
                    updated_subnet.get('host_routes', []))
                kwargs['options'] = {'option121': {'static_routes': sr}}
                kwargs.pop('host_routes', None)
                if (gw_ip is not None and 'gateway_ip' not in kwargs and
                    gw_ip != updated_subnet['gateway_ip']):
                    kwargs['gateway_ip'] = gw_ip
            if kwargs:
                dhcp_service = nsx_db.get_nsx_service_binding(
                    context.session, orig_subnet['network_id'],
                    nsxlib_consts.SERVICE_DHCP)
                if dhcp_service:
                    try:
                        self.nsxlib.dhcp_server.update(
                            dhcp_service['nsx_service_id'], **kwargs)
                    except nsx_lib_exc.ManagerError:
                        with excutils.save_and_reraise_exception():
                            LOG.error(
                                "Unable to update logical DHCP server "
                                "%(server)s for network %(network)s",
                                {'server': dhcp_service['nsx_service_id'],
                                 'network': orig_subnet['network_id']})
                    if 'options' in kwargs:
                        # Need to update the static binding of every VM in
                        # this logical DHCP server.
                        bindings = nsx_db.get_nsx_dhcp_bindings_by_service(
                            context.session, dhcp_service['nsx_service_id'])
                        for binding in bindings:
                            port = self._get_port(context, binding['port_id'])
                            dhcp_opts = port.get(ext_edo.EXTRADHCPOPTS)
                            self._update_dhcp_binding_on_server(
                                context, binding, port['mac_address'],
                                binding['ip_address'],
                                port['network_id'],
                                gateway_ip=kwargs.get('gateway_ip', False),
                                dhcp_opts=dhcp_opts,
                                options=kwargs.get('options'),
                                subnet=updated_subnet)

        return updated_subnet

    def _has_active_port(self, context, network_id):
        ports_in_use = context.session.query(models_v2.Port).filter_by(
            network_id=network_id).all()
        return not all([p.device_owner in
                        db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS
                        for p in ports_in_use]) if ports_in_use else False

    def _delete_network_disable_dhcp(self, context, network_id):
        # Disable native DHCP and delete DHCP ports before network deletion
        lock = 'nsxv3_network_' + network_id
        with locking.LockManager.get_lock(lock):
            # Disable native DHCP if there is no other existing port
            # besides DHCP port.
            if not self._has_active_port(context, network_id):
                self._disable_native_dhcp(context, network_id)

    def _retry_delete_network(self, context, network_id):
        """This method attempts to retry the delete on a network if there are
           AUTO_DELETE_PORT_OWNERS left. This is to avoid a race condition
           between delete_network and the dhcp creating a port on the network.
        """
        first_try = True
        while True:
            try:
                with db_api.CONTEXT_WRITER.using(context):
                    self._process_l3_delete(context, network_id)
                    return super(NsxPluginV3Base, self).delete_network(
                        context, network_id)
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

    def _get_dhcp_options(self, context, ip, extra_dhcp_opts, net_id,
                          subnet):
        # Always add option121.
        net_az = self.get_network_az_by_net_id(context, net_id)
        options = {'option121': {'static_routes': [
            {'network': '%s' % net_az.native_metadata_route,
             'next_hop': '0.0.0.0'},
            {'network': '%s' % net_az.native_metadata_route,
             'next_hop': ip}]}}
        if subnet:
            sr, gateway_ip = self.nsxlib.native_dhcp.build_static_routes(
                subnet.get('gateway_ip'), subnet.get('cidr'),
                subnet.get('host_routes', []))
            options['option121']['static_routes'].extend(sr)
        # Adding extra options only if configured on port
        if extra_dhcp_opts:
            other_opts = []
            for opt in extra_dhcp_opts:
                opt_name = opt['opt_name']
                if opt['opt_value'] is not None:
                    # None value means - delete this option. Since we rebuild
                    # the options from scratch, it can be ignored.
                    opt_val = opt['opt_value']
                    if opt_name == 'classless-static-route':
                        # Add to the option121 static routes
                        net, ip = opt_val.split(',')
                        options['option121']['static_routes'].append({
                            'network': net, 'next_hop': ip})
                    else:
                        other_opts.append({
                            'code': nsxlib_utils.get_dhcp_opt_code(opt_name),
                            'values': [opt_val]})
            if other_opts:
                options['others'] = other_opts
        return options

    def _update_dhcp_binding_on_server(self, context, binding, mac, ip,
                                       net_id, gateway_ip=False,
                                       dhcp_opts=None, options=None,
                                       subnet=None):
        try:
            data = {'mac_address': mac, 'ip_address': ip}
            if ip != binding['ip_address']:
                data['host_name'] = 'host-%s' % ip.replace('.', '-')
                data['options'] = self._get_dhcp_options(
                    context, ip, dhcp_opts, net_id,
                    subnet)
            elif (dhcp_opts is not None or
                  options is not None):
                data['options'] = self._get_dhcp_options(
                    context, ip, dhcp_opts, net_id,
                    subnet)
            if gateway_ip is not False:
                # Note that None is valid for gateway_ip, means deleting it.
                data['gateway_ip'] = gateway_ip

            self.nsxlib.dhcp_server.update_binding(
                binding['nsx_service_id'], binding['nsx_binding_id'], **data)
            LOG.debug("Updated static binding (mac: %(mac)s, ip: %(ip)s, "
                      "gateway: %(gateway)s) for port %(port)s on "
                      "logical DHCP server %(server)s",
                      {'mac': mac, 'ip': ip, 'gateway': gateway_ip,
                       'port': binding['port_id'],
                       'server': binding['nsx_service_id']})
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to update static binding (mac: %(mac)s, "
                          "ip: %(ip)s, gateway: %(gateway)s) for port "
                          "%(port)s on logical DHCP server %(server)s",
                          {'mac': mac, 'ip': ip, 'gateway': gateway_ip,
                           'port': binding['port_id'],
                           'server': binding['nsx_service_id']})

    def _validate_extra_dhcp_options(self, opts):
        if not opts or not self._has_native_dhcp_metadata():
            return
        for opt in opts:
            opt_name = opt['opt_name']
            opt_val = opt['opt_value']
            if opt_name == 'classless-static-route':
                # separate validation for option121
                if opt_val is not None:
                    try:
                        net, ip = opt_val.split(',')
                    except Exception:
                        msg = (_("Bad value %(val)s for DHCP option "
                                 "%(name)s") % {'name': opt_name,
                                                'val': opt_val})
                        raise n_exc.InvalidInput(error_message=msg)
            elif not nsxlib_utils.get_dhcp_opt_code(opt_name):
                msg = (_("DHCP option %s is not supported") % opt_name)
                raise n_exc.InvalidInput(error_message=msg)

    def _is_vlan_router_interface_supported(self):
        """Should be implemented by each plugin"""

    def _is_ddi_supported_on_network(self, context, network_id):
        result, _ = self._is_ddi_supported_on_net_with_type(
            context, network_id)
        return result

    def _is_ddi_supported_on_net_with_type(self, context, network_id):
        net = self.get_network(context, network_id)
        # NSX current does not support transparent VLAN ports for
        # DHCP and metadata
        if cfg.CONF.vlan_transparent:
            if net.get('vlan_transparent') is True:
                return False, "VLAN transparent"
        # NSX current does not support flat network ports for
        # DHCP and metadata
        if net.get(pnet.NETWORK_TYPE) == utils.NsxV3NetworkTypes.FLAT:
            return False, "flat"
        # supported for overlay networks, and for vlan networks depending on
        # NSX version
        is_overlay = self._is_overlay_network(context, network_id)
        net_type = "overlay" if is_overlay else "non-overlay"
        return (is_overlay or
                self._is_vlan_router_interface_supported()), net_type

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

    def _cidrs_overlap(self, cidr0, cidr1):
        return cidr0.first <= cidr1.last and cidr1.first <= cidr0.last

    def _validate_address_space(self, context, subnet):
        # Only working for IPv4 at the moment
        if (subnet['ip_version'] != 4):
            return

        # get the subnet IPs
        if ('allocation_pools' in subnet and
            validators.is_attr_set(subnet['allocation_pools'])):
            # use the pools instead of the cidr
            subnet_networks = [
                netaddr.IPRange(pool.get('start'), pool.get('end'))
                for pool in subnet.get('allocation_pools')]
        else:
            cidr = subnet.get('cidr')
            if not validators.is_attr_set(cidr):
                return
            subnet_networks = [netaddr.IPNetwork(subnet['cidr'])]

        # Check if subnet overlaps with shared address space.
        # This is checked on the backend when attaching subnet to a router.
        shared_ips_cidrs = self._get_conf_attr('transit_networks')
        for subnet_net in subnet_networks:
            for shared_ips in shared_ips_cidrs:
                if netaddr.IPSet(subnet_net) & netaddr.IPSet([shared_ips]):
                    msg = _("Subnet overlaps with shared address space "
                            "%s") % shared_ips
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)

        # Ensure that the NSX uplink cidr does not lie on the same subnet as
        # the external subnet
        filters = {'id': [subnet['network_id']],
                   'router:external': [True]}
        external_nets = self.get_networks(context, filters=filters)
        tier0_routers = [ext_net[pnet.PHYSICAL_NETWORK]
                         for ext_net in external_nets
                         if ext_net.get(pnet.PHYSICAL_NETWORK)]

        for tier0_rtr in set(tier0_routers):
            tier0_cidrs = self._get_tier0_uplink_cidrs(tier0_rtr)
            for cidr in tier0_cidrs:
                tier0_subnet = netaddr.IPNetwork(cidr).cidr
                for subnet_network in subnet_networks:
                    if self._cidrs_overlap(tier0_subnet, subnet_network):
                        msg = _("External subnet cannot overlap with T0 "
                                "router cidr %s") % cidr
                        LOG.error(msg)
                        raise n_exc.InvalidInput(error_message=msg)

    def _need_router_no_dnat_rules(self, subnet):
        # NAT is not supported for IPv6
        return (subnet['ip_version'] == 4)

    def _need_router_snat_rules(self, context, router_id, subnet,
                                gw_address_scope):
        # NAT is not supported for IPv6
        if subnet['ip_version'] != 4:
            return False

        # if the subnets address scope is the same as the gateways:
        # no need for SNAT
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
                return False
        return True

    def _get_mdproxy_port_name(self, net_name, net_id):
        return utils.get_name_and_uuid('%s-%s' % ('mdproxy',
                                                  net_name or 'network'),
                                       net_id)

    def _create_net_mdproxy_port(self, context, network, az, nsx_net_id):
        if (not self.nsxlib or
            not self._has_native_dhcp_metadata()):
            return
        is_ddi_network = self._is_ddi_supported_on_network(
            context, network['id'])
        if is_ddi_network:
            # Enable native metadata proxy for this network.
            tags = self.nsxlib.build_v3_tags_payload(
                network, resource_type='os-neutron-net-id',
                project_name=context.tenant_name)
            name = self._get_mdproxy_port_name(network['name'],
                                               network['id'])
            md_port = self.nsxlib.logical_port.create(
                nsx_net_id, az._native_md_proxy_uuid,
                tags=tags, name=name,
                attachment_type=nsxlib_consts.ATTACHMENT_MDPROXY)
            LOG.debug("Created MD-Proxy logical port %(port)s "
                      "for network %(network)s",
                      {'port': md_port['id'],
                       'network': network['id']})

    def _delete_nsx_port_by_network(self, network_id):
        if not self.nsxlib:
            return
        port_id = self.nsxlib.get_id_by_resource_and_tag(
            self.nsxlib.logical_port.resource_type,
            'os-neutron-net-id', network_id)
        if port_id:
            self.nsxlib.logical_port.delete(port_id)

    def _support_vlan_router_interfaces(self):
        """Should be implemented by each plugin"""
        pass

    def _validate_multiple_subnets_routers(self, context, router_id,
                                           net_id, subnet):
        network = self.get_network(context, net_id)
        net_type = network.get(pnet.NETWORK_TYPE)
        if (net_type and
            not self._support_vlan_router_interfaces() and
            not self._is_overlay_network(context, net_id)):
            err_msg = (_("Only overlay networks can be attached to a logical "
                         "router. Network %(net_id)s is a %(net_type)s based "
                         "network") % {'net_id': net_id, 'net_type': net_type})
            LOG.error(err_msg)
            raise n_exc.InvalidInput(error_message=err_msg)
        # Unable to attach a trunked network to a router interface
        if cfg.CONF.vlan_transparent:
            if network.get('vlan_transparent') is True:
                err_msg = (_("Transparent VLAN networks cannot be attached to "
                             "a logical router."))
                LOG.error(err_msg)
                raise n_exc.InvalidInput(error_message=err_msg)
        port_filters = {'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                        'network_id': [net_id]}
        intf_ports = self.get_ports(context.elevated(), filters=port_filters)
        router_ids = [port['device_id']
                      for port in intf_ports if port['device_id']]
        if len(router_ids) > 0:
            err_msg = _("Only one subnet of each IP version in a network "
                        "%(net_id)s can be attached to router, one subnet "
                        "is already attached to router %(router_id)s") % {
                'net_id': net_id,
                'router_id': router_ids[0]}
            if router_id in router_ids:
                # We support 2 subnets from same net only for dual stack case
                if not subnet:
                    # No IP provided on connected port
                    LOG.error(err_msg)
                    raise n_exc.InvalidInput(error_message=err_msg)
                for port in intf_ports:
                    if port['device_id'] != router_id:
                        continue
                    if 'fixed_ips' in port and port['fixed_ips']:
                        ex_subnet = self.get_subnet(
                            context.elevated(),
                            port['fixed_ips'][0]['subnet_id'])
                        if ex_subnet['ip_version'] == subnet['ip_version']:
                            # attach to the same router with same IP version
                            LOG.error(err_msg)
                            raise n_exc.InvalidInput(error_message=err_msg)
            else:
                # attach to multiple routers
                LOG.error(err_msg)
                raise l3_exc.RouterInterfaceAttachmentConflict(reason=err_msg)

    def _router_has_edge_fw_rules(self, context, router):
        if not router.gw_port_id:
            # No GW -> No rule on the edge firewall
            return False

        if self.fwaas_callbacks and self.fwaas_callbacks.fwaas_enabled:
            ports = self._get_router_interfaces(context, router.id)
            return self.fwaas_callbacks.router_with_fwg(context, ports)
