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


from oslo_log import log as logging

from neutron.extensions import securitygroup as ext_sg
from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api import validators
from neutron_lib.exceptions import allowedaddresspairs as addr_exc
from neutron_lib.exceptions import port_security as psec_exc

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import utils
from vmware_nsx.db import extended_security_group as extended_sec
from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.extensions import secgroup_rule_local_ip_prefix as sg_prefix
from vmware_nsx.plugins.common import plugin

LOG = logging.getLogger(__name__)


class NsxPluginV3Base(plugin.NsxPluginBase,
                      extended_sec.ExtendedSecurityGroupPropertiesMixin):
    """Common methods for NSX-V3 plugins"""

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
