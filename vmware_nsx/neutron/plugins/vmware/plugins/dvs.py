# Copyright 2012 VMware, Inc.
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

import uuid

from oslo.utils import excutils
from oslo_log import log as logging

from neutron.api import extensions as neutron_extensions
from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as n_exc
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import portbindings_db
from neutron.db import portsecurity_db
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import portbindings as pbin
from neutron.extensions import portsecurity as psec
from neutron.extensions import providernet as pnet

from vmware_nsx.neutron.plugins import vmware
from vmware_nsx.neutron.plugins.vmware.common import config  # noqa
from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.common import utils as c_utils
from vmware_nsx.neutron.plugins.vmware.dbexts import db as nsx_db
from vmware_nsx.neutron.plugins.vmware import dhcpmeta_modes
from vmware_nsx.neutron.plugins.vmware.dvs import dvs
from vmware_nsx.neutron.plugins.vmware.dvs import dvs_utils

LOG = logging.getLogger(__name__)


class NsxDvsV2(addr_pair_db.AllowedAddressPairsMixin,
               agentschedulers_db.DhcpAgentSchedulerDbMixin,
               db_base_plugin_v2.NeutronDbPluginV2,
               dhcpmeta_modes.DhcpMetadataAccess,
               external_net_db.External_net_db_mixin,
               portbindings_db.PortBindingMixin,
               portsecurity_db.PortSecurityDbMixin):

    supported_extension_aliases = ["allowed-address-pairs",
                                   "binding",
                                   "mac-learning",
                                   "multi-provider",
                                   "port-security",
                                   "provider",
                                   "quotas",
                                   "external-net"]

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self):
        super(NsxDvsV2, self).__init__()
        config.validate_config_options()
        LOG.debug('Driver support: DVS: %s' % dvs_utils.dvs_is_enabled())
        neutron_extensions.append_api_extensions_path([vmware.NSX_EXT_PATH])
        self._dvs = dvs.DvsManager()

        # Common driver code
        self.base_binding_dict = {
            pbin.VIF_TYPE: pbin.VIF_TYPE_DVS,
            pbin.VIF_DETAILS: {
                # TODO(rkukura): Replace with new VIF security details
                pbin.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}

        self.setup_dhcpmeta_access()

    def _extend_network_dict_provider(self, context, network,
                                      multiprovider=None, bindings=None):
        if not bindings:
            bindings = nsx_db.get_network_bindings(context.session,
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

    def _dvs_get_id(self, net_data):
        if net_data['name'] == '':
            return net_data['id']
        else:
            # Maximum name length is 80 characters. 'id' length is 36
            # maximum prefix for name is 43
            return '%s-%s' % (net_data['name'][:43], net_data['id'])

    def _dvs_create_network(self, context, network):
        net_data = network['network']
        if net_data['admin_state_up'] is False:
            LOG.warning(_("Network with admin_state_up=False are not yet "
                          "supported by this plugin. Ignoring setting for "
                          "network %s"), net_data.get('name', '<unknown>'))
        net_data['id'] = str(uuid.uuid4())
        vlan_tag = 0
        if net_data.get(pnet.NETWORK_TYPE) == c_utils.NetworkTypes.VLAN:
            vlan_tag = net_data.get(pnet.SEGMENTATION_ID, 0)
        dvs_id = self._dvs_get_id(net_data)
        self._dvs.add_port_group(dvs_id, vlan_tag)

        try:
            with context.session.begin(subtransactions=True):
                new_net = super(NsxDvsV2, self).create_network(context,
                                                               network)
                # Process port security extension
                self._process_network_port_security_create(
                    context, net_data, new_net)

                nsx_db.add_network_binding(
                    context.session, new_net['id'],
                    net_data.get(pnet.NETWORK_TYPE),
                    net_data.get(pnet.PHYSICAL_NETWORK),
                    vlan_tag)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_('Failed to create network'))
                self._dvs.delete_port_group(dvs_id)

        new_net[pnet.NETWORK_TYPE] = net_data.get(pnet.NETWORK_TYPE)
        new_net[pnet.PHYSICAL_NETWORK] = 'dvs'
        new_net[pnet.SEGMENTATION_ID] = vlan_tag
        self.handle_network_dhcp_access(context, new_net,
                                        action='create_network')
        return new_net

    def create_network(self, context, network):
        return self._dvs_create_network(context, network)

    def _dvs_delete_network(self, context, id):
        network = self._get_network(context, id)
        dvs_id = self._dvs_get_id(network)
        super(NsxDvsV2, self).delete_network(context, id)
        try:
            self._dvs.delete_port_group(dvs_id)
        except Exception:
            LOG.exception(_('Unable to delete DVS port group %s'), id)
        self.handle_network_dhcp_access(context, id, action='delete_network')

    def delete_network(self, context, id):
        self._dvs_delete_network(context, id)

    def _dvs_get_network(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            # goto to the plugin DB and fetch the network
            network = self._get_network(context, id)
            # Don't do field selection here otherwise we won't be able
            # to add provider networks fields
            net_result = self._make_network_dict(network)
            self._extend_network_dict_provider(context, net_result)
        return self._fields(net_result, fields)

    def get_network(self, context, id, fields=None):
        return self._dvs_get_network(context, id, fields=None)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        filters = filters or {}
        with context.session.begin(subtransactions=True):
            networks = (
                super(NsxDvsV2, self).get_networks(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            for net in networks:
                self._extend_network_dict_provider(context, net)
        return [self._fields(network, fields) for network in networks]

    def update_network(self, context, id, network):
        raise nsx_exc.NsxPluginException(
            err_msg=_("Unable to update DVS network"))

    def create_port(self, context, port):
        # If PORTSECURITY is not the default value ATTR_NOT_SPECIFIED
        # then we pass the port to the policy engine. The reason why we don't
        # pass the value to the policy engine when the port is
        # ATTR_NOT_SPECIFIED is for the case where a port is created on a
        # shared network that is not owned by the tenant.
        port_data = port['port']

        with context.session.begin(subtransactions=True):
            # First we allocate port in neutron database
            neutron_db = super(NsxDvsV2, self).create_port(context, port)
            # Update fields obtained from neutron db (eg: MAC address)
            port["port"].update(neutron_db)
            self.handle_port_metadata_access(context, neutron_db)
            # port security extension checks
            (port_security, has_ip) = self._determine_port_security_and_has_ip(
                context, port_data)
            port_data[psec.PORTSECURITY] = port_security
            self._process_port_port_security_create(
                context, port_data, neutron_db)
            # allowed address pair checks
            if attr.is_attr_set(port_data.get(addr_pair.ADDRESS_PAIRS)):
                if not port_security:
                    raise addr_pair.AddressPairAndPortSecurityRequired()
                else:
                    self._process_create_allowed_address_pairs(
                        context, neutron_db,
                        port_data[addr_pair.ADDRESS_PAIRS])
            else:
                # remove ATTR_NOT_SPECIFIED
                port_data[addr_pair.ADDRESS_PAIRS] = []

            LOG.debug(_("create_port completed on NSX for tenant "
                        "%(tenant_id)s: (%(id)s)"), port_data)

            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         port_data)
        # DB Operation is complete, perform DVS operation
        port_data = port['port']

        self.handle_port_dhcp_access(context, port_data, action='create_port')
        return port_data

    def update_port(self, context, id, port):
        changed_fixed_ips = 'fixed_ips' in port['port']
        delete_addr_pairs = self._check_update_deletes_allowed_address_pairs(
            port)
        has_addr_pairs = self._check_update_has_allowed_address_pairs(port)

        with context.session.begin(subtransactions=True):
            ret_port = super(NsxDvsV2, self).update_port(
                context, id, port)
            # Save current mac learning state to check whether it's
            # being updated or not
            # copy values over - except fixed_ips as
            # they've already been processed
            port['port'].pop('fixed_ips', None)
            ret_port.update(port['port'])

            # populate port_security setting
            if psec.PORTSECURITY not in port['port']:
                ret_port[psec.PORTSECURITY] = self._get_port_security_binding(
                    context, id)
            # validate port security and allowed address pairs
            if not ret_port[psec.PORTSECURITY]:
                #  has address pairs in request
                if has_addr_pairs:
                    raise addr_pair.AddressPairAndPortSecurityRequired()
                elif not delete_addr_pairs:
                    # check if address pairs are in db
                    ret_port[addr_pair.ADDRESS_PAIRS] = (
                        self.get_allowed_address_pairs(context, id))
                    if ret_port[addr_pair.ADDRESS_PAIRS]:
                        raise addr_pair.AddressPairAndPortSecurityRequired()

            if delete_addr_pairs or has_addr_pairs:
                # delete address pairs and read them in
                self._delete_allowed_address_pairs(context, id)
                self._process_create_allowed_address_pairs(
                    context, ret_port, ret_port[addr_pair.ADDRESS_PAIRS])
            elif changed_fixed_ips:
                self._check_fixed_ips_and_address_pairs_no_overlap(context,
                                                                   ret_port)

            if psec.PORTSECURITY in port['port']:
                self._process_port_port_security_update(
                    context, port['port'], ret_port)

            LOG.debug(_("Updating port: %s"), port)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         ret_port)
        return ret_port

    def delete_port(self, context, id, l3_port_check=True,
                    nw_gw_port_check=True):
        """Deletes a port on a specified Virtual Network.

        If the port contains a remote interface attachment, the remote
        interface is first un-plugged and then the port is deleted.

        :returns: None
        :raises: exception.PortInUse
        :raises: exception.PortNotFound
        :raises: exception.NetworkNotFound
        """
        neutron_db_port = self.get_port(context, id)

        with context.session.begin(subtransactions=True):
            # metadata_dhcp_host_route
            self.handle_port_metadata_access(
                context, neutron_db_port, is_delete=True)
            super(NsxDvsV2, self).delete_port(context, id)
        self.handle_port_dhcp_access(
            context, neutron_db_port, action='delete_port')

    def get_router(self, context, id, fields=None):
        # DVS backend cannot support logical router.
        msg = (_("Unable to get info for router %s on DVS backend") % id)
        raise n_exc.BadRequest(resource="router", msg=msg)

    def create_router(self, context, router):
        # DVS backend cannot support logical router
        msg = (_("Unable to create router %s on DVS backend") %
               router['router']['name'])
        raise n_exc.BadRequest(resource="router", msg=msg)

    def update_router(self, context, router_id, router):
        # DVS backend cannot support logical router
        msg = (_("Unable to update router %s on DVS backend") % router_id)
        raise n_exc.BadRequest(resource="router", msg=msg)

    def delete_router(self, context, router_id):
        # DVS backend cannot support logical router.
        msg = (_("Unable to delete router %s on DVS backend") % router_id)
        raise n_exc.BadRequest(resource="router", msg=msg)

    def add_router_interface(self, context, router_id, interface_info):
        # DVS backend cannot support logical router
        msg = _("Unable to add router interface to network on DVS backend")
        raise n_exc.BadRequest(resource="router", msg=msg)

    def remove_router_interface(self, context, router_id, interface_info):
        # DVS backend cannot support logical router
        msg = _("Unable to remove router interface to network on DVS backend")
        raise n_exc.BadRequest(resource="router", msg=msg)

    def delete_floatingip(self, context, id):
        # DVS backend cannot support floating ips
        msg = _("Cannot bind a floating ip to ports on DVS backend")
        raise n_exc.BadRequest(resource="port", msg=msg)

    def disassociate_floatingips(self, context, port_id):
        # DVS backend cannot support floating ips
        msg = _("Cannot bind a floating ip to ports on DVS backend")
        raise n_exc.BadRequest(resource="port", msg=msg)

    def create_security_group(self, context, security_group, default_sg=False):
        raise NotImplementedError(
            _("Create security group not supported for DVS"))

    def update_security_group(self, context, secgroup_id, security_group):
        raise NotImplementedError(
            _("Update security group not supported for DVS"))

    def delete_security_group(self, context, security_group_id):
        raise NotImplementedError(
            _("Delete security group not supported for DVS"))

    def create_security_group_rule(self, context, security_group_rule):
        raise NotImplementedError(
            _("Create security group rule not supported for DVS"))

    def create_security_group_rule_bulk(self, context, security_group_rule):
        raise NotImplementedError(
            _("Create security group rule not supported for DVS"))

    def delete_security_group_rule(self, context, sgrid):
        raise NotImplementedError(
            _("Delete security group rule not supported for DVS"))
