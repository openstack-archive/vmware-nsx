#m Copyright 2012 VMware, Inc.
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

import weakref

from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api import faults
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib import context as q_context
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import allowedaddresspairs as addr_exc
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.exceptions import port_security as psec_exc
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils
import six
from sqlalchemy import exc as sql_exc
from sqlalchemy.orm import exc as sa_exc
import webob.exc

from neutron.api import extensions as neutron_extensions
from neutron.db import _model_query as model_query
from neutron.db import _resource_extend as resource_extend
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import api as db_api
from neutron.db import db_base_plugin_v2
from neutron.db import dns_db
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
from neutron.db import l3_attrs_db
from neutron.db import l3_db
from neutron.db import l3_dvr_db
from neutron.db import l3_gwmode_db
from neutron.db.models import l3 as l3_db_models
from neutron.db.models import securitygroup as securitygroup_model  # noqa
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import portsecurity_db
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_db
from neutron.extensions import providernet
from neutron.extensions import securitygroup as ext_sg
from neutron.quota import resource_registry
from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext
from neutron_lib.api.definitions import extraroute as xroute_apidef
from neutron_lib.api.definitions import multiprovidernet as mpnet_apidef
from neutron_lib.api.definitions import portbindings as pbin
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.exceptions import extraroute as xroute_exc
from neutron_lib.exceptions import multiprovidernet as mpnet_exc
from neutron_lib.plugins import utils

import vmware_nsx
from vmware_nsx._i18n import _
from vmware_nsx.api_client import exception as api_exc
from vmware_nsx.common import config  # noqa
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import nsx_utils
from vmware_nsx.common import securitygroups as sg_utils
from vmware_nsx.common import sync
from vmware_nsx.common import utils as c_utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import maclearning as mac_db
from vmware_nsx.db import networkgw_db
from vmware_nsx.db import nsx_models
from vmware_nsx.db import qos_db
from vmware_nsx.dhcp_meta import modes as dhcpmeta_modes
from vmware_nsx.extensions import maclearning as mac_ext
from vmware_nsx.extensions import networkgw
from vmware_nsx.extensions import qos_queue as qos
from vmware_nsx.nsxlib.mh import l2gateway as l2gwlib
from vmware_nsx.nsxlib.mh import queue as queuelib
from vmware_nsx.nsxlib.mh import router as routerlib
from vmware_nsx.nsxlib.mh import secgroup as secgrouplib
from vmware_nsx.nsxlib.mh import switch as switchlib

LOG = logging.getLogger(__name__)

NSX_NOSNAT_RULES_ORDER = 10
NSX_FLOATINGIP_NAT_RULES_ORDER = 224
NSX_EXTGW_NAT_RULES_ORDER = 255
NSX_DEFAULT_NEXTHOP = '1.1.1.1'


class NsxPluginV2(addr_pair_db.AllowedAddressPairsMixin,
                  agentschedulers_db.DhcpAgentSchedulerDbMixin,
                  db_base_plugin_v2.NeutronDbPluginV2,
                  dhcpmeta_modes.DhcpMetadataAccess,
                  l3_dvr_db.L3_NAT_with_dvr_db_mixin,
                  external_net_db.External_net_db_mixin,
                  extradhcpopt_db.ExtraDhcpOptMixin,
                  extraroute_db.ExtraRoute_db_mixin,
                  l3_gwmode_db.L3_NAT_db_mixin,
                  mac_db.MacLearningDbMixin,
                  networkgw_db.NetworkGatewayMixin,
                  portbindings_db.PortBindingMixin,
                  portsecurity_db.PortSecurityDbMixin,
                  qos_db.QoSDbMixin,
                  securitygroups_db.SecurityGroupDbMixin,
                  dns_db.DNSDbMixin):

    supported_extension_aliases = ["allowed-address-pairs",
                                   "binding",
                                   "dvr",
                                   "ext-gw-mode",
                                   xroute_apidef.ALIAS,
                                   "mac-learning",
                                   "multi-provider",
                                   "network-gateway",
                                   "port-security",
                                   "provider",
                                   "qos-queue",
                                   "quotas",
                                   "external-net",
                                   "extra_dhcp_opt",
                                   "router",
                                   "security-group",
                                   constants.SUBNET_ALLOCATION_EXT_ALIAS]

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    # Map nova zones to cluster for easy retrieval
    novazone_cluster_map = {}

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
        LOG.warning("The NSX-MH plugin is deprecated and may be removed "
                    "in the O or the P cycle")
        super(NsxPluginV2, self).__init__()
        # TODO(salv-orlando): Replace These dicts with
        # collections.defaultdict for better handling of default values
        # Routines for managing logical ports in NSX
        self.port_special_owners = [l3_db.DEVICE_OWNER_ROUTER_GW,
                                    l3_db.DEVICE_OWNER_ROUTER_INTF]
        self._port_drivers = {
            'create': {constants.DEVICE_OWNER_ROUTER_GW:
                       self._nsx_create_ext_gw_port,
                       constants.DEVICE_OWNER_FLOATINGIP:
                       self._nsx_create_fip_port,
                       constants.DEVICE_OWNER_ROUTER_INTF:
                       self._nsx_create_router_port,
                       constants.DEVICE_OWNER_DVR_INTERFACE:
                       self._nsx_create_router_port,
                       networkgw_db.DEVICE_OWNER_NET_GW_INTF:
                       self._nsx_create_l2_gw_port,
                       'default': self._nsx_create_port},
            'delete': {constants.DEVICE_OWNER_ROUTER_GW:
                       self._nsx_delete_ext_gw_port,
                       constants.DEVICE_OWNER_ROUTER_INTF:
                       self._nsx_delete_router_port,
                       constants.DEVICE_OWNER_DVR_INTERFACE:
                       self._nsx_delete_router_port,
                       constants.DEVICE_OWNER_FLOATINGIP:
                       self._nsx_delete_fip_port,
                       networkgw_db.DEVICE_OWNER_NET_GW_INTF:
                       self._nsx_delete_port,
                       'default': self._nsx_delete_port}
        }

        neutron_extensions.append_api_extensions_path(
            [vmware_nsx.NSX_EXT_PATH])
        self.cfg_group = 'NSX'  # group name for nsx section in nsx.ini
        self.nsx_opts = cfg.CONF.NSX
        self.nsx_sync_opts = cfg.CONF.NSX_SYNC
        self.cluster = nsx_utils.create_nsx_cluster(
            cfg.CONF,
            self.nsx_opts.concurrent_connections,
            self.nsx_opts.nsx_gen_timeout)

        self.base_binding_dict = {
            pbin.VIF_TYPE: pbin.VIF_TYPE_OVS,
            pbin.VIF_DETAILS: {
                # TODO(rkukura): Replace with new VIF security details
                pbin.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}

        self._extend_fault_map()
        self.setup_dhcpmeta_access()
        # Set this flag to false as the default gateway has not
        # been yet updated from the config file
        self._is_default_net_gw_in_sync = False
        # Create a synchronizer instance for backend sync
        self._synchronizer = sync.NsxSynchronizer(
            weakref.proxy(self), self.cluster,
            self.nsx_sync_opts.state_sync_interval,
            self.nsx_sync_opts.min_sync_req_delay,
            self.nsx_sync_opts.min_chunk_size,
            self.nsx_sync_opts.max_random_sync_delay)

    def _ensure_default_network_gateway(self):
        if self._is_default_net_gw_in_sync:
            return
        # Add the gw in the db as default, and unset any previous default
        def_l2_gw_uuid = self.cluster.default_l2_gw_service_uuid
        try:
            ctx = q_context.get_admin_context()
            self._unset_default_network_gateways(ctx)
            if not def_l2_gw_uuid:
                return
            try:
                def_network_gw = self._get_network_gateway(ctx,
                                                           def_l2_gw_uuid)
            except networkgw_db.GatewayNotFound:
                # Create in DB only - don't go to backend
                def_gw_data = {'id': def_l2_gw_uuid,
                               'name': 'default L2 gateway service',
                               'devices': [],
                               'tenant_id': ctx.tenant_id}
                gw_res_name = networkgw.GATEWAY_RESOURCE_NAME.replace('-', '_')
                def_network_gw = super(
                    NsxPluginV2, self).create_network_gateway(
                        ctx, {gw_res_name: def_gw_data})
            # In any case set is as default
            self._set_default_network_gateway(ctx, def_network_gw['id'])
            # Ensure this method is executed only once
            self._is_default_net_gw_in_sync = True
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception("Unable to process default l2 gw service: "
                              "%s",
                              def_l2_gw_uuid)

    def _build_ip_address_list(self, context, fixed_ips, subnet_ids=None):
        """Build ip_addresses data structure for logical router port.

        No need to perform validation on IPs - this has already been
        done in the l3_db mixin class.
        """
        ip_addresses = []
        for ip in fixed_ips:
            if not subnet_ids or (ip['subnet_id'] in subnet_ids):
                subnet = self._get_subnet(context, ip['subnet_id'])
                ip_prefix = '%s/%s' % (ip['ip_address'],
                                       subnet['cidr'].split('/')[1])
                ip_addresses.append(ip_prefix)
        return ip_addresses

    def _create_and_attach_router_port(self, cluster, context,
                                       nsx_router_id, port_data,
                                       attachment_type, attachment,
                                       attachment_vlan=None,
                                       subnet_ids=None):
        # Use a fake IP address if gateway port is not 'real'
        ip_addresses = (port_data.get('fake_ext_gw') and
                        ['0.0.0.0/31'] or
                        self._build_ip_address_list(context,
                                                    port_data['fixed_ips'],
                                                    subnet_ids))
        try:
            lrouter_port = routerlib.create_router_lport(
                cluster, nsx_router_id, port_data.get('tenant_id', 'fake'),
                port_data.get('id', 'fake'), port_data.get('name', 'fake'),
                port_data.get('admin_state_up', True), ip_addresses,
                port_data.get('mac_address'))
            LOG.debug("Created NSX router port:%s", lrouter_port['uuid'])
        except api_exc.NsxApiException:
            LOG.exception("Unable to create port on NSX logical router "
                          "%s",
                          nsx_router_id)
            raise nsx_exc.NsxPluginException(
                err_msg=_("Unable to create logical router port for neutron "
                          "port id %(port_id)s on router %(nsx_router_id)s") %
                {'port_id': port_data.get('id'),
                 'nsx_router_id': nsx_router_id})
        self._update_router_port_attachment(cluster, context, nsx_router_id,
                                            port_data, lrouter_port['uuid'],
                                            attachment_type, attachment,
                                            attachment_vlan)
        return lrouter_port

    def _update_router_gw_info(self, context, router_id, info):
        # NOTE(salvatore-orlando): We need to worry about rollback of NSX
        # configuration in case of failures in the process
        # Ref. LP bug 1102301
        router = self._get_router(context, router_id)
        # Check whether SNAT rule update should be triggered
        # NSX also supports multiple external networks so there is also
        # the possibility that NAT rules should be replaced
        current_ext_net_id = router.gw_port_id and router.gw_port.network_id
        new_ext_net_id = info and info.get('network_id')
        # SNAT should be enabled unless info['enable_snat'] is
        # explicitly set to false
        enable_snat = new_ext_net_id and info.get('enable_snat', True)
        # Remove if ext net removed, changed, or if snat disabled
        remove_snat_rules = (current_ext_net_id and
                             new_ext_net_id != current_ext_net_id or
                             router.enable_snat and not enable_snat)
        # Add rules if snat is enabled, and if either the external network
        # changed or snat was previously disabled
        # NOTE: enable_snat == True implies new_ext_net_id != None
        add_snat_rules = (enable_snat and
                          (new_ext_net_id != current_ext_net_id or
                           not router.enable_snat))
        router = super(NsxPluginV2, self)._update_router_gw_info(
            context, router_id, info, router=router)
        # Add/Remove SNAT rules as needed
        # Create an elevated context for dealing with metadata access
        # cidrs which are created within admin context
        ctx_elevated = context.elevated()
        if remove_snat_rules or add_snat_rules:
            cidrs = self._find_router_subnets_cidrs(ctx_elevated, router_id)
        nsx_router_id = nsx_utils.get_nsx_router_id(
            context.session, self.cluster, router_id)
        if remove_snat_rules:
            # Be safe and concede NAT rules might not exist.
            # Therefore, use min_num_expected=0
            for cidr in cidrs:
                routerlib.delete_nat_rules_by_match(
                    self.cluster, nsx_router_id, "SourceNatRule",
                    max_num_expected=1, min_num_expected=0,
                    raise_on_len_mismatch=False,
                    source_ip_addresses=cidr)
        if add_snat_rules:
            ip_addresses = self._build_ip_address_list(
                ctx_elevated, router.gw_port['fixed_ips'])
            # Set the SNAT rule for each subnet (only first IP)
            for cidr in cidrs:
                cidr_prefix = int(cidr.split('/')[1])
                routerlib.create_lrouter_snat_rule(
                    self.cluster, nsx_router_id,
                    ip_addresses[0].split('/')[0],
                    ip_addresses[0].split('/')[0],
                    order=NSX_EXTGW_NAT_RULES_ORDER - cidr_prefix,
                    match_criteria={'source_ip_addresses': cidr})

    def _update_router_port_attachment(self, cluster, context,
                                       nsx_router_id, port_data,
                                       nsx_router_port_id,
                                       attachment_type,
                                       attachment,
                                       attachment_vlan=None):
        if not nsx_router_port_id:
            nsx_router_port_id = self._find_router_gw_port(context, port_data)
        try:
            routerlib.plug_router_port_attachment(cluster, nsx_router_id,
                                                  nsx_router_port_id,
                                                  attachment,
                                                  attachment_type,
                                                  attachment_vlan)
            LOG.debug("Attached %(att)s to NSX router port %(port)s",
                      {'att': attachment, 'port': nsx_router_port_id})
        except api_exc.NsxApiException:
            # Must remove NSX logical port
            routerlib.delete_router_lport(cluster, nsx_router_id,
                                          nsx_router_port_id)
            LOG.exception("Unable to plug attachment in NSX logical "
                          "router port %(r_port_id)s, associated with "
                          "Neutron %(q_port_id)s",
                          {'r_port_id': nsx_router_port_id,
                           'q_port_id': port_data.get('id')})
            raise nsx_exc.NsxPluginException(
                err_msg=(_("Unable to plug attachment in router port "
                           "%(r_port_id)s for neutron port id %(q_port_id)s "
                           "on router %(router_id)s") %
                         {'r_port_id': nsx_router_port_id,
                          'q_port_id': port_data.get('id'),
                          'router_id': nsx_router_id}))

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
                cidrs.append(self._get_subnet(context,
                                              ip.subnet_id).cidr)
        return cidrs

    def _nsx_find_lswitch_for_port(self, context, port_data):
        network = self._get_network(context, port_data['network_id'])
        return self._handle_lswitch_selection(
            context, self.cluster, network)

    def _nsx_create_port_helper(self, session, ls_uuid, port_data,
                                do_port_security=True):
        # Convert Neutron security groups identifiers into NSX security
        # profiles identifiers
        nsx_sec_profile_ids = [
            nsx_utils.get_nsx_security_group_id(
                session, self.cluster, neutron_sg_id) for
            neutron_sg_id in (port_data[ext_sg.SECURITYGROUPS] or [])]
        return switchlib.create_lport(self.cluster,
                                      ls_uuid,
                                      port_data['tenant_id'],
                                      port_data['id'],
                                      port_data['name'],
                                      port_data['device_id'],
                                      port_data['admin_state_up'],
                                      port_data['mac_address'],
                                      port_data['fixed_ips'],
                                      port_data[psec.PORTSECURITY],
                                      nsx_sec_profile_ids,
                                      port_data.get(qos.QUEUE),
                                      port_data.get(mac_ext.MAC_LEARNING),
                                      port_data.get(addr_apidef.ADDRESS_PAIRS))

    def _handle_create_port_exception(self, context, port_id,
                                      ls_uuid, lp_uuid):
        with excutils.save_and_reraise_exception():
            # rollback nsx logical port only if it was successfully
            # created on NSX. Should this command fail the original
            # exception will be raised.
            if lp_uuid:
                # Remove orphaned port from NSX
                switchlib.delete_port(self.cluster, ls_uuid, lp_uuid)
            # rollback the neutron-nsx port mapping
            nsx_db.delete_neutron_nsx_port_mapping(context.session,
                                                   port_id)
            LOG.exception("An exception occurred while creating the "
                          "neutron port %s on the NSX plaform", port_id)

    def _nsx_create_port(self, context, port_data):
        """Driver for creating a logical switch port on NSX platform."""
        # FIXME(salvatore-orlando): On the NSX platform we do not really have
        # external networks. So if as user tries and create a "regular" VIF
        # port on an external network we are unable to actually create.
        # However, in order to not break unit tests, we need to still create
        # the DB object and return success
        if self._network_is_external(context, port_data['network_id']):
            LOG.info("NSX plugin does not support regular VIF ports on "
                     "external networks. Port %s will be down.",
                     port_data['network_id'])
            # No need to actually update the DB state - the default is down
            return port_data
        lport = None
        selected_lswitch = None
        try:
            selected_lswitch = self._nsx_find_lswitch_for_port(context,
                                                               port_data)
            lport = self._nsx_create_port_helper(context.session,
                                                 selected_lswitch['uuid'],
                                                 port_data,
                                                 True)
            nsx_db.add_neutron_nsx_port_mapping(
                context.session, port_data['id'],
                selected_lswitch['uuid'], lport['uuid'])
            if port_data['device_owner'] not in self.port_special_owners:
                switchlib.plug_vif_interface(
                    self.cluster, selected_lswitch['uuid'],
                    lport['uuid'], "VifAttachment", port_data['id'])
            LOG.debug("_nsx_create_port completed for port %(name)s "
                      "on network %(network_id)s. The new port id is "
                      "%(id)s.", port_data)
        except (api_exc.NsxApiException, n_exc.NeutronException):
            self._handle_create_port_exception(
                context, port_data['id'],
                selected_lswitch and selected_lswitch['uuid'],
                lport and lport['uuid'])
        except db_exc.DBError as e:
            if (port_data['device_owner'] == constants.DEVICE_OWNER_DHCP and
                isinstance(e.inner_exception, sql_exc.IntegrityError)):
                LOG.warning(
                    "Concurrent network deletion detected; Back-end "
                    "Port %(nsx_id)s creation to be rolled back for "
                    "Neutron port: %(neutron_id)s",
                    {'nsx_id': lport['uuid'],
                     'neutron_id': port_data['id']})
                if selected_lswitch and lport:
                    try:
                        switchlib.delete_port(self.cluster,
                                              selected_lswitch['uuid'],
                                              lport['uuid'])
                    except n_exc.NotFound:
                        LOG.debug("NSX Port %s already gone", lport['uuid'])

    def _nsx_delete_port(self, context, port_data):
        # FIXME(salvatore-orlando): On the NSX platform we do not really have
        # external networks. So deleting regular ports from external networks
        # does not make sense. However we cannot raise as this would break
        # unit tests.
        if self._network_is_external(context, port_data['network_id']):
            LOG.info("NSX plugin does not support regular VIF ports on "
                     "external networks. Port %s will be down.",
                     port_data['network_id'])
            return
        nsx_switch_id, nsx_port_id = nsx_utils.get_nsx_switch_and_port_id(
            context.session, self.cluster, port_data['id'])
        if not nsx_port_id:
            LOG.debug("Port '%s' was already deleted on NSX platform", id)
            return
        # TODO(bgh): if this is a bridged network and the lswitch we just got
        # back will have zero ports after the delete we should garbage collect
        # the lswitch.
        try:
            switchlib.delete_port(self.cluster, nsx_switch_id, nsx_port_id)
            LOG.debug("_nsx_delete_port completed for port %(port_id)s "
                      "on network %(net_id)s",
                      {'port_id': port_data['id'],
                       'net_id': port_data['network_id']})
        except n_exc.NotFound:
            LOG.warning("Port %s not found in NSX", port_data['id'])

    def _nsx_delete_router_port(self, context, port_data):
        # Delete logical router port
        nsx_router_id = nsx_utils.get_nsx_router_id(
            context.session, self.cluster, port_data['device_id'])
        nsx_switch_id, nsx_port_id = nsx_utils.get_nsx_switch_and_port_id(
            context.session, self.cluster, port_data['id'])
        if not nsx_port_id:
            LOG.warning(
                "Neutron port %(port_id)s not found on NSX backend. "
                "Terminating delete operation. A dangling router port "
                "might have been left on router %(router_id)s",
                {'port_id': port_data['id'],
                 'router_id': nsx_router_id})
            return
        try:
            routerlib.delete_peer_router_lport(self.cluster,
                                               nsx_router_id,
                                               nsx_switch_id,
                                               nsx_port_id)
        except api_exc.NsxApiException:
            # Do not raise because the issue might as well be that the
            # router has already been deleted, so there would be nothing
            # to do here
            LOG.exception("Ignoring exception as this means the peer "
                          "for port '%s' has already been deleted.",
                          nsx_port_id)

        # Delete logical switch port
        self._nsx_delete_port(context, port_data)

    def _nsx_create_router_port(self, context, port_data):
        """Driver for creating a switch port to be connected to a router."""
        # No router ports on external networks!
        if self._network_is_external(context, port_data['network_id']):
            raise nsx_exc.NsxPluginException(
                err_msg=(_("It is not allowed to create router interface "
                           "ports on external networks as '%s'") %
                         port_data['network_id']))
        ls_port = None
        selected_lswitch = None
        try:
            selected_lswitch = self._nsx_find_lswitch_for_port(
                context, port_data)
            # Do not apply port security here!
            ls_port = self._nsx_create_port_helper(
                context.session, selected_lswitch['uuid'],
                port_data, False)
            # Assuming subnet being attached is on first fixed ip
            # element in port data
            subnet_id = None
            if len(port_data['fixed_ips']):
                subnet_id = port_data['fixed_ips'][0]['subnet_id']
            nsx_router_id = nsx_utils.get_nsx_router_id(
                context.session, self.cluster, port_data['device_id'])
            # Create peer port on logical router
            self._create_and_attach_router_port(
                self.cluster, context, nsx_router_id, port_data,
                "PatchAttachment", ls_port['uuid'],
                subnet_ids=[subnet_id])
            nsx_db.add_neutron_nsx_port_mapping(
                context.session, port_data['id'],
                selected_lswitch['uuid'], ls_port['uuid'])
            LOG.debug("_nsx_create_router_port completed for port "
                      "%(name)s on network %(network_id)s. The new "
                      "port id is %(id)s.",
                      port_data)
        except (api_exc.NsxApiException, n_exc.NeutronException):
            self._handle_create_port_exception(
                context, port_data['id'],
                selected_lswitch and selected_lswitch['uuid'],
                ls_port and ls_port['uuid'])

    def _find_router_gw_port(self, context, port_data):
        router_id = port_data['device_id']
        if not router_id:
            raise n_exc.BadRequest(_("device_id field must be populated in "
                                   "order to create an external gateway "
                                   "port for network %s"),
                                   port_data['network_id'])
        nsx_router_id = nsx_utils.get_nsx_router_id(
            context.session, self.cluster, router_id)
        lr_port = routerlib.find_router_gw_port(context, self.cluster,
                                                nsx_router_id)
        if not lr_port:
            raise nsx_exc.NsxPluginException(
                err_msg=(_("The gateway port for the NSX router %s "
                           "was not found on the backend")
                         % nsx_router_id))
        return lr_port

    @lockutils.synchronized('vmware', 'neutron-')
    def _nsx_create_ext_gw_port(self, context, port_data):
        """Driver for creating an external gateway port on NSX platform."""
        # TODO(salvatore-orlando): Handle NSX resource
        # rollback when something goes not quite as expected
        lr_port = self._find_router_gw_port(context, port_data)
        ip_addresses = self._build_ip_address_list(context,
                                                   port_data['fixed_ips'])
        # This operation actually always updates a NSX logical port
        # instead of creating one. This is because the gateway port
        # is created at the same time as the NSX logical router, otherwise
        # the fabric status of the NSX router will be down.
        # admin_status should always be up for the gateway port
        # regardless of what the user specifies in neutron
        nsx_router_id = nsx_utils.get_nsx_router_id(
            context.session, self.cluster, port_data['device_id'])
        routerlib.update_router_lport(self.cluster,
                                      nsx_router_id,
                                      lr_port['uuid'],
                                      port_data['tenant_id'],
                                      port_data['id'],
                                      port_data['name'],
                                      True,
                                      ip_addresses)
        ext_network = self.get_network(context, port_data['network_id'])
        if ext_network.get(pnet.NETWORK_TYPE) == c_utils.NetworkTypes.L3_EXT:
            # Update attachment
            physical_network = (ext_network[pnet.PHYSICAL_NETWORK] or
                                self.cluster.default_l3_gw_service_uuid)
            self._update_router_port_attachment(
                self.cluster, context, nsx_router_id, port_data,
                lr_port['uuid'],
                "L3GatewayAttachment",
                physical_network,
                ext_network[pnet.SEGMENTATION_ID])

        LOG.debug("_nsx_create_ext_gw_port completed on external network "
                  "%(ext_net_id)s, attached to router:%(router_id)s. "
                  "NSX port id is %(nsx_port_id)s",
                  {'ext_net_id': port_data['network_id'],
                   'router_id': nsx_router_id,
                   'nsx_port_id': lr_port['uuid']})

    @lockutils.synchronized('vmware', 'neutron-')
    def _nsx_delete_ext_gw_port(self, context, port_data):
        # TODO(salvatore-orlando): Handle NSX resource
        # rollback when something goes not quite as expected
        try:
            router_id = port_data['device_id']
            nsx_router_id = nsx_utils.get_nsx_router_id(
                context.session, self.cluster, router_id)
            if not nsx_router_id:
                LOG.debug("No object found on backend for router %s. This "
                          "that the router was already deleted and no "
                          "further action is needed for resetting the "
                          "external gateway port", router_id)
                return
            lr_port = self._find_router_gw_port(context, port_data)
            # Delete is actually never a real delete, otherwise the NSX
            # logical router will stop working
            routerlib.update_router_lport(self.cluster,
                                          nsx_router_id,
                                          lr_port['uuid'],
                                          port_data['tenant_id'],
                                          port_data['id'],
                                          port_data['name'],
                                          True,
                                          ['0.0.0.0/31'])
            # Reset attachment
            self._update_router_port_attachment(
                self.cluster, context, nsx_router_id, port_data,
                lr_port['uuid'],
                "L3GatewayAttachment",
                self.cluster.default_l3_gw_service_uuid)
            LOG.debug("_nsx_delete_ext_gw_port completed on external network "
                      "%(ext_net_id)s, attached to NSX router:%(router_id)s",
                      {'ext_net_id': port_data['network_id'],
                       'router_id': nsx_router_id})
        except n_exc.NotFound:
            LOG.debug("Logical router resource %s not found "
                      "on NSX platform : the router may have "
                      "already been deleted",
                      port_data['device_id'])
        except api_exc.NsxApiException:
            raise nsx_exc.NsxPluginException(
                err_msg=_("Unable to update logical router"
                          "on NSX Platform"))

    def _nsx_create_l2_gw_port(self, context, port_data):
        """Create a switch port, and attach it to a L2 gateway attachment."""
        # FIXME(salvatore-orlando): On the NSX platform we do not really have
        # external networks. So if as user tries and create a "regular" VIF
        # port on an external network we are unable to actually create.
        # However, in order to not break unit tests, we need to still create
        # the DB object and return success
        if self._network_is_external(context, port_data['network_id']):
            LOG.info("NSX plugin does not support regular VIF ports on "
                     "external networks. Port %s will be down.",
                     port_data['network_id'])
            # No need to actually update the DB state - the default is down
            return port_data
        lport = None
        try:
            selected_lswitch = self._nsx_find_lswitch_for_port(
                context, port_data)
            lport = self._nsx_create_port_helper(
                context.session,
                selected_lswitch['uuid'],
                port_data,
                True)
            nsx_db.add_neutron_nsx_port_mapping(
                context.session, port_data['id'],
                selected_lswitch['uuid'], lport['uuid'])
            l2gwlib.plug_l2_gw_service(
                self.cluster,
                selected_lswitch['uuid'],
                lport['uuid'],
                port_data['device_id'],
                int(port_data.get('gw:segmentation_id') or 0))
        except Exception:
            with excutils.save_and_reraise_exception():
                if lport:
                    switchlib.delete_port(self.cluster,
                                          selected_lswitch['uuid'],
                                          lport['uuid'])
        LOG.debug("_nsx_create_l2_gw_port completed for port %(name)s "
                  "on network %(network_id)s. The new port id "
                  "is %(id)s.", port_data)

    def _nsx_create_fip_port(self, context, port_data):
        # As we do not create ports for floating IPs in NSX,
        # this is a no-op driver
        pass

    def _nsx_delete_fip_port(self, context, port_data):
        # As we do not create ports for floating IPs in NSX,
        # this is a no-op driver
        pass

    def _extend_fault_map(self):
        """Extends the Neutron Fault Map.

        Exceptions specific to the NSX Plugin are mapped to standard
        HTTP Exceptions.
        """
        faults.FAULT_MAP.update({nsx_exc.InvalidNovaZone:
                                 webob.exc.HTTPBadRequest,
                                 nsx_exc.NoMorePortsException:
                                 webob.exc.HTTPBadRequest,
                                 nsx_exc.MaintenanceInProgress:
                                 webob.exc.HTTPServiceUnavailable,
                                 nsx_exc.InvalidSecurityCertificate:
                                 webob.exc.HTTPBadRequest})

    def _validate_provider_create(self, context, network):
        segments = network.get(mpnet_apidef.SEGMENTS)
        if not validators.is_attr_set(segments):
            return

        mpnet_apidef.check_duplicate_segments(segments)
        for segment in segments:
            network_type = segment.get(pnet.NETWORK_TYPE)
            physical_network = segment.get(pnet.PHYSICAL_NETWORK)
            physical_network_set = validators.is_attr_set(physical_network)
            segmentation_id = segment.get(pnet.SEGMENTATION_ID)
            network_type_set = validators.is_attr_set(network_type)
            segmentation_id_set = validators.is_attr_set(segmentation_id)

            # If the physical_network_uuid isn't passed in use the default one.
            if not physical_network_set:
                physical_network = cfg.CONF.default_tz_uuid

            err_msg = None
            if not network_type_set:
                err_msg = _("%s required") % pnet.NETWORK_TYPE
            elif network_type in (c_utils.NetworkTypes.GRE,
                                  c_utils.NetworkTypes.STT,
                                  c_utils.NetworkTypes.FLAT):
                if segmentation_id_set:
                    err_msg = _("Segmentation ID cannot be specified with "
                                "flat network type")
            elif network_type == c_utils.NetworkTypes.VLAN:
                if not segmentation_id_set:
                    err_msg = _("Segmentation ID must be specified with "
                                "vlan network type")
                elif (segmentation_id_set and
                      not utils.is_valid_vlan_tag(segmentation_id)):
                    err_msg = (_("%(segmentation_id)s out of range "
                                 "(%(min_id)s through %(max_id)s)") %
                               {'segmentation_id': segmentation_id,
                                'min_id': constants.MIN_VLAN_TAG,
                                'max_id': constants.MAX_VLAN_TAG})
                else:
                    # Verify segment is not already allocated
                    bindings = (
                        nsx_db.get_network_bindings_by_vlanid_and_physical_net(
                            context.session, segmentation_id,
                            physical_network)
                    )
                    if bindings:
                        raise n_exc.VlanIdInUse(
                            vlan_id=segmentation_id,
                            physical_network=physical_network)
            elif network_type == c_utils.NetworkTypes.L3_EXT:
                if (segmentation_id_set and
                    not utils.is_valid_vlan_tag(segmentation_id)):
                    err_msg = (_("%(segmentation_id)s out of range "
                                 "(%(min_id)s through %(max_id)s)") %
                               {'segmentation_id': segmentation_id,
                                'min_id': constants.MIN_VLAN_TAG,
                                'max_id': constants.MAX_VLAN_TAG})
                # Network must be external
                if not network.get(extnet_apidef.EXTERNAL):
                    err_msg = (_("The l3_ext provide network type can be "
                                 "used with external networks only"))
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
                network[mpnet_apidef.SEGMENTS] = [
                    {pnet.NETWORK_TYPE: binding.binding_type,
                     pnet.PHYSICAL_NETWORK: binding.phy_uuid,
                     pnet.SEGMENTATION_ID: binding.vlan_id}
                    for binding in bindings]

    def extend_port_dict_binding(self, port_res, port_db):
        super(NsxPluginV2, self).extend_port_dict_binding(port_res, port_db)
        port_res[pbin.VNIC_TYPE] = pbin.VNIC_NORMAL

    def _handle_lswitch_selection(self, context, cluster, network):
        # NOTE(salv-orlando): This method used to select a NSX logical switch
        # with an available port, and create a new logical switch if
        # necessary. As there is no more need to perform switch chaining in
        # NSX, the logic for creating a new logical switch has been removed.
        max_ports = self.nsx_opts.max_lp_per_overlay_ls
        network_bindings = nsx_db.get_network_bindings(
            context.session, network['id'])
        for network_binding in network_bindings:
            if network_binding.binding_type in (c_utils.NetworkTypes.FLAT,
                                                c_utils.NetworkTypes.VLAN):
                max_ports = self.nsx_opts.max_lp_per_bridged_ls
        # This is still necessary as there could be chained switches in
        # the deployment and the code needs to find the first one with
        # an available slot for a port
        lswitches = nsx_utils.fetch_nsx_switches(
            context.session, cluster, network['id'])
        try:
            return [ls for ls in lswitches
                    if (ls['_relations']['LogicalSwitchStatus']
                        ['lport_count'] < max_ports)].pop(0)
        except IndexError:
            # Too bad, no switch where a port can be created
            LOG.debug("No switch has available ports (%d checked)",
                      len(lswitches))
            raise nsx_exc.NoMorePortsException(network=network.id)

    def _convert_to_nsx_transport_zones(self, cluster, network=None,
                                        bindings=None):
        # TODO(salv-orlando): Remove this method and call nsx-utils direct
        return nsx_utils.convert_to_nsx_transport_zones(
            cluster.default_tz_uuid, network, bindings,
            default_transport_type=cfg.CONF.NSX.default_transport_type)

    def _convert_to_transport_zones_dict(self, network):
        """Converts the provider request body to multiprovider.
        Returns: True if request is multiprovider False if provider
        and None if neither.
        """
        if any(validators.is_attr_set(network.get(f))
               for f in (pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                         pnet.SEGMENTATION_ID)):
            if validators.is_attr_set(network.get(mpnet_apidef.SEGMENTS)):
                raise mpnet_exc.SegmentsSetInConjunctionWithProviders()
            # convert to transport zone list
            network[mpnet_apidef.SEGMENTS] = [
                {pnet.NETWORK_TYPE: network[pnet.NETWORK_TYPE],
                 pnet.PHYSICAL_NETWORK: network[pnet.PHYSICAL_NETWORK],
                 pnet.SEGMENTATION_ID: network[pnet.SEGMENTATION_ID]}]
            del network[pnet.NETWORK_TYPE]
            del network[pnet.PHYSICAL_NETWORK]
            del network[pnet.SEGMENTATION_ID]
            return False
        if validators.is_attr_set(mpnet_apidef.SEGMENTS):
            return True

    def create_network(self, context, network):
        net_data = network['network']
        tenant_id = net_data['tenant_id']
        self._ensure_default_security_group(context, tenant_id)
        # Process the provider network extension
        provider_type = self._convert_to_transport_zones_dict(net_data)
        self._validate_provider_create(context, net_data)
        # Replace ATTR_NOT_SPECIFIED with None before sending to NSX
        for key, value in six.iteritems(network['network']):
            if value is constants.ATTR_NOT_SPECIFIED:
                net_data[key] = None
        # FIXME(arosen) implement admin_state_up = False in NSX
        if net_data['admin_state_up'] is False:
            LOG.warning("Network with admin_state_up=False are not yet "
                        "supported by this plugin. Ignoring setting for "
                        "network %s", net_data.get('name', '<unknown>'))
        transport_zone_config = self._convert_to_nsx_transport_zones(
            self.cluster, net_data)
        external = net_data.get(extnet_apidef.EXTERNAL)
        # NOTE(salv-orlando): Pre-generating uuid for Neutron
        # network. This will be removed once the network create operation
        # becomes an asynchronous task
        net_data['id'] = str(uuidutils.generate_uuid())
        if (not validators.is_attr_set(external) or
            validators.is_attr_set(external) and not external):
            lswitch = switchlib.create_lswitch(
                self.cluster, net_data['id'],
                tenant_id, net_data.get('name'),
                transport_zone_config,
                shared=net_data.get(constants.SHARED))

        with db_api.context_manager.writer.using(context):
            new_net = super(NsxPluginV2, self).create_network(context,
                                                              network)
            # Process port security extension
            self._process_network_port_security_create(
                context, net_data, new_net)
            # DB Operations for setting the network as external
            self._process_l3_create(context, new_net, net_data)
            # Process QoS queue extension
            net_queue_id = net_data.get(qos.QUEUE)
            if net_queue_id:
                # Raises if not found
                self.get_qos_queue(context, net_queue_id)
                self._process_network_queue_mapping(
                    context, new_net, net_queue_id)
            # Add mapping between neutron network and NSX switch
            if (not validators.is_attr_set(external) or
                validators.is_attr_set(external) and not external):
                nsx_db.add_neutron_nsx_network_mapping(
                    context.session, new_net['id'],
                    lswitch['uuid'])
            if (net_data.get(mpnet_apidef.SEGMENTS) and
                isinstance(provider_type, bool)):
                net_bindings = []
                for tz in net_data[mpnet_apidef.SEGMENTS]:
                    segmentation_id = tz.get(pnet.SEGMENTATION_ID, 0)
                    segmentation_id_set = validators.is_attr_set(
                        segmentation_id)
                    if not segmentation_id_set:
                        segmentation_id = 0
                    net_bindings.append(nsx_db.add_network_binding(
                        context.session, new_net['id'],
                        tz.get(pnet.NETWORK_TYPE),
                        tz.get(pnet.PHYSICAL_NETWORK),
                        segmentation_id))
                if provider_type:
                    nsx_db.set_multiprovider_network(context.session,
                                                     new_net['id'])
                self._extend_network_dict_provider(context, new_net,
                                                   provider_type,
                                                   net_bindings)

        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        net_model = self._get_network(context, new_net['id'])
        resource_extend.apply_funcs('networks', new_net, net_model)
        self.handle_network_dhcp_access(context, new_net,
                                        action='create_network')
        return new_net

    def delete_network(self, context, id):
        external = self._network_is_external(context, id)
        # Before removing entry from Neutron DB, retrieve NSX switch
        # identifiers for removing them from backend
        if not external:
            lswitch_ids = nsx_utils.get_nsx_switch_ids(
                context.session, self.cluster, id)
        self._process_l3_delete(context, id)
        nsx_db.delete_network_bindings(context.session, id)
        super(NsxPluginV2, self).delete_network(context, id)

        # Do not go to NSX for external networks
        if not external:
            try:
                switchlib.delete_networks(self.cluster, id, lswitch_ids)
            except n_exc.NotFound:
                LOG.warning("The following logical switches were not "
                            "found on the NSX backend:%s", lswitch_ids)
        self.handle_network_dhcp_access(context, id, action='delete_network')
        LOG.debug("Delete network complete for network: %s", id)

    def get_network(self, context, id, fields=None):
        with db_api.context_manager.writer.using(context):
            # goto to the plugin DB and fetch the network
            network = self._get_network(context, id)
            if (self.nsx_sync_opts.always_read_status or
                fields and 'status' in fields):
                # External networks are not backed by nsx lswitches
                if not network.external:
                    # Perform explicit state synchronization
                    self._synchronizer.synchronize_network(context, network)
            # Don't do field selection here otherwise we won't be able
            # to add provider networks fields
            net_result = self._make_network_dict(network,
                                                 context=context)
            self._extend_network_dict_provider(context, net_result)
        return db_utils.resource_fields(net_result, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        filters = filters or {}
        with db_api.context_manager.reader.using(context):
            networks = (
                super(NsxPluginV2, self).get_networks(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            for net in networks:
                self._extend_network_dict_provider(context, net)
        return (networks if not fields else
                [db_utils.resource_fields(network,
                                          fields) for network in networks])

    def update_network(self, context, id, network):
        providernet._raise_if_updates_provider_attributes(network['network'])
        if network["network"].get("admin_state_up") is False:
            raise NotImplementedError(_("admin_state_up=False networks "
                                        "are not supported."))
        with db_api.context_manager.writer.using(context):
            net = super(NsxPluginV2, self).update_network(context, id, network)
            if psec.PORTSECURITY in network['network']:
                self._process_network_port_security_update(
                    context, network['network'], net)
            net_queue_id = network['network'].get(qos.QUEUE)
            if net_queue_id:
                self._delete_network_queue_mapping(context, id)
                self._process_network_queue_mapping(context, net, net_queue_id)
            self._process_l3_update(context, net, network['network'])
            self._extend_network_dict_provider(context, net)
        # If provided, update port name on backend; treat backend failures as
        # not critical (log error, but do not raise)
        if 'name' in network['network']:
            # in case of chained switches update name only for the first one
            nsx_switch_ids = nsx_utils.get_nsx_switch_ids(
                context.session, self.cluster, id)
            if not nsx_switch_ids or len(nsx_switch_ids) < 1:
                LOG.warning("Unable to find NSX mappings for neutron "
                            "network:%s", id)
            try:
                switchlib.update_lswitch(self.cluster,
                                         nsx_switch_ids[0],
                                         network['network']['name'])
            except api_exc.NsxApiException as e:
                LOG.warning("Logical switch update on NSX backend failed. "
                            "Neutron network id:%(net_id)s; "
                            "NSX lswitch id:%(lswitch_id)s;"
                            "Error:%(error)s",
                            {'net_id': id, 'lswitch_id': nsx_switch_ids[0],
                             'error': e})

        return net

    def create_port(self, context, port):
        # If PORTSECURITY is not the default value ATTR_NOT_SPECIFIED
        # then we pass the port to the policy engine. The reason why we don't
        # pass the value to the policy engine when the port is
        # ATTR_NOT_SPECIFIED is for the case where a port is created on a
        # shared network that is not owned by the tenant.
        port_data = port['port']
        dhcp_opts = port_data.get(edo_ext.EXTRADHCPOPTS, [])
        # Set port status as 'DOWN'. This will be updated by backend sync.
        port_data['status'] = constants.PORT_STATUS_DOWN
        with db_api.context_manager.writer.using(context):
            # First we allocate port in neutron database
            neutron_db = super(NsxPluginV2, self).create_port(context, port)
            neutron_port_id = neutron_db['id']
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
            if validators.is_attr_set(port_data.get(
                    addr_apidef.ADDRESS_PAIRS)):
                if not port_security:
                    raise addr_exc.AddressPairAndPortSecurityRequired()
                else:
                    self._process_create_allowed_address_pairs(
                        context, neutron_db,
                        port_data[addr_apidef.ADDRESS_PAIRS])
            else:
                # remove ATTR_NOT_SPECIFIED
                port_data[addr_apidef.ADDRESS_PAIRS] = []

            # security group extension checks
            # NOTE: check_update_has_security_groups works fine for
            # create operations as well
            if port_security and has_ip:
                self._ensure_default_security_group_on_port(context, port)
            elif self._check_update_has_security_groups(
                 {'port': port_data}):
                raise psec_exc.PortSecurityAndIPRequiredForSecurityGroups()
            port_data[ext_sg.SECURITYGROUPS] = (
                self._get_security_groups_on_port(context, port))
            self._process_port_create_security_group(
                context, port_data, port_data[ext_sg.SECURITYGROUPS])
            # QoS extension checks
            port_queue_id = self._check_for_queue_and_create(
                context, port_data)
            self._process_port_queue_mapping(
                context, port_data, port_queue_id)
            if (isinstance(port_data.get(mac_ext.MAC_LEARNING), bool)):
                self._create_mac_learning_state(context, port_data)
            elif mac_ext.MAC_LEARNING in port_data:
                port_data.pop(mac_ext.MAC_LEARNING)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         port_data)
            self._process_port_create_extra_dhcp_opts(context, port_data,
                                                      dhcp_opts)
            # For some reason the port bindings DB mixin does not handle
            # the VNIC_TYPE attribute, which is required by nova for
            # setting up VIFs.
            context.session.flush()
            port_data[pbin.VNIC_TYPE] = pbin.VNIC_NORMAL

        # DB Operation is complete, perform NSX operation
        try:
            port_data = port['port'].copy()
            port_create_func = self._port_drivers['create'].get(
                port_data['device_owner'],
                self._port_drivers['create']['default'])
            port_create_func(context, port_data)
            LOG.debug("port created on NSX backend for tenant "
                      "%(tenant_id)s: (%(id)s)", port_data)
        except n_exc.NotFound:
            LOG.warning("Logical switch for network %s was not "
                        "found in NSX.", port_data['network_id'])
            # Put port in error on neutron DB
            with db_api.context_manager.writer.using(context):
                port = self._get_port(context, neutron_port_id)
                port_data['status'] = constants.PORT_STATUS_ERROR
                port['status'] = port_data['status']
                context.session.add(port)
        except Exception:
            # Port must be removed from neutron DB
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to create port or set port "
                          "attachment in NSX.")
                with db_api.context_manager.writer.using(context):
                    self.ipam.delete_port(context, neutron_port_id)
        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        port_model = self._get_port(context, neutron_port_id)
        resource_extend.apply_funcs('ports', port_data, port_model)
        self.handle_port_dhcp_access(context, port_data, action='create_port')
        return port_data

    def update_port(self, context, id, port):
        delete_security_groups = self._check_update_deletes_security_groups(
            port)
        has_security_groups = self._check_update_has_security_groups(port)
        delete_addr_pairs = self._check_update_deletes_allowed_address_pairs(
            port)
        has_addr_pairs = self._check_update_has_allowed_address_pairs(port)

        with db_api.context_manager.writer.using(context):
            ret_port = super(NsxPluginV2, self).update_port(
                context, id, port)

            # Save current mac learning state to check whether it's
            # being updated or not
            old_mac_learning_state = ret_port.get(mac_ext.MAC_LEARNING)
            # copy values over - except fixed_ips as
            # they've already been processed
            port['port'].pop('fixed_ips', None)
            ret_port.update(port['port'])
            tenant_id = ret_port['tenant_id']
            self._update_extra_dhcp_opts_on_port(context, id, port, ret_port)

            # populate port_security setting
            if psec.PORTSECURITY not in port['port']:
                ret_port[psec.PORTSECURITY] = self._get_port_security_binding(
                    context, id)
            has_ip = self._ip_on_port(ret_port)
            # validate port security and allowed address pairs
            if not ret_port[psec.PORTSECURITY]:
                #  has address pairs in request
                if has_addr_pairs:
                    raise addr_exc.AddressPairAndPortSecurityRequired()
                elif not delete_addr_pairs:
                    # check if address pairs are in db
                    ret_port[addr_apidef.ADDRESS_PAIRS] = (
                        self.get_allowed_address_pairs(context, id))
                    if ret_port[addr_apidef.ADDRESS_PAIRS]:
                        raise addr_exc.AddressPairAndPortSecurityRequired()

            if (delete_addr_pairs or has_addr_pairs):
                # delete address pairs and read them in
                self._delete_allowed_address_pairs(context, id)
                self._process_create_allowed_address_pairs(
                    context, ret_port, ret_port[addr_apidef.ADDRESS_PAIRS])
            # checks if security groups were updated adding/modifying
            # security groups, port security is set and port has ip
            if not (has_ip and ret_port[psec.PORTSECURITY]):
                if has_security_groups:
                    raise psec_exc.PortSecurityAndIPRequiredForSecurityGroups()
                # Update did not have security groups passed in. Check
                # that port does not have any security groups already on it.
                filters = {'port_id': [id]}
                security_groups = (
                    super(NsxPluginV2, self)._get_port_security_group_bindings(
                        context, filters)
                )
                if security_groups and not delete_security_groups:
                    raise psec_exc.PortSecurityPortHasSecurityGroup()

            if (delete_security_groups or has_security_groups):
                # delete the port binding and read it with the new rules.
                self._delete_port_security_group_bindings(context, id)
                sgids = self._get_security_groups_on_port(context, port)
                self._process_port_create_security_group(context, ret_port,
                                                         sgids)

            if psec.PORTSECURITY in port['port']:
                self._process_port_port_security_update(
                    context, port['port'], ret_port)

            port_queue_id = self._check_for_queue_and_create(
                context, ret_port)
            # Populate the mac learning attribute
            new_mac_learning_state = port['port'].get(mac_ext.MAC_LEARNING)
            if (new_mac_learning_state is not None and
                old_mac_learning_state != new_mac_learning_state):
                self._update_mac_learning_state(context, id,
                                                new_mac_learning_state)
                ret_port[mac_ext.MAC_LEARNING] = new_mac_learning_state
            self._delete_port_queue_mapping(context, ret_port['id'])
            self._process_port_queue_mapping(context, ret_port,
                                             port_queue_id)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         ret_port)
            nsx_switch_id, nsx_port_id = nsx_utils.get_nsx_switch_and_port_id(
                context.session, self.cluster, id)
            # Convert Neutron security groups identifiers into NSX security
            # profiles identifiers
            nsx_sec_profile_ids = [
                nsx_utils.get_nsx_security_group_id(
                    context.session, self.cluster, neutron_sg_id) for
                neutron_sg_id in (ret_port[ext_sg.SECURITYGROUPS] or [])]

        # Perform the NSX operation outside of the DB transaction
        LOG.debug("Updating port %s on NSX backend", ret_port['id'])
        if nsx_port_id:
            try:
                switchlib.update_port(
                    self.cluster, nsx_switch_id, nsx_port_id,
                    id, tenant_id,
                    ret_port['name'],
                    ret_port['device_id'],
                    ret_port['admin_state_up'],
                    ret_port['mac_address'],
                    ret_port['fixed_ips'],
                    ret_port[psec.PORTSECURITY],
                    nsx_sec_profile_ids,
                    ret_port[qos.QUEUE],
                    ret_port.get(mac_ext.MAC_LEARNING),
                    ret_port.get(addr_apidef.ADDRESS_PAIRS))

                # Update the port status from nsx. If we fail here hide it
                # since the port was successfully updated but we were not
                # able to retrieve the status.
                ret_port['status'] = switchlib.get_port_status(
                    self.cluster, nsx_switch_id,
                    nsx_port_id)
            # FIXME(arosen) improve exception handling.
            except Exception:
                ret_port['status'] = constants.PORT_STATUS_ERROR
                LOG.exception("Unable to update port id: %s.",
                              nsx_port_id)

        # If nsx_port_id is not in database or in nsx put in error state.
        else:
            ret_port['status'] = constants.PORT_STATUS_ERROR
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
        # if needed, check to see if this is a port owned by
        # a l3 router.  If so, we should prevent deletion here
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        neutron_db_port = self.get_port(context, id)
        # Perform the same check for ports owned by layer-2 gateways
        if nw_gw_port_check:
            self.prevent_network_gateway_port_deletion(context,
                                                       neutron_db_port)
        port_delete_func = self._port_drivers['delete'].get(
            neutron_db_port['device_owner'],
            self._port_drivers['delete']['default'])

        port_delete_func(context, neutron_db_port)
        self.disassociate_floatingips(context, id)
        with db_api.context_manager.writer.using(context):
            queue = self._get_port_queue_bindings(context, {'port_id': [id]})
            # metadata_dhcp_host_route
            self.handle_port_metadata_access(
                context, neutron_db_port, is_delete=True)
            super(NsxPluginV2, self).delete_port(context, id)
            # Delete qos queue if possible
            if queue:
                self.delete_qos_queue(context, queue[0]['queue_id'], False)
        self.handle_port_dhcp_access(
            context, neutron_db_port, action='delete_port')

    def get_port(self, context, id, fields=None):
        with db_api.context_manager.writer.using(context):
            if (self.nsx_sync_opts.always_read_status or
                fields and 'status' in fields):
                # Perform explicit state synchronization
                db_port = self._get_port(context, id)
                self._synchronizer.synchronize_port(
                    context, db_port)
                return self._make_port_dict(db_port, fields)
            else:
                return super(NsxPluginV2, self).get_port(context, id, fields)

    def get_router(self, context, id, fields=None):
        with db_api.context_manager.writer.using(context):
            if (self.nsx_sync_opts.always_read_status or
                fields and 'status' in fields):
                db_router = self._get_router(context, id)
                # Perform explicit state synchronization
                self._synchronizer.synchronize_router(
                    context, db_router)
                return self._make_router_dict(db_router, fields)
            else:
                return super(NsxPluginV2, self).get_router(context, id, fields)

    def _create_lrouter(self, context, router, nexthop):
        tenant_id = router['tenant_id']
        distributed = router.get('distributed')
        try:
            lrouter = routerlib.create_lrouter(
                self.cluster, router['id'],
                tenant_id, router['name'], nexthop,
                distributed=(validators.is_attr_set(distributed) and
                             distributed))
        except nsx_exc.InvalidVersion:
            msg = _("Cannot create a distributed router with the NSX "
                    "platform currently in execution. Please, try "
                    "without specifying the 'distributed' attribute.")
            LOG.exception(msg)
            raise n_exc.BadRequest(resource='router', msg=msg)
        except api_exc.NsxApiException:
            err_msg = _("Unable to create logical router on NSX Platform")
            LOG.exception(err_msg)
            raise nsx_exc.NsxPluginException(err_msg=err_msg)

        # Create the port here - and update it later if we have gw_info
        try:
            self._create_and_attach_router_port(
                self.cluster, context, lrouter['uuid'], {'fake_ext_gw': True},
                "L3GatewayAttachment",
                self.cluster.default_l3_gw_service_uuid)
        except nsx_exc.NsxPluginException:
            LOG.exception("Unable to create L3GW port on logical router "
                          "%(router_uuid)s. Verify Default Layer-3 "
                          "Gateway service %(def_l3_gw_svc)s id is "
                          "correct",
                          {'router_uuid': lrouter['uuid'],
                           'def_l3_gw_svc':
                           self.cluster.default_l3_gw_service_uuid})
            # Try and remove logical router from NSX
            routerlib.delete_lrouter(self.cluster, lrouter['uuid'])
            # Return user a 500 with an apter message
            raise nsx_exc.NsxPluginException(
                err_msg=(_("Unable to create router %s on NSX backend") %
                         router['id']))
        lrouter['status'] = constants.ACTIVE
        return lrouter

    def _process_extra_attr_router_create(self, context, router_db, r):
        for extra_attr in l3_attrs_db.get_attr_info().keys():
            if extra_attr in r:
                self.set_extra_attr_value(context, router_db,
                                          extra_attr, r[extra_attr])

    def create_router(self, context, router):
        # NOTE(salvatore-orlando): We completely override this method in
        # order to be able to use the NSX ID as Neutron ID
        # TODO(salvatore-orlando): Propose upstream patch for allowing
        # 3rd parties to specify IDs as we do with l2 plugin
        r = router['router']
        has_gw_info = False
        tenant_id = r['tenant_id']
        # default value to set - nsx wants it (even if we don't have it)
        nexthop = NSX_DEFAULT_NEXTHOP
        # if external gateway info are set, then configure nexthop to
        # default external gateway
        if 'external_gateway_info' in r and r.get('external_gateway_info'):
            has_gw_info = True
            gw_info = r['external_gateway_info']
            del r['external_gateway_info']
            # The following DB read will be performed again when updating
            # gateway info. This is not great, but still better than
            # creating NSX router here and updating it later
            network_id = (gw_info.get('network_id', None) if gw_info
                          else None)
            if network_id:
                ext_net = self._get_network(context, network_id)
                if not ext_net.external:
                    msg = (_("Network '%s' is not a valid external "
                             "network") % network_id)
                    raise n_exc.BadRequest(resource='router', msg=msg)
                if ext_net.subnets:
                    ext_subnet = ext_net.subnets[0]
                    nexthop = ext_subnet.gateway_ip
        # NOTE(salv-orlando): Pre-generating uuid for Neutron
        # router. This will be removed once the router create operation
        # becomes an asynchronous task
        neutron_router_id = str(uuidutils.generate_uuid())
        r['id'] = neutron_router_id
        # Populate distributed attribute in order to ensure the appropriate
        # type of router is created in the NSX backend
        r['distributed'] = l3_dvr_db.is_distributed_router(r)
        lrouter = self._create_lrouter(context, r, nexthop)
        # TODO(salv-orlando): Deal with backend object removal in case
        # of db failures
        with db_api.context_manager.writer.using(context):
            # Transaction nesting is needed to avoid foreign key violations
            # when processing the distributed router binding
            with db_api.context_manager.writer.using(context):
                router_db = l3_db_models.Router(
                    id=neutron_router_id,
                    tenant_id=tenant_id,
                    name=r['name'],
                    admin_state_up=r['admin_state_up'],
                    status=lrouter['status'])
                context.session.add(router_db)
                self._process_extra_attr_router_create(context, router_db, r)
                # Ensure neutron router is moved into the transaction's buffer
                context.session.flush()
                # Add mapping between neutron and nsx identifiers
                nsx_db.add_neutron_nsx_router_mapping(
                    context.session, router_db['id'], lrouter['uuid'])

            if has_gw_info:
                # NOTE(salv-orlando): This operation has been moved out of the
                # database transaction since it performs several NSX queries,
                # ithis ncreasing the risk of deadlocks between eventlet and
                # sqlalchemy operations.
                # Set external gateway and remove router in case of failure
                try:
                    self._update_router_gw_info(context, router_db['id'],
                                                gw_info)
                except (n_exc.NeutronException, api_exc.NsxApiException):
                    with excutils.save_and_reraise_exception():
                        # As setting gateway failed, the router must be deleted
                        # in order to ensure atomicity
                        router_id = router_db['id']
                        LOG.warning("Failed to set gateway info for router "
                                    "being created:%s - removing router",
                                    router_id)
                        self.delete_router(context, router_id)
                        LOG.info("Create router failed while setting external "
                                 "gateway. Router:%s has been removed from "
                                 "DB and backend",
                                 router_id)
        return self._make_router_dict(router_db)

    def _update_lrouter(self, context, router_id, name, nexthop, routes=None):
        nsx_router_id = nsx_utils.get_nsx_router_id(
            context.session, self.cluster, router_id)
        return routerlib.update_lrouter(
            self.cluster, nsx_router_id, name,
            nexthop, routes=routes)

    def _update_lrouter_routes(self, context, router_id, routes):
        nsx_router_id = nsx_utils.get_nsx_router_id(
            context.session, self.cluster, router_id)
        routerlib.update_explicit_routes_lrouter(
            self.cluster, nsx_router_id, routes)

    def update_router(self, context, router_id, router):
        # Either nexthop is updated or should be kept as it was before
        r = router['router']
        nexthop = None
        if 'external_gateway_info' in r and r.get('external_gateway_info'):
            gw_info = r['external_gateway_info']
            # The following DB read will be performed again when updating
            # gateway info. This is not great, but still better than
            # creating NSX router here and updating it later
            network_id = (gw_info.get('network_id', None) if gw_info
                          else None)
            if network_id:
                ext_net = self._get_network(context, network_id)
                if not ext_net.external:
                    msg = (_("Network '%s' is not a valid external "
                             "network") % network_id)
                    raise n_exc.BadRequest(resource='router', msg=msg)
                if ext_net.subnets:
                    ext_subnet = ext_net.subnets[0]
                    nexthop = ext_subnet.gateway_ip
        try:
            for route in r.get('routes', []):
                if route['destination'] == '0.0.0.0/0':
                    msg = _("'routes' cannot contain route '0.0.0.0/0', "
                            "this must be updated through the default "
                            "gateway attribute")
                    raise n_exc.BadRequest(resource='router', msg=msg)
            previous_routes = self._update_lrouter(
                context, router_id, r.get('name'),
                nexthop, routes=r.get('routes'))
        # NOTE(salv-orlando): The exception handling below is not correct, but
        # unfortunately nsxlib raises a neutron notfound exception when an
        # object is not found in the underlying backend
        except n_exc.NotFound:
            # Put the router in ERROR status
            with db_api.context_manager.writer.using(context):
                router_db = self._get_router(context, router_id)
                router_db['status'] = constants.NET_STATUS_ERROR
            raise nsx_exc.NsxPluginException(
                err_msg=_("Logical router %s not found "
                          "on NSX Platform") % router_id)
        except api_exc.NsxApiException:
            raise nsx_exc.NsxPluginException(
                err_msg=_("Unable to update logical router on NSX Platform"))
        except nsx_exc.InvalidVersion:
            msg = _("Request cannot contain 'routes' with the NSX "
                    "platform currently in execution. Please, try "
                    "without specifying the static routes.")
            LOG.exception(msg)
            raise n_exc.BadRequest(resource='router', msg=msg)
        try:
            return super(NsxPluginV2, self).update_router(context,
                                                          router_id, router)
        except (xroute_exc.InvalidRoutes,
                xroute_exc.RouterInterfaceInUseByRoute,
                xroute_exc.RoutesExhausted):
            with excutils.save_and_reraise_exception():
                # revert changes made to NSX
                self._update_lrouter_routes(
                    context, router_id, previous_routes)

    def _delete_lrouter(self, context, router_id, nsx_router_id):
        # The neutron router id (router_id) is ignored in this routine,
        # but used in plugins deriving from this one
        routerlib.delete_lrouter(self.cluster, nsx_router_id)

    def delete_router(self, context, router_id):
        with db_api.context_manager.writer.using(context):
            # NOTE(salv-orlando): These checks will be repeated anyway when
            # calling the superclass. This is wasteful, but is the simplest
            # way of ensuring a consistent removal of the router both in
            # the neutron Database and in the NSX backend.
            self._ensure_router_not_in_use(context, router_id)
            # TODO(salv-orlando): This call should have no effect on delete
            # router, but if it does, it should not happen within a
            # transaction, and it should be restored on rollback
            self.handle_router_metadata_access(
                context, router_id, interface=None)

        nsx_router_id = nsx_utils.get_nsx_router_id(
            context.session, self.cluster, router_id)
        # It is safe to remove the router from the database, so remove it
        # from the backend
        if nsx_router_id:
            try:
                self._delete_lrouter(context, router_id, nsx_router_id)
            except n_exc.NotFound:
                # This is not a fatal error, but needs to be logged
                LOG.warning("Logical router '%s' not found "
                            "on NSX Platform", router_id)
            except api_exc.NsxApiException:
                raise nsx_exc.NsxPluginException(
                    err_msg=(_("Unable to delete logical router '%s' "
                            "on NSX Platform") % nsx_router_id))
        else:
            # If no mapping is found it is likely that the logical router does
            # not exist anymore in the backend. This is not a fatal condition,
            # but will result in an exception is "None" is passed to
            # _delete_lrouter
            LOG.warning("No mapping found for logical router '%s' "
                        "on NSX Platform", router_id)

        # Remove the NSX mapping first in order to ensure a mapping to
        # a non-existent NSX router is not left in the DB in case of
        # failure while removing the router from the neutron DB
        try:
            nsx_db.delete_neutron_nsx_router_mapping(
                context.session, router_id)
        except db_exc.DBError as d_exc:
            # Do not make this error fatal
            LOG.warning("Unable to remove NSX mapping for Neutron router "
                        "%(router_id)s because of the following exception:"
                        "%(d_exc)s", {'router_id': router_id,
                                      'd_exc': str(d_exc)})
        # Perform the actual delete on the Neutron DB
        super(NsxPluginV2, self).delete_router(context, router_id)

    def _add_subnet_snat_rule(self, context, router, subnet):
        gw_port = router.gw_port
        if gw_port and router.enable_snat:
            # There is a change gw_port might have multiple IPs
            # In that case we will consider only the first one
            if gw_port.get('fixed_ips'):
                snat_ip = gw_port['fixed_ips'][0]['ip_address']
                cidr_prefix = int(subnet['cidr'].split('/')[1])
                nsx_router_id = nsx_utils.get_nsx_router_id(
                    context.session, self.cluster, router['id'])
                routerlib.create_lrouter_snat_rule(
                    self.cluster, nsx_router_id, snat_ip, snat_ip,
                    order=NSX_EXTGW_NAT_RULES_ORDER - cidr_prefix,
                    match_criteria={'source_ip_addresses': subnet['cidr']})

    def _delete_subnet_snat_rule(self, context, router, subnet):
        # Remove SNAT rule if external gateway is configured
        if router.gw_port:
            nsx_router_id = nsx_utils.get_nsx_router_id(
                context.session, self.cluster, router['id'])
            routerlib.delete_nat_rules_by_match(
                self.cluster, nsx_router_id, "SourceNatRule",
                max_num_expected=1, min_num_expected=1,
                raise_on_len_mismatch=False,
                source_ip_addresses=subnet['cidr'])

    def add_router_interface(self, context, router_id, interface_info):
        # When adding interface by port_id we need to create the
        # peer port on the nsx logical router in this routine
        port_id = interface_info.get('port_id')
        router_iface_info = super(NsxPluginV2, self).add_router_interface(
            context, router_id, interface_info)
        # router_iface_info will always have a subnet_id attribute
        subnet_id = router_iface_info['subnet_id']
        nsx_router_id = nsx_utils.get_nsx_router_id(
            context.session, self.cluster, router_id)
        if port_id:
            port_data = self.get_port(context, port_id)
            # If security groups are present we need to remove them as
            # this is a router port and disable port security.
            if port_data['security_groups']:
                self.update_port(context, port_id,
                                 {'port': {'security_groups': [],
                                           psec.PORTSECURITY: False}})
            nsx_switch_id, nsx_port_id = nsx_utils.get_nsx_switch_and_port_id(
                context.session, self.cluster, port_id)
            # Unplug current attachment from lswitch port
            switchlib.plug_vif_interface(self.cluster, nsx_switch_id,
                                         nsx_port_id, "NoAttachment")
            # Create logical router port and plug patch attachment
            self._create_and_attach_router_port(
                self.cluster, context, nsx_router_id, port_data,
                "PatchAttachment", nsx_port_id, subnet_ids=[subnet_id])
        subnet = self._get_subnet(context, subnet_id)
        # If there is an external gateway we need to configure the SNAT rule.
        # Fetch router from DB
        router = self._get_router(context, router_id)
        self._add_subnet_snat_rule(context, router, subnet)
        routerlib.create_lrouter_nosnat_rule(
            self.cluster, nsx_router_id,
            order=NSX_NOSNAT_RULES_ORDER,
            match_criteria={'destination_ip_addresses': subnet['cidr']})

        # Ensure the NSX logical router has a connection to a 'metadata access'
        # network (with a proxy listening on its DHCP port), by creating it
        # if needed.
        self.handle_router_metadata_access(
            context, router_id, interface=router_iface_info)
        LOG.debug("Add_router_interface completed for subnet:%(subnet_id)s "
                  "and router:%(router_id)s",
                  {'subnet_id': subnet_id, 'router_id': router_id})
        return router_iface_info

    def get_l3_agents_hosting_routers(self, context, routers):
        # This method is just a stub added because is required by the l3 dvr
        # mixin. That's so much for a management layer which is plugin
        # agnostic
        return []

    def _create_snat_intf_ports_if_not_exists(self, context, router):
        # VMware plugins do not need SNAT interface ports
        return []

    def _add_csnat_router_interface_port(self, context, router, network_id,
                                         subnet_id, do_pop=True):
        # VMware plugins do not need SNAT interface ports
        return

    def _delete_csnat_router_interface_ports(self, context, router,
                                             subnet_id=None):
        # VMware plugins do not need SNAT interface ports
        return

    def remove_router_interface(self, context, router_id, interface_info):
        # The code below is duplicated from base class, but comes handy
        # as we need to retrieve the router port id before removing the port
        subnet = None
        subnet_id = None
        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
            # find subnet_id - it is need for removing the SNAT rule
            port = self._get_port(context, port_id)
            if port.get('fixed_ips'):
                subnet_id = port['fixed_ips'][0]['subnet_id']
            if not (port['device_owner'] in
                    constants.ROUTER_INTERFACE_OWNERS and
                    port['device_id'] == router_id):
                raise l3_exc.RouterInterfaceNotFound(
                    router_id=router_id, port_id=port_id)
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self._get_subnet(context, subnet_id)
            rport_qry = context.session.query(models_v2.Port)
            ports = rport_qry.filter_by(
                device_id=router_id,
                network_id=subnet['network_id']).filter(
                    models_v2.Port.device_owner.in_(
                        constants.ROUTER_INTERFACE_OWNERS))
            for p in ports:
                if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                    port_id = p['id']
                    break
            else:
                raise l3_exc.RouterInterfaceNotFoundForSubnet(
                    router_id=router_id, subnet_id=subnet_id)
        # Finally remove the data from the Neutron DB
        # This will also destroy the port on the logical switch
        info = super(NsxPluginV2, self).remove_router_interface(
            context, router_id, interface_info)

        try:
            # Ensure the connection to the 'metadata access network'
            # is removed  (with the network) if this the last subnet
            # on the router
            self.handle_router_metadata_access(
                context, router_id, interface=None)
            if not subnet:
                subnet = self._get_subnet(context, subnet_id)
            router = self._get_router(context, router_id)
            # If router is enabled_snat = False there are no snat rules to
            # delete.
            if router.enable_snat:
                self._delete_subnet_snat_rule(context, router, subnet)
            # Relax the minimum expected number as the nosnat rules
            # do not exist in 2.x deployments
            nsx_router_id = nsx_utils.get_nsx_router_id(
                context.session, self.cluster, router_id)
            routerlib.delete_nat_rules_by_match(
                self.cluster, nsx_router_id, "NoSourceNatRule",
                max_num_expected=1, min_num_expected=0,
                raise_on_len_mismatch=False,
                destination_ip_addresses=subnet['cidr'])
        except n_exc.NotFound:
            LOG.error("Logical router resource %s not found "
                      "on NSX platform", router_id)
        except api_exc.NsxApiException:
            raise nsx_exc.NsxPluginException(
                err_msg=(_("Unable to update logical router"
                           "on NSX Platform")))
        return info

    def _retrieve_and_delete_nat_rules(self, context, floating_ip_address,
                                       internal_ip, nsx_router_id,
                                       min_num_rules_expected=0):
        """Finds and removes NAT rules from a NSX router."""
        # NOTE(salv-orlando): The context parameter is ignored in this method
        # but used by derived classes
        try:
            # Remove DNAT rule for the floating IP
            routerlib.delete_nat_rules_by_match(
                self.cluster, nsx_router_id, "DestinationNatRule",
                max_num_expected=1,
                min_num_expected=min_num_rules_expected,
                destination_ip_addresses=floating_ip_address)

            # Remove SNAT rules for the floating IP
            routerlib.delete_nat_rules_by_match(
                self.cluster, nsx_router_id, "SourceNatRule",
                max_num_expected=1,
                min_num_expected=min_num_rules_expected,
                source_ip_addresses=internal_ip)
            routerlib.delete_nat_rules_by_match(
                self.cluster, nsx_router_id, "SourceNatRule",
                max_num_expected=1,
                min_num_expected=min_num_rules_expected,
                destination_ip_addresses=internal_ip)

        except api_exc.NsxApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception("An error occurred while removing NAT rules "
                              "on the NSX platform for floating ip:%s",
                              floating_ip_address)
        except nsx_exc.NatRuleMismatch:
            # Do not surface to the user
            LOG.warning("An incorrect number of matching NAT rules "
                        "was found on the NSX platform")

    def _remove_floatingip_address(self, context, fip_db):
        # Remove floating IP address from logical router port
        # Fetch logical port of router's external gateway
        router_id = fip_db.router_id
        nsx_router_id = nsx_utils.get_nsx_router_id(
            context.session, self.cluster, router_id)
        nsx_gw_port_id = routerlib.find_router_gw_port(
            context, self.cluster, nsx_router_id)['uuid']
        ext_neutron_port_db = self._get_port(context.elevated(),
                                             fip_db.floating_port_id)
        nsx_floating_ips = self._build_ip_address_list(
            context.elevated(), ext_neutron_port_db['fixed_ips'])
        routerlib.update_lrouter_port_ips(self.cluster,
                                          nsx_router_id,
                                          nsx_gw_port_id,
                                          ips_to_add=[],
                                          ips_to_remove=nsx_floating_ips)

    def _floatingip_status(self, floatingip_db, associated):
        if (associated and
            floatingip_db['status'] != constants.FLOATINGIP_STATUS_ACTIVE):
            return constants.FLOATINGIP_STATUS_ACTIVE
        elif (not associated and
              floatingip_db['status'] != constants.FLOATINGIP_STATUS_DOWN):
            return constants.FLOATINGIP_STATUS_DOWN
        # in any case ensure the status is not reset by this method!
        return floatingip_db['status']

    def _update_fip_assoc(self, context, fip, floatingip_db, external_port):
        """Update floating IP association data.

        Overrides method from base class.
        The method is augmented for creating NAT rules in the process.
        """
        # Store router currently serving the floating IP
        old_router_id = floatingip_db.router_id
        port_id, internal_ip, router_id = self._check_and_get_fip_assoc(
            context, fip, floatingip_db)
        floating_ip = floatingip_db['floating_ip_address']
        # If there's no association router_id will be None
        if router_id:
            nsx_router_id = nsx_utils.get_nsx_router_id(
                context.session, self.cluster, router_id)
            self._retrieve_and_delete_nat_rules(
                context, floating_ip, internal_ip, nsx_router_id)
        nsx_floating_ips = self._build_ip_address_list(
            context.elevated(), external_port['fixed_ips'])
        floating_ip = floatingip_db['floating_ip_address']
        # Retrieve and delete existing NAT rules, if any
        if old_router_id:
            nsx_old_router_id = nsx_utils.get_nsx_router_id(
                context.session, self.cluster, old_router_id)
            # Retrieve the current internal ip
            _p, _s, old_internal_ip = self._internal_fip_assoc_data(
                context, {'id': floatingip_db.id,
                          'port_id': floatingip_db.fixed_port_id,
                          'fixed_ip_address':
                              str(floatingip_db.fixed_ip_address),
                          'tenant_id': floatingip_db.tenant_id},
                floatingip_db.tenant_id)
            nsx_gw_port_id = routerlib.find_router_gw_port(
                context, self.cluster, nsx_old_router_id)['uuid']
            self._retrieve_and_delete_nat_rules(
                context, floating_ip, old_internal_ip, nsx_old_router_id)
            routerlib.update_lrouter_port_ips(
                self.cluster, nsx_old_router_id, nsx_gw_port_id,
                ips_to_add=[], ips_to_remove=nsx_floating_ips)

        if router_id:
            nsx_gw_port_id = routerlib.find_router_gw_port(
                context, self.cluster, nsx_router_id)['uuid']
            # Re-create NAT rules only if a port id is specified
            if fip.get('port_id'):
                try:
                    # Setup DNAT rules for the floating IP
                    routerlib.create_lrouter_dnat_rule(
                        self.cluster, nsx_router_id, internal_ip,
                        order=NSX_FLOATINGIP_NAT_RULES_ORDER,
                        match_criteria={'destination_ip_addresses':
                                        floating_ip})
                    # Setup SNAT rules for the floating IP
                    # Create a SNAT rule for enabling connectivity to the
                    # floating IP from the same network as the internal port
                    # Find subnet id for internal_ip from fixed_ips
                    internal_port = self._get_port(context, port_id)
                    # Cchecks not needed on statements below since otherwise
                    # _internal_fip_assoc_data would have raised
                    subnet_ids = [ip['subnet_id'] for ip in
                                  internal_port['fixed_ips'] if
                                  ip['ip_address'] == internal_ip]
                    internal_subnet_cidr = self._build_ip_address_list(
                        context, internal_port['fixed_ips'],
                        subnet_ids=subnet_ids)[0]
                    routerlib.create_lrouter_snat_rule(
                        self.cluster, nsx_router_id, floating_ip, floating_ip,
                        order=NSX_NOSNAT_RULES_ORDER - 1,
                        match_criteria={'source_ip_addresses':
                                        internal_subnet_cidr,
                                        'destination_ip_addresses':
                                        internal_ip})
                    # setup snat rule such that src ip of an IP packet when
                    # using floating is the floating ip itself.
                    routerlib.create_lrouter_snat_rule(
                        self.cluster, nsx_router_id, floating_ip, floating_ip,
                        order=NSX_FLOATINGIP_NAT_RULES_ORDER,
                        match_criteria={'source_ip_addresses': internal_ip})

                    # Add Floating IP address to router_port
                    routerlib.update_lrouter_port_ips(
                        self.cluster, nsx_router_id, nsx_gw_port_id,
                        ips_to_add=nsx_floating_ips, ips_to_remove=[])
                except api_exc.NsxApiException:
                    LOG.exception("An error occurred while creating NAT "
                                  "rules on the NSX platform for floating "
                                  "ip:%(floating_ip)s mapped to "
                                  "internal ip:%(internal_ip)s",
                                  {'floating_ip': floating_ip,
                                   'internal_ip': internal_ip})
                    msg = _("Failed to update NAT rules for floatingip update")
                    raise nsx_exc.NsxPluginException(err_msg=msg)
        # Update also floating ip status (no need to call base class method)
        new_status = self._floatingip_status(floatingip_db, router_id)
        floatingip_db.fixed_ip_address = internal_ip
        floatingip_db.fixed_port_id = port_id
        floatingip_db.router_id = router_id
        floatingip_db.status = new_status

        return {'fixed_ip_address': internal_ip,
                'fixed_port_id': port_id,
                'router_id': router_id,
                'last_known_router_id': None,
                'floating_ip_address': floatingip_db.floating_ip_address,
                'floating_network_id': floatingip_db.floating_network_id,
                'floating_ip_id': floatingip_db.id,
                'context': context}

    @lockutils.synchronized('vmware', 'neutron-')
    def create_floatingip(self, context, floatingip):
        return super(NsxPluginV2, self).create_floatingip(context, floatingip)

    @lockutils.synchronized('vmware', 'neutron-')
    def update_floatingip(self, context, floatingip_id, floatingip):
        return super(NsxPluginV2, self).update_floatingip(context,
                                                          floatingip_id,
                                                          floatingip)

    @lockutils.synchronized('vmware', 'neutron-')
    def delete_floatingip(self, context, id):
        fip_db = self._get_floatingip(context, id)
        # Check whether the floating ip is associated or not
        if fip_db.fixed_port_id:
            nsx_router_id = nsx_utils.get_nsx_router_id(
                context.session, self.cluster, fip_db.router_id)
            self._retrieve_and_delete_nat_rules(context,
                                                fip_db.floating_ip_address,
                                                fip_db.fixed_ip_address,
                                                nsx_router_id,
                                                min_num_rules_expected=1)
            # Remove floating IP address from logical router port
            self._remove_floatingip_address(context, fip_db)
        return super(NsxPluginV2, self).delete_floatingip(context, id)

    def disassociate_floatingips(self, context, port_id):
        try:
            fip_qry = context.session.query(l3_db_models.FloatingIP)
            fip_dbs = fip_qry.filter_by(fixed_port_id=port_id)

            for fip_db in fip_dbs:
                nsx_router_id = nsx_utils.get_nsx_router_id(
                    context.session, self.cluster, fip_db.router_id)
                self._retrieve_and_delete_nat_rules(context,
                                                    fip_db.floating_ip_address,
                                                    fip_db.fixed_ip_address,
                                                    nsx_router_id,
                                                    min_num_rules_expected=1)
                self._remove_floatingip_address(context, fip_db)
        except sa_exc.NoResultFound:
            LOG.debug("The port '%s' is not associated with floating IPs",
                      port_id)
        except n_exc.NotFound:
            LOG.warning("Nat rules not found in nsx for port: %s", id)

        # NOTE(ihrachys): L3 agent notifications don't make sense for
        # NSX VMWare plugin since there is no L3 agent in such setup, so
        # disabling them here.
        super(NsxPluginV2, self).disassociate_floatingips(
            context, port_id, do_notify=False)

    def create_network_gateway(self, context, network_gateway):
        """Create a layer-2 network gateway.

        Create the gateway service on NSX platform and corresponding data
        structures in Neutron datase.
        """
        gw_data = network_gateway[networkgw.GATEWAY_RESOURCE_NAME]
        tenant_id = gw_data['tenant_id']
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        # Validate provided gateway device list
        self._validate_device_list(context, tenant_id, gw_data)
        devices = gw_data['devices']
        # Populate default physical network where not specified
        for device in devices:
            if not device.get('interface_name'):
                device['interface_name'] = (self.cluster.
                                            nsx_default_interface_name)
        try:
            # Replace Neutron device identifiers with NSX identifiers
            dev_map = dict((dev['id'], dev['interface_name']) for
                           dev in devices)
            nsx_devices = []
            for db_device in self._query_gateway_devices(
                context, filters={'id': [device['id'] for device in devices]}):
                nsx_devices.append(
                    {'id': db_device['nsx_id'],
                     'interface_name': dev_map[db_device['id']]})
            nsx_res = l2gwlib.create_l2_gw_service(
                self.cluster, tenant_id, gw_data['name'], nsx_devices)
            nsx_uuid = nsx_res.get('uuid')
        except api_exc.Conflict:
            raise nsx_exc.L2GatewayAlreadyInUse(gateway=gw_data['name'])
        except api_exc.NsxApiException:
            err_msg = _("Unable to create l2_gw_service for: %s") % gw_data
            LOG.exception(err_msg)
            raise nsx_exc.NsxPluginException(err_msg=err_msg)
        gw_data['id'] = nsx_uuid
        return super(NsxPluginV2, self).create_network_gateway(
            context, network_gateway, validate_device_list=False)

    def delete_network_gateway(self, context, gateway_id):
        """Remove a layer-2 network gateway.

        Remove the gateway service from NSX platform and corresponding data
        structures in Neutron datase.
        """
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        with db_api.context_manager.writer.using(context):
            try:
                super(NsxPluginV2, self).delete_network_gateway(
                    context, gateway_id)
                l2gwlib.delete_l2_gw_service(self.cluster, gateway_id)
            except api_exc.ResourceNotFound:
                # Do not cause a 500 to be returned to the user if
                # the corresponding NSX resource does not exist
                LOG.exception("Unable to remove gateway service from "
                              "NSX plaform - the resource was not found")

    def get_network_gateway(self, context, id, fields=None):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        return super(NsxPluginV2, self).get_network_gateway(context,
                                                            id, fields)

    def get_network_gateways(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        # Ensure the tenant_id attribute is populated on returned gateways
        return super(NsxPluginV2, self).get_network_gateways(
            context, filters, fields, sorts, limit, marker, page_reverse)

    def update_network_gateway(self, context, id, network_gateway):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        # Update gateway on backend when there's a name change
        name = network_gateway[networkgw.GATEWAY_RESOURCE_NAME].get('name')
        if name:
            try:
                l2gwlib.update_l2_gw_service(self.cluster, id, name)
            except api_exc.NsxApiException:
                # Consider backend failures as non-fatal, but still warn
                # because this might indicate something dodgy is going on
                LOG.warning("Unable to update name on NSX backend "
                            "for network gateway: %s", id)
        return super(NsxPluginV2, self).update_network_gateway(
            context, id, network_gateway)

    def connect_network(self, context, network_gateway_id,
                        network_mapping_info):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        try:
            return super(NsxPluginV2, self).connect_network(
                context, network_gateway_id, network_mapping_info)
        except api_exc.Conflict:
            raise nsx_exc.L2GatewayAlreadyInUse(gateway=network_gateway_id)

    def disconnect_network(self, context, network_gateway_id,
                           network_mapping_info):
        # Ensure the default gateway in the config file is in sync with the db
        self._ensure_default_network_gateway()
        return super(NsxPluginV2, self).disconnect_network(
            context, network_gateway_id, network_mapping_info)

    def _get_nsx_device_id(self, context, device_id):
        return self._get_gateway_device(context, device_id)['nsx_id']

    def _rollback_gw_device(self, context, device_id, gw_data=None,
                            new_status=None, is_create=False):
        LOG.error("Rolling back database changes for gateway device %s "
                  "because of an error in the NSX backend", device_id)
        with db_api.context_manager.writer.using(context):
            query = model_query.query_with_hooks(
                context, nsx_models.NetworkGatewayDevice).filter(
                    nsx_models.NetworkGatewayDevice.id == device_id)
            if is_create:
                query.delete(synchronize_session=False)
            else:
                super(NsxPluginV2, self).update_gateway_device(
                    context, device_id,
                    {networkgw.DEVICE_RESOURCE_NAME: gw_data})
                if new_status:
                    query.update({'status': new_status},
                                 synchronize_session=False)

    # TODO(salv-orlando): Handlers for Gateway device operations should be
    # moved into the appropriate nsx_handlers package once the code for the
    # blueprint nsx-async-backend-communication merges
    def create_gateway_device_handler(self, context, gateway_device,
                                      client_certificate):
        neutron_id = gateway_device['id']
        try:
            nsx_res = l2gwlib.create_gateway_device(
                self.cluster,
                gateway_device['tenant_id'],
                gateway_device['name'],
                neutron_id,
                self.cluster.default_tz_uuid,
                gateway_device['connector_type'],
                gateway_device['connector_ip'],
                client_certificate)

            # Fetch status (it needs another NSX API call)
            device_status = nsx_utils.get_nsx_device_status(self.cluster,
                                                            nsx_res['uuid'])

            # set NSX GW device in neutron database and update status
            with db_api.context_manager.writer.using(context):
                query = model_query.query_with_hooks(
                    context, nsx_models.NetworkGatewayDevice).filter(
                        nsx_models.NetworkGatewayDevice.id == neutron_id)
                query.update({'status': device_status,
                              'nsx_id': nsx_res['uuid']},
                             synchronize_session=False)
            LOG.debug("Neutron gateway device: %(neutron_id)s; "
                      "NSX transport node identifier: %(nsx_id)s; "
                      "Operational status: %(status)s.",
                      {'neutron_id': neutron_id,
                       'nsx_id': nsx_res['uuid'],
                       'status': device_status})
            return device_status
        except (nsx_exc.InvalidSecurityCertificate, api_exc.NsxApiException):
            with excutils.save_and_reraise_exception():
                self._rollback_gw_device(context, neutron_id, is_create=True)

    def update_gateway_device_handler(self, context, gateway_device,
                                      old_gateway_device_data,
                                      client_certificate):
        nsx_id = gateway_device['nsx_id']
        neutron_id = gateway_device['id']
        try:
            l2gwlib.update_gateway_device(
                self.cluster,
                nsx_id,
                gateway_device['tenant_id'],
                gateway_device['name'],
                neutron_id,
                self.cluster.default_tz_uuid,
                gateway_device['connector_type'],
                gateway_device['connector_ip'],
                client_certificate)

            # Fetch status (it needs another NSX API call)
            device_status = nsx_utils.get_nsx_device_status(self.cluster,
                                                            nsx_id)
            # update status
            with db_api.context_manager.writer.using(context):
                query = model_query.query_with_hooks(
                    context, nsx_models.NetworkGatewayDevice).filter(
                        nsx_models.NetworkGatewayDevice.id == neutron_id)
                query.update({'status': device_status},
                             synchronize_session=False)
            LOG.debug("Neutron gateway device: %(neutron_id)s; "
                      "NSX transport node identifier: %(nsx_id)s; "
                      "Operational status: %(status)s.",
                      {'neutron_id': neutron_id,
                       'nsx_id': nsx_id,
                       'status': device_status})
            return device_status
        except (nsx_exc.InvalidSecurityCertificate, api_exc.NsxApiException):
            with excutils.save_and_reraise_exception():
                self._rollback_gw_device(context, neutron_id,
                                         gw_data=old_gateway_device_data)
        except n_exc.NotFound:
            # The gateway device was probably deleted in the backend.
            # The DB change should be rolled back and the status must
            # be put in error
            with excutils.save_and_reraise_exception():
                self._rollback_gw_device(context, neutron_id,
                                         gw_data=old_gateway_device_data,
                                         new_status=networkgw_db.ERROR)

    def get_gateway_device(self, context, device_id, fields=None):
        # Get device from database
        gw_device = super(NsxPluginV2, self).get_gateway_device(
            context, device_id, fields, include_nsx_id=True)
        # Fetch status from NSX
        nsx_id = gw_device['nsx_id']
        device_status = nsx_utils.get_nsx_device_status(self.cluster, nsx_id)
        # TODO(salv-orlando): Asynchronous sync for gateway device status
        # Update status in database
        with db_api.context_manager.writer.using(context):
            query = model_query.query_with_hooks(
                context, nsx_models.NetworkGatewayDevice).filter(
                    nsx_models.NetworkGatewayDevice.id == device_id)
            query.update({'status': device_status},
                         synchronize_session=False)
        gw_device['status'] = device_status
        return gw_device

    def get_gateway_devices(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        # Get devices from database
        devices = super(NsxPluginV2, self).get_gateway_devices(
            context, filters, fields, include_nsx_id=True)
        # Fetch operational status from NSX, filter by tenant tag
        # TODO(salv-orlando): Asynchronous sync for gateway device status
        tenant_id = context.tenant_id if not context.is_admin else None
        nsx_statuses = nsx_utils.get_nsx_device_statuses(self.cluster,
                                                         tenant_id)
        # Update statuses in database
        with db_api.context_manager.writer.using(context):
            for device in devices:
                new_status = nsx_statuses.get(device['nsx_id'])
                if new_status:
                    device['status'] = new_status
        return devices

    def create_gateway_device(self, context, gateway_device):
        # NOTE(salv-orlando): client-certificate will not be stored
        # in the database
        device_data = gateway_device[networkgw.DEVICE_RESOURCE_NAME]
        client_certificate = device_data.pop('client_certificate')
        gw_device = super(NsxPluginV2, self).create_gateway_device(
            context, gateway_device)
        # DB operation was successful, perform NSX operation
        gw_device['status'] = self.create_gateway_device_handler(
            context, gw_device, client_certificate)
        return gw_device

    def update_gateway_device(self, context, device_id,
                              gateway_device):
        # NOTE(salv-orlando): client-certificate will not be stored
        # in the database
        client_certificate = (
            gateway_device[networkgw.DEVICE_RESOURCE_NAME].pop(
                'client_certificate', None))
        # Retrive current state from DB in case a rollback should be needed
        old_gw_device_data = super(NsxPluginV2, self).get_gateway_device(
            context, device_id, include_nsx_id=True)
        gw_device = super(NsxPluginV2, self).update_gateway_device(
            context, device_id, gateway_device, include_nsx_id=True)
        # DB operation was successful, perform NSX operation
        gw_device['status'] = self.update_gateway_device_handler(
            context, gw_device, old_gw_device_data, client_certificate)
        gw_device.pop('nsx_id')
        return gw_device

    def delete_gateway_device(self, context, device_id):
        nsx_device_id = self._get_nsx_device_id(context, device_id)
        super(NsxPluginV2, self).delete_gateway_device(
            context, device_id)
        # DB operation was successful, perform NSX operation
        # TODO(salv-orlando): State consistency with neutron DB
        # should be ensured even in case of backend failures
        try:
            l2gwlib.delete_gateway_device(self.cluster, nsx_device_id)
        except n_exc.NotFound:
            LOG.warning("Removal of gateway device: %(neutron_id)s failed "
                        "on NSX backend (NSX id:%(nsx_id)s) because the "
                        "NSX resource was not found",
                        {'neutron_id': device_id, 'nsx_id': nsx_device_id})
        except api_exc.NsxApiException:
            with excutils.save_and_reraise_exception():
                # In this case a 500 should be returned
                LOG.exception("Removal of gateway device: %(neutron_id)s "
                              "failed on NSX backend (NSX id:%(nsx_id)s). "
                              "Neutron and NSX states have diverged.",
                              {'neutron_id': device_id,
                               'nsx_id': nsx_device_id})

    def create_security_group(self, context, security_group, default_sg=False):
        """Create security group.

        If default_sg is true that means we are creating a default security
        group and we don't need to check if one exists.
        """
        s = security_group.get('security_group')

        tenant_id = s['tenant_id']
        if not default_sg:
            self._ensure_default_security_group(context, tenant_id)
        # NOTE(salv-orlando): Pre-generating Neutron ID for security group.
        neutron_id = str(uuidutils.generate_uuid())
        nsx_secgroup = secgrouplib.create_security_profile(
            self.cluster, tenant_id, neutron_id, s)
        with db_api.context_manager.writer.using(context):
            s['id'] = neutron_id
            sec_group = super(NsxPluginV2, self).create_security_group(
                context, security_group, default_sg)
            context.session.flush()
            # Add mapping between neutron and nsx identifiers
            nsx_db.add_neutron_nsx_security_group_mapping(
                context.session, neutron_id, nsx_secgroup['uuid'])
        return sec_group

    def update_security_group(self, context, secgroup_id, security_group):
        secgroup = (super(NsxPluginV2, self).
                    update_security_group(context,
                                          secgroup_id,
                                          security_group))
        if ('name' in security_group['security_group'] and
            secgroup['name'] != 'default'):
            nsx_sec_profile_id = nsx_utils.get_nsx_security_group_id(
                context.session, self.cluster, secgroup_id)
            try:
                name = security_group['security_group']['name']
                secgrouplib.update_security_profile(
                    self.cluster, nsx_sec_profile_id, name)
            except (n_exc.NotFound, api_exc.NsxApiException) as e:
                # Reverting the DB change is not really worthwhile
                # for a mismatch between names. It's the rules that
                # we care about.
                LOG.error('Error while updating security profile '
                          '%(uuid)s with name %(name)s: %(error)s.',
                          {'uuid': secgroup_id, 'name': name, 'error': e})
        return secgroup

    def delete_security_group(self, context, security_group_id):
        """Delete a security group.

        :param security_group_id: security group rule to remove.
        """
        with db_api.context_manager.writer.using(context):
            security_group = super(NsxPluginV2, self).get_security_group(
                context, security_group_id)
            if not security_group:
                raise ext_sg.SecurityGroupNotFound(id=security_group_id)

            if security_group['name'] == 'default' and not context.is_admin:
                raise ext_sg.SecurityGroupCannotRemoveDefault()

            filters = {'security_group_id': [security_group['id']]}
            if super(NsxPluginV2, self)._get_port_security_group_bindings(
                context, filters):
                raise ext_sg.SecurityGroupInUse(id=security_group['id'])
            nsx_sec_profile_id = nsx_utils.get_nsx_security_group_id(
                context.session, self.cluster, security_group_id)

            try:
                secgrouplib.delete_security_profile(
                    self.cluster, nsx_sec_profile_id)
            except n_exc.NotFound:
                # The security profile was not found on the backend
                # do not fail in this case.
                LOG.warning("The NSX security profile %(sec_profile_id)s, "
                            "associated with the Neutron security group "
                            "%(sec_group_id)s was not found on the "
                            "backend",
                            {'sec_profile_id': nsx_sec_profile_id,
                             'sec_group_id': security_group_id})
            except api_exc.NsxApiException:
                # Raise and fail the operation, as there is a problem which
                # prevented the sec group from being removed from the backend
                LOG.exception("An exception occurred while removing the "
                              "NSX security profile %(sec_profile_id)s, "
                              "associated with Netron security group "
                              "%(sec_group_id)s",
                              {'sec_profile_id': nsx_sec_profile_id,
                               'sec_group_id': security_group_id})
                raise nsx_exc.NsxPluginException(
                    _("Unable to remove security group %s from backend"),
                    security_group['id'])
            return super(NsxPluginV2, self).delete_security_group(
                context, security_group_id)

    def _validate_security_group_rules(self, context, rules):
        for rule in rules['security_group_rules']:
            r = rule.get('security_group_rule')
            port_based_proto = (self._get_ip_proto_number(r['protocol'])
                                in constants.IP_PROTOCOL_MAP.values())
            if (not port_based_proto and
                (r['port_range_min'] is not None or
                 r['port_range_max'] is not None)):
                msg = (_("Port values not valid for "
                         "protocol: %s") % r['protocol'])
                raise n_exc.BadRequest(resource='security_group_rule',
                                       msg=msg)
        return super(NsxPluginV2, self)._validate_security_group_rules(context,
                                                                       rules)

    def create_security_group_rule(self, context, security_group_rule):
        """Create a single security group rule."""
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def create_security_group_rule_bulk(self, context, security_group_rules):
        """Create security group rules.

        :param security_group_rule: list of rules to create
        """
        s = security_group_rules.get('security_group_rules')

        # TODO(arosen) is there anyway we could avoid having the update of
        # the security group rules in nsx outside of this transaction?
        with db_api.context_manager.writer.using(context):
            security_group_id = self._validate_security_group_rules(
                context, security_group_rules)
            # Check to make sure security group exists
            security_group = super(NsxPluginV2, self).get_security_group(
                context, security_group_id)

            if not security_group:
                raise ext_sg.SecurityGroupNotFound(id=security_group_id)
            # Check for duplicate rules
            self._check_for_duplicate_rules(context, security_group_id, s)
            # gather all the existing security group rules since we need all
            # of them to PUT to NSX.
            existing_rules = self.get_security_group_rules(
                context, {'security_group_id': [security_group['id']]})
            combined_rules = sg_utils.merge_security_group_rules_with_current(
                context.session, self.cluster, s, existing_rules)
            nsx_sec_profile_id = nsx_utils.get_nsx_security_group_id(
                context.session, self.cluster, security_group_id)
            secgrouplib.update_security_group_rules(self.cluster,
                                                    nsx_sec_profile_id,
                                                    combined_rules)
            return super(
                NsxPluginV2, self).create_security_group_rule_bulk_native(
                    context, security_group_rules)

    def delete_security_group_rule(self, context, sgrid):
        """Delete a security group rule
        :param sgrid: security group id to remove.
        """
        with db_api.context_manager.writer.using(context):
            # determine security profile id
            security_group_rule = (
                super(NsxPluginV2, self).get_security_group_rule(
                    context, sgrid))
            if not security_group_rule:
                raise ext_sg.SecurityGroupRuleNotFound(id=sgrid)

            sgid = security_group_rule['security_group_id']
            current_rules = self.get_security_group_rules(
                context, {'security_group_id': [sgid]})
            current_rules_nsx = sg_utils.get_security_group_rules_nsx_format(
                context.session, self.cluster, current_rules, True)

            sg_utils.remove_security_group_with_id_and_id_field(
                current_rules_nsx, sgrid)
            nsx_sec_profile_id = nsx_utils.get_nsx_security_group_id(
                context.session, self.cluster, sgid)
            secgrouplib.update_security_group_rules(
                self.cluster, nsx_sec_profile_id, current_rules_nsx)
            return super(NsxPluginV2, self).delete_security_group_rule(context,
                                                                       sgrid)

    def create_qos_queue(self, context, qos_queue, check_policy=True):
        q = qos_queue.get('qos_queue')
        self._validate_qos_queue(context, q)
        q['id'] = queuelib.create_lqueue(self.cluster, q)
        return super(NsxPluginV2, self).create_qos_queue(context, qos_queue)

    def delete_qos_queue(self, context, queue_id, raise_in_use=True):
        filters = {'queue_id': [queue_id]}
        queues = self._get_port_queue_bindings(context, filters)
        if queues:
            if raise_in_use:
                raise qos.QueueInUseByPort()
            else:
                return
        queuelib.delete_lqueue(self.cluster, queue_id)
        return super(NsxPluginV2, self).delete_qos_queue(context, queue_id)
