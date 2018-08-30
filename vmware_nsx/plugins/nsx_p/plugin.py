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

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
import webob.exc

from neutron.db import _resource_extend as resource_extend
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import api as db_api
from neutron.db import dns_db
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
from neutron.db import l3_attrs_db
from neutron.db import l3_gwmode_db
from neutron.db.models import l3 as l3_db_models
from neutron.db.models import securitygroup as securitygroup_model  # noqa
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import portsecurity_db
from neutron.db import securitygroups_db
from neutron.db import vlantransparent_db
from neutron.extensions import providernet
from neutron.quota import resource_registry
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api import faults
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc

from vmware_nsx._i18n import _
from vmware_nsx.common import config  # noqa
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import l3_rpc_agent_api
from vmware_nsx.common import locking
from vmware_nsx.common import managers
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import extended_security_group_rule as extend_sg_rule
from vmware_nsx.db import maclearning as mac_db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.common import plugin as nsx_plugin_common
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils

from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as nsxlib_consts
from vmware_nsxlib.v3 import utils as nsxlib_utils

LOG = log.getLogger(__name__)


@resource_extend.has_resource_extenders
class NsxPolicyPlugin(agentschedulers_db.AZDhcpAgentSchedulerDbMixin,
                      addr_pair_db.AllowedAddressPairsMixin,
                      nsx_plugin_common.NsxPluginBase,
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
                                   "port-security-groups-filtering"]

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

        self.cfg_group = 'nsx_p'  # group name for nsx_p section in nsx.ini

        self._prepare_default_rules()

        # subscribe the init complete method last, so it will be called only
        # if init was successful
        registry.subscribe(self.init_complete,
                           resources.PROCESS,
                           events.AFTER_INIT)

    def _validate_nsx_policy_version(self):
        self._nsx_version = self.nsxpolicy.get_version()
        LOG.info("NSX Version: %s", self._nsx_version)
        if not self.nsxpolicy.feature_supported(
            nsxlib_consts.FEATURE_NSX_POLICY_NETWORKING):
            msg = (_("The NSX Policy plugin cannot be used with NSX version "
                     "%(ver)s") % {'ver': self._nsx_version})
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def _prepare_default_rules(self):
        #TODO(asarfaty): implement
        pass

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

    def _create_network_at_the_backend(self, context, net_data):
        #TODO(asarfaty): implement, using nsx-id the same as the neutron id
        pass

    def _validate_external_net_create(self, net_data):
        #TODO(asarfaty): implement
        pass

    def create_network(self, context, network):
        net_data = network['network']

        #TODO(asarfaty): network validation
        external = net_data.get(external_net.EXTERNAL)
        is_external_net = validators.is_attr_set(external) and external
        tenant_id = net_data['tenant_id']

        self._ensure_default_security_group(context, tenant_id)

        if is_external_net:
            self._validate_external_net_create(net_data)

        # Create the neutron network
        with db_api.context_manager.writer.using(context):
            # Create network in Neutron
            created_net = super(NsxPolicyPlugin, self).create_network(
                context, network)
            self._extension_manager.process_create_network(
                context, net_data, created_net)
            if psec.PORTSECURITY not in net_data:
                net_data[psec.PORTSECURITY] = True
            self._process_network_port_security_create(
                context, net_data, created_net)
            self._process_l3_create(context, created_net, net_data)

        # Create the backend NSX network
        if not is_external_net:
            try:
                self._create_network_at_the_backend(context, net_data)
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
        with db_api.context_manager.writer.using(context):
            self._process_l3_delete(context, network_id)
            return super(NsxPolicyPlugin, self).delete_network(
                context, network_id)
        if not self._network_is_external(context, network_id):
            # TODO(asarfaty) delete the NSX logical network
            pass

    def update_network(self, context, id, network):
        original_net = super(NsxPolicyPlugin, self).get_network(context, id)
        net_data = network['network']
        LOG.debug("Updating network %s %s->%s", id, original_net, net_data)
        # Neutron does not support changing provider network values
        providernet._raise_if_updates_provider_attributes(net_data)
        extern_net = self._network_is_external(context, id)

        # Do not support changing external/non-external networks
        if (external_net.EXTERNAL in net_data and
            net_data[external_net.EXTERNAL] != extern_net):
            err_msg = _("Cannot change the router:external flag of a network")
            raise n_exc.InvalidInput(error_message=err_msg)

        updated_net = super(NsxPolicyPlugin, self).update_network(context, id,
                                                                  network)
        self._extension_manager.process_update_network(context, net_data,
                                                       updated_net)
        self._process_l3_update(context, updated_net, network['network'])

        #TODO(asarfaty): update the Policy manager

        return updated_net

    def get_network(self, context, id, fields=None):
        with db_api.context_manager.reader.using(context):
            # Get network from Neutron database
            network = self._get_network(context, id)
            # Don't do field selection here otherwise we won't be able to add
            # provider networks fields
            net = self._make_network_dict(network, context=context)
        return db_utils.resource_fields(net, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        # Get networks from Neutron database
        filters = filters or {}
        with db_api.context_manager.reader.using(context):
            networks = (
                super(NsxPolicyPlugin, self).get_networks(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            # TODO(asarfaty) Add plugin/provider network fields

        return (networks if not fields else
                [db_utils.resource_fields(network,
                                          fields) for network in networks])

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

    def _create_port_at_the_backend(self, context, port_data):
        #TODO(asarfaty): implement
        pass

    def _cleanup_port(self, context, port_id, lport_id):
        super(NsxPolicyPlugin, self).delete_port(context, port_id)
        #TODO(asarfaty): Delete the NSX logical port

    def base_create_port(self, context, port):
        neutron_db = super(NsxPolicyPlugin, self).create_port(context, port)
        self._extension_manager.process_create_port(
            context, port['port'], neutron_db)
        return neutron_db

    def create_port(self, context, port, l2gw_port_check=False):
        port_data = port['port']
        self._validate_max_ips_per_port(port_data.get('fixed_ips', []),
                                        port_data.get('device_owner'))

        with db_api.context_manager.writer.using(context):
            is_external_net = self._network_is_external(
                context, port_data['network_id'])
            if is_external_net:
                self._assert_on_external_net_with_compute(port_data)

            neutron_db = self.base_create_port(context, port)
            port["port"].update(neutron_db)

        if not is_external_net:
            try:
                self._create_port_at_the_backend(context, port_data)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.error('Failed to create port %(id)s on NSX '
                              'backend. Exception: %(e)s',
                              {'id': neutron_db['id'], 'e': e})
                    self._cleanup_port(context, neutron_db['id'], None)

        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        port_model = self._get_port(context, port_data['id'])
        resource_extend.apply_funcs('ports', port_data, port_model)

        kwargs = {'context': context, 'port': neutron_db}
        registry.notify(resources.PORT, events.AFTER_CREATE, self, **kwargs)
        return neutron_db

    def delete_port(self, context, port_id,
                    l3_port_check=True, l2gw_port_check=True,
                    force_delete_dhcp=False,
                    force_delete_vpn=False):
        port = self.get_port(context, port_id)
        if not self._network_is_external(context, port['network_id']):
            #TODO(asarfaty): Delete the NSX logical port
            pass

        self.disassociate_floatingips(context, port_id)

        super(NsxPolicyPlugin, self).delete_port(context, port_id)

    def _update_port_on_backend(self, context, lport_id,
                                original_port, updated_port):
        #TODO(asarfaty): implement
        pass

    def update_port(self, context, id, port):
        with db_api.context_manager.writer.using(context):
            # get the original port, and keep it honest as it is later used
            # for notifications
            original_port = super(NsxPolicyPlugin, self).get_port(context, id)
            port_data = port['port']
            is_external_net = self._network_is_external(
                context, original_port['network_id'])
            if is_external_net:
                self._assert_on_external_net_with_compute(port_data)
            device_owner = (port_data['device_owner']
                            if 'device_owner' in port_data
                            else original_port.get('device_owner'))
            self._validate_max_ips_per_port(
                port_data.get('fixed_ips', []), device_owner)

            updated_port = super(NsxPolicyPlugin, self).update_port(context,
                                                                    id, port)
            self._extension_manager.process_update_port(context, port_data,
                                                        updated_port)
            # copy values over - except fixed_ips as
            # they've already been processed
            port_data.pop('fixed_ips', None)
            updated_port.update(port_data)

        # update the port in the backend, only if it exists in the DB
        # (i.e not external net)
        if not is_external_net:
            self._update_port_on_backend(context, id,
                                         original_port, updated_port)

        # Make sure the port revision is updated
        if 'revision_number' in updated_port:
            port_model = self._get_port(context, id)
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

    def get_port(self, context, id, fields=None):
        port = super(NsxPolicyPlugin, self).get_port(context, id, fields=None)
        if 'id' in port:
            port_model = self._get_port(context, port['id'])
            resource_extend.apply_funcs('ports', port, port_model)
        return db_utils.resource_fields(port, fields)

    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        filters = filters or {}
        self._update_filters_with_sec_group(context, filters)
        with db_api.context_manager.reader.using(context):
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
        return (ports if not fields else
                [db_utils.resource_fields(port, fields) for port in ports])

    def _update_router_gw_info(self, context, router_id, info):
        router = self._get_router(context, router_id)
        super(NsxPolicyPlugin, self)._update_router_gw_info(
            context, router_id, info, router=router)
        #TODO(asarfaty): Update the NSX

    def create_router(self, context, router):
        r = router['router']
        gw_info = self._extract_external_gw(context, router, is_extract=True)
        with db_api.context_manager.writer.using(context):
            router = super(NsxPolicyPlugin, self).create_router(
                context, router)
            router_db = self._get_router(context, router['id'])
            self._process_extra_attr_router_create(context, router_db, r)
        #TODO(asarfaty): Create the NSX logical router and add DB mapping
        LOG.debug("Created router %s: %s. GW info %s",
                  router['id'], r, gw_info)
        return self.get_router(context, router['id'])

    def delete_router(self, context, router_id):
        router = self.get_router(context, router_id)
        if router.get(l3_apidef.EXTERNAL_GW_INFO):
            self._update_router_gw_info(context, router_id, {})
        nsx_router_id = nsx_db.get_nsx_router_id(
            context.session, router_id)
        ret_val = super(NsxPolicyPlugin, self).delete_router(
            context, router_id)
        if nsx_router_id:
            #TODO(asarfaty): delete the NSX logical router
            pass

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
        network_id = self._get_interface_network(context, interface_info)
        extern_net = self._network_is_external(context, network_id)
        router_db = self._get_router(context, router_id)
        gw_network_id = (router_db.gw_port.network_id if router_db.gw_port
                         else None)
        LOG.debug("Adding router %s interface %s with GW %s",
                  router_id, network_id, gw_network_id)
        # A router interface cannot be an external network
        if extern_net:
            msg = _("An external network cannot be attached as "
                    "an interface to a router")
            raise n_exc.InvalidInput(error_message=msg)

        # Update the interface of the neutron router
        info = super(NsxPolicyPlugin, self).add_router_interface(
             context, router_id, interface_info)

        #TODO(asarfaty) Update the NSX logical router ports
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        #TODO(asarfaty) Update the NSX logical router ports
        info = super(NsxPolicyPlugin, self).remove_router_interface(
            context, router_id, interface_info)
        return info

    def create_floatingip(self, context, floatingip):
        new_fip = super(NsxPolicyPlugin, self).create_floatingip(
                context, floatingip, initial_status=(
                    const.FLOATINGIP_STATUS_ACTIVE
                    if floatingip['floatingip']['port_id']
                    else const.FLOATINGIP_STATUS_DOWN))
        router_id = new_fip['router_id']
        if not router_id:
            return new_fip
        #TODO(asarfaty): Update the NSX router
        return new_fip

    def delete_floatingip(self, context, fip_id):
        fip = self.get_floatingip(context, fip_id)
        router_id = fip['router_id']
        port_id = fip['port_id']
        LOG.debug("Deleting floating IP %s. Router %s, Port %s",
                  fip_id, router_id, port_id)

        if router_id:
            nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                     router_id)
            if nsx_router_id:
                #TODO(asarfaty): Update the NSX router
                pass

        super(NsxPolicyPlugin, self).delete_floatingip(context, fip_id)

    def update_floatingip(self, context, fip_id, floatingip):
        old_fip = self.get_floatingip(context, fip_id)
        old_port_id = old_fip['port_id']
        new_status = (const.FLOATINGIP_STATUS_ACTIVE
                      if floatingip['floatingip'].get('port_id')
                      else const.FLOATINGIP_STATUS_DOWN)
        new_fip = super(NsxPolicyPlugin, self).update_floatingip(
            context, fip_id, floatingip)
        router_id = new_fip['router_id']
        new_port_id = new_fip['port_id']

        nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                 router_id)
        if nsx_router_id:
            #TODO(asarfaty): Update the NSX router
            LOG.debug("Updating floating IP %s. Router %s, Port %s "
                      "(old port %s)",
                      fip_id, router_id, new_port_id, old_port_id)

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
            nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                     fip_db.router_id)
            if nsx_router_id:
                # TODO(asarfaty): Update the NSX logical router
                pass
            self.update_floatingip_status(context, fip_db.id,
                                          const.FLOATINGIP_STATUS_DOWN)

        super(NsxPolicyPlugin, self).disassociate_floatingips(
            context, port_id, do_notify=False)

    def _create_security_group_backend_resources(self, secgroup):
        # TODO(asarfaty): implement
        pass

    def create_security_group(self, context, security_group, default_sg=False):
        secgroup = security_group['security_group']

        if not default_sg:
            tenant_id = secgroup['tenant_id']
            self._ensure_default_security_group(context, tenant_id)

        self._create_security_group_backend_resources(secgroup)
        with db_api.context_manager.writer.using(context):
            secgroup_db = (
                super(NsxPolicyPlugin, self).create_security_group(
                    context, security_group, default_sg))

            # TODO(asarfaty) save NSX->Neutron mappings
            self._process_security_group_properties_create(context,
                                                           secgroup_db,
                                                           secgroup,
                                                           default_sg)

        return secgroup_db

    def update_security_group(self, context, id, security_group):
        orig_secgroup = self.get_security_group(
            context, id, fields=['id', 'name', 'description'])
        LOG.debug("Updating SG %s -> %s", orig_secgroup,
                  security_group['security_group'])
        with db_api.context_manager.writer.using(context):
            secgroup_res = super(NsxPolicyPlugin, self).update_security_group(
                context, id, security_group)
            self._process_security_group_properties_update(
                context, secgroup_res, security_group['security_group'])
        #TODO(asarfaty): Update the NSX backend
        return secgroup_res

    def delete_security_group(self, context, id):
        super(NsxPolicyPlugin, self).delete_security_group(context, id)
        #TODO(asarfaty): Update the nSX backend

    def create_security_group_rule(self, context, security_group_rule):
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def create_security_group_rule_bulk(self, context, security_group_rules):
        sg_rules = security_group_rules['security_group_rules']
        for r in sg_rules:
            # TODO(asarfaty): create rules at the NSX
            pass

        with db_api.context_manager.writer.using(context):
            rules_db = (super(NsxPolicyPlugin,
                              self).create_security_group_rule_bulk_native(
                                  context, security_group_rules))
            for i, r in enumerate(sg_rules):
                self._process_security_group_rule_properties(
                    context, rules_db[i], r['security_group_rule'])
        return rules_db

    def delete_security_group_rule(self, context, id):
        #TODO(asarfaty): Update the nSX backend
        super(NsxPolicyPlugin, self).delete_security_group_rule(context, id)
