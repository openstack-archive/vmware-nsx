# Copyright 2014 VMware, Inc.
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

from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context as n_context
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils

from neutron.db import _resource_extend as resource_extend
from neutron.db import _utils as db_utils
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import api as db_api
from neutron.db.availability_zone import router as router_az_db
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db.models import l3 as l3_db_models
from neutron.db.models import securitygroup as securitygroup_model  # noqa
from neutron.db import models_v2
from neutron.db import portsecurity_db
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_db
from neutron.quota import resource_registry
from neutron_lib.api import validators
from neutron_lib import exceptions as n_exc

from vmware_nsx.common import availability_zones as nsx_com_az
from vmware_nsx.common import config
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import managers as nsx_managers
from vmware_nsx.db import (
    routertype as rt_rtr)
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import nsx_portbindings_db as pbin_db
from vmware_nsx.extensions import advancedserviceproviders as as_providers
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.common import plugin as nsx_plugin_common
from vmware_nsx.plugins.dvs import plugin as dvs
from vmware_nsx.plugins.nsx_v import plugin as v
from vmware_nsx.plugins.nsx_v3 import plugin as t
from vmware_nsx.services.lbaas.nsx import lb_driver_v2

LOG = logging.getLogger(__name__)
TVD_PLUGIN_TYPE = "Nsx-TVD"


@resource_extend.has_resource_extenders
class NsxTVDPlugin(agentschedulers_db.AZDhcpAgentSchedulerDbMixin,
                   addr_pair_db.AllowedAddressPairsMixin,
                   agents_db.AgentDbMixin,
                   nsx_plugin_common.NsxPluginBase,
                   rt_rtr.RouterType_mixin,
                   external_net_db.External_net_db_mixin,
                   extraroute_db.ExtraRoute_db_mixin,
                   extradhcpopt_db.ExtraDhcpOptMixin,
                   router_az_db.RouterAvailabilityZoneMixin,
                   l3_gwmode_db.L3_NAT_db_mixin,
                   pbin_db.NsxPortBindingMixin,
                   portsecurity_db.PortSecurityDbMixin,
                   securitygroups_db.SecurityGroupDbMixin,
                   nsx_com_az.NSXAvailabilityZonesPluginCommon,
                   projectpluginmap.ProjectPluginMapPluginBase):

    supported_extension_aliases = ['project-plugin-map']

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

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
        self._extension_manager = nsx_managers.ExtensionManager()
        LOG.info("Start NSX TVD Plugin")
        # Validate configuration
        config.validate_nsx_config_options()
        super(NsxTVDPlugin, self).__init__()

        # init the different supported plugins
        self.init_plugins()

        # init the extensions supported by any of the plugins
        self.init_extensions()
        self.lbv2_driver = lb_driver_v2.EdgeLoadbalancerDriverV2()

        self._unsubscribe_callback_events()

    @staticmethod
    def plugin_type():
        return TVD_PLUGIN_TYPE

    @staticmethod
    def is_tvd_plugin():
        return True

    def _init_plugin(self, map_type, plugin_class):
        try:
            self.plugins[map_type] = plugin_class()
        except Exception as e:
            LOG.warning("%s plugin will not be supported: %s",
                        map_type.upper(), e)
            if map_type == self.default_plugin:
                msg = (_("The default plugin %(def)s failed to start. "
                         "Reason: %(reason)s") % {'def': self.default_plugin,
                                                  'reason': e})
                LOG.error(msg)
                raise nsx_exc.NsxPluginException(err_msg=msg)
        else:
            LOG.info("%s plugin will be supported", map_type.upper())

    def init_plugins(self):
        # initialize all supported plugins
        self.plugins = {}
        self.as_providers = {}
        # update the default plugin for new projects
        self.default_plugin = cfg.CONF.nsx_tvd.default_plugin
        plugins = [(projectpluginmap.NsxPlugins.NSX_T, t.NsxV3Plugin),
                   (projectpluginmap.NsxPlugins.NSX_V, v.NsxVPluginV2),
                   (projectpluginmap.NsxPlugins.DVS, dvs.NsxDvsV2)]
        for (map_type, plugin_class) in plugins:
            self._init_plugin(map_type, plugin_class)
        if not len(self.plugins):
            msg = _("No active plugins were found")
            raise nsx_exc.NsxPluginException(err_msg=msg)

        for k, val in self.plugins.items():
            if "advanced-service-providers" in val.supported_extension_aliases:
                self.as_providers[k] = val
        LOG.info("NSX-TVD plugin will use %s as the default plugin",
            self.default_plugin)

        # validate the availability zones configuration
        self.init_availability_zones()

    def get_plugin_by_type(self, plugin_type):
        return self.plugins.get(plugin_type)

    def init_extensions(self):
        # Support all the extensions supported by any of the plugins
        extensions = []
        for plugin in self.plugins:
            extensions.extend(self.plugins[plugin].supported_extension_aliases)
        self.supported_extension_aliases.extend(list(set(extensions)))

        # mark extensions which are supported by only one of the plugins
        self._unsupported_fields = {}
        for plugin in self.plugins:
            # TODO(asarfaty): add other resources here
            plugin_type = self.plugins[plugin].plugin_type()
            self._unsupported_fields[plugin_type] = {'router': [],
                                                     'port': [],
                                                     'security_group': []}

            # router size and type are supported only by the V plugin
            if plugin_type in [t.NsxV3Plugin.plugin_type(),
                               dvs.NsxDvsV2.plugin_type()]:
                self._unsupported_fields[plugin_type]['router'] = [
                    'router_size', 'router_type']

            # port mac learning, and provider sg are not supported by
            # the dvs plugin
            if plugin_type in [dvs.NsxDvsV2.plugin_type()]:
                self._unsupported_fields[plugin_type]['port'] = [
                    'mac_learning_enabled', 'provider_security_groups']

            # security group policy can be supported only by nsx-v
            if plugin_type in [t.NsxV3Plugin.plugin_type(),
                               dvs.NsxDvsV2.plugin_type()]:
                self._unsupported_fields[plugin_type]['security_group'] = [
                    'policy']

    def init_availability_zones(self):
        # Make sure there are no overlaps between v/t availability zones
        if (self.plugins.get(projectpluginmap.NsxPlugins.NSX_V) and
            self.plugins.get(projectpluginmap.NsxPlugins.NSX_T) and
            bool(set(cfg.CONF.nsxv.availability_zones) &
                 set(cfg.CONF.nsx_v3.availability_zones))):
            msg = _("Cannot use the same availability zones in NSX-V and T")
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def _unsubscribe_callback_events(self):
        # unsubscribe the callback that should be called on all plugins
        # other that NSX-T.
        registry.unsubscribe_all(
            l3_db.L3_NAT_dbonly_mixin._prevent_l3_port_delete_callback)

        # Instead we will subscribe our internal callback.
        registry.subscribe(self._prevent_l3_port_delete_callback,
                           resources.PORT, events.BEFORE_DELETE)

    @staticmethod
    def _prevent_l3_port_delete_callback(resource, event, trigger, **kwargs):
        """Register a callback to replace the default one

        This callback will prevent port deleting only if the port plugin
        is not NSX-T (in NSX-T plugin it was already handled)
        """
        context = kwargs['context']
        port_id = kwargs['port_id']
        port_check = kwargs['port_check']
        l3plugin = directory.get_plugin(plugin_constants.L3)
        if l3plugin and port_check:
            # if not nsx-t - call super code
            core_plugin = directory.get_plugin()
            db_port = core_plugin._get_port(context, port_id)
            p = core_plugin._get_plugin_from_net_id(
                context, db_port['network_id'])
            if p.plugin_type() != projectpluginmap.NsxPlugins.NSX_T:
                l3plugin.prevent_l3_port_deletion(context, port_id)

    def _validate_obj_extensions(self, data, plugin_type, obj_type):
        """prevent configuration of unsupported extensions"""
        for field in self._unsupported_fields[plugin_type][obj_type]:
            if validators.is_attr_set(data.get(field)):
                err_msg = (_('Can not support %(field)s extension for '
                             '%(obj_type)s %(p)s plugin') % {
                           'field': field,
                           'obj_type': obj_type,
                           'p': plugin_type})
                raise n_exc.InvalidInput(error_message=err_msg)

    def _cleanup_obj_fields(self, data, plugin_type, obj_type):
        """Remove data of unsupported extensions"""
        for field in self._unsupported_fields[plugin_type][obj_type]:
            if field in data:
                del data[field]

    def _list_availability_zones(self, context, filters=None):
        p = self._get_plugin_for_request(context, filters)
        if p:
            return p._list_availability_zones(context, filters=filters)
        return []

    def validate_availability_zones(self, context, resource_type,
                                    availability_zones):
        p = self._get_plugin_from_project(context, context.project_id)
        return p.validate_availability_zones(context, resource_type,
                                             availability_zones)

    def _get_plugin_from_net_id(self, context, net_id):
        # get the network using the super plugin - here we use the
        # _get_network (so as not to call the make dict method)
        network = self._get_network(context, net_id)
        return self._get_plugin_from_project(context, network['tenant_id'])

    def get_network_availability_zones(self, net_db):
        ctx = n_context.get_admin_context()
        p = self._get_plugin_from_project(ctx, net_db['tenant_id'])
        return p.get_network_availability_zones(net_db)

    def create_network(self, context, network):
        net_data = network['network']
        tenant_id = net_data['tenant_id']
        self._ensure_default_security_group(context, tenant_id)
        p = self._get_plugin_from_project(context, tenant_id)
        return p.create_network(context, network)

    @db_api.retry_if_session_inactive()
    def create_network_bulk(self, context, networks):
        #Implement create bulk so that the plugin calculation will be done once
        objects = []
        items = networks['networks']

        # look at the first network to find out the project & plugin
        net_data = items[0]['network']
        tenant_id = net_data['tenant_id']
        self._ensure_default_security_group(context, tenant_id)
        p = self._get_plugin_from_project(context, tenant_id)

        # create all networks one by one
        try:
            with db_api.context_manager.writer.using(context):
                for item in items:
                    objects.append(p.create_network(context, item))
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error("An exception occurred while creating "
                          "the networks:%(item)s",
                          {'item': item})
        return objects

    def delete_network(self, context, id):
        p = self._get_plugin_from_net_id(context, id)
        p.delete_network(context, id)

    def get_network(self, context, id, fields=None):
        p = self._get_plugin_from_net_id(context, id)
        return p.get_network(context, id, fields=fields)

    def _get_plugin_for_request(self, context, filters, keys=None):
        project_id = context.project_id
        if filters:
            if filters.get('tenant_id'):
                project_id = filters.get('tenant_id')
            elif filters.get('project_id'):
                project_id = filters.get('project_id')
            else:
                # we have specific filters on the request. If those are
                # specific enough, we should not filter by project
                if filters.get('id'):
                    return
                if keys:
                    for key in keys:
                        if filters.get(key):
                            return
            # If there are multiple tenants/projects being requested then
            # we will not filter according to the plugin
            if isinstance(project_id, list):
                return
        return self._get_plugin_from_project(context, project_id)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        # Read project plugin to filter relevant projects according to
        # plugin
        req_p = self._get_plugin_for_request(context, filters,
                                             keys=['shared'])
        filters = filters or {}
        with db_api.context_manager.reader.using(context):
            networks = (
                super(NsxTVDPlugin, self).get_networks(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            for net in networks[:]:
                p = self._get_plugin_from_project(context, net['tenant_id'])
                if p == req_p or req_p is None:
                    p._extend_get_network_dict_provider(context, net)
                else:
                    networks.remove(net)
        return (networks if not fields else
                [db_utils.resource_fields(network,
                                          fields) for network in networks])

    def update_network(self, context, id, network):
        p = self._get_plugin_from_net_id(context, id)
        return p.update_network(context, id, network)

    def create_port(self, context, port):
        net_id = port['port']['network_id']
        p = self._get_plugin_from_net_id(context, net_id)
        self._validate_obj_extensions(
            port['port'], p.plugin_type(), 'port')
        new_port = p.create_port(context, port)
        self._cleanup_obj_fields(
            new_port, p.plugin_type(), 'port')
        return new_port

    def update_port(self, context, id, port):
        db_port = self._get_port(context, id)
        p = self._get_plugin_from_net_id(context, db_port['network_id'])
        self._validate_obj_extensions(
            port['port'], p.plugin_type(), 'port')
        return p.update_port(context, id, port)

    def delete_port(self, context, id, **kwargs):
        db_port = self._get_port(context, id)
        p = self._get_plugin_from_net_id(context, db_port['network_id'])
        p.delete_port(context, id, **kwargs)

    def get_port(self, context, id, fields=None):
        db_port = self._get_port(context, id)
        p = self._get_plugin_from_net_id(context, db_port['network_id'])
        port = p.get_port(context, id, fields=fields)
        self._cleanup_obj_fields(
            port, p.plugin_type(), 'port')
        return port

    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        # Read project plugin to filter relevant projects according to
        # plugin
        req_p = self._get_plugin_for_request(context, filters,
                                             keys=['device_id'])
        filters = filters or {}
        with db_api.context_manager.reader.using(context):
            ports = (
                super(NsxTVDPlugin, self).get_ports(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            # Add port extensions
            for port in ports[:]:
                port_model = None
                if 'id' in port:
                    port_model = self._get_port(context, port['id'])
                    resource_extend.apply_funcs('ports', port, port_model)
                p = self._get_plugin_from_net_id(context, port['network_id'])
                if p == req_p or req_p is None:
                    if hasattr(p, '_extend_get_port_dict_qos_and_binding'):
                        p._extend_get_port_dict_qos_and_binding(context, port)
                    else:
                        if not port_model:
                            port_model = port
                        p._extend_port_dict_binding(port, port_model)
                    if hasattr(p,
                               '_remove_provider_security_groups_from_list'):
                        p._remove_provider_security_groups_from_list(port)
                    self._cleanup_obj_fields(
                        port, p.plugin_type(), 'port')
                else:
                    ports.remove(port)
        return (ports if not fields else
                [db_utils.resource_fields(port, fields) for port in ports])

    def _get_subnet_plugin_by_id(self, context, subnet_id):
        db_subnet = self._get_subnet(context, subnet_id)
        return self._get_plugin_from_net_id(context, db_subnet['network_id'])

    def get_subnet(self, context, id, fields=None):
        p = self._get_subnet_plugin_by_id(context, id)
        return p.get_subnet(context, id, fields=fields)

    def get_subnets(self, context, filters=None, fields=None, sorts=None,
                    limit=None, marker=None, page_reverse=False):
        # Check if we need to invoke metadata search. Here we are unable to
        # filter according to projects as this is from the nova api service
        # so we invoke on all plugins that support this extension
        if ((fields and as_providers.ADV_SERVICE_PROVIDERS in fields)
            or (filters and filters.get(as_providers.ADV_SERVICE_PROVIDERS))):
            for plugin in self.as_providers.values():
                subnets = plugin.get_subnets(context, filters=filters,
                                             fields=fields, sorts=sorts,
                                             limit=limit, marker=marker,
                                             page_reverse=page_reverse)
                if subnets:
                    return subnets
            return []
        else:
            # Read project plugin to filter relevant projects according to
            # plugin
            req_p = self._get_plugin_for_request(context, filters)
            filters = filters or {}
            subnets = super(NsxTVDPlugin, self).get_subnets(
                context, filters=filters, fields=fields, sorts=sorts,
                limit=limit, marker=marker, page_reverse=page_reverse)
            for subnet in subnets[:]:
                p = self._get_plugin_from_project(context, subnet['tenant_id'])
                if req_p and p != req_p:
                    subnets.remove(subnet)
            return subnets

    def delete_subnet(self, context, id):
        p = self._get_subnet_plugin_by_id(context, id)
        p.delete_subnet(context, id)

    def _get_subnet_plugin(self, context, subnet_data):
        # get the plugin of the associated network
        net_id = subnet_data['network_id']
        net_plugin = self._get_plugin_from_net_id(context, net_id)
        # make sure it matches the plugin of the current tenant
        tenant_id = subnet_data['tenant_id']
        tenant_plugin = self._get_plugin_from_project(context, tenant_id)
        if tenant_plugin.plugin_type() != net_plugin.plugin_type():
            err_msg = (_('Subnet should belong to the %s plugin '
                         'as the network') % net_plugin.plugin_type())
            raise n_exc.InvalidInput(error_message=err_msg)
        return net_plugin

    def create_subnet(self, context, subnet):
        p = self._get_subnet_plugin(context, subnet['subnet'])
        return p.create_subnet(context, subnet)

    def create_subnet_bulk(self, context, subnets):
        # look at the first subnet to find out the project & plugin
        items = subnets['subnets']
        p = self._get_subnet_plugin(context, items[0]['subnet'])
        return p.create_subnet_bulk(context, subnets)

    def update_subnet(self, context, id, subnet):
        p = self._get_subnet_plugin_by_id(context, id)
        return p.update_subnet(context, id, subnet)

    def get_router_availability_zones(self, router):
        ctx = n_context.get_admin_context()
        p = self._get_plugin_from_project(ctx, router['tenant_id'])
        return p.get_router_availability_zones(router)

    def _validate_router_gw_plugin(self, context, router_plugin,
                                   gw_info):
        if gw_info and gw_info.get('network_id'):
            net_plugin = self._get_plugin_from_net_id(
                context, gw_info['network_id'])
            if net_plugin.plugin_type() != router_plugin.plugin_type():
                err_msg = (_('Router gateway should belong to the %s plugin '
                             'as the router') % router_plugin.plugin_type())
                raise n_exc.InvalidInput(error_message=err_msg)

    def _validate_router_interface_plugin(self, context, router_plugin,
                                          interface_info):
        is_port, is_sub = self._validate_interface_info(interface_info)
        if is_port:
            net_id = self._get_port(
                context, interface_info['port_id'])['network_id']
        elif is_sub:
            net_id = self._get_subnet(
                context, interface_info['subnet_id'])['network_id']
        net_plugin = self._get_plugin_from_net_id(context, net_id)
        if net_plugin.plugin_type() != router_plugin.plugin_type():
            err_msg = (_('Router interface should belong to the %s plugin '
                         'as the router') % router_plugin.plugin_type())
            raise n_exc.InvalidInput(error_message=err_msg)

    def _get_plugin_from_router_id(self, context, router_id):
        # get the router using the super plugin - here we use the
        # _get_router (so as not to call the make dict method)
        router = self._get_router(context, router_id)
        return self._get_plugin_from_project(context, router['tenant_id'])

    def create_router(self, context, router):
        tenant_id = router['router']['tenant_id']
        self._ensure_default_security_group(context, tenant_id)
        p = self._get_plugin_from_project(context, tenant_id)
        self._validate_router_gw_plugin(context, p, router['router'].get(
            'external_gateway_info'))
        self._validate_obj_extensions(
            router['router'], p.plugin_type(), 'router')
        new_router = p.create_router(context, router)
        self._cleanup_obj_fields(
            new_router, p.plugin_type(), 'router')
        return new_router

    def update_router(self, context, router_id, router):
        p = self._get_plugin_from_router_id(context, router_id)
        self._validate_router_gw_plugin(context, p, router['router'].get(
            'external_gateway_info'))
        self._validate_obj_extensions(
            router['router'], p.plugin_type(), 'router')
        return p.update_router(context, router_id, router)

    def get_router(self, context, id, fields=None):
        p = self._get_plugin_from_router_id(context, id)
        router = p.get_router(context, id, fields=fields)
        self._cleanup_obj_fields(router, p.plugin_type(), 'router')
        return router

    def delete_router(self, context, id):
        p = self._get_plugin_from_router_id(context, id)
        p.delete_router(context, id)

    def add_router_interface(self, context, router_id, interface_info):
        p = self._get_plugin_from_router_id(context, router_id)
        self._validate_router_interface_plugin(context, p, interface_info)
        return p.add_router_interface(context, router_id, interface_info)

    def remove_router_interface(self, context, router_id, interface_info):
        p = self._get_plugin_from_router_id(context, router_id)
        return p.remove_router_interface(context, router_id, interface_info)

    def _validate_fip_router_plugin(self, context, fip_plugin, fip_data):
        if 'router_id' in fip_data:
            router_plugin = self._get_plugin_from_router_id(
                context, fip_data['router_id'])
            if router_plugin.plugin_type() != fip_plugin.plugin_type():
                err_msg = (_('Floatingip router should belong to the %s '
                             'plugin as the floatingip') %
                           fip_plugin.plugin_type())
                raise n_exc.InvalidInput(error_message=err_msg)

    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        # Read project plugin to filter relevant projects according to
        # plugin
        req_p = self._get_plugin_for_request(context, filters)
        routers = super(NsxTVDPlugin, self).get_routers(
            context, filters=filters, fields=fields, sorts=sorts,
            limit=limit, marker=marker, page_reverse=page_reverse)
        for router in routers[:]:
            p = self._get_plugin_from_project(context, router['tenant_id'])
            if req_p and p != req_p:
                routers.remove(router)
        return routers

    def create_floatingip(self, context, floatingip):
        net_id = floatingip['floatingip']['floating_network_id']
        p = self._get_plugin_from_net_id(context, net_id)
        self._validate_fip_router_plugin(context, p, floatingip['floatingip'])
        return p.create_floatingip(context, floatingip)

    def update_floatingip(self, context, id, floatingip):
        fip = self._get_floatingip(context, id)
        net_id = fip['floating_network_id']
        p = self._get_plugin_from_net_id(context, net_id)
        self._validate_fip_router_plugin(context, p, floatingip['floatingip'])
        return p.update_floatingip(context, id, floatingip)

    def delete_floatingip(self, context, id):
        fip = self._get_floatingip(context, id)
        net_id = fip['floating_network_id']
        p = self._get_plugin_from_net_id(context, net_id)
        return p.delete_floatingip(context, id)

    def get_floatingip(self, context, id, fields=None):
        fip = self._get_floatingip(context, id)
        net_id = fip['floating_network_id']
        p = self._get_plugin_from_net_id(context, net_id)
        return p.get_floatingip(context, id, fields=fields)

    def get_floatingips(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        # Read project plugin to filter relevant projects according to
        # plugin
        req_p = self._get_plugin_for_request(context, filters)
        fips = super(NsxTVDPlugin, self).get_floatingips(
            context, filters=filters, fields=fields, sorts=sorts,
            limit=limit, marker=marker, page_reverse=page_reverse)
        for fip in fips[:]:
            p = self._get_plugin_from_project(context,
                                              fip['tenant_id'])
            if req_p and p != req_p:
                fips.remove(fip)
        return fips

    def disassociate_floatingips(self, context, port_id):
        db_port = self._get_port(context, port_id)
        p = self._get_plugin_from_net_id(context, db_port['network_id'])
        return p.disassociate_floatingips(context, port_id)

    def _get_plugin_from_sg_id(self, context, sg_id):
        sg = self._get_security_group(context, sg_id)
        return self._get_plugin_from_project(context, sg['tenant_id'])

    def create_security_group(self, context, security_group,
                              default_sg=False):
        if not default_sg:
            secgroup = security_group['security_group']
            tenant_id = secgroup['tenant_id']
            self._ensure_default_security_group(context, tenant_id)

        p = self._get_plugin_from_project(context, context.project_id)
        self._validate_obj_extensions(
            security_group['security_group'], p.plugin_type(),
            'security_group')

        new_sg = p.create_security_group(context, security_group,
                                         default_sg=default_sg)
        self._cleanup_obj_fields(
            new_sg, p.plugin_type(), 'security_group')
        return new_sg

    def delete_security_group(self, context, id):
        p = self._get_plugin_from_sg_id(context, id)
        p.delete_security_group(context, id)

    def update_security_group(self, context, id, security_group):
        p = self._get_plugin_from_sg_id(context, id)
        self._validate_obj_extensions(
            security_group['security_group'], p.plugin_type(),
            'security_group')
        return p.update_security_group(context, id, security_group)

    def get_security_group(self, context, id, fields=None):
        p = self._get_plugin_from_sg_id(context, id)
        sg = p.get_security_group(context, id, fields=fields)
        self._cleanup_obj_fields(
            sg, p.plugin_type(), 'security_group')
        return sg

    def get_security_groups(self, context, filters=None, fields=None,
                            sorts=None, limit=None,
                            marker=None, page_reverse=False, default_sg=False):
        # Read project plugin to filter relevant projects according to
        # plugin
        req_p = self._get_plugin_for_request(context, filters)
        sgs = super(NsxTVDPlugin, self).get_security_groups(
            context, filters=filters, fields=fields, sorts=sorts,
            limit=limit, marker=marker, page_reverse=page_reverse,
            default_sg=default_sg)
        for sg in sgs[:]:
            p = self._get_plugin_from_project(context, sg['tenant_id'])
            if req_p and p != req_p:
                sgs.remove(sg)
        return sgs

    def create_security_group_rule_bulk(self, context, security_group_rules):
        p = self._get_plugin_from_project(context, context.project_id)
        return p.create_security_group_rule_bulk(context,
                                                 security_group_rules)

    def create_security_group_rule(self, context, security_group_rule):
        p = self._get_plugin_from_project(context, context.project_id)
        return p.create_security_group_rule(context, security_group_rule)

    def delete_security_group_rule(self, context, id):
        rule_db = self._get_security_group_rule(context, id)
        sg_id = rule_db['security_group_id']
        p = self._get_plugin_from_sg_id(context, sg_id)
        p.delete_security_group_rule(context, id)

    def get_security_group_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        # Read project plugin to filter relevant projects according to
        # plugin
        req_p = self._get_plugin_for_request(context, filters)
        rules = super(NsxTVDPlugin, self).get_security_group_rules(
            context, filters=filters, fields=fields, sorts=sorts,
            limit=limit, marker=marker, page_reverse=page_reverse)
        for rule in rules[:]:
            p = self._get_plugin_from_project(context, rule['tenant_id'])
            if req_p and p != req_p:
                rules.remove(rule)
        return rules

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME])
    def _ext_extend_network_dict(result, netdb):
        ctx = n_context.get_admin_context()
        # get the core plugin as this is a static method with no 'self'
        plugin = directory.get_plugin()
        p = plugin._get_plugin_from_project(ctx, netdb['tenant_id'])
        with db_api.context_manager.writer.using(ctx):
            p._extension_manager.extend_network_dict(
                ctx.session, netdb, result)

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _ext_extend_port_dict(result, portdb):
        ctx = n_context.get_admin_context()
        # get the core plugin as this is a static method with no 'self'
        plugin = directory.get_plugin()
        p = plugin._get_plugin_from_project(ctx, portdb['tenant_id'])
        with db_api.context_manager.writer.using(ctx):
            p._extension_manager.extend_port_dict(
                ctx.session, portdb, result)

    @staticmethod
    @resource_extend.extends([subnet_def.COLLECTION_NAME])
    def _ext_extend_subnet_dict(result, subnetdb):
        ctx = n_context.get_admin_context()
        # get the core plugin as this is a static method with no 'self'
        plugin = directory.get_plugin()
        p = plugin._get_plugin_from_project(ctx, subnetdb['tenant_id'])
        with db_api.context_manager.writer.using(ctx):
            p._extension_manager.extend_subnet_dict(
                ctx.session, subnetdb, result)

    def _get_project_plugin_dict(self, data):
        return {'id': data['project'],
                'project': data['project'],
                'plugin': data['plugin'],
                'tenant_id': data['project']}

    def create_project_plugin_map(self, context, project_plugin_map,
                                  internal=False):
        data = project_plugin_map['project_plugin_map']

        # validations:
        # 1. validate it doesn't already exist
        if nsx_db.get_project_plugin_mapping(
            context.session, data['project']):
            raise projectpluginmap.ProjectPluginAlreadyExists(
                project_id=data['project'])
        if not internal:
            # 2. only admin user is allowed
            if not context.is_admin:
                raise projectpluginmap.ProjectPluginAdminOnly()
            # 3. Validate the project id
            # TODO(asarfaty): Validate project id exists in keystone
            if not uuidutils.is_uuid_like(data['project']):
                raise projectpluginmap.ProjectPluginIllegalId(
                    project_id=data['project'])
            # 4. Check that plugin is available
            if data['plugin'] not in self.plugins:
                raise projectpluginmap.ProjectPluginNotAvailable(
                    plugin=data['plugin'])

        # Add the entry to the DB and return it
        LOG.info("Adding mapping between project %(project)s and plugin "
                 "%(plugin)s", {'project': data['project'],
                                'plugin': data['plugin']})
        nsx_db.add_project_plugin_mapping(context.session,
                                          data['project'],
                                          data['plugin'])
        return self._get_project_plugin_dict(data)

    def get_project_plugin_map(self, context, id, fields=None):
        data = nsx_db.get_project_plugin_mapping(context.session, id)
        if data:
            return self._get_project_plugin_dict(data)
        else:
            raise n_exc.ObjectNotFound(id=id)

    def get_project_plugin_maps(self, context, filters=None, fields=None,
                                sorts=None, limit=None, marker=None,
                                page_reverse=False):
        # TODO(asarfaty) filter the results
        mappings = nsx_db.get_project_plugin_mappings(context.session)
        return [self._get_project_plugin_dict(data) for data in mappings]

    def get_plugin_type_from_project(self, context, project_id):
        """Get the correct plugin type for this project.

        Look for the project in the DB.
        If not there - add an entry with the default plugin
        """
        plugin_type = self.default_plugin
        if not project_id:
            # if the project_id is empty - return the default one and do not
            # add to db (used by admin context to get actions)
            return plugin_type

        mapping = nsx_db.get_project_plugin_mapping(
            context.session, project_id)
        if mapping:
            plugin_type = mapping['plugin']
        else:
            # add a new entry with the default plugin
            try:
                self.create_project_plugin_map(
                    context,
                    {'project_plugin_map': {'plugin': plugin_type,
                                            'project': project_id}},
                    internal=True)
            except projectpluginmap.ProjectPluginAlreadyExists:
                # Maybe added by another thread
                pass
        if not self.plugins.get(plugin_type):
            msg = (_("Cannot use unsupported plugin %(plugin)s for project "
                     "%(project)s") % {'plugin': plugin_type,
                                       'project': project_id})
            raise nsx_exc.NsxPluginException(err_msg=msg)

        LOG.debug("Using %s plugin for project %s", plugin_type, project_id)
        return plugin_type

    def _get_plugin_from_project(self, context, project_id):
        """Get the correct plugin for this project.

        Look for the project in the DB.
        If not there - add an entry with the default plugin
        """
        plugin_type = self.get_plugin_type_from_project(context, project_id)
        return self.plugins[plugin_type]

    def get_housekeeper(self, context, name, fields=None):
        p = self._get_plugin_from_project(context, context.project_id)
        if hasattr(p, 'housekeeper'):
            return p.housekeeper.get(name)
        msg = _("Housekeeper %s not found") % name
        raise nsx_exc.NsxPluginException(err_msg=msg)

    def get_housekeepers(self, context, filters=None, fields=None, sorts=None,
                         limit=None, marker=None, page_reverse=False):
        p = self._get_plugin_for_request(context, filters)
        if p and hasattr(p, 'housekeeper'):
            return p.housekeeper.list()
        return []

    def update_housekeeper(self, context, name, housekeeper):
        p = self._get_plugin_from_project(context, context.project_id)
        if hasattr(p, 'housekeeper'):
            p.housekeeper.run(context, name)
        return p.housekeeper.get(name)

    def get_address_scopes(self, context, filters=None, fields=None,
                           sorts=None, limit=None, marker=None,
                           page_reverse=False):
        # Read project plugin to filter relevant projects according to
        # plugin
        req_p = self._get_plugin_for_request(context, filters)
        address_scopes = super(NsxTVDPlugin, self).get_address_scopes(
            context, filters=filters, fields=fields, sorts=sorts,
            limit=limit, marker=marker, page_reverse=page_reverse)
        for address_scope in address_scopes[:]:
            p = self._get_plugin_from_project(context,
                                              address_scope['tenant_id'])
            if req_p and p != req_p:
                address_scopes.remove(address_scope)
        return address_scopes

    def get_subnetpools(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        # Read project plugin to filter relevant projects according to
        # plugin
        req_p = self._get_plugin_for_request(context, filters)
        pools = super(NsxTVDPlugin, self).get_subnetpools(
            context, filters=filters, fields=fields, sorts=sorts,
            limit=limit, marker=marker, page_reverse=page_reverse)
        for pool in pools[:]:
            p = self._get_plugin_from_project(context,
                                              pool['tenant_id'])
            if req_p and p != req_p:
                pools.remove(pool)
        return pools

    def get_nsx_policy(self, context, id, fields=None):
        # Extension supported only by the nsxv plugin
        p = self._get_plugin_from_project(context, context.project_id)
        if p.plugin_type() != v.NsxVPluginV2.plugin_type():
            err_msg = (_('Can not support %(field)s extension for '
                         '%(p)s plugin') % {
                       'field': 'nsx-policy',
                       'p': p.plugin_type()})
            raise n_exc.InvalidInput(error_message=err_msg)

        return p.get_nsx_policy(context, id, fields=fields)

    def get_nsx_policies(self, context, filters=None, fields=None,
                         sorts=None, limit=None, marker=None,
                         page_reverse=False):
        # Extension supported only by the nsxv plugin
        p = self._get_plugin_from_project(context, context.project_id)
        if p.plugin_type() != v.NsxVPluginV2.plugin_type():
            return []
        return p.get_nsx_policies(context, filters=filters, fields=fields,
                                  sorts=sorts, limit=limit, marker=marker,
                                  page_reverse=page_reverse)
