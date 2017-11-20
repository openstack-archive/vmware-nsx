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
from neutron_lib import context as n_context
from neutron_lib.plugins import directory
from oslo_log import log as logging

from neutron.db import _resource_extend as resource_extend
from neutron.db import _utils as db_utils
from neutron.db import agents_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import api as db_api
from neutron.db.availability_zone import router as router_az_db
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
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
from vmware_nsx.common import config  # noqa
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import managers as nsx_managers
from vmware_nsx.db import (
    routertype as rt_rtr)
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import nsx_portbindings_db as pbin_db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.common import plugin as nsx_plugin_common
from vmware_nsx.plugins.dvs import plugin as dvs
from vmware_nsx.plugins.nsx_v import plugin as v
from vmware_nsx.plugins.nsx_v3 import plugin as t

LOG = logging.getLogger(__name__)
TVD_PLUGIN_TYPE = "Nsx-TVD"


@resource_extend.has_resource_extenders
class NsxTVDPlugin(addr_pair_db.AllowedAddressPairsMixin,
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

    __native_bulk_support = False
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
        LOG.info("This plugin is experimental!")
        # Validate configuration
        config.validate_nsx_config_options()
        super(NsxTVDPlugin, self).__init__()

        # init the different supported plugins
        self.init_plugins()

        # init the extensions supported by any of the plugins
        self.init_extensions()

    @staticmethod
    def plugin_type():
        return TVD_PLUGIN_TYPE

    @staticmethod
    def is_tvd_plugin():
        return True

    def init_plugins(self):
        # initialize all supported plugins
        self.plugins = {}
        try:
            self.plugins[projectpluginmap.NsxPlugins.NSX_T] = t.NsxV3Plugin()
        except Exception as e:
            LOG.info("NSX-T plugin will not be supported: %s", e)

        try:
            self.plugins[projectpluginmap.NsxPlugins.NSX_V] = v.NsxVPluginV2()
        except Exception as e:
            LOG.info("NSX-V plugin will not be supported: %s", e)

        try:
            self.plugins[projectpluginmap.NsxPlugins.DVS] = dvs.NsxDvsV2()
        except Exception as e:
            LOG.info("DVS plugin will not be supported: %s", e)

        if not len(self.plugins):
            msg = _("No active plugins were found")
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # update the default plugin for new projects
        # TODO(asarfaty): make the default configurable?
        if projectpluginmap.NsxPlugins.NSX_T in self.plugins:
            self.default_plugin = projectpluginmap.NsxPlugins.NSX_T
        else:
            self.default_plugin = self.plugins[0].key
        LOG.info("NSX-TVD plugin will use %s as the default plugin",
            self.default_plugin)

    def get_plugin_by_type(self, plugin_type):
        return self.plugins.get(plugin_type)

    def init_extensions(self):
        # Support all the extensions supported by any of the plugins
        extensions = []
        for plugin in self.plugins:
            extensions.extend(self.plugins[plugin].supported_extension_aliases)
        self.supported_extension_aliases = list(set(extensions))

        # mark extensions which are supported by only one of the plugins
        self._unsupported_fields = {}
        for plugin in self.plugins:
            # TODO(asarfaty): add other resources here
            plugin_type = self.plugins[plugin].plugin_type()
            self._unsupported_fields[plugin_type] = {'router': []}

        # router size and type are supported only by the V plugin
        self._unsupported_fields[t.NsxV3Plugin.plugin_type()]['router'] = [
            'router_size', 'router_type']

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
        p = self._get_plugin_from_project(context, context.project_id)
        return p._list_availability_zones(context, filters=filters)

    def validate_availability_zones(self, context, resource_type,
                                    availability_zones):
        p = self._get_plugin_from_project(context, context.project_id)
        return p.validate_availability_zones(context, resource_type,
                                             availability_zones)

    def _get_plugin_from_net_id(self, context, net_id):
        # get the network using the super plugin - here we use the
        # _get_network (so as not to call the make dict method)
        network = super(NsxTVDPlugin, self)._get_network(context, net_id)
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

    def delete_network(self, context, id):
        p = self._get_plugin_from_net_id(context, id)
        p.delete_network(context, id)

    def get_network(self, context, id, fields=None):
        p = self._get_plugin_from_net_id(context, id)
        return p.get_network(context, id, fields=fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        filters = filters or {}
        with db_api.context_manager.reader.using(context):
            networks = (
                super(NsxTVDPlugin, self).get_networks(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            for net in networks:
                p = self._get_plugin_from_project(context, net['tenant_id'])
                p._extend_get_network_dict_provider(context, net)
        return (networks if not fields else
                [db_utils.resource_fields(network,
                                          fields) for network in networks])

    def update_network(self, context, id, network):
        p = self._get_plugin_from_net_id(context, id)
        return p.update_network(context, id, network)

    def create_port(self, context, port):
        id = port['port']['network_id']
        p = self._get_plugin_from_net_id(context, id)
        return p.create_port(context, port)

    def update_port(self, context, id, port):
        db_port = self._get_port(context, id)
        p = self._get_plugin_from_net_id(context, db_port['network_id'])
        return p.update_port(context, id, port)

    def delete_port(self, context, id, **kwargs):
        db_port = self._get_port(context, id)
        p = self._get_plugin_from_net_id(context, db_port['network_id'])
        p.delete_port(context, id, **kwargs)

    def get_port(self, context, id, fields=None):
        db_port = self._get_port(context, id)
        p = self._get_plugin_from_net_id(context, db_port['network_id'])
        return p.get_port(context, id, fields=fields)

    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        filters = filters or {}
        with db_api.context_manager.reader.using(context):
            ports = (
                super(NsxTVDPlugin, self).get_ports(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            # Add port extensions
            for port in ports:
                if 'id' in port:
                    port_model = self._get_port(context, port['id'])
                    resource_extend.apply_funcs('ports', port, port_model)
                p = self._get_plugin_from_net_id(context, port['network_id'])
                p._extend_get_port_dict_qos_and_binding(context, port)
                p._remove_provider_security_groups_from_list(port)
        return (ports if not fields else
                [db_utils.resource_fields(port, fields) for port in ports])

    def get_subnet(self, context, id, fields=None):
        db_subnet = self._get_subnet(context, id)
        p = self._get_plugin_from_net_id(context, db_subnet['network_id'])
        return p.get_subnet(context, id, fields=fields)

    def get_subnets(self, context, filters=None, fields=None, sorts=None,
                    limit=None, marker=None, page_reverse=False):
        # The subnets is tricky as the metadata requests make use of the
        # get subnet. So there are two use cases here:
        # 1. that the metadata request returns a value
        # 2. that this is a general subnet query.
        # If none found then we return default plugin subnets
        default_plugin_subnets = []
        for plugin in self.plugins.values():
            subnets = plugin.get_subnets(context, filters=filters,
                                         fields=fields, sorts=sorts,
                                         limit=limit, marker=marker,
                                         page_reverse=page_reverse)
            if subnets:
                return subnets
            if self.plugins[self.default_plugin] == plugin:
                default_plugin_subnets = subnets
        return default_plugin_subnets

    def delete_subnet(self, context, id):
        db_subnet = self._get_subnet(context, id)
        p = self._get_plugin_from_net_id(context, db_subnet['network_id'])
        p.delete_subnet(context, id)

    def create_subnet(self, context, subnet):
        id = subnet['subnet']['network_id']
        p = self._get_plugin_from_net_id(context, id)
        return p.create_subnet(context, subnet)

    def update_subnet(self, context, id, subnet):
        db_subnet = self._get_subnet(context, id)
        p = self._get_plugin_from_net_id(context, db_subnet['network_id'])
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
            net_id = self.get_port(
                context, interface_info['port_id'])['network_id']
        elif is_sub:
            net_id = self.get_subnet(
                context, interface_info['subnet_id'])['network_id']
        net_plugin = self._get_plugin_from_net_id(context, net_id)
        if net_plugin.plugin_type() != router_plugin.plugin_type():
            err_msg = (_('Router interface should belong to the %s plugin '
                         'as the router') % router_plugin.plugin_type())
            raise n_exc.InvalidInput(error_message=err_msg)

    def _get_plugin_from_router_id(self, context, router_id):
        # get the router using the super plugin - here we use the
        # _get_router (so as not to call the make dict method)
        router = super(NsxTVDPlugin, self)._get_router(context, router_id)
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
            router['router'], p.plugin_type(), 'router')
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

    def disassociate_floatingips(self, context, port_id):
        db_port = self._get_port(context, port_id)
        p = self._get_plugin_from_net_id(context, db_port['network_id'])
        return p.disassociate_floatingips(context, port_id)

    def _get_plugin_from_sg_id(self, context, sg_id):
        # get the router using the super plugin - here we use the
        # _get_router (so as not to call the make dict method)
        sg = super(NsxTVDPlugin, self)._get_security_group(context, sg_id)
        return self._get_plugin_from_project(context, sg['tenant_id'])

    # TODO(asarfaty): no need to create on both any more?
    def create_security_group(self, context, security_group,
                              default_sg=False):
        if not default_sg:
            secgroup = security_group['security_group']
            tenant_id = secgroup['tenant_id']
            self._ensure_default_security_group(context, tenant_id)

        p = self._get_plugin_from_project(context, context.project_id)
        return p.create_security_group(context, security_group,
                                       default_sg=default_sg)

    def delete_security_group(self, context, id):
        p = self._get_plugin_from_sg_id(context, id)
        p.delete_security_group(context, id)
        # self._v.delete_security_group(context, id, delete_base=False)
        # self._t.delete_security_group(context, id)

    def update_security_group(self, context, id, security_group):
        p = self._get_plugin_from_sg_id(context, id)
        return p.update_security_group(context, id, security_group)
        #self._t.update_security_group(context, id, security_group)
        #return self._v.update_security_group(context, id, security_group)

    def create_security_group_rule_bulk(self, context, security_group_rules):
        p = self._get_plugin_from_project(context, context.project_id)
        return p.create_security_group_rule_bulk(context,
                                                 security_group_rules)
        # sg_rules = security_group_rules['security_group_rules']
        # for r in sg_rules:
        #     r['security_group_rule']['id'] = (
        #         r['security_group_rule'].get('id') or
        #         uuidutils.generate_uuid())
        # sgs = self._t.create_security_group_rule_bulk(context,
        #                                               security_group_rules)
        # self._v.create_security_group_rule_bulk(context,
        #                                         security_group_rules,
        #                                         base_create=False)
        # return sgs

    def create_security_group_rule(self, context, security_group_rule):
        p = self._get_plugin_from_project(context, context.project_id)
        return p.create_security_group_rule(context, security_group_rule)
        # security_group_rule['security_group_rule']['id'] = (
        #     security_group_rule['security_group_rule'].get('id') or
        #     uuidutils.generate_uuid())
        # sg = self._t.create_security_group_rule(context, security_group_rule)
        # self._v.create_security_group_rule(context, security_group_rule,
        #                                    create_base=False)
        # return sg

    def delete_security_group_rule(self, context, id):
        p = self._get_plugin_from_sg_id(context, id)
        p.delete_security_group_rule(context, id)
        # self._v.delete_security_group_rule(context, id, delete_base=False)
        # self._t.delete_security_group_rule(context, id)

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

    def create_project_plugin_map(self, context, project_plugin_map):
        # TODO(asarfaty): Validate project id exists
        data = project_plugin_map['project_plugin_map']
        if nsx_db.get_project_plugin_mapping(
            context.session, data['project']):
            raise projectpluginmap.ProjectPluginAlreadyExists(
                project_id=data['project'])
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

    def _get_plugin_from_project(self, context, project_id):
        """Get the correct plugin for this project.

        Look for the project in the DB.
        If not there - add an entry with the default plugin
        """
        plugin_type = self.default_plugin
        mapping = nsx_db.get_project_plugin_mapping(
            context.session, project_id)
        if mapping:
            plugin_type = mapping['plugin']
        else:
            self.create_project_plugin_map(context,
                {'project_plugin_map': {'plugin': plugin_type,
                                        'project': project_id}})
        if not self.plugins.get(plugin_type):
            msg = (_("Cannot use unsupported plugin %(plugin)s for project "
                     "%(project)s") % {'plugin': plugin_type,
                                       'project': project_id})
            raise nsx_exc.NsxPluginException(err_msg=msg)

        LOG.debug("Using %s plugin", plugin_type)
        return self.plugins[plugin_type]
