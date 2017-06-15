# Copyright 2013 VMware, Inc
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

from distutils import version
import random
import time

from neutron_lib import constants as lib_const
from neutron_lib import context as q_context
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import excutils
from sqlalchemy.orm import exc as sa_exc

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsxv_exc
from vmware_nsx.common import nsxv_constants
from vmware_nsx.common import utils
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import constants
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.plugins.nsx_v.vshield.tasks import (
    constants as task_constants)
from vmware_nsx.plugins.nsx_v.vshield.tasks import tasks

LOG = logging.getLogger(__name__)


class EdgeApplianceDriver(object):
    def __init__(self):
        super(EdgeApplianceDriver, self).__init__()
        # store the last task per edge that has the latest config
        self.updated_task = {
            'nat': {},
            'route': {},
        }
        random.seed()

    def _assemble_edge(self, name, appliance_size="compact",
                       deployment_container_id=None, datacenter_moid=None,
                       enable_aesni=True, dist=False,
                       enable_fips=False, remote_access=False,
                       edge_ha=False):
        edge = {
            'name': name,
            'fqdn': None,
            'enableAesni': enable_aesni,
            'enableFips': enable_fips,
            'featureConfigs': {
                'features': [
                    {
                        'featureType': 'firewall_4.0',
                        'globalConfig': {
                            'tcpTimeoutEstablished': 7200
                        }
                    }
                ]
            },
            'cliSettings': {
                'remoteAccess': remote_access
            },
            'autoConfiguration': {
                'enabled': False,
                'rulePriority': 'high'
            },
            'appliances': {
                'applianceSize': appliance_size
            },
        }
        if not dist:
            edge['type'] = "gatewayServices"
            edge['vnics'] = {'vnics': []}
        else:
            edge['type'] = "distributedRouter"
            edge['interfaces'] = {'interfaces': []}

        if deployment_container_id:
            edge['appliances']['deploymentContainerId'] = (
                deployment_container_id)
        if datacenter_moid:
            edge['datacenterMoid'] = datacenter_moid

        if not dist and edge_ha:
            self._enable_high_availability(edge)

        return edge

    def _select_datastores(self, availability_zone):
        primary_ds = availability_zone.datastore_id
        secondary_ds = availability_zone.ha_datastore_id
        if availability_zone.ha_placement_random:
            # we want to switch primary and secondary datastores
            # half of the times, to balance it
            if random.random() > 0.5:
                primary_ds = availability_zone.ha_datastore_id
                secondary_ds = availability_zone.datastore_id
        return primary_ds, secondary_ds

    def _assemble_edge_appliances(self, availability_zone):
        appliances = []
        if availability_zone.ha_datastore_id and availability_zone.edge_ha:
            # create appliance with HA
            primary_ds, secondary_ds = self._select_datastores(
                availability_zone)
            appliances.append(self._assemble_edge_appliance(
                availability_zone.resource_pool,
                primary_ds))
            appliances.append(self._assemble_edge_appliance(
                availability_zone.resource_pool,
                secondary_ds))
        elif availability_zone.datastore_id:
            # Single datastore
            appliances.append(self._assemble_edge_appliance(
                availability_zone.resource_pool,
                availability_zone.datastore_id))
        return appliances

    def _assemble_edge_appliance(self, resource_pool_id, datastore_id):
        appliance = {}
        if resource_pool_id:
            appliance['resourcePoolId'] = resource_pool_id
        if datastore_id:
            appliance['datastoreId'] = datastore_id
        return appliance

    def _assemble_edge_vnic(self, name, index, portgroup_id, tunnel_index=-1,
                            primary_address=None, subnet_mask=None,
                            secondary=None,
                            type="internal",
                            enable_proxy_arp=False,
                            enable_send_redirects=True,
                            is_connected=True,
                            mtu=1500,
                            address_groups=None):
        vnic = {
            'index': index,
            'name': name,
            'type': type,
            'portgroupId': portgroup_id,
            'mtu': mtu,
            'enableProxyArp': enable_proxy_arp,
            'enableSendRedirects': enable_send_redirects,
            'isConnected': is_connected
        }
        if address_groups is None:
            address_groups = []
        if not address_groups:
            if primary_address and subnet_mask:
                address_group = {
                    'primaryAddress': primary_address,
                    'subnetMask': subnet_mask
                }
                if secondary:
                    address_group['secondaryAddresses'] = {
                        'ipAddress': secondary,
                        'type': 'secondary_addresses'
                    }

                vnic['addressGroups'] = {
                    'addressGroups': [address_group]
                }
            else:
                vnic['subInterfaces'] = {'subInterfaces': address_groups}
        else:
            if tunnel_index < 0:
                vnic['addressGroups'] = {'addressGroups': address_groups}
            else:
                vnic['subInterfaces'] = {'subInterfaces': address_groups}

        return vnic

    def _assemble_vdr_interface(self, portgroup_id,
                                primary_address=None, subnet_mask=None,
                                secondary=None,
                                type="internal",
                                is_connected=True,
                                mtu=1500,
                                address_groups=None):
        interface = {
            'type': type,
            'connectedToId': portgroup_id,
            'mtu': mtu,
            'isConnected': is_connected
        }
        if address_groups is None:
            address_groups = []
        if not address_groups:
            if primary_address and subnet_mask:
                address_group = {
                    'primaryAddress': primary_address,
                    'subnetMask': subnet_mask
                }
                if secondary:
                    address_group['secondaryAddresses'] = {
                        'ipAddress': secondary,
                        'type': 'secondary_addresses'
                    }

                interface['addressGroups'] = {
                    'addressGroups': [address_group]
                }
        else:
            interface['addressGroups'] = {'addressGroups': address_groups}
        interfaces = {'interfaces': [interface]}

        return interfaces

    def _edge_status_to_level(self, status):
        if status == 'GREEN':
            status_level = constants.RouterStatus.ROUTER_STATUS_ACTIVE
        elif status in ('GREY', 'YELLOW'):
            status_level = constants.RouterStatus.ROUTER_STATUS_DOWN
        else:
            status_level = constants.RouterStatus.ROUTER_STATUS_ERROR
        return status_level

    def _enable_loadbalancer(self, edge):
        if (not edge.get('featureConfigs') or
            not edge['featureConfigs'].get('features')):
            edge['featureConfigs'] = {'features': []}
        edge['featureConfigs']['features'].append(
            {'featureType': 'loadbalancer_4.0',
             'enabled': True})

    def _enable_high_availability(self, edge):
        if (not edge.get('featureConfigs') or
            not edge['featureConfigs'].get('features')):
            edge['featureConfigs'] = {'features': []}
        edge['featureConfigs']['features'].append(
            {'featureType': 'highavailability_4.0',
             'enabled': True})

    def get_edge_status(self, edge_id):
        try:
            response = self.vcns.get_edge_status(edge_id)[1]
            status_level = self._edge_status_to_level(
                response['edgeStatus'])
        except exceptions.VcnsApiException as e:
            LOG.error("VCNS: Failed to get edge %(edge_id)s status: "
                      "Reason: %(reason)s",
                      {'edge_id': edge_id, 'reason': e.response})
            status_level = constants.RouterStatus.ROUTER_STATUS_ERROR
            try:
                desc = jsonutils.loads(e.response)
                if desc.get('errorCode') == (
                    constants.VCNS_ERROR_CODE_EDGE_NOT_RUNNING):
                    status_level = constants.RouterStatus.ROUTER_STATUS_DOWN
            except ValueError:
                LOG.error('Error code not present. %s', e.response)

        return status_level

    def get_interface(self, edge_id, vnic_index):
        # get vnic interface address groups
        try:
            return self.vcns.query_interface(edge_id, vnic_index)
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception("NSXv: Failed to query vnic %s", vnic_index)

    def update_interface(self, router_id, edge_id, index, network,
                         tunnel_index=-1, address=None, netmask=None,
                         secondary=None, is_connected=True,
                         address_groups=None):
        LOG.debug("VCNS: update vnic %(index)d: %(addr)s %(netmask)s", {
            'index': index, 'addr': address, 'netmask': netmask})
        if index == constants.EXTERNAL_VNIC_INDEX:
            name = constants.EXTERNAL_VNIC_NAME
            intf_type = 'uplink'
        else:
            name = constants.INTERNAL_VNIC_NAME + str(index)
            if tunnel_index < 0:
                intf_type = 'internal'
            else:
                intf_type = 'trunk'

        config = self._assemble_edge_vnic(
            name, index, network, tunnel_index,
            address, netmask, secondary, type=intf_type,
            address_groups=address_groups, is_connected=is_connected)

        self.vcns.update_interface(edge_id, config)

    def add_vdr_internal_interface(self, edge_id,
                                   network, address=None, netmask=None,
                                   secondary=None, address_groups=None,
                                   type="internal", is_connected=True):
        LOG.debug("Add VDR interface on edge: %s", edge_id)
        if address_groups is None:
            address_groups = []
        interface_req = (
            self._assemble_vdr_interface(network, address, netmask, secondary,
                                         address_groups=address_groups,
                                         is_connected=is_connected, type=type))
        self.vcns.add_vdr_internal_interface(edge_id, interface_req)
        header, response = self.vcns.get_edge_interfaces(edge_id)
        for interface in response['interfaces']:
            if interface['connectedToId'] == network:
                vnic_index = int(interface['index'])
                return vnic_index

    def update_vdr_internal_interface(self, edge_id, index, network,
                                      address_groups=None, is_connected=True):
        if not address_groups:
            address_groups = []
        interface = {
            'type': 'internal',
            'connectedToId': network,
            'mtu': 1500,
            'isConnected': is_connected,
            'addressGroups': {'addressGroup': address_groups}
        }
        interface_req = {'interface': interface}
        try:
            header, response = self.vcns.update_vdr_internal_interface(
                edge_id, index, interface_req)
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception("Failed to update vdr interface on edge: "
                              "%s", edge_id)

    def delete_vdr_internal_interface(self, edge_id, interface_index):
        LOG.debug("Delete VDR interface on edge: %s", edge_id)
        try:
            header, response = self.vcns.delete_vdr_internal_interface(
                edge_id, interface_index)
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception("Failed to delete vdr interface on edge: "
                              "%s",
                              edge_id)

    def delete_interface(self, router_id, edge_id, index):
        LOG.debug("Deleting vnic %(vnic_index)s: on edge %(edge_id)s",
                  {'vnic_index': index, 'edge_id': edge_id})
        try:
            self.vcns.delete_interface(edge_id, index)
        except exceptions.ResourceNotFound:
            LOG.error('Failed to delete vnic %(vnic_index)s on edge '
                      '%(edge_id)s: edge was not found',
                      {'vnic_index': index,
                       'edge_id': edge_id})
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception("Failed to delete vnic %(vnic_index)s: "
                              "on edge %(edge_id)s",
                              {'vnic_index': index,
                               'edge_id': edge_id})

        LOG.debug("Deletion complete vnic %(vnic_index)s: on edge %(edge_id)s",
                  {'vnic_index': index, 'edge_id': edge_id})

    def deploy_edge(self, context, router_id, name, internal_network,
                    dist=False, loadbalancer_enable=True,
                    appliance_size=nsxv_constants.LARGE,
                    availability_zone=None, deploy_metadata=False):

        edge_name = name
        edge = self._assemble_edge(
            edge_name, datacenter_moid=availability_zone.datacenter_moid,
            deployment_container_id=self.deployment_container_id,
            appliance_size=appliance_size, remote_access=False, dist=dist,
            edge_ha=availability_zone.edge_ha)
        appliances = self._assemble_edge_appliances(availability_zone)
        if appliances:
            edge['appliances']['appliances'] = appliances

        if not dist:
            vnic_external = self._assemble_edge_vnic(
                constants.EXTERNAL_VNIC_NAME, constants.EXTERNAL_VNIC_INDEX,
                availability_zone.external_network, type="uplink")
            edge['vnics']['vnics'].append(vnic_external)
        else:
            edge['mgmtInterface'] = {
                'connectedToId': availability_zone.external_network,
                'name': "mgmtInterface"}
        if internal_network:
            vnic_inside = self._assemble_edge_vnic(
                constants.INTERNAL_VNIC_NAME, constants.INTERNAL_VNIC_INDEX,
                internal_network,
                edge_utils.get_vdr_transit_network_plr_address(),
                edge_utils.get_vdr_transit_network_netmask(),
                type="internal")
            edge['vnics']['vnics'].append(vnic_inside)

        # If default login credentials for Edge are set, configure accordingly
        if (cfg.CONF.nsxv.edge_appliance_user and
            cfg.CONF.nsxv.edge_appliance_password):
            edge['cliSettings'].update({
                'userName': cfg.CONF.nsxv.edge_appliance_user,
                'password': cfg.CONF.nsxv.edge_appliance_password})

        if not dist and loadbalancer_enable:
            self._enable_loadbalancer(edge)

        edge_id = None
        try:
            header = self.vcns.deploy_edge(edge)[0]
            edge_id = header.get('location', '/').split('/')[-1]

            if edge_id:
                nsxv_db.update_nsxv_router_binding(
                    context.session, router_id, edge_id=edge_id)
                if not dist:
                    # Init Edge vnic binding
                    nsxv_db.init_edge_vnic_binding(
                        context.session, edge_id)
            else:
                if router_id:
                    nsxv_db.update_nsxv_router_binding(
                        context.session, router_id,
                        status=lib_const.ERROR)
                error = _('Failed to deploy edge')
                raise nsxv_exc.NsxPluginException(err_msg=error)

            self.callbacks.complete_edge_creation(
                context, edge_id, name, router_id, dist, True,
                availability_zone=availability_zone,
                deploy_metadata=deploy_metadata)

        except exceptions.VcnsApiException:
            self.callbacks.complete_edge_creation(
                context, edge_id, name, router_id, dist, False,
                availability_zone=availability_zone)
            with excutils.save_and_reraise_exception():
                LOG.exception("NSXv: deploy edge failed.")
        return edge_id

    def update_edge(self, context, router_id, edge_id, name, internal_network,
                    dist=False, loadbalancer_enable=True,
                    appliance_size=nsxv_constants.LARGE,
                    set_errors=False, availability_zone=None):
        """Update edge name."""
        edge = self._assemble_edge(
            name, datacenter_moid=availability_zone.datacenter_moid,
            deployment_container_id=self.deployment_container_id,
            appliance_size=appliance_size, remote_access=False, dist=dist,
            edge_ha=availability_zone.edge_ha)
        edge['id'] = edge_id
        appliances = self._assemble_edge_appliances(availability_zone)
        if appliances:
            edge['appliances']['appliances'] = appliances

        if not dist:
            vnic_external = self._assemble_edge_vnic(
                constants.EXTERNAL_VNIC_NAME, constants.EXTERNAL_VNIC_INDEX,
                availability_zone.external_network, type="uplink")
            edge['vnics']['vnics'].append(vnic_external)
        else:
            edge['mgmtInterface'] = {
                'connectedToId': availability_zone.external_network,
                'name': "mgmtInterface"}

        if internal_network:
            internal_vnic = self._assemble_edge_vnic(
                constants.INTERNAL_VNIC_NAME, constants.INTERNAL_VNIC_INDEX,
                internal_network,
                edge_utils.get_vdr_transit_network_plr_address(),
                edge_utils.get_vdr_transit_network_netmask(),
                type="internal")
            edge['vnics']['vnics'].append(internal_vnic)
        if not dist and loadbalancer_enable:
            self._enable_loadbalancer(edge)

        try:
            self.vcns.update_edge(edge_id, edge)
            self.callbacks.complete_edge_update(
                context, edge_id, router_id, True, set_errors)
        except exceptions.VcnsApiException as e:
            LOG.error("Failed to update edge: %s",
                      e.response)
            self.callbacks.complete_edge_update(
                context, edge_id, router_id, False, set_errors)
            return False

        return True

    def rename_edge(self, edge_id, name):
        """rename edge."""
        try:
            # First get the current edge structure
            # [0] is the status, [1] is the body
            edge = self.vcns.get_edge(edge_id)[1]
            if edge['name'] == name:
                LOG.debug('Edge %s is already named %s', edge_id, name)
                return
            # remove some data that will make the update fail
            edge_utils.remove_irrelevant_keys_from_edge_request(edge)
            # set the new name in the request
            edge['name'] = name
            # update the edge
            self.vcns.update_edge(edge_id, edge)
        except exceptions.VcnsApiException as e:
            LOG.error("Failed to rename edge: %s",
                      e.response)

    def resize_edge(self, edge_id, size):
        """update the size of a router edge."""
        try:
            # First get the current edge structure
            # [0] is the status, [1] is the body
            edge = self.vcns.get_edge(edge_id)[1]
            if edge.get('appliances'):
                if edge['appliances']['applianceSize'] == size:
                    LOG.debug('Edge %s is already with size %s',
                              edge_id, size)
                    return
            ver = self.vcns.get_version()
            if version.LooseVersion(ver) < version.LooseVersion('6.2.3'):
                # remove some data that will make the update fail
                edge_utils.remove_irrelevant_keys_from_edge_request(edge)

            # set the new size in the request
            edge['appliances']['applianceSize'] = size
            # update the edge
            self.vcns.update_edge(edge_id, edge)
        except exceptions.VcnsApiException as e:
            LOG.error("Failed to resize edge: %s", e.response)

    def delete_edge(self, context, router_id, edge_id, dist=False):
        LOG.debug("Deleting edge %s", edge_id)
        if context is None:
            context = q_context.get_admin_context()
        try:
            LOG.debug("Deleting router binding %s", router_id)
            nsxv_db.delete_nsxv_router_binding(context.session, router_id)
            if not dist:
                LOG.debug("Deleting vnic bindings for edge %s", edge_id)
                nsxv_db.clean_edge_vnic_binding(context.session, edge_id)
        except sa_exc.NoResultFound:
            LOG.warning("Router Binding for %s not found", router_id)

        if edge_id:
            try:
                self.vcns.delete_edge(edge_id)
                return True
            except exceptions.ResourceNotFound:
                return True
            except exceptions.VcnsApiException as e:
                LOG.exception("VCNS: Failed to delete %(edge_id)s:\n"
                              "%(response)s",
                              {'edge_id': edge_id, 'response': e.response})
                return False
            except Exception:
                LOG.exception("VCNS: Failed to delete %s", edge_id)
                return False

    def _assemble_nat_rule(self, action, original_address,
                           translated_address,
                           vnic_index=None,
                           enabled=True,
                           protocol='any',
                           original_port='any',
                           translated_port='any'):
        nat_rule = {}
        nat_rule['action'] = action
        if vnic_index is not None:
            nat_rule['vnic'] = vnic_index
        nat_rule['originalAddress'] = original_address
        nat_rule['translatedAddress'] = translated_address
        nat_rule['enabled'] = enabled
        nat_rule['protocol'] = protocol
        nat_rule['originalPort'] = original_port
        nat_rule['translatedPort'] = translated_port

        return nat_rule

    def get_nat_config(self, edge_id):
        try:
            return self.vcns.get_nat_config(edge_id)[1]
        except exceptions.VcnsApiException as e:
            LOG.exception("VCNS: Failed to get nat config:\n%s",
                          e.response)
            raise e

    def update_nat_rules(self, edge_id, snats, dnats, indices=None):
        LOG.debug("VCNS: update nat rule\n"
                  "SNAT:%(snat)s\n"
                  "DNAT:%(dnat)s\n"
                  "INDICES: %(index)s\n", {
                        'snat': snats, 'dnat': dnats, 'index': indices})
        nat_rules = []

        for dnat in dnats:
            vnic_index = None
            if 'vnic_index' in dnat:
                vnic_index = dnat['vnic_index']
            if vnic_index or not indices:
                # we are adding a predefined index or
                # adding to all interfaces
                nat_rules.append(self._assemble_nat_rule(
                    'dnat', dnat['dst'], dnat['translated'],
                    vnic_index=vnic_index
                ))
                nat_rules.append(self._assemble_nat_rule(
                    'snat', dnat['translated'], dnat['dst'],
                    vnic_index=vnic_index
                ))
            else:
                for index in indices:
                    nat_rules.append(self._assemble_nat_rule(
                        'dnat', dnat['dst'], dnat['translated'],
                        vnic_index=index
                    ))
                    nat_rules.append(self._assemble_nat_rule(
                        'snat', dnat['translated'], dnat['dst'],
                        vnic_index=index
                    ))

        for snat in snats:
            vnic_index = None
            if 'vnic_index' in snat:
                vnic_index = snat['vnic_index']
            if vnic_index or not indices:
                # we are adding a predefined index
                # or adding to all interfaces
                nat_rules.append(self._assemble_nat_rule(
                    'snat', snat['src'], snat['translated'],
                    vnic_index=vnic_index
                ))
            else:
                for index in indices:
                    nat_rules.append(self._assemble_nat_rule(
                        'snat', snat['src'], snat['translated'],
                        vnic_index=index
                    ))

        nat = {
            'featureType': 'nat',
            'rules': {
                'natRulesDtos': nat_rules
            }
        }

        try:
            self.vcns.update_nat_config(edge_id, nat)
            return True
        except exceptions.VcnsApiException as e:
            LOG.exception("VCNS: Failed to create snat rule:\n%s",
                          e.response)
            return False

    def update_routes(self, edge_id, gateway, routes):
        if gateway:
            gateway = gateway.split('/')[0]

        static_routes = []
        for route in routes:
            if route.get('vnic_index') is None:
                static_routes.append({
                    "description": "",
                    "vnic": constants.INTERNAL_VNIC_INDEX,
                    "network": route['cidr'],
                    "nextHop": route['nexthop']
                })
            else:
                static_routes.append({
                    "description": "",
                    "vnic": route['vnic_index'],
                    "network": route['cidr'],
                    "nextHop": route['nexthop']
                })
        request = {
            "staticRoutes": {
                "staticRoutes": static_routes
            }
        }
        if gateway:
            request["defaultRoute"] = {
                "description": "default-gateway",
                "gatewayAddress": gateway
            }
        try:
            self.vcns.update_routes(edge_id, request)
            return True
        except exceptions.VcnsApiException as e:
            LOG.exception("VCNS: Failed to update routes:\n%s",
                          e.response)
            return False

    def create_lswitch(self, name, tz_config, tags=None,
                       port_isolation=False, replication_mode="service"):
        lsconfig = {
            'display_name': utils.check_and_truncate(name),
            "tags": tags or [],
            "type": "LogicalSwitchConfig",
            "_schema": "/ws.v1/schema/LogicalSwitchConfig",
            "transport_zones": tz_config
        }
        if port_isolation is bool:
            lsconfig["port_isolation_enabled"] = port_isolation
        if replication_mode:
            lsconfig["replication_mode"] = replication_mode

        response = self.vcns.create_lswitch(lsconfig)[1]
        return response

    def delete_lswitch(self, lswitch_id):
        self.vcns.delete_lswitch(lswitch_id)

    def get_loadbalancer_config(self, edge_id):
        try:
            header, response = self.vcns.get_loadbalancer_config(
                edge_id)
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception("Failed to get service config")
        return response

    def enable_service_loadbalancer(self, edge_id):
        config = self.get_loadbalancer_config(
            edge_id)
        if not config['enabled']:
            config['enabled'] = True
        try:
            self.vcns.enable_service_loadbalancer(edge_id, config)
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception("Failed to enable loadbalancer "
                              "service config")

    def _delete_port_group(self, task):
        try:
            self.vcns.delete_port_group(
                task.userdata['dvs_id'],
                task.userdata['port_group_id'])
        except Exception as e:
            LOG.error('Unable to delete %(pg)s exception %(ex)s',
                      {'pg': task.userdata['port_group_id'],
                       'ex': e})
            return task_constants.TaskStatus.ERROR
        return task_constants.TaskStatus.COMPLETED

    def _retry_task(self, task):
        delay = 0.5
        max_retries = max(cfg.CONF.nsxv.retries, 1)
        args = task.userdata.get('args', [])
        kwargs = task.userdata.get('kwargs', {})
        retry_number = task.userdata['retry_number']
        retry_command = task.userdata['retry_command']
        try:
            retry_command(*args, **kwargs)
        except Exception as exc:
            LOG.debug("Task %(name)s retry %(retry)s failed %(exc)s",
                      {'name': task.name,
                       'exc': exc,
                       'retry': retry_number})
            retry_number += 1
            if retry_number > max_retries:
                with excutils.save_and_reraise_exception():
                    LOG.exception("Failed to %s", task.name)
            else:
                task.userdata['retry_number'] = retry_number
                # Sleep twice as long as the previous retry
                tts = (2 ** (retry_number - 1)) * delay
                time.sleep(min(tts, 60))
                return task_constants.TaskStatus.PENDING
        LOG.info("Task %(name)s completed.", {'name': task.name})
        return task_constants.TaskStatus.COMPLETED

    def delete_port_group(self, dvs_id, port_group_id):
        task_name = 'delete-port-group-%s-%s' % (port_group_id, dvs_id)
        userdata = {'retry_number': 1,
                    'retry_command': self.vcns.delete_port_group,
                    'args': [dvs_id, port_group_id]}
        task = tasks.Task(task_name, port_group_id,
                          self._retry_task,
                          status_callback=self._retry_task,
                          userdata=userdata)
        self.task_manager.add(task)

    def delete_virtual_wire(self, vw_id):
        task_name = 'delete-virtualwire-%s' % vw_id
        userdata = {'retry_number': 1,
                    'retry_command': self.vcns.delete_virtual_wire,
                    'args': [vw_id]}
        task = tasks.Task(task_name, vw_id,
                          self._retry_task,
                          status_callback=self._retry_task,
                          userdata=userdata)
        self.task_manager.add(task)

    def create_bridge(self, device_name, bridge):
        try:
            self.vcns.create_bridge(device_name, bridge)
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception("Failed to create bridge in the %s",
                              device_name)

    def delete_bridge(self, device_name):
        try:
            self.vcns.delete_bridge(device_name)
        except exceptions.VcnsApiException:
            LOG.exception("Failed to delete bridge in the %s",
                          device_name)

    def update_edge_ha(self, edge_id):
        ha_request = {
            'featureType': "highavailability_4.0",
            'enabled': True}
        self.vcns.enable_ha(edge_id, ha_request)

    def update_edge_syslog(self, edge_id, syslog_config, router_id):
        if 'server_ip' not in syslog_config:
            LOG.warning("Server IP missing in syslog config for %s",
                        router_id)
            return

        protocol = syslog_config.get('protocol', 'tcp')
        if protocol not in ['tcp', 'udp']:
            LOG.warning("Invalid protocol in syslog config for %s",
                        router_id)
            return

        loglevel = syslog_config.get('log_level')
        if loglevel and loglevel not in edge_utils.SUPPORTED_EDGE_LOG_LEVELS:
            LOG.warning("Invalid loglevel in syslog config for %s",
                        router_id)
            return

        server_ip = syslog_config['server_ip']
        request = {'featureType': 'syslog',
                   'protocol': protocol,
                   'serverAddresses': {'ipAddress': [server_ip],
                                       'type': 'IpAddressesDto'}}

        # edge allows up to 2 syslog servers
        if 'server2_ip' in syslog_config:
            request['serverAddresses']['ipAddress'].append(
                    syslog_config['server2_ip'])

        self.vcns.update_edge_syslog(edge_id, request)

        # update log level for routing in separate API call
        if loglevel:
            edge_utils.update_edge_loglevel(self.vcns, edge_id,
                                            'routing', loglevel)
