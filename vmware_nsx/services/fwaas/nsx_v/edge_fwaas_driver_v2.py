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

from neutron_lib import context as n_context
from oslo_log import log as logging

from neutron_lib.exceptions import firewall_v2 as exceptions
from neutron_lib.plugins import directory

from vmware_nsx.common import locking
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.services.fwaas.common import fwaas_driver_base

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas V2 NSX-V driver'


class EdgeFwaasVDriverV2(fwaas_driver_base.EdgeFwaasDriverBaseV2):
    """NSX-V driver for Firewall As A Service - V2."""

    def __init__(self):
        super(EdgeFwaasVDriverV2, self).__init__(FWAAS_DRIVER_NAME)
        self._core_plugin = None

    @property
    def core_plugin(self):
        """Get the NSX-V core plugin"""
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
            if self._core_plugin.is_tvd_plugin():
                self._core_plugin = self._core_plugin.get_plugin_by_type(
                    projectpluginmap.NsxPlugins.NSX_V)
                if not self._core_plugin:
                    # The NSX-V plugin was not initialized
                    return
            # make sure plugin init was completed
            if not self._core_plugin.init_is_complete:
                self._core_plugin.init_complete(None, None, {})
        return self._core_plugin

    def should_apply_firewall_to_router(self, router_data,
                                        raise_exception=True):
        """Return True if the firewall rules allowed to be added the router

        Return False in those cases:
        - router without an external gateway (rule may be added later when
                                              there is a gateway)

        Raise an exception if the router is unsupported
        (and raise_exception is True):
        - shared router (not supported)
        - md proxy router (not supported)

        """
        if (not router_data.get('distributed') and
            router_data.get('router_type') == 'shared'):
            LOG.error("Cannot apply firewall to shared router %s",
                      router_data['id'])
            if raise_exception:
                raise exceptions.FirewallInternalDriverError(
                    driver=self.driver_name)
            return False

        if router_data.get('name', '').startswith('metadata_proxy_router'):
            LOG.error("Cannot apply firewall to the metadata proxy router %s",
                      router_data['id'])
            if raise_exception:
                raise exceptions.FirewallInternalDriverError(
                    driver=self.driver_name)
            return False

        if not router_data.get('external_gateway_info'):
            LOG.info("Cannot apply firewall to router %s with no gateway",
                     router_data['id'])
            return False

        return True

    def _update_backend_routers(self, apply_list, fwg_id):
        """Update all the affected routers on the backend"""
        LOG.info("Updating routers firewall for firewall group %s", fwg_id)
        context = n_context.get_admin_context()
        routers = set()
        routers_mapping = {}
        # the apply_list is a list of tuples: routerInfo, port-id
        for router_info, port_id in apply_list:
            # Skip dummy entries that were added only to avoid errors
            if isinstance(router_info, str):
                continue
            # Skip unsupported routers
            if not self.should_apply_firewall_to_router(router_info.router):
                continue

            lookup_id = None
            router_id = router_info.router_id
            if router_info.router.get('distributed'):
                # Distributed router (need to update the plr edge)
                lookup_id = self.core_plugin.edge_manager.get_plr_by_tlr_id(
                    context, router_id)
            else:
                # Exclusive router
                lookup_id = router_id
            if lookup_id:
                # look for the edge id in the DB
                edge_id = edge_utils.get_router_edge_id(context, lookup_id)
                if edge_id:
                    routers_mapping[router_id] = {'edge_id': edge_id,
                                                  'lookup_id': lookup_id}
                    routers.add(router_id)

        # update each router once using the core plugin
        for router_id in routers:
            router_db = self.core_plugin._get_router(context, router_id)
            edge_id = routers_mapping[router_id]['edge_id']
            LOG.info("Updating FWaaS rules for router %s on edge %s",
                router_id, edge_id)
            router_lookup_id = routers_mapping[router_id]['lookup_id']
            try:
                with locking.LockManager.get_lock(str(edge_id)):
                    self.core_plugin.update_router_firewall(
                        context, router_lookup_id, router_db)
            except Exception as e:
                # catch known library exceptions and raise Fwaas generic
                # exception
                LOG.error("Failed to update firewall rules on edge "
                          "%(edge_id)s for router %(rtr)s: %(e)s",
                          {'e': e, 'rtr': router_id, 'edge_id': edge_id})
                raise exceptions.FirewallInternalDriverError(
                    driver=self.driver_name)
