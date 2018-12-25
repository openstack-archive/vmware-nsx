# Copyright 2014 VMware, Inc
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

import abc

import six

from neutron.db import l3_db
from neutron.db import models_v2
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsxv_exc
from vmware_nsx.common import nsxv_constants
from vmware_nsx.plugins.nsx_v import availability_zones as nsx_az
from vmware_nsx.plugins.nsx_v.vshield import edge_utils


@six.add_metaclass(abc.ABCMeta)
class RouterAbstractDriver(object):
    """Abstract router driver that expose API for nsxv plugin."""

    @abc.abstractmethod
    def get_type(self):
        pass

    @abc.abstractmethod
    def create_router(self, context, lrouter, appliance_size=None,
                      allow_metadata=True):
        pass

    @abc.abstractmethod
    def update_router(self, context, router_id, router):
        pass

    @abc.abstractmethod
    def delete_router(self, context, router_id):
        pass

    @abc.abstractmethod
    def update_routes(self, context, router_id, nexthop):
        pass

    @abc.abstractmethod
    def _update_router_gw_info(self, context, router_id, info):
        pass

    @abc.abstractmethod
    def add_router_interface(self, context, router_id, interface_info):
        pass

    @abc.abstractmethod
    def remove_router_interface(self, context, router_id, interface_info):
        pass

    @abc.abstractmethod
    def _update_edge_router(self, context, router_id):
        pass


class RouterBaseDriver(RouterAbstractDriver):

    def __init__(self, plugin):
        self.plugin = plugin
        self.nsx_v = plugin.nsx_v
        self.edge_manager = plugin.edge_manager
        self.vcns = self.nsx_v.vcns
        self._availability_zones = nsx_az.NsxVAvailabilityZones()

    def _notify_after_router_edge_association(self, context, router):
        registry.publish(nsxv_constants.SERVICE_EDGE, events.AFTER_CREATE,
                         self, payload=events.DBEventPayload(
                             context, states=(router,)))

    def _notify_before_router_edge_association(self, context, router,
                                               edge_id=None):
        registry.publish(nsxv_constants.SERVICE_EDGE, events.BEFORE_DELETE,
                         self, payload=events.DBEventPayload(
                             context, states=(router,), resource_id=edge_id))

    def _get_external_network_id_by_router(self, context, router_id):
        """Get router's external network id if it has."""
        router = self.plugin.get_router(context, router_id)
        ports_qry = context.session.query(models_v2.Port)
        gw_ports = ports_qry.filter_by(
            device_id=router_id,
            device_owner=l3_db.DEVICE_OWNER_ROUTER_GW,
            id=router['gw_port_id']).all()

        if gw_ports:
            return gw_ports[0]['network_id']

    def _get_edge_id_or_raise(self, context, router_id):
        edge_id = edge_utils.get_router_edge_id(context, router_id)
        if not edge_id:
            error = (_("Failed to get router %(rid)s edge Id") %
                     {'rid': router_id})
            raise nsxv_exc.NsxPluginException(err_msg=error)
        return edge_id

    def update_nat_rules(self, context, router, router_id):
        self.plugin._update_nat_rules(context, router, router_id)

    def update_router_interface_ip(self, context, router_id, port_id,
                                   int_net_id, old_ip, new_ip, subnet_mask):
        """Update the fixed ip of a router interface.
        This implementation will not work for distributed routers,
        and there is a different implementation in that driver class
        """
        # get the edge-id of this router
        edge_id = edge_utils.get_router_edge_id(context, router_id)
        if not edge_id:
            # This may be a shared router that was not attached to an edge yet
            return

        # find out if the port is uplink or internal
        router = self.plugin._get_router(context, router_id)
        is_uplink = (port_id == router.gw_port_id)

        # update the edge interface configuration
        self.edge_manager.update_interface_addr(
            context, edge_id, old_ip, new_ip,
            subnet_mask, is_uplink=is_uplink)

        # Also update the nat rules
        if is_uplink:
            self.update_nat_rules(context, router, router_id)

    def get_router_az(self, lrouter):
        return self.plugin.get_router_az(lrouter)

    def get_router_az_and_flavor_by_id(self, context, router_id):
        lrouter = self.plugin.get_router(context, router_id)
        return (self.get_router_az(lrouter), lrouter.get('flavor_id'))

    def get_router_az_by_id(self, context, router_id):
        lrouter = self.plugin.get_router(context, router_id)
        return self.get_router_az(lrouter)

    def _update_nexthop(self, context, router_id, newnexthop):
        """Update the router edge on gateway subnet default gateway change."""
        self.plugin._update_routes(context, router_id, newnexthop)
