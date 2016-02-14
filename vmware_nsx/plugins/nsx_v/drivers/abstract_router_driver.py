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