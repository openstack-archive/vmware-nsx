# Copyright 2015 OpenStack Foundation
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

from neutron.db import db_base_plugin_v2
from oslo_log import log


LOG = log.getLogger(__name__)


class NSXv3Plugin(db_base_plugin_v2.NeutronDbPluginV2):

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self):
        super(NSXv3Plugin, self).__init__()
        LOG.info(_("Starting NSXv3Plugin"))
        # XXXX Read in config

    def create_network(self, context, network):
        # TODO(arosen) - call to backend
        network = super(NSXv3Plugin, self).create_network(context,
                                                          network)
        return network

    def delete_network(self, context, id):
        # TODO(arosen) - call to backend
        return super(NSXv3Plugin, self).delete_network(context, id)

    def update_network(self, context, id, network):
        # TODO(arosen) - call to backend
        return super(NSXv3Plugin, self).update_network(context, id,
                                                       network)

    def create_port(self, context, port):
        # TODO(arosen) - call to backend
        port = super(NSXv3Plugin, self).create_port(context,
                                                    port)
        return port

    def delete_port(self, context, id, l3_port_check=True):
        # TODO(arosen) - call to backend
        return super(NSXv3Plugin, self).delete_port(context, id)

    def update_port(self, context, id, port):
        # TODO(arosen) - call to backend
        return super(NSXv3Plugin, self).update_port(context, id,
                                                    port)

    def create_router(self, context, router):
        # TODO(arosen) - call to backend
        router = super(NSXv3Plugin, self).create_router(context,
                                                        router)
        return router

    def delete_router(self, context, router_id):
        # TODO(arosen) - call to backend
        return super(NSXv3Plugin, self).delete_router(context,
                                                      router_id)

    def update_router(self, context, router_id, router):
        # TODO(arosen) - call to backend
        return super(NSXv3Plugin, self).update_router(context, id,
                                                      router)
