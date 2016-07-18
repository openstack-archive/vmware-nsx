# Copyright 2015 VMware, Inc.  All rights reserved.
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

from neutron import context as neutron_context
from neutron.db import common_db_mixin as common_db

from vmware_nsx import plugin
from vmware_nsx.plugins.nsx_v.vshield import vcns


def get_nsxv_client():
    return vcns.Vcns(
        address=cfg.CONF.nsxv.manager_uri,
        user=cfg.CONF.nsxv.user,
        password=cfg.CONF.nsxv.password,
        ca_file=cfg.CONF.nsxv.ca_file,
        insecure=cfg.CONF.nsxv.insecure)


class NeutronDbClient(common_db.CommonDbMixin):
    def __init__(self):
        super(NeutronDbClient, self)
        self.context = neutron_context.get_admin_context()


class NsxVPluginWrapper(plugin.NsxVPlugin):
    def _start_rpc_listeners(self):
        pass

    def _validate_config(self):
        pass

    def _extend_get_network_dict_provider(self, context, net):
        self._extend_network_dict_provider(context, net)
        # skip getting the Qos policy ID because get_object calls
        # plugin init again on admin-util environment


def get_nsxv_backend_edges():
    """Get a list of all the backend edges and some of their attributes
    """
    nsxv = get_nsxv_client()
    edges = nsxv.get_edges()[1]
    edges = edges['edgePage'].get('data', [])
    backend_edges = []
    for edge in edges:
        # get all the relevant backend information for this edge
        edge_data = {
            'id': edge.get('id'),
            'name': edge.get('name'),
            'size': edge['appliancesSummary'].get(
                'applianceSize') if edge.get('appliancesSummary') else None,
            'type': edge.get('edgeType')
        }
        backend_edges.append(edge_data)
    return backend_edges
