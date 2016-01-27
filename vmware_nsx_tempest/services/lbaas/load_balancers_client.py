# Copyright 2014 Rackspace US Inc.  All rights reserved.
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

from tempest.lib.services.network import base


class LoadBalancersClient(base.BaseNetworkClient):
    resource = 'loadbalancer'
    resource_plural = 'loadbalancers'
    path = 'lbaas/loadbalancers'
    resource_base_path = '/%s' % path
    resource_object_path = '/%s/%%s' % path
    resource_object_status_path = '/%s/%%s/statuses' % path
    resource_object_stats_path = '/%s/%%s/stats' % path

    def create_load_balancer(self, **kwargs):
        uri = self.resource_base_path
        post_data = {self.resource: kwargs}
        return self.create_resource(uri, post_data)

    def update_load_balancer(self, load_balancer_id, **kwargs):
        uri = self.resource_object_path % load_balancer_id
        post_data = {self.resource: kwargs}
        return self.update_resource(uri, post_data)

    def show_load_balancer(self, load_balancer_id, **fields):
        uri = self.resource_object_path % load_balancer_id
        return self.show_resource(uri, **fields)

    def show_load_balancer_status_tree(self, load_balancer_id, **fields):
        uri = self.resource_object_status_path % load_balancer_id
        return self.show_resource(uri, **fields)

    def show_load_balancer_stats(self, load_balancer_id, **fields):
        uri = self.resource_object_stats_path % load_balancer_id
        return self.show_resource(uri, **fields)

    def delete_load_balancer(self, load_balancer_id):
        uri = self.resource_object_path % load_balancer_id
        return self.delete_resource(uri)

    def list_load_balancers(self, **filters):
        uri = self.resource_base_path
        return self.list_resources(uri, **filters)


def get_client(client_mgr):
    """create a lbaas load-balancers client from manager or networks_client

    For itempest user:
        from itempest import load_our_solar_system as osn
        from vmware_nsx_tempest.services.lbaas import load_balancers_client
        lbaas_client = load_balancers_client.get_client(osn.adm.manager)
    For tempest user:
        lbaas_client = load_balancers_client.get_client(osn.adm)
    """
    manager = getattr(client_mgr, 'manager', client_mgr)
    net_client = getattr(manager, 'networks_client')
    try:
        _params = manager.default_params_with_timeout_values.copy()
    except Exception:
        _params = {}
    client = LoadBalancersClient(net_client.auth_provider,
                                 net_client.service,
                                 net_client.region,
                                 net_client.endpoint_type,
                                 **_params)
    return client
