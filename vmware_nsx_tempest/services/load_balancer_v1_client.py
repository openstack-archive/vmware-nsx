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

import time

from tempest.lib.common.utils import misc as misc_utils
from tempest.lib import exceptions as lib_exc

from tempest import exceptions
from vmware_nsx_tempest._i18n import _
from vmware_nsx_tempest.services import network_client_base as base

POOL_RID = 'pools'
VIP_RID = 'vips'
HEALTHMONITOR_RID = 'health_monitors'
MEMBER_RID = 'members'


class LoadBalancerV1Client(base.BaseNetworkClient):

    def _list_lb(self, lb_resource, **filters):
        resource_name_s, resource_name_p = _g_resource_namelist(lb_resource)
        req_uri = '/lb/%s' % (resource_name_p)
        return self.list_resources(req_uri, **filters)

    def _show_lb(self, lb_resource, resource_id, **fields):
        resource_name_s, resource_name_p = _g_resource_namelist(lb_resource)
        req_uri = '/lb/%s/%s' % (resource_name_p, resource_id)
        return self.show_resource(req_uri, **fields)

    def _delete_lb(self, lb_resource, resource_id):
        resource_name_s, resource_name_p = _g_resource_namelist(lb_resource)
        req_uri = '/lb/%s/%s' % (resource_name_p, resource_id)
        return self.delete_resource(req_uri)

    def _create_lb(self, lb_resource, **kwargs):
        resource_name_s, resource_name_p = _g_resource_namelist(lb_resource)
        req_uri = '/lb/%s' % (resource_name_p)
        post_body = {resource_name_s: kwargs}
        return self.create_resource(req_uri, post_body)

    def _update_lb(self, lb_resource, resource_id, **kwargs):
        resource_name_s, resource_name_p = _g_resource_namelist(lb_resource)
        req_uri = '/lb/%s/%s' % (resource_name_p, resource_id)
        post_body = {resource_name_s: kwargs}
        return self.update_resource(req_uri, post_body)

    def show_agent_hosting_pool(self, pool_id):
        """Get loadbalancer agent hosting a pool."""
        req_uri = "/lb/pools/%s/loadbalancer-agent" % (pool_id)
        return self.show_resource(req_uri)

    def associate_health_monitor_with_pool(self, health_monitor_id, pool_id):
        """Create a mapping between a health monitor and a pool."""
        post_body = {'health_monitor': {'id': health_monitor_id}}
        req_uri = '/lb/pools/%s/%s' % (pool_id, HEALTHMONITOR_RID)
        return self.create_resource(req_uri, post_body)

    def create_health_monitor(self, **kwargs):
        """Create a health monitor."""
        create_kwargs = dict(
            type=kwargs.pop('type', 'TCP'),
            max_retries=kwargs.pop('nax_retries', 3),
            timeout=kwargs.pop('timeout', 1),
            delay=kwargs.pop('delay', 4),
        )
        create_kwargs.update(**kwargs)
        return self._create_lb(HEALTHMONITOR_RID, **create_kwargs)

    def delete_health_monitor(self, health_monitor_id):
        """Delete a given health monitor."""
        return self._delete_lb(HEALTHMONITOR_RID, health_monitor_id)

    def disassociate_health_monitor_with_pool(self, health_monitor_id,
                                              pool_id):
        """Remove a mapping from a health monitor to a pool."""
        req_uri = ('/lb/pools/%s/%s/%s'
                   % (pool_id, HEALTHMONITOR_RID, health_monitor_id))
        return self.delete_resource(req_uri)

    def list_health_monitors(self, **filters):
        """List health monitors that belong to a given tenant."""
        return self._list_lb(HEALTHMONITOR_RID, **filters)

    def show_health_monitor(self, health_monitor_id):
        """Show information of a given health monitor."""
        return self._show_lb(HEALTHMONITOR_RID, health_monitor_id)

    def update_health_monitor(self, health_monitor_id,
                              show_then_update=False, **kwargs):
        """Update a given health monitor."""
        body = (self.show_health_monitor(health_monitor_id)['health_monitor']
                if show_then_update else {})
        body.update(**kwargs)
        return self._update_lb(HEALTHMONITOR_RID,
                               health_monitor_id, **body)

    # tempest create_member(self,protocol_port, pool, ip_version)
    # we use pool_id
    def create_member(self, protocol_port, pool_id,
                      ip_version=4, **kwargs):
        """Create a member."""
        create_kwargs = dict(
            protocol_port=protocol_port,
            pool_id=pool_id,
            address=("fd00:abcd" if ip_version == 6 else "10.0.9.46"),
        )
        create_kwargs.update(**kwargs)
        return self._create_lb(MEMBER_RID, **create_kwargs)

    def delete_member(self, member_id):
        """Delete a given member."""
        return self._delete_lb(MEMBER_RID, member_id)

    def list_members(self, **filters):
        """List members that belong to a given tenant."""
        return self._list_lb(MEMBER_RID, **filters)

    def show_member(self, member_id):
        """Show information of a given member."""
        return self._show_lb(MEMBER_RID, member_id)

    def update_member(self, member_id,
                      show_then_update=False, **kwargs):
        """Update a given member."""
        body = (self.show_member(member_id)['member']
                if show_then_update else {})
        body.update(**kwargs)
        return self._update_lb(MEMBER_RID, member_id, **body)

    def create_pool(self, name, lb_method, protocol, subnet_id,
                    **kwargs):
        """Create a pool."""
        lb_method = lb_method or 'ROUND_ROBIN'
        protocol = protocol or 'HTTP'
        create_kwargs = dict(
            name=name, lb_method=lb_method,
            protocol=protocol, subnet_id=subnet_id,
        )
        create_kwargs.update(kwargs)
        return self._create_lb(POOL_RID, **create_kwargs)

    def delete_pool(self, pool_id):
        """Delete a given pool."""
        return self._delete_lb(POOL_RID, pool_id)

    def list_pools(self, **filters):
        """List pools that belong to a given tenant."""
        return self._list_lb(POOL_RID, **filters)

    def list_lb_pool_stats(self, pool_id, **filters):
        """Retrieve stats for a given pool."""
        req_uri = '/lb/pools/%s/stats' % (pool_id)
        return self.list_resources(req_uri, **filters)

    def list_pool_on_agents(self, **filters):
        """List the pools on a loadbalancer agent."""
        pass

    def show_pool(self, pool_id):
        """Show information of a given pool."""
        return self._show_lb(POOL_RID, pool_id)

    def update_pool(self, pool_id, show_then_update=False, **kwargs):
        """Update a given pool."""
        body = (self.show_pool(pool_id)['pool']
                if show_then_update else {})
        body.update(**kwargs)
        return self._update_lb(POOL_RID, pool_id, **body)

    def create_vip(self, pool_id, **kwargs):
        """Create a vip."""
        create_kwargs = dict(
            pool_id=pool_id,
            protocol=kwargs.pop('protocol', 'HTTP'),
            protocol_port=kwargs.pop('protocol_port', 80),
            name=kwargs.pop('name', None),
            address=kwargs.pop('address', None),
        )
        for k in create_kwargs.keys():
            if create_kwargs[k] is None:
                create_kwargs.pop(k)
        create_kwargs.update(**kwargs)
        # subnet_id needed to create vip
        return self._create_lb(VIP_RID, **create_kwargs)

    def delete_vip(self, vip_id):
        """Delete a given vip."""
        return self._delete_lb(VIP_RID, vip_id)

    def list_vips(self, **filters):
        """List vips that belong to a given tenant."""
        return self._list_lb(VIP_RID, **filters)

    def show_vip(self, vip_id):
        """Show information of a given vip."""
        return self._show_lb(VIP_RID, vip_id)

    def update_vip(self, vip_id, show_then_update=False, **kwargs):
        """Update a given vip."""
        body = (self.show_vip(vip_id)['vip']
                if show_then_update else {})
        body.update(**kwargs)
        return self._update_lb(VIP_RID, vip_id, **body)

    # Following 3 methods are specifically to load-balancer V1 client.
    # They are being implemented by the pareant tempest.lib.common.rest_client
    # with different calling signatures, only id, no resoure_type. Because,
    # starting in Liberty release, each resource should have its own client.
    # Since V1 is deprecated, we are not going to change it, and
    # copy following 2 methods for V1 LB client only.
    def wait_for_resource_deletion(self, resource_type, id, client=None):
        """Waits for a resource to be deleted."""
        start_time = int(time.time())
        while True:
            if self.is_resource_deleted(resource_type, id, client=client):
                return
            if int(time.time()) - start_time >= self.build_timeout:
                raise exceptions.TimeoutException
            time.sleep(self.build_interval)

    def is_resource_deleted(self, resource_type, id, client=None):
        if client is None:
            client = self
        method = 'show_' + resource_type
        try:
            getattr(client, method)(id)
        except AttributeError:
            raise Exception(_("Unknown resource type %s ") % resource_type)
        except lib_exc.NotFound:
            return True
        return False

    def wait_for_resource_status(self, fetch, status, interval=None,
                                 timeout=None):
        """This has different calling signature then rest_client.

        @summary: Waits for a network resource to reach a status
        @param fetch: the callable to be used to query the resource status
        @type fecth: callable that takes no parameters and returns the resource
        @param status: the status that the resource has to reach
        @type status: String
        @param interval: the number of seconds to wait between each status
          query
        @type interval: Integer
        @param timeout: the maximum number of seconds to wait for the resource
          to reach the desired status
        @type timeout: Integer
        """
        if not interval:
            interval = self.build_interval
        if not timeout:
            timeout = self.build_timeout
        start_time = time.time()

        while time.time() - start_time <= timeout:
            resource = fetch()
            if resource['status'] == status:
                return
            time.sleep(interval)

        # At this point, the wait has timed out
        message = 'Resource %s' % (str(resource))
        message += ' failed to reach status %s' % status
        message += ' (current: %s)' % resource['status']
        message += ' within the required time %s' % timeout
        caller = misc_utils.find_test_caller()
        if caller:
            message = '(%s) %s' % (caller, message)
        raise exceptions.TimeoutException(message)


def _g_resource_namelist(lb_resource):
    if lb_resource[-1] == 's':
        return (lb_resource[:-1], lb_resource)
    return (lb_resource, lb_resource + "s")


def destroy_tenant_lb(lbv1_client):
    for o in lbv1_client.list_members():
        lbv1_client.delete_member(o['id'])
    for o in lbv1_client.list_health_monitors():
        lbv1_client.delete_health_monitor(o['id'])
    for o in lbv1_client.list_vips():
        lbv1_client.delete_vip(o['id'])
    for o in lbv1_client.list_pools():
        lbv1_client.delete_pool(o['id'])


def get_client(client_mgr):
    """create a v1 load balancer client

    For itempest user:
        from itempest import load_our_solar_system as osn
        from vmware_nsx_tempest.services import load_balancer_v1_client
        lbv1 = load_balancer_v1_client.get_client(osn.adm.manager)
    For tempest user:
        lbv1 = load_balancer_v1_client.get_client(cls.os_adm)
    """
    manager = getattr(client_mgr, 'manager', client_mgr)
    net_client = getattr(manager, 'networks_client')
    try:
        _params = manager.default_params_with_timeout_values.copy()
    except Exception:
        _params = {}
    client = LoadBalancerV1Client(net_client.auth_provider,
                                  net_client.service,
                                  net_client.region,
                                  net_client.endpoint_type,
                                  **_params)
    return client
