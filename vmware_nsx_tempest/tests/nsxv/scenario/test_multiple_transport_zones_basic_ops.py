# Copyright 2016 OpenStack Foundation
# Copyright 2016 VMware Inc
# All Rights Reserved.
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
import re
import six

from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest import test

from vmware_nsx_tempest.services import nsxv_client
from vmware_nsx_tempest.tests.nsxv.scenario import (
    manager_topo_deployment as dmgr)
from vmware_nsx_tempest.tests.nsxv.scenario import (
    network_addon_methods as HELO)

CONF = config.CONF


class TestMultipleTransportZonesBasicOps(dmgr.TopoDeployScenarioManager):

    """Base class provides MTZ networks basic operations:

    1: create MTZ networks and a tenant network.
    2: create router and attached networks at step 1.
    3: Boot one VM at each network.
    4: select one VM, assign floatingip and from it ping other VMs'
       fixed-ip to assure that VMs attached to different vdn_scope_ids,
       and tennat network are asscessible.
    """

    @classmethod
    def skip_checks(cls):
        super(TestMultipleTransportZonesBasicOps, cls).skip_checks()
        if not (CONF.network.project_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        for ext in ['router', 'provider']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TestMultipleTransportZonesBasicOps, cls).resource_setup()
        manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                               CONF.nsxv.manager_uri).group(0)
        cls.vsm = nsxv_client.VSMClient(
            manager_ip, CONF.nsxv.user, CONF.nsxv.password)
        cls.nsxv_scope_ids = cls.get_all_scope_id_list(with_default_scope=True)
        if len(cls.nsxv_scope_ids) < 2:
            msg = "Only one transport zone deployed. Need at least 2."
            raise cls.skipException(msg)
        cls.provider_network_type = getattr(CONF.nsxv,
                                            "provider_network_type",
                                            'vxlan')
        cls.MAX_MTZ = getattr(CONF.nsxv, 'max_mtz', 0) or 3

    @classmethod
    def resource_cleanup(cls):
        super(TestMultipleTransportZonesBasicOps, cls).resource_cleanup()

    @classmethod
    def get_all_scope_id_list(cls, with_default_scope=False):
        """return all scope IDs w/wo the default scope defined in NSX."""
        scopes = cls.vsm.get_all_vdn_scopes()
        scope_id_list = [x['objectId'] for x in scopes]
        if with_default_scope:
            return scope_id_list
        try:
            scope_id_list.remove(CONF.nsxv.vdn_scope_id)
        except Exception:
            pass
        return scope_id_list

    def setup(self):
        super(TestMultipleTransportZonesBasicOps, self).setUp()
        self.tp_svrs = {}

    def tearDown(self):
        self.delete_all_servers()
        super(TestMultipleTransportZonesBasicOps, self).tearDown()

    def create_project_network_subnet(self, name_prefix='mtz-project',
                                      client_mgr=None):
        client_mgr = client_mgr or self.manager
        network_name = data_utils.rand_name(name_prefix)
        network, subnet = HELO.create_network_subnet(
            self, client_mgr=client_mgr, name=network_name)
        return (network['id'], network, subnet)

    def create_mtz_network_subnet(self, scope_id, tenant_project_id,
                                  cidr=None, cidr_offset=0):
        """MTZ networks can only be created by ADMIN

        All tenant network resources will be created by ADMIN.
        """
        networks_client = self.admin_manager.networks_client
        subnets_client = self.admin_manager.subnets_client
        network_name = data_utils.rand_name('mtz-net')
        create_body = {'name': network_name,
                       'provider:network_type': self.provider_network_type,
                       'provider:physical_network': scope_id}
        network = HELO.create_network(self, client=networks_client,
                                      tenant_id=tenant_project_id,
                                      **create_body)
        subnet = HELO.create_subnet(self, network, client=subnets_client,
                                    name=network_name,
                                    tenant_id=tenant_project_id,
                                    cidr=cidr, cidr_offset=cidr_offset)
        lswitch_list = self.vsm.get_all_logical_switches(scope_id)
        lswitch_list = [x for x in lswitch_list if x['name'] == network['id']]
        msg = ("network=%s is not configured by specified vdn_scope_id=%s"
               % (network['id'], scope_id))
        self.assertTrue(len(lswitch_list) == 1, msg=msg)
        return (network['id'], network, subnet)

    def create_router_by_type(self, router_type, client=None,
                              name=None, **kwargs):
        routers_client = client or self.manager.routers_client
        create_kwargs = dict(namestart='mtz-', external_gateway_info={
            "network_id": CONF.network.public_network_id})
        if router_type in ('shared', 'exclusive'):
            create_kwargs['router_type'] = router_type
        elif router_type in ('distributed'):
            create_kwargs['distributed'] = True
        create_kwargs.update(**kwargs)
        router = HELO.router_create(self, client=routers_client,
                                    **create_kwargs)
        return router

    def create_router_and_add_interfaces(self, router_type, nets,
                                         client_mgr=None):
        client_mgr = client_mgr or self.admin_manager
        routers_client = client_mgr.routers_client
        router = self.create_router_by_type(router_type,
                                            client=routers_client)
        if router_type == 'exclusive':
            router_nsxv_name = '%s-%s' % (router['name'], router['id'])
            exc_edge = self.vsm.get_edge(router_nsxv_name)
            self.assertIsNotNone(exc_edge)
            self.assertEqual(exc_edge['edgeType'], 'gatewayServices')
        for net_id, (s_id, network, subnet, sg) in six.iteritems(nets):
            # import pdb; pdb.set_trace()
            HELO.router_interface_add(self, router['id'], subnet['id'],
                                      client=routers_client)
        return router

    def clear_router_gateway_and_interfaces(self, router, nets, client=None):
        routers_client = client or self.manager.routers_client
        HELO.router_gateway_clear(self, router['id'],
                                  client=routers_client)
        for net_id, (s_id, network, subnet, sg) in six.iteritems(nets):
            test_utils.call_and_ignore_notfound_exc(
                HELO.router_interface_delete,
                self, router['id'], subnet['id'], client=routers_client)

    def _test_router_with_network_and_mtz_networks(self, router_type):
        """router attached with multiple TZs and one tenant network."""
        client_mgr = self.manager
        scope_id_list = self.get_all_scope_id_list(with_default_scope=True)
        nets = {}
        net_id, network, subnet = self.create_project_network_subnet(
            'mtz-tenant', client_mgr=client_mgr)
        tenant_project_id = client_mgr.networks_client.tenant_id
        # create security_group with loginable rules
        security_group = self._create_security_group(
            security_groups_client=client_mgr.security_groups_client,
            security_group_rules_client=client_mgr.security_group_rules_client,
            namestart='mtz-tenant')
        nets[net_id] = [None, network, subnet, security_group]
        for cidr_step in range(0, self.MAX_MTZ):
            s_id = scope_id_list[cidr_step % len(scope_id_list)]
            net_id, network, subnet = self.create_mtz_network_subnet(
                s_id, tenant_project_id, cidr_offset=(cidr_step + 2))
            nets[net_id] = [s_id, network, subnet, security_group]
        router = self.create_router_and_add_interfaces(router_type, nets,
                                                       client_mgr=client_mgr)
        return router, nets

    def run_servers_connectivity_test(self, servers):
        # select one from the servers
        net_id_list = servers.keys()
        net_id = net_id_list[0]
        other_net_id_list = net_id_list[1:]
        username, password = self.get_image_userpass()
        nsv = self.tp_svrs[net_id]
        serv = nsv['server']
        floatingip = self.create_floatingip_for_server(
            serv, client_mgr=self.manager)
        msg = ("Associate floatingip[%s] to server[%s]"
               % (floatingip, serv['name']))
        self._check_floatingip_connectivity(
            floatingip, serv, should_connect=True, msg=msg)
        serv_fip = floatingip['floating_ip_address']
        dmgr.rm_sshkey(serv_fip)
        ssh_client = dmgr.get_remote_client_by_password(
            serv_fip, username, password)
        not_reachable_list = []
        for nid in other_net_id_list:
            o_svr = servers[nid]['server']
            o_net = servers[nid]['network']
            o_ipaddr = self.get_server_fixed_ip(o_svr, o_net)
            reachable = dmgr.is_reachable(ssh_client, o_ipaddr)
            if not reachable:
                not_reachable_list.append(o_ipaddr)
        self.assertTrue(
            len(not_reachable_list) == 0,
            ("Following Servers are not reachable: %s" % not_reachable_list))

    def get_server_fixed_ip(self, server, network):
        addr_list = server['addresses'][network['name']]
        for addr in addr_list:
            if addr['OS-EXT-IPS:type'] == 'fixed':
                return addr['addr']
        return None

    def wait_for_servers_become_active(self, servers, client=None):
        servers_client = client or self.admin_manager.servers_client
        net_id_list = servers.keys()
        for net_id in net_id_list:
            nsv = self.tp_svrs[net_id]
            serv = nsv['server']
            waiters.wait_for_server_status(
                servers_client, serv['id'], 'ACTIVE')
            # update server context. A server might not have ip address
            # if not in running/active state
            act_server = servers_client.show_server(serv['id'])
            self.tp_svrs[net_id]['server'] = act_server.get('server',
                                                            act_server)

    def delete_all_servers(self, client=None):
        servers_client = client or self.admin_manager.servers_client
        for net_id in six.iterkeys(self.tp_svrs):
            server = self.tp_svrs[net_id]['server']
            test_utils.call_and_ignore_notfound_exc(
                servers_client.delete, server['id'])
            dmgr.waitfor_servers_terminated(servers_client)

    def run_mtz_basic_ops(self, router_type):
        self.tp_svrs = {}
        router, nets = self._test_router_with_network_and_mtz_networks(
            router_type)
        servers_client = self.manager.servers_client
        for net_id in six.iterkeys(nets):
            s_id, network, subnet, security_group = nets[net_id]
            """
            servers_client = (self.manager.servers_client if s_id is None
                              else self.admin_manager.servers_client)
            """
            security_groups = [{'name': security_group['id']}]
            svr = self.create_server_on_network(
                network, security_groups,
                name=network['name'],
                servers_client=servers_client,
                wait_on_boot=False)
            self.tp_svrs[net_id] = dict(server=svr, s_id=s_id,
                                        network=network, subnet=subnet,
                                        security_group=security_group,
                                        servers_client=servers_client)
        self.wait_for_servers_become_active(self.tp_svrs)
        self.run_servers_connectivity_test(self.tp_svrs)


class TestMTZBasicOpsOverSharedRouter(TestMultipleTransportZonesBasicOps):
    @test.idempotent_id('190790fe-4cc4-4bb3-ae3e-4fa2031ca4e2')
    def test_mtz_basic_ops_over_shared_router(self):
        self.run_mtz_basic_ops(router_type='shared')


class TestMTZBasicOpsOverExclusiveRouter(TestMultipleTransportZonesBasicOps):
    @test.idempotent_id('caf2be55-ea49-4783-87bf-103fcc5783db')
    def test_mtz_basic_ops_over_exclusive_router(self):
        self.run_mtz_basic_ops(router_type='exclusive')
