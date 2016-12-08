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

import six
import time

from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest import test

from vmware_nsx_tempest.tests.nsxv.scenario import (
    manager_topo_deployment as dmgr)
from vmware_nsx_tempest.tests.nsxv.scenario import (
    network_addon_methods as HELO)

CONF = config.CONF
LOG = dmgr.manager.log.getLogger(__name__)


class TestAdminPolicyBasicOps(dmgr.TopoDeployScenarioManager):
    """Test VMs with security-group-policy traffic is managed by NSX

    Test topology:
        TOPO:

            logical-router nasa-router] -- [ public GW]
                |
                +--- [Tenant jpl interface/subnet x.y.34.0/24]
                |    |                    |
                |    + [vm-nasa-jpl-3]    + [vm-nasa-jpl-4]
                |
                +--- [Tenant ames interface/subnet x.y.12.0/24]
                |    |                     |
                |    + [vm-nasa-ames-1]    + [vm-nasa-ames-2]

        Test topology setup and traffic forwarding validation:

            1. 2 tenants (ames, jpl) each tenant has 2 VMs, and boot with
               security-group with policy==policy_AA which must allow
               ping and ssh services as automation relys on this to make
               sure test environment network connectivity is an OK.
               NOTE:
                   primary user: ames -- NASA Ames Research Center
                   alt user: jpl  -- NASA Jet Propulsion Laboratory
            2. Admin create router (nasa-router) with both tenants' network
               so tenant:ames and tenant:jpl can talk to each other
               according to policy_AA.
            3. under policy_AA, all servers can be ping and ssh from anywhere
            4. Admin change tenant:jpl's policy to policy_BB
            5. Tenant jpl's VMs are not pingable, ssh still OK
               Tenant ames's MVs, both ping and ssh are OK
            6. Admin change tenant:ames's policy to policy_BB
               VMs from ames and jpl are not pingalbe; ssh is OK

    ATTENTION:
        config nsxv.default_policy_id is policy_AA
        config nsxv.alt_policy_is is policy_BB

        The testbed needs to have policy_AA and policy_BB created
        and matched with the default_policy_id & alt_plicy_id under
        session nsxv of tempest.conf or devstack local.conf.

    Test Configuration setup:
        please refer to vmware_nsx_tempest/doc/README-AdminPolicy.rst
    """

    @classmethod
    def skip_checks(cls):
        super(TestAdminPolicyBasicOps, cls).skip_checks()
        if not test.is_extension_enabled('security-group-policy', 'network'):
            msg = "Extension security-group-policy is not enabled."
            raise cls.skipException(msg)
        if not (CONF.nsxv.alt_policy_id.startswith('policy-') and
                CONF.nsxv.default_policy_id.startswith('policy-')):
            msg = "default and alt policy ids not set correctly."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(TestAdminPolicyBasicOps, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.cmgr_ames = cls.get_client_manager('primary')
        cls.cmgr_jpl = cls.get_client_manager('alt')

    @classmethod
    def resource_setup(cls):
        super(TestAdminPolicyBasicOps, cls).resource_setup()
        cls.policy_AA = CONF.nsxv.default_policy_id
        cls.policy_BB = CONF.nsxv.alt_policy_id
        cls.conn_timeout = CONF.scenario.waitfor_connectivity

    @classmethod
    def resource_cleanup(cls):
        super(TestAdminPolicyBasicOps, cls).resource_cleanup()

    def setUp(self):
        super(TestAdminPolicyBasicOps, self).setUp()
        self.server_id_list = []
        self.exc_step = 0
        self.exc_msg = ("Admin-Policy-Traffic-Forwarding"
                        " Validation Steps:\n")

    def tearDown(self):
        # delete all servers and make sure they are terminated
        servers_client = self.cmgr_adm.servers_client
        server_id_list = getattr(self, 'server_id_list', [])
        for server_id in server_id_list:
            servers_client.delete_server(server_id)
        for server_id in server_id_list:
            waiters.wait_for_server_termination(servers_client, server_id)
        # delete all floating-ips
        if hasattr(self, 'fip_nasa_ames_1'):
            self.delete_floatingip(self.cmgr_ames, self.fip_nasa_ames_1)
        if hasattr(self, 'fip_nasa_jpl_3'):
            self.delete_floatingip(self.cmgr_jpl, self.fip_nasa_jpl_3)
        super(TestAdminPolicyBasicOps, self).tearDown()

    def log_exc_msg(self, msg):
        self.exc_step += 1
        self.exc_msg += ("#%02d %s %s\n" %
                         (self.exc_step, time.strftime("%H:%M:%S"), msg))

    def delete_floatingip(self, cmgr, net_floatingip):
        test_utils.call_and_ignore_notfound_exc(
            cmgr.floating_ips_client.delete_floatingip,
            net_floatingip.get('id'))

    def delete_security_group(self, sg_client, sg_id):
        sg_client.delete_security_group(sg_id)

    def update_security_group_policy(self, sg_id, policy_id):
        sg_client = self.cmgr_adm.security_groups_client
        sg = sg_client.update_security_group(sg_id, policy=policy_id)
        sg = sg.get('security_group', sg)
        self.assertEqual(policy_id, sg.get('policy'))
        return sg

    def create_security_group_policy(self, policy_id, tenant_id,
                                     name_prefix=None):
        sg_name = data_utils.rand_name(name_prefix or 'admin-policy')
        sg_client = self.cmgr_adm.security_groups_client
        sg_dict = dict(name=sg_name, policy=policy_id)
        if tenant_id:
            sg_dict['tenant_id'] = tenant_id
        sg = sg_client.create_security_group(**sg_dict)
        sg = sg.get('security_group', sg)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_security_group,
                        sg_client, sg.get('id'))
        return sg

    def create_networks(self, cmgr,
                        name_prefix=None, cidr_offset=0):
        net_name = data_utils.rand_name(name_prefix or 'admin-policy')
        network = self.create_network(client=cmgr.networks_client,
                                      name=net_name)
        network = network.get('network', network)
        subnet_kwargs = dict(name=net_name, cidr_offset=cidr_offset)
        subnet = self.create_subnet(network,
                                    client=cmgr.subnets_client,
                                    **subnet_kwargs)
        subnet = subnet.get('subnet', subnet)
        return (network, subnet)

    def create_router_by_type(self, router_type, client=None, **kwargs):
        routers_client = client or self.cmgr_adm.routers_client
        create_kwargs = dict(namestart='nasa-router', external_gateway_info={
            "network_id": CONF.network.public_network_id})
        if router_type in ('shared', 'exclusive'):
            create_kwargs['router_type'] = router_type
        elif router_type in ('distributed'):
            create_kwargs['distributed'] = True
        create_kwargs.update(**kwargs)
        router = HELO.router_create(self, client=routers_client,
                                    **create_kwargs)
        return router

    def create_router_and_add_interfaces(self, router_type, subnet_list):
        routers_client = self.cmgr_adm.routers_client
        router = self.create_router_by_type(router_type)
        for subnet in subnet_list:
            HELO.router_interface_add(self, router['id'], subnet['id'],
                                      client=routers_client)
        # check interfaces/subnets are added to router
        router_port_list = self.get_router_port_list(self.cmgr_adm,
                                                     router['id'])
        for subnet in subnet_list:
            added = self.rports_have_subnet_id(router_port_list, subnet['id'])
            self.assertTrue(
                added,
                "subnet_id:%s is not added to router" % subnet['id'])
        return router

    def rports_have_subnet_id(self, router_port_list, subnet_id):
        for rport in router_port_list:
            for fips in rport.get('fixed_ips', []):
                if subnet_id == fips['subnet_id']:
                    return True
        return False

    def get_router_port_list(self, cmgr, router_id):
        device_owner = u'network:router_interface'
        ports_client = cmgr.ports_client
        port_list = ports_client.list_ports(device_id=router_id,
                                            device_owner=device_owner)
        port_list = port_list.get('ports', port_list)
        return port_list

    def create_servers_on_networks(self, cmgr, sv_name, networks_info):
        network = networks_info.get('network')
        security_group = networks_info.get('security_group')
        security_groups = [{'name': security_group['id']}]
        svr = self.create_server_on_network(
            network, security_groups, name=sv_name,
            wait_on_boot=False,
            servers_client=cmgr.servers_client)
        self.server_id_list.append(svr.get('id'))
        return svr

    def get_server_info(self, cmgr, server_id):
        """Get server's ip addresses"""
        svr = cmgr.servers_client.show_server(server_id)
        svr = svr.get('server', svr)
        sinfo = dict(id=svr['id'], name=svr['name'],
                     security_gropus=svr['security_groups'],
                     fixed_ip_address=None, floating_ip_address=None)
        addresses = svr.get('addresses')
        for n_addresses in six.itervalues(addresses):
            for n_addr in n_addresses:
                if n_addr['OS-EXT-IPS:type'] == 'fixed':
                    if not sinfo['fixed_ip_address']:
                        sinfo['fixed_ip_address'] = n_addr['addr']
                elif n_addr['OS-EXT-IPS:type'] == 'floating':
                    if not sinfo['floating_ip_address']:
                        sinfo['floating_ip_address'] = n_addr['addr']
        return sinfo

    def create_floatingip_for_server(self, cmgr, server):
        username, password = self.get_image_userpass()
        try:
            floatingip = super(
                TestAdminPolicyBasicOps,
                self).create_floatingip_for_server(
                server, client_mgr=cmgr, and_check_assigned=True)
        except Exception as ex:
            floatingip = None
            msg = (self.exc_msg +
                   ("\n**FAIL to associate floatingip to server[%s]\n%s"
                    % (server['name'], str(ex))))
            self.assertTrue(floatingip, msg)
        fix_ip = floatingip['fixed_ip_address']
        float_ip = floatingip['floating_ip_address']
        self.log_exc_msg(("  floatingip[%s] created for server[%s,%s]"
                          " and is pingable." %
                          (float_ip, server.get('name'), fix_ip)))
        return floatingip

    def wait_for_servers_become_active(self):
        servers_client = self.cmgr_adm.servers_client
        for server_id in self.server_id_list:
            waiters.wait_for_server_status(
                servers_client, server_id, 'ACTIVE')

    def find_servers_ips(self):
        self.server_ips = {}
        self.jpl_ips = {}
        self.server_ips['1'] = self.get_server_info(
            self.cmgr_ames, self.vm_nasa_ames_1['id'])
        self.server_ips['2'] = self.get_server_info(
            self.cmgr_ames, self.vm_nasa_ames_2['id'])
        self.server_ips['3'] = self.get_server_info(
            self.cmgr_jpl, self.vm_nasa_jpl_3['id'])
        self.server_ips['4'] = self.get_server_info(
            self.cmgr_jpl, self.vm_nasa_jpl_4['id'])

    def create_nasa_ames_network_and_servers(self, security_group=None):
        sg = security_group or self.sg_ames
        net, subnet = self.create_networks(self.cmgr_ames, 'nasa-ames', 1)
        self.netinfo_ames = dict(network=net, subnet=subnet,
                                 security_group=sg)
        self.vm_nasa_ames_1 = self.create_servers_on_networks(
            self.cmgr_ames, 'vm-nasa-ames-1', self.netinfo_ames)
        self.vm_nasa_ames_2 = self.create_servers_on_networks(
            self.cmgr_ames, 'vm-nasa-ames-2', self.netinfo_ames)

    def create_nasa_jpl_network_and_servers(self, security_group=None):
        sg = security_group or self.sg_jpl
        # jpl and ames attached to the same router, CIDR cannot overlap
        net, subnet = self.create_networks(self.cmgr_jpl, 'nasa-jpl', 3)
        self.netinfo_jpl = dict(network=net, subnet=subnet,
                                security_group=sg)
        self.vm_nasa_jpl_3 = self.create_servers_on_networks(
            self.cmgr_jpl, 'vm-nasa-jpl-3', self.netinfo_jpl)
        self.vm_nasa_jpl_4 = self.create_servers_on_networks(
            self.cmgr_jpl, 'vm-nasa-jpl-4', self.netinfo_jpl)

    def create_nasa_topo(self, router_type=None):
        router_type = router_type or 'shared'
        self.sg_ames = self.create_security_group_policy(
            self.policy_AA,
            self.cmgr_ames.networks_client.tenant_id,
            name_prefix='nasa-ames')
        self.sg_jpl = self.create_security_group_policy(
            self.policy_AA,
            self.cmgr_jpl.networks_client.tenant_id,
            name_prefix='nasa-jpl')
        self.create_nasa_ames_network_and_servers(self.sg_ames)
        self.create_nasa_jpl_network_and_servers(self.sg_jpl)
        subnet_list = [self.netinfo_ames.get('subnet'),
                       self.netinfo_jpl.get('subnet')]
        self.nasa_router = self.create_router_and_add_interfaces(
            router_type, subnet_list)
        self.wait_for_servers_become_active()
        # associate floating-ip to servers and pingable
        self.fip_nasa_ames_1 = self.create_floatingip_for_server(
            self.cmgr_ames, self.vm_nasa_ames_1)
        self.fip_nasa_jpl_3 = self.create_floatingip_for_server(
            self.cmgr_jpl, self.vm_nasa_jpl_3)
        self.find_servers_ips()

    def host_ssh_reachable(self, host_id, host_ip):
        username, password = self.get_image_userpass()
        try:
            ssh_client = dmgr.get_remote_client_by_password(
                host_ip, username, password)
        except Exception as ex:
            ssh_client = None
            msg = (self.exc_msg +
                   ("\n**FAIL to ssh to host[%s=%s]\n%s" %
                    (host_id, str(ex))))
            self.assertTrue(ssh_client, msg)
        self.log_exc_msg(
            ("  SSH host[%s] floatingip[%s] OK" % (host_id, host_ip)))
        return ssh_client

    def host_can_reach_ips(self, host_id, host_ssh, ip_type, ip_list):
        for dest_ip in ip_list:
            reachable = dmgr.is_reachable(host_ssh, dest_ip,
                                          time_out=self.conn_timeout)
            msg = (self.exc_msg +
                   ("\n  *FAILURE* VM[%s] cannot PING %s[%s]" %
                    (host_id, ip_type, dest_ip)))
            if not reachable:
                reachable = dmgr.is_reachable(host_ssh, dest_ip,
                                              time_out=self.conn_timeout)
            dmgr.STEPINTO_DEBUG_IF_TRUE(not reachable)
            self.assertTrue(reachable, msg)
            self.log_exc_msg(
                ("  VM[%s] can PING %s[%s]" % (host_id, ip_type, dest_ip)))

    def host_cannot_reach_ips(self, host_id, host_ssh, ip_type, ip_list):
        for dest_ip in ip_list:
            not_reachable = dmgr.isnot_reachable(host_ssh, dest_ip,
                                                 time_out=self.conn_timeout,
                                                 ping_timeout=5.0)
            msg = (self.exc_msg +
                   ("\n  *FAILURE* VM[%s] shouldn't able to PING %s[%s]" %
                    (host_id, ip_type, dest_ip)))
            if not not_reachable:
                not_reachable = dmgr.isnot_reachable(
                    host_ssh, dest_ip, time_out=self.conn_timeout,
                    ping_timeout=5.0)
            dmgr.STEPINTO_DEBUG_IF_TRUE(not not_reachable)
            self.assertTrue(not_reachable, msg)
            self.log_exc_msg(
                ("  VM[%s] is not able to PING %s[%s]" %
                 (host_id, ip_type, dest_ip)))

    def ican_reach_ip(self, ip_addr, ping_timeout=5):
        ip_type = 'floating-ip'
        for x in range(int(self.conn_timeout / ping_timeout)):
            reachable = self.ping_ip_address(ip_addr,
                                             ping_timeout=ping_timeout)
            if reachable:
                break
            time.sleep(2.0)
        msg = (self.exc_msg +
               ("\n  *FAILURE* Tempest cannot PING %s[%s]" %
                (ip_type, ip_addr)))
        if not reachable:
            reachable = self.ping_ip_address(ip_addr,
                                             ping_timeout=ping_timeout)
        dmgr.STEPINTO_DEBUG_IF_TRUE(not reachable)
        self.assertTrue(reachable, msg)
        self.log_exc_msg("  Tempest can PING %s[%s]" % (ip_type, ip_addr))

    def icannot_reach_ip(self, ip_addr, ping_timeout=5):
        ip_type = 'floating-ip'
        for x in range(int(self.conn_timeout / ping_timeout)):
            reachable = self.ping_ip_address(ip_addr,
                                             ping_timeout=ping_timeout)
            if not reachable:
                break
            time.sleep(ping_timeout)
        msg = (self.exc_msg +
               ("\n  *FAILURE* Tempest should not PING %s[%s]" %
                (ip_type, ip_addr)))
        if reachable:
            reachable = self.ping_ip_address(ip_addr,
                                             ping_timeout=ping_timeout)
        dmgr.STEPINTO_DEBUG_IF_TRUE(reachable)
        self.assertFalse(reachable, msg)
        self.log_exc_msg(("  Tempest isnot able to PING %s[%s]" %
                          (ip_type, ip_addr)))

    def run_admin_policy_op_scenario(self, router_type):
        self.log_exc_msg(("Setup admin-policy test with router-type[%s]" %
                          router_type))
        self.create_nasa_topo(router_type)
        self.jpl_private_ips = [y['fixed_ip_address']
            for x, y in six.iteritems(self.server_ips)
            if x > '2']
        self.ames_private_ips = [y['fixed_ip_address']
            for x, y in six.iteritems(self.server_ips)
            if x < '3']

        self.run_policy_AA_on_ames_AA_on_jpl()
        self.run_policy_AA_on_ames_BB_on_jpl()
        self.run_policy_BB_on_ames_BB_on_jpl()

        dmgr.LOG.debug(self.exc_msg)

    def run_policy_AA_on_ames_AA_on_jpl(self):
        self.log_exc_msg(("### tenant:jpl=policy_AA[%s]"
                          ", tenant:ames=policy_AA[%s]" %
                          (self.policy_AA, self.policy_AA)))
        # at the beginning, can ssh to VM with floating-ip
        self.log_exc_msg(
            "Tempest can ping & ssh vm-nasa-ames-1's floatingip")
        self.ican_reach_ip(self.fip_nasa_ames_1['floating_ip_address'])
        ames_1_ssh = self.host_ssh_reachable(
            "nasa-ames-1",
            self.fip_nasa_ames_1['floating_ip_address'])

        # from vm-nasa-ames-1 can ping all other private-ips
        self.log_exc_msg(("vm-nasa-ames-1[%s] can ping all private-ips"
                          % (self.server_ips['1']['fixed_ip_address'])))
        self.host_can_reach_ips('nasa-ames-1', ames_1_ssh,
                                'ame-private-ip', self.ames_private_ips)
        self.host_can_reach_ips('nasa-ames-1', ames_1_ssh,
                                'jp-private-ip', self.jpl_private_ips)
        # from vm-nasa-jpl_3 can ping all other private-ips
        self.log_exc_msg(
            "Tempest can ping & ssh vm-nasa-jpl-3's floatingip")
        self.ican_reach_ip(self.fip_nasa_jpl_3['floating_ip_address'])
        jpl_3_ssh = self.host_ssh_reachable(
            "nasa-jpl-3",
            self.fip_nasa_jpl_3['floating_ip_address'])
        self.log_exc_msg(("vm-nasa-jpl-3[%s] can ping all private-ips"
                          % (self.server_ips['3']['fixed_ip_address'])))
        self.host_can_reach_ips('nasa-jpl-3', jpl_3_ssh,
                                'jp-private-ip', self.jpl_private_ips)
        self.host_can_reach_ips('nasa-jpl-3', jpl_3_ssh,
                                'ames-private-ip', self.ames_private_ips)
        # within VM can ping both tanants' floating-ips
        self.log_exc_msg(
            "vm-nasa-ames-1 can ping vm-nasa-jpl-1's floatingip")
        self.host_can_reach_ips(
            'nasa-ames-1', ames_1_ssh, 'jpl-floating-ip',
            [self.fip_nasa_jpl_3['floating_ip_address']])
        self.log_exc_msg(
            "vm-nasa-jpl-3 can ping vm-nasa-ames-3's floatingip")
        self.host_can_reach_ips(
            'nasa-jpl-3', jpl_3_ssh, 'nasa-floating-ip',
            [self.fip_nasa_ames_1['floating_ip_address']])

    def run_policy_AA_on_ames_BB_on_jpl(self):
        # from vm-nasa-ames-1 can ping all other private-ips
        self.log_exc_msg(
            ("Update tenant:jpl to use policy_BB[%s] with group-ping"
             % self.policy_BB))
        # admin update jpl to policy_BB_GP
        self.update_security_group_policy(self.sg_jpl['id'], self.policy_BB)
        # cannot ping vm-nasa-jpl-3, can ssh to both tenants' floating-ips
        self.log_exc_msg(("### tenant:jpl=policy_BB[%s]"
                          ", tenant:ames=policy_AA[%s]" %
                          (self.policy_BB, self.policy_AA)))
        self.log_exc_msg(
            "Tempest can ping & ssh vm-nasa-ames-1's floatingip")
        self.ican_reach_ip(self.fip_nasa_ames_1['floating_ip_address'])
        ames_1_ssh = self.host_ssh_reachable(
            "nasa-ames-1",
            self.fip_nasa_ames_1['floating_ip_address'])
        self.log_exc_msg("Tempest can ssh vm-nasa-jpl-3's floatingip"
                         ", but not ping")
        self.icannot_reach_ip(self.fip_nasa_jpl_3['floating_ip_address'])
        jpl_3_ssh = self.host_ssh_reachable(
            "nasa-jpl-3",
            self.fip_nasa_jpl_3['floating_ip_address'])
        # vm-nasa-jpl_3 can ping its private-ips, not other tenants
        self.log_exc_msg(("vm-nasa-jpl-3[%s] can reach all private-ips"
                          % (self.server_ips['3']['fixed_ip_address'])))
        self.host_can_reach_ips('nasa-jpl-3', jpl_3_ssh,
                                'jpl-private-ip', self.jpl_private_ips)
        self.host_can_reach_ips('nasa-jpl-3', jpl_3_ssh,
                                'ames-private-ip', self.ames_private_ips)
        # nasa_ames_1 can not ping private-ips of tenant jpl
        # as policy_BB:ping only allowed from the same security-group
        self.log_exc_msg(("vm-nasa-ames-1[%s] can reach ames's rivate-ips"
                          ", not jpl's private-ips"
                          % (self.server_ips['1']['fixed_ip_address'])))
        self.host_can_reach_ips('nasa-ames-1', ames_1_ssh,
                                'ames-private-ip', self.ames_private_ips)
        self.host_cannot_reach_ips('nasa-ames-1', ames_1_ssh,
                                   'jpl-private-ip', self.jpl_private_ips)
        self.log_exc_msg(
            "vm-nasa-ames-1 cannot ping vm-nasa-jpl-1's floatingip")
        self.host_cannot_reach_ips(
            'nasa-ames-1', ames_1_ssh, 'jpl-floating-ip',
            [self.fip_nasa_jpl_3['floating_ip_address']])
        self.log_exc_msg(
            "vm-nasa-jpl-3 cannot ping vm-nasa-ames-3's floatingip")
        self.host_cannot_reach_ips(
            'nasa-jpl-3', jpl_3_ssh, 'ames-floating-ip',
            [self.fip_nasa_ames_1['floating_ip_address']])

    def run_policy_BB_on_ames_BB_on_jpl(self):
        ### tenant jpl:policy_BB_GP, tenant ames:policy_BB_GP
        self.log_exc_msg(
            ("Update tenant:ames to use policy_BB[%s] with group-ping"
             % self.policy_BB))
        # admin update ames to policy_BB
        self.update_security_group_policy(self.sg_ames['id'], self.policy_BB)
        # cannot ping all VMs, but can ssh to both tenants' floating-ips
        self.log_exc_msg(("### tenant:jpl=policy_BB[%s]"
                          ", tenant:ames=policy_BB[%s]" %
                          (self.policy_BB, self.policy_BB)))
        self.log_exc_msg("Tempest can ssh vvm-nasa-ames-1's floatingip &"
                         " vm-nasa-jpl-3's floatingip, but not ping.")
        self.icannot_reach_ip(self.fip_nasa_ames_1['floating_ip_address'])
        self.icannot_reach_ip(self.fip_nasa_jpl_3['floating_ip_address'])
        ames_1_ssh = self.host_ssh_reachable(
            "nasa-ames-1",
            self.fip_nasa_ames_1['floating_ip_address'])
        jpl_3_ssh = self.host_ssh_reachable(
            "nasa-jpl-3",
            self.fip_nasa_jpl_3['floating_ip_address'])
        self.log_exc_msg(("vm-nasa-jpl-3[%s] can reach jpl private-ips"
                          ", not ames"
                          % (self.server_ips['3']['fixed_ip_address'])))
        self.host_can_reach_ips('nasa-jpl-3', jpl_3_ssh,
                                'private-ip', self.jpl_private_ips)
        self.host_cannot_reach_ips('nasa-jpl-3', jpl_3_ssh,
                                   'private-ip', self.ames_private_ips)
        self.log_exc_msg(("vm-nasa-ames-1[%s] can reach ames private-ips"
                          ", not jpl"
                          % (self.server_ips['1']['fixed_ip_address'])))
        self.host_can_reach_ips('nasa-ames-1', ames_1_ssh,
                                'private-ip', self.ames_private_ips)
        self.host_cannot_reach_ips('nasa-ames-1', ames_1_ssh,
                                   'private-ip', self.jpl_private_ips)
        self.log_exc_msg(
            "vm-nasa-ames-1 cannot ping vm-nasa-jpl-1's floatingip")
        self.host_cannot_reach_ips(
            'nasa-ames-1', ames_1_ssh, 'floating-ip',
            [self.fip_nasa_jpl_3['floating_ip_address']])
        self.log_exc_msg(
            "vm-nasa-jpl-3 cannot ping vm-nasa-ames-3's floatingip")
        self.host_cannot_reach_ips(
            'nasa-jpl-3', jpl_3_ssh, 'floating-ip',
            [self.fip_nasa_ames_1['floating_ip_address']])


class TestAdminPolicySharedRouter(TestAdminPolicyBasicOps):
    @test.idempotent_id('78f45717-5f95-4ef5-b2a4-a1b4700ef688')
    def test_admin_policy_ops_with_shared_router(self):
        self.run_admin_policy_op_scenario('shared')


class TestAdminPolicyExclusiveRouter(TestAdminPolicyBasicOps):
    @test.idempotent_id('68345852-da2e-4f46-816b-0afc59470a45')
    def test_admin_policy_ops_with_exclusive_router(self):
        self.run_admin_policy_op_scenario('exclusive')


class TestAdminPolicyDistributedRouter(TestAdminPolicyBasicOps):
    @test.idempotent_id('76adbfbb-a2e5-40fa-8930-84e7ece87bd5')
    def test_admin_policy_ops_with_distributed_router(self):
        self.run_admin_policy_op_scenario('distributed')
