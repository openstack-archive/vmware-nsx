# Copyright 2015 OpenStack Foundation
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

import collections
import os
import re
import subprocess
import time
import traceback

from tempest.common.utils.linux import remote_client
from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.scenario import manager
from tempest import test

from vmware_nsx_tempest.tests.nsxv.scenario import (
    network_addon_methods as HELO)

CONF = config.CONF
LOG = manager.log.getLogger(__name__)

Floating_IP_tuple = collections.namedtuple(
    'Floating_IP_tuple', ['floating_ip', 'server'])

Z_VM2_DEST = "VM[%(h_ipaddr)s] %(msg)s [%(helper)s %(d_ipaddr)s]"

# Before checking for floatingIP and server connectivity, we need to wait
# x seconds for the control-plane to push configuration to data-plane
# prior to process add/update/delete requests.
WAITTIME_AFTER_DISASSOC_FLOATINGIP = CONF.scenario.waitfor_disassoc
WAITTIME_AFTER_ASSOC_FLOATINGIP = CONF.scenario.waitfor_assoc
WAITTIME_FOR_CONNECTIVITY = CONF.scenario.waitfor_connectivity
DNS_SERVERS_IPV4 = CONF.network.dns_servers
OUTSIDE_WORLD_SERVERS = CONF.scenario.outside_world_servers
# iptype
IPTYPE_FLOATING = 'floating-ip'
IPTYPE_FIXED = 'fixed-ip'
IPTYPE_OUTSIDE_SERVER = 'outside-server'


class TopoDeployScenarioManager(manager.NetworkScenarioTest):
    """Purposes for TopoDeployScenarionManager:

        1. Each deployment scenarion create its network resources, so
           call set_network_resource at setup_credentials() to overwrite it.
        2. setUp() is for test framework. Test case topology is part of
           test and is configured during test() cycle.
        3. net_resources.py overwrite resourses.py so the method to add
           interfaces to routers are inline with CLI, and support router
           owned by admin, but subnets are primary/alt clients.
           -- mechanism removed with patch 320495
           -- we are relaying on the test framework to delete resources
              in the reverse order of creating.
        4. Ping is used for Data-plane testing. OUTSIDE_WORLD_SERVERS ping
           test make sense when tenant's DNS is pirvate to provider.
        5. Teardown is high cost, each test should perform its un-config to
           complete the whole tenant life-cycle.
        WARNING: you need to increase your quota to run in parallel as
        you might run out of quota when things went wrong.
    """

    # defined at test.py; used to create client managers
    credentials = ['admin', 'primary', 'alt']
    # router attributes used to create the tenant's router
    tenant_router_attrs = {}

    @classmethod
    def skip_checks(cls):
        super(TopoDeployScenarioManager, cls).skip_checks()
        for ext in ['router', 'security-group']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)

    @classmethod
    def check_preconditions(cls):
        super(TopoDeployScenarioManager, cls).check_preconditions()
        if not (CONF.network.project_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            cls.enabled = False
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        # Each client's network is created when client manager is created,
        # and client manager is created at setup_credentials.
        # topo-deploy scenarion manager asks not to create network resources.
        cls.set_network_resources(False, False, False, False)
        super(TopoDeployScenarioManager, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        super(TopoDeployScenarioManager, cls).resource_setup()
        cls.namestart = 'topo-deploy-tenant'
        cls.public_network_id = CONF.network.public_network_id
        # The creation of the 2nd tenant is defined by class.credentials
        # cls.alt_manager = clients.Manager(credentials=cls.alt_credentials())
        cls.alt_tenant_id = cls.alt_manager.identity_client.tenant_id

    @classmethod
    def resource_cleanup(cls):
        super(TopoDeployScenarioManager, cls).resource_cleanup()

    def setUp(self):
        super(TopoDeployScenarioManager, self).setUp()
        self.servers_on_net = {}

    def tearDown(self):
        super(TopoDeployScenarioManager, self).tearDown()

    # overwrite parent class which does not accept NSX-v extension
    def _create_router(self, client_mgr=None, tenant_id=None,
                       namestart='topo-deploy', **kwargs):
        client_mgr = client_mgr or self.manager
        routers_client = getattr(client_mgr, "routers_client")
        router = HELO.router_create(self, client=routers_client,
                                    tenant_id=tenant_id,
                                    namestart=namestart,
                                    **kwargs)
        return router

    def _router_set_gateway(self, router_id, network_id, client=None):
        routers_client = client or self.routers_client
        return HELO.router_gateway_set(self, router_id, network_id,
                                       client=routers_client)

    def _router_clear_gateway(self, router_id, client=None):
        routers_client = client or self.routers_client
        return HELO.router_gateway_clear(self, router_id,
                                         client=routers_client)

    def _router_update_extra_routes(self, router_id, routes, client=None):
        routers_client = client or self.routers_client
        router = routers_client.update_route(self, router_id,
                                             routes=routes)
        return router['router']

    def _router_delete_extra_routes(self, router_id, client=None):
        routers_client = client or self.routers_client
        return HELO.router_delete_extra_routes(self, router_id,
                                               routers_client)

    def _router_add_interface(self, net_router, net_subnet, client_mgr):
        routers_client = client_mgr.routers_client
        return HELO.router_interface_add(self, net_router['id'],
                                         net_subnet['id'], routers_client)

    def router_interface_add(self, router_id, subnet_id, client=None):
        routers_client = client or self.routers_client
        return HELO.router_interface_add(self, router_id, subnet_id,
                                         routers_client)

    def router_interface_delete(self, router_id, subnet_id, client=None):
        routers_client = client or self.routers_client
        return HELO.router_interface_delete(self, router_id, subnet_id,
                                            routers_client)

    def create_server_on_network(self, networks, security_groups=None,
                                 name=None, image=None, wait_on_boot=True,
                                 flavor=None, servers_client=None,
                                 key_name=None, tenant_id=None):
        name = name or data_utils.rand_name('topo-deploy-vm')
        if security_groups is None:
            security_groups = [{'name': 'default'}]
        if type(networks) in (list, tuple):
            network_ifs = [{'uuid': nw['id']} for nw in networks]
        else:
            network_ifs = [{'uuid': networks['id']}]
        create_kwargs = {
            'networks': network_ifs,
            'security_groups': security_groups,
        }
        if key_name:
            create_kwargs['key_name'] = key_name
        if tenant_id:
            if not (servers_client and servers_client.tenant_id == tenant_id):
                create_kwargs['tenant_id'] = tenant_id
        LOG.debug("TopoDeploy Create server name=%(name)s"
                  ", create_kwargs=%(create_kwargs)s",
                  {'name': name, 'create_kwargs': str(create_kwargs)})
        server = self.create_server(
            name=name, image=image, wait_on_boot=wait_on_boot,
            servers_client=servers_client, flavor=flavor,
            tenant_id=tenant_id, create_kwargs=create_kwargs)
        return server

    # overwrite parent classes; add servers_client
    # BUG https://bugs.launchpad.net/tempest/+bug/1416175
    def create_server(self, name=None, image=None, flavor=None,
                      wait_on_boot=True, wait_on_delete=True,
                      servers_client=None, tenant_id=None,
                      create_kwargs=None):
        """Creates VM instance.

        @param image: image from which to create the instance
        @param wait_on_boot: wait for status ACTIVE before continue
        @param wait_on_delete: force synchronous delete on cleanup
        @param servers_client: the servers_client to create VM
        @param create_kwargs: additional details for instance creation
        @return: server dict
        """
        name = name or data_utils.rand_name('topo-deploy-vm')
        image = image or CONF.compute.image_ref
        flavor = flavor or CONF.compute.flavor_ref
        servers_client = servers_client or self.servers_client
        create_kwargs = create_kwargs or {}
        if type(tenant_id) in (str, unicode):
            if servers_client.tenant_id != tenant_id:
                create_kwargs['tenant_id'] = tenant_id

        xmsg = ("Creating a server name=%(name)s, image=%(image)s"
                ", flavor=%(flavor)s, create_kwargs=%(create_kwargs)s" %
                {'name': name, 'image': image, 'flavor': flavor,
                 'create_kwargs': str(create_kwargs)})
        LOG.debug(xmsg)
        server_resp = servers_client.create_server(
            name=name, imageRef=image, flavorRef=flavor, **create_kwargs)
        server = server_resp['server']
        if wait_on_delete:
            self.addCleanup(
                waiters.wait_for_server_termination,
                servers_client, server['id'])
        self.addCleanup_with_wait(
            waiter_callable=waiters.wait_for_server_termination,
            thing_id=server['id'], thing_id_param='server_id',
            waiter_client=servers_client,
            cleanup_callable=test_utils.call_and_ignore_notfound_exc,
            cleanup_args=[servers_client.delete_server, server['id']])
        if wait_on_boot:
            waiters.wait_for_server_status(
                client=servers_client,
                server_id=server['id'], status='ACTIVE')
        # The instance retrieved on creation is missing network
        # details, necessitating retrieval after it becomes active to
        # ensure correct details.
        server_resp = servers_client.show_server(server['id'])
        server = server_resp['server']
        self.assertEqual(server['name'], name)
        self.servers_on_net[server['id']] = server
        return server

    def create_provider_network(self, client_mgr=None, create_body=None):
        name = create_body.get('name', None) or data_utils.rand_name('P-net')
        create_body['name'] = name
        client_mgr = client_mgr or self.admin_manager
        net_network = HELO.create_network(
            self, client=client_mgr.networks_client, **create_body)
        return net_network

    def create_provider_subnet(self, client_mgr=None, create_body=None):
        client_mgr = client_mgr or self.admin_manager
        subnets_client = client_mgr.subnets_client
        body = subnets_client.create_subnet(**create_body)
        net_subnet = body['subnet']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        subnets_client.delete_subnet,
                        net_subnet['id'])
        return net_subnet

    def setup_project_network(self, external_network_id,
                             client_mgr=None,
                             namestart=None, client=None,
                             tenant_id=None, cidr_offset=0,
                             **kwargs):
        """NOTE:

            Refer to create_networks@scenario/manager.py which might refer
            to public_router_id which we dont' want to use.

            The test class can define class variable tenant_router_attrs
            to create different type of routers, or overwrite with kwargs.
        """
        name = namestart or data_utils.rand_name('topo-deploy-tenant')
        client_mgr = client_mgr or self.manager
        # _create_router() edits distributed and router_type
        # Child classes use class var tenant_router_attrs to define
        # tenant's router type, however, caller can overwrite it with kwargs.
        distributed = kwargs.get('distributed',
                                 self.tenant_router_attrs.get('distributed'))
        router_type = kwargs.get('router_type',
                                 self.tenant_router_attrs.get('router_type'))
        net_router = self._create_router(
            client_mgr=client_mgr, tenant_id=tenant_id,
            namestart=name,
            distributed=distributed, router_type=router_type)
        self._router_set_gateway(net_router['id'], external_network_id,
                                 client=client_mgr.routers_client)
        net_network, net_subnet = self.create_network_subnet(
            client_mgr=client_mgr, name=net_router['name'],
            tenant_id=tenant_id, cidr_offset=cidr_offset)
        self._router_add_interface(net_router, net_subnet, client_mgr)
        return net_network, net_subnet, net_router

    def create_network_subnet(self, client_mgr=None,
                              tenant_id=None, name=None, cidr_offset=0):
        client_mgr = client_mgr or self.manager
        tenant_id = tenant_id or _g_tenant_id(client_mgr.networks_client)
        name = name or data_utils.rand_name('topo-deploy-network')
        net_network = self.create_network(
            client=client_mgr.networks_client,
            tenant_id=tenant_id, name=name)
        net_subnet = self.create_subnet(
            client=client_mgr.subnets_client,
            network=net_network,
            cidr_offset=cidr_offset, name=net_network['name'])
        return net_network, net_subnet

    # cloned from _create_network@manager.py. Allow name parameter
    def create_network(self, client=None, tenant_id=None, name=None,
                       **kwargs):
        networks_client = client or self.networks_client
        tenant_id = tenant_id or _g_tenant_id(networks_client)
        name = name or data_utils.rand_name('topo-deploy-network')
        return HELO.create_network(self, client=networks_client,
                                   tenant_id=tenant_id, name=name,
                                   **kwargs)

    def create_subnet(self, network, client=None,
                      gateway='', cidr=None, mask_bits=None,
                      ip_version=None, cidr_offset=0,
                      allocation_pools=None, dns_nameservers=None,
                      **kwargs):
        subnets_client = client or self.subnets_client
        kwargs.update(client=subnets_client, gateway=gateway,
                      cidr=cidr, cidr_offset=cidr_offset,
                      mask_bits=mask_bits, ip_version=ip_version,
                      allocation_pools=allocation_pools,
                      dns_nameservers=dns_nameservers)
        return HELO.create_subnet(self, network, **kwargs)

    def create_floatingip_for_server(self, server, external_network_id=None,
                                     port_id=None, client_mgr=None):
        client_mgr = client_mgr or self.manager
        net_floatingip = self.create_floating_ip(
            server,
            external_network_id=external_network_id,
            port_id=port_id,
            client=client_mgr.floating_ips_client)
        server_pingable = self._waitfor_associated_floatingip(net_floatingip)
        self.assertTrue(
            server_pingable,
            msg="Expect server to be reachable after floatingip assigned.")
        return net_floatingip

    def _waitfor_associated_floatingip(self, net_floatingip):
        host_ip = net_floatingip['floating_ip_address']
        return self.waitfor_host_connected(host_ip)

    def waitfor_host_connected(self, host_ip, ping_timeout=5, msg=None):
        PING_START = 'ping-progress-start'
        PING_INSESSION = 'ping-progress-in-session'
        PING_DONE = 'ping-progress-completed'
        PING_TIMEOUT = 'ping-progress-timeout'
        if msg and type(msg) in (str, unicode):
            xmsg = ("waitfor_host_connected ip=%(ip)s! %(msg)s" %
                    {'ip': host_ip, 'msg': msg})
            LOG.debug(xmsg)
        t0 = time.time()
        t1 = time.time() + WAITTIME_FOR_CONNECTIVITY
        LOG.debug("VM-IP[%(ip)s] %(msg)s: %(t1)s.",
                  {'ip': host_ip, 'msg': PING_START, 't1': t0})
        while (time.time() < t1):
            # waitfor backend to create floatingip & linkages
            time.sleep(WAITTIME_AFTER_ASSOC_FLOATINGIP)
            server_pingable = self.ping_ip_address(
                host_ip, ping_timeout=ping_timeout)
            if server_pingable:
                xmsg = ("VM-IP[%(ip)s] %(msg)s: %(t1)s (%(t2)s)." %
                        {'ip': host_ip, 'msg': PING_DONE,
                         't1': time.time(), 't2': (time.time() - t0)})
                LOG.debug(xmsg)
                break
            xmsg = ("VM-IP[%(ip)s] %(msg)s, redo after %(t1)s seconds." %
                    {'ip': host_ip, 'msg': PING_INSESSION,
                     't1': WAITTIME_AFTER_ASSOC_FLOATINGIP})
            LOG.debug(xmsg)
        if not server_pingable:
            xmsg = ("VM-IP[%(ip)s] %(msg)s: %(t1)s (%(t2)s)." %
                    {'ip': host_ip, 'msg': PING_TIMEOUT,
                     't1': time.time(), 't2': (time.time() - t0)})
            LOG.debug(xmsg)
        return server_pingable

    def disassociate_floatingip(self, net_floatingip, client=None,
                                and_delete=False):
        floating_ips_client = client or self.floating_ips_client
        kwargs = dict(port_id=None)
        floating_ip = floating_ips_client.update_floatingip(
            net_floatingip['id'], **kwargs)
        floating_ip = floating_ip.get('floatingip', floating_ip)
        self.assertIsNone(floating_ip['port_id'])
        if and_delete:
            floating_ips_client.delete_floatingip(floating_ip['id'])
        return floating_ip

    def associate_floatingip(self, net_floatingip, to_server, client=None):
        floating_ips_client = client or self.floating_ips_client
        port_id, _ = self._get_server_port_id_and_ip4(to_server)
        kwargs = dict(port_id=port_id)
        floating_ip = floating_ips_client.update_floatingip(
            net_floatingip['id'], **kwargs)['floatingip']
        self.assertEqual(port_id, floating_ip['port_id'])
        return floating_ip

    def check_networks(self, net_network, net_subnet=None, net_router=None):
        return HELO.check_networks(self, net_network, net_subnet, net_router)

    # use this carefully, as it expect existence of floating_ip_tuple
    def check_public_network_connectivity(self, should_connect=True,
                                          msg=None, ping_timeout=30):
        """Verifies connectivty

        To a VM via public network and floating IP, and verifies
        floating IP has resource status is correct.

        @param should_connect: bool. determines if connectivity check is
            negative or positive.
        @param msg: Failure message to add to Error message. Should describe
            the place in the test scenario where the method was called,
            to indicate the context of the failure
        """
        floating_ip, server = self.floating_ip_tuple
        return self._check_floatingip_connectivity(
            floating_ip, server, should_connect, msg, ping_timeout)

    def _check_floatingip_connectivity(self, floating_ip, server,
                                       should_connect=True,
                                       msg=None, ping_timeout=30):
        ip_address = floating_ip['floating_ip_address']
        floatingip_status = 'ACTIVE' if should_connect else 'DOWN'
        is_pingable = self.ping_ip_address(ip_address,
                                           ping_timeout=ping_timeout)
        msg = msg if msg else (
            "Timeout out waiting for %s to become reachable" % ip_address)
        if should_connect:
            self.assertTrue(is_pingable, msg=msg)
        else:
            self.assertFalse(is_pingable, msg=msg)
        self.check_floating_ip_status(floating_ip, floatingip_status)

    def get_image_userpass(self):
        return (CONF.validation.image_ssh_user,
                CONF.validation.image_ssh_password)

    def get_server_image(self):
        return CONF.compute.image_ref

    def get_server_flavor(self):
        return CONF.compute.flavor_ref


# common utilities
def make_node_info(net_floatingip, username, password,
                   include_outside_servers=False):
    floating_ip_address = net_floatingip['floating_ip_address']
    fixed_ip_address = net_floatingip['fixed_ip_address']
    node = dict(ipaddr=floating_ip_address,
                username=username, password=password)
    node['dest'] = [dict(ipaddr=floating_ip_address,
                         reachable=None, helper=IPTYPE_FLOATING),
                    dict(ipaddr=fixed_ip_address,
                         reachable=None, helper=IPTYPE_FIXED)]
    if include_outside_servers:
        outside_servers = dict(ipaddr=OUTSIDE_WORLD_SERVERS[0],
                               reachable=None, helper=IPTYPE_OUTSIDE_SERVER)
        node['dest'].append(outside_servers)

    return node


# we want to check the dest[iptype] is not reachable for
# at least (x_contd=2+=1 to make it is not really reachable.
def check_host_not_reachable(host, dest_list, iptype_list,
                             time_out=10, repeat_cnt=12,
                             x_contd=2):
    not_connected = 0
    for x in range(0, 12):
        not_reachable = check_host_is_reachable(
            host, dest_list, iptype_list, time_out=time_out)
        if not_reachable:
            not_connected += 1
        else:
            not_connected = 0
        if not_connected > x_contd:
            return True
    return False


# check_hosts_connectivity
def check_host_is_reachable(host, dest_list, iptype_list, time_out=120):
    rm_sshkey(host['ipaddr'])
    ssh_client = get_remote_client_by_password(host['ipaddr'],
                                               host['username'],
                                               host['password'])
    n_not_reachable = 0
    for dest in dest_list:
        for iptype in iptype_list:
            if not dest_has_iptype(dest, iptype):
                dest['reachable'] = None
                continue
            dest['reachable'] = is_reachable(
                ssh_client, dest['ipaddr'], time_out=time_out)
            if not dest['reachable']:
                n_not_reachable += 1
                xmsg = {'h_ipaddr': host['ipaddr'],
                        'msg': "can-not-reach-dest",
                        'helper': dest['helper'],
                        'd_ipaddr': dest['ipaddr']}
                LOG.debug(Z_VM2_DEST, xmsg)
            else:
                xmsg = {'h_ipaddr': host['ipaddr'],
                        'msg': "can-not-dest",
                        'helper': dest['helper'],
                        'd_ipaddr': dest['ipaddr']}
                LOG.debug(Z_VM2_DEST, xmsg)
    return (False if n_not_reachable else True)


def dest_has_iptype(dest, iptype):
    if ('helper' in dest and
            re.search(iptype, dest['helper'], re.I)):
        return True
    return False


def check_hosts_connectivity(host, dest_list, ignore_helper=None,
                             time_out=120):
    rm_sshkey(host['ipaddr'])
    ssh_client = get_remote_client_by_password(host['ipaddr'],
                                               host['username'],
                                               host['password'])
    n_not_reachable = 0
    for dest in dest_list:
        # caller can say to ignore dest ipaddr
        if ('helper' in dest and type(ignore_helper) in (str, unicode) and
                re.search(ignore_helper, dest['helper'], re.I)):
            dest['reachable'] = None
            continue
        dest['reachable'] = is_reachable(ssh_client, dest['ipaddr'],
                                         time_out=time_out)
        if not dest['reachable']:
            n_not_reachable += 1
            xmsg = {'h_ipaddr': host['ipaddr'],
                    'msg': "can-not-reach-dest",
                    'helper': dest['helper'],
                    'd_ipaddr': dest['ipaddr']}
            LOG.debug(Z_VM2_DEST, xmsg)
        else:
            xmsg = {'h_ipaddr': host['ipaddr'],
                    'msg': "can-reach-dest",
                    'helper': dest['helper'],
                    'd_ipaddr': dest['ipaddr']}
            LOG.debug(Z_VM2_DEST, xmsg)

    return n_not_reachable


def rm_sshkey(ip_addr):
    # ssh-keygen -f "/home/stack/.ssh/known_hosts" -R 10.34.57.3
    kh_file = os.path.join(os.environ.get('HOME', '/home/stack'),
                           '.ssh/known_hosts')
    cmd = ['ssh-keygen', '-f', kh_file, '-R', ip_addr]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    proc.communicate()
    return proc.returncode


def is_reachable(ssh_client, dest_ip, time_out=60.0, ping_timeout=5.0):
    for now in run_till_timeout(time_out, ping_timeout):
        reachable = dest_is_reachable(ssh_client, dest_ip)
        if reachable:
            return True
        LOG.debug("DEST[%(ip)s] NOT-REACHABLE, retry in %(t1)s seconds.",
                  {'ip': dest_ip, 't1': time_out})
    return False


def isnot_reachable(ssh_client, dest_ip, time_out=60.0, ping_timeout=5.0,
                    idle_time=2.0):
    if idle_time > 0.0:
        time.sleep(idle_time)
    for now in run_till_timeout(time_out, ping_timeout):
        reachable = dest_is_reachable(ssh_client, dest_ip)
        if not reachable:
            return True
        LOG.debug("DEST[%(ip)s] IS-REACHABLE, retry in %(t1)s seconds.",
                  {'ip': dest_ip, 't1': time_out})
    return False


def dest_is_reachable(ssh_client, dest_ip):
    XPTN = r"(\d+).*transmit.*(\d+).*receive.*(\d+).*loss"
    try:
        result = ssh_client.ping_host(dest_ip)
        m = re.search(XPTN, result, (re.I | re.M))
        if m and int(m.group(1)) > 0 and int(m.group(3)) == 0:
            return True
        else:
            return False
    except Exception:
        tb_str = traceback.format_exc()
        mesg = ("ERROR on testing dest_ip[%s] is reachable:\n%s" %
                (dest_ip, tb_str))
        LOG.debug(mesg)
        return False


def run_till_timeout(seconds_to_try, interval=5.0):
    now, end_time = time.time(), time.time() + seconds_to_try
    while now < end_time:
        yield now
        time.sleep(interval)
        now = time.time()


def _g_tenant_id(os_client):
    try:
        return os_client.tenant_id
    except Exception:
        return os_client.rest_client.tenant_id


def get_remote_client_by_password(client_ip, username, password):
    ssh_client = remote_client.RemoteClient(client_ip, username, password)
    return ssh_client


def delete_all_servers(tenant_servers_client, trys=5):
    # try at least trys+1 time to delete servers, otherwise
    # network resources can not be deleted
    for s in tenant_servers_client.list_servers()['servers']:
        tenant_servers_client.delete_server(s['id'])
    for x in range(0, trys):
        try:
            waitfor_servers_terminated(tenant_servers_client)
            return
        except Exception:
            pass
    # last try
    waitfor_servers_terminated(tenant_servers_client)


def waitfor_servers_terminated(tenant_servers_client, pause=2.0):
    while (True):
        s_list = tenant_servers_client.list_servers()['servers']
        if len(s_list) < 1:
            return
        time.sleep(pause)
