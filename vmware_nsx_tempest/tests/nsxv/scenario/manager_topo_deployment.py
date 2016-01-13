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

import net_resources

from tempest.common.utils.linux import remote_client
from tempest.common import waiters
from tempest import config
from tempest.scenario import manager
from tempest import test

import netaddr
from tempest_lib.common.utils import data_utils
from tempest_lib import exceptions

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
        if not (CONF.network.tenant_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either tenant_networks_reachable must be "true", or '
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

    # bypass pareant _create_router() to use the net_resources module.
    # Scenario: routers belong to admin, subnets belon to tenent
    def _create_router(self, client_mgr=None, tenant_id=None,
                       namestart='topo-deploy', **kwargs):
        client_mgr = client_mgr or self.manager
        router_client = client_mgr.network_client

        if not tenant_id:
            tenant_id = router_client.tenant_id
        distributed = kwargs.pop('distributed', None)
        router_type = kwargs.pop('router_type', None)
        if distributed in (True, False):
            kwargs['distributed'] = distributed
        elif router_type in ('shared', 'exclusive'):
            kwargs['router_type'] = router_type
        name = data_utils.rand_name(namestart)
        result = router_client.create_router(name=name,
                                             admin_state_up=True,
                                             tenant_id=tenant_id,
                                             **kwargs)
        router = net_resources.DeletableRouter(client=router_client,
                                               **result['router'])
        self.assertEqual(router.name, name)
        self.addCleanup(self.delete_wrapper, router.delete)
        return router

    def create_server_on_network(self, networks, security_groups=None,
                                 name=None, image=None, wait_on_boot=True,
                                 flavor=None, servers_client=None):
        name = name or data_utils.rand_name('topo-deploy-vm')
        if security_groups is None:
            security_groups = [{'name': 'default'}]
        if type(networks) in (list, tuple):
            network_ifs = [{'uuid': nw.id} for nw in networks]
        else:
            network_ifs = [{'uuid': networks.id}]
        create_kwargs = {
            'networks': network_ifs,
            'security_groups': security_groups,
        }
        LOG.debug("TopoDeploy Create server name=%(name)s"
                  ", create_kwargs=%(create_kwargs)s",
                  {'name': name, 'create_kwargs': str(create_kwargs)})
        server = self.create_server(
            name=name, image=image, wait_on_boot=wait_on_boot,
            servers_client=servers_client, flavor=flavor,
            create_kwargs=create_kwargs)
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
            cleanup_callable=self.delete_wrapper,
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
        networks_client = client_mgr.networks_client
        body = networks_client.create_network(**create_body)
        net_network = net_resources.DeletableNetwork(
            networks_client=networks_client, **body['network'])
        self.assertEqual(net_network.name, name)
        self.addCleanup(self.delete_wrapper, net_network.delete)
        return net_network

    def create_provider_subnet(self, client_mgr=None, create_body=None):
        client_mgr = client_mgr or self.admin_manager
        subnets_client = client_mgr.subnets_client
        body = subnets_client.create_subnet(**create_body)
        net_subnet = net_resources.DeletableSubnet(
            subnets_client=subnets_client, **body['subnet'])
        self.addCleanup(self.delete_wrapper, net_subnet.delete)
        return net_subnet

    def setup_tenant_network(self, external_network_id,
                             client_mgr=None,
                             namestart=None, client=None,
                             tenant_id=None, cidr_offset=0):
        """NOTE:

            Refer to create_networks@scenario/manager.py which might refer
            to public_router_id which we dont' want to use.

            The test class can define class variable tenant_router_attrs
            to create different type of routers.
        """
        # namestart = namestart if namestart else 'topo-deploy-tenant'
        name = namestart or data_utils.rand_name('topo-deploy-tenant')
        client_mgr = client_mgr or self.manager
        # _create_router() editing distributed and router_type
        distributed = self.tenant_router_attrs.get('distributed')
        router_type = self.tenant_router_attrs.get('router_type')
        # child class use class var tenant_router_attrs to define
        # tenant's router type.
        net_router = self._create_router(
            client_mgr=client_mgr, tenant_id=tenant_id,
            namestart=name,
            distributed=distributed, router_type=router_type)
        net_router.set_gateway(external_network_id)
        net_network, net_subnet = self.create_network_subnet(
            client_mgr=client_mgr,
            tenant_id=tenant_id, name=net_router.name,
            cidr_offset=cidr_offset)
        # different from the resources.py
        net_router.add_interface(net_subnet)
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
        client = client or self.networks_client
        tenant_id = tenant_id or _g_tenant_id(client)
        name = name or data_utils.rand_name('topo-deploy-network')
        result = client.create_network(name=name, tenant_id=tenant_id,
                                       **kwargs)
        net_network = net_resources.DeletableNetwork(
            client=client, networks_client=client,
            **result['network'])
        self.assertEqual(net_network.name, name)
        self.addCleanup(self.delete_wrapper, net_network.delete)
        return net_network

    def create_subnet(self, network, client=None,
                      gateway='', cidr=None, mask_bits=None,
                      ip_version=None, cidr_offset=0,
                      allocation_pools=None, dns_nameservers=None,
                      **kwargs):
        client = client or self.subnets_client
        ip_version = ip_version or 4
        post_body = get_subnet_create_options(
            network['id'], ip_version,
            gateway=gateway, cidr=cidr, cidr_offset=cidr_offset,
            mask_bits=mask_bits, **kwargs)
        if allocation_pools:
            post_body['allocation_pools'] = allocation_pools
        if dns_nameservers:
            post_body['dns_nameservers'] = dns_nameservers
        LOG.debug("create_subnet args: %s", post_body)
        body = client.create_subnet(**post_body)
        net_subnet = net_resources.DeletableSubnet(
            client=client, subnets_client=client,
            **body['subnet'])
        self.addCleanup(self.delete_wrapper, net_subnet.delete)
        return net_subnet

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

    def disassociate_floatingip(self, net_floatingip, and_delete=False):
        self._disassociate_floating_ip(net_floatingip)
        if and_delete:
            net_floatingip.delete()

    def associate_floatingip(self, net_floatingip, to_server):
        self._associate_floating_ip(net_floatingip, to_server)

    def check_networks(self, net_network, net_subnet=None, net_router=None):
        seen_nets = self._list_networks()
        seen_names = [n['name'] for n in seen_nets]
        seen_ids = [n['id'] for n in seen_nets]
        self.assertIn(net_network.name, seen_names)
        self.assertIn(net_network.id, seen_ids)

        if net_subnet:
            seen_subnets = self._list_subnets()
            seen_net_ids = [n['network_id'] for n in seen_subnets]
            seen_subnet_ids = [n['id'] for n in seen_subnets]
            self.assertIn(net_network.id, seen_net_ids)
            self.assertIn(net_subnet.id, seen_subnet_ids)

        if net_router:
            seen_routers = self._list_routers()
            seen_router_ids = [n['id'] for n in seen_routers]
            seen_router_names = [n['name'] for n in seen_routers]
            self.assertIn(net_router.name, seen_router_names)
            self.assertIn(net_router.id, seen_router_ids)

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
        ip_address = floating_ip.floating_ip_address
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
    node = dict(ipaddr=net_floatingip.floating_ip_address,
                username=username, password=password)
    node['dest'] = [dict(ipaddr=net_floatingip.floating_ip_address,
                         reachable=None, helper=IPTYPE_FLOATING),
                    dict(ipaddr=net_floatingip.fixed_ip_address,
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


def get_subnet_create_options(network_id, ip_version=4,
                              gateway='', cidr=None, mask_bits=None,
                              num_subnet=1, gateway_offset=1, cidr_offset=0,
                              **kwargs):
    """When cidr_offset>0 it request only one subnet-options:

        subnet = get_subnet_create_options('abcdefg', 4, num_subnet=4)[3]
        subnet = get_subnet_create_options('abcdefg', 4, cidr_offset=3)
    """

    gateway_not_set = gateway == ''
    if ip_version == 4:
        cidr = cidr or netaddr.IPNetwork(CONF.network.tenant_network_cidr)
        mask_bits = mask_bits or CONF.network.tenant_network_mask_bits
    elif ip_version == 6:
        cidr = (
            cidr or netaddr.IPNetwork(CONF.network.tenant_network_v6_cidr))
        mask_bits = mask_bits or CONF.network.tenant_network_v6_mask_bits
    # Find a cidr that is not in use yet and create a subnet with it
    subnet_list = []
    if cidr_offset > 0:
        num_subnet = cidr_offset + 1
    for subnet_cidr in cidr.subnet(mask_bits):
        if gateway_not_set:
            gateway_ip = gateway or (
                str(netaddr.IPAddress(subnet_cidr) + gateway_offset))
        else:
            gateway_ip = gateway
        try:
            subnet_body = dict(network_id=network_id,
                               cidr=str(subnet_cidr),
                               ip_version=ip_version,
                               gateway_ip=gateway_ip,
                               **kwargs)
            if num_subnet <= 1:
                return subnet_body
            subnet_list.append(subnet_body)
            if len(subnet_list) >= num_subnet:
                if cidr_offset > 0:
                    # user request the 'cidr_offset'th of cidr
                    return subnet_list[cidr_offset]
                # user request list of cidr
                return subnet_list
        except exceptions.BadRequest as e:
            is_overlapping_cidr = 'overlaps with another subnet' in str(e)
            if not is_overlapping_cidr:
                raise
    else:
        message = 'Available CIDR for subnet creation could not be found'
        raise exceptions.BuildErrorException(message)
    return {}


def get_remote_client_by_password(client_ip, username, password):
    ssh_client = remote_client.RemoteClient(client_ip, username, password)
    return ssh_client


def delete_all_servers(tenant_servers_client):
    for s in tenant_servers_client.list_servers()['servers']:
        tenant_servers_client.delete_server(s['id'])
    waitfor_servers_terminated(tenant_servers_client)


def waitfor_servers_terminated(tenant_servers_client, pause=2.0):
    while (True):
        s_list = tenant_servers_client.list_servers()['servers']
        if len(s_list) < 1:
            return
        time.sleep(pause)
