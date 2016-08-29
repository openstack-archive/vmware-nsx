# Copyright 2016 VMware Inc
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

import os
from oslo_log import log as logging
import six
import subprocess

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest import test

import base_provider as base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ProjectDeleteTest(base.BaseAdminNetworkTest):
    """Check Purge network resources using tenant-Id.

    Validate that network resources which are not in use should get
    deleted once neutron purge <tenant-id> is called.
    """
    @classmethod
    def skip_checks(cls):
        super(ProjectDeleteTest, cls).skip_checks()
        if not (CONF.network.project_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        if not (CONF.auth.admin_username and CONF.auth.admin_password and
                CONF.auth.admin_project_name):
            msg = ('admin_username admin_password and admin_project_name\
                   should be provided in tempest.conf')
            raise cls.skipException(msg)
        process_obj = subprocess.Popen('neutron --version', shell=True,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT)
        neutron_version = process_obj.stdout.readlines()
        if neutron_version[0] < '4.1.2':
            msg = ("Please update neutron verion,"
                   "run pip --upgrade pip and"
                   "pip install python-neutronclient upgrade")
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(ProjectDeleteTest, cls).setup_clients()

    @classmethod
    def resource_setup(cls):
        super(ProjectDeleteTest, cls).resource_setup()

    @classmethod
    def create_tenant(self):
        self.admin_manager.tenants_client

    @classmethod
    def create_network_subnet(self, cidr=None, cidr_offset=0):
        network_name = data_utils.rand_name('project-network-')
        resp = self.create_network(network_name)
        network = resp.get('network', resp)
        net_id = network['id']
        resp = self.create_subnet(network,
                                  name=network_name,
                                  cidr=cidr,
                                  cidr_offset=cidr_offset)
        subnet = resp.get('subnet', resp)
        resp = self.show_network(net_id)
        s_network = resp.get('network', resp)
        return (net_id, s_network, subnet)

    def create_router_by_type(self, router_type, name=None, **kwargs):
        routers_client = self.admin_manager.routers_client
        router_name = name or data_utils.rand_name('mtz-')
        create_kwargs = dict(name=router_name, external_gateway_info={
            "network_id": CONF.network.public_network_id})
        if router_type in ('shared', 'exclusive'):
            create_kwargs['router_type'] = router_type
        elif router_type in ('distributed'):
            create_kwargs['distributed'] = True
        kwargs.update(create_kwargs)
        router = routers_client.create_router(**kwargs)
        router = router['router'] if 'router' in router else router
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        routers_client.delete_router, router['id'])
        self.assertEqual(router['name'], router_name)
        return (routers_client, router)

    def create_router_and_add_interfaces(self, router_type, nets):
        (routers_client, router) = self.create_router_by_type(router_type)
        for net_id, (network, subnet) in six.iteritems(nets):
            # register to cleanup before adding interfaces so interfaces
            # and router can be deleted if test is aborted.
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            routers_client.remove_router_interface,
                            router['id'], subnet_id=subnet['id'])
            routers_client.add_router_interface(
                router['id'], subnet_id=subnet['id'])
        return router

    @test.idempotent_id('44e24f6b-9d9e-41a7-9d54-09d79b77dea5')
    def test_project_delete_purge_using_non_admin(self):
        nets = {}
        net_id, network, subnet = self.create_network_subnet(cidr_offset=0)
        nets[net_id] = (network, subnet)
        router_type = 'shared'
        self.create_router_and_add_interfaces(router_type, nets)
        uri = CONF.identity.uri
        os.environ['OS_AUTH_URL'] = uri
        os.environ['OS_REGION_NAME'] = 'nova'
        os.environ['OS_USERNAME'] = CONF.auth.admin_username
        os.environ['OS_TENANT_NAME'] = CONF.auth.admin_project_name
        os.environ['OS_PASSWORD'] = CONF.auth.admin_password
        name = data_utils.rand_name('tenant-delete-')
        tenant = self.admin_manager.tenants_client.create_tenant(name=name)
        username = name + 'user'
        kwargs = {'name': username, 'pass': 'password'}
        tenant_user = self.admin_manager.users_client.create_user(**kwargs)
        os.environ['OS_USERNAME'] = tenant_user['user']['username']
        os.environ['OS_TENANT_NAME'] = tenant['tenant']['name']
        os.environ['OS_PASSWORD'] = 'password'
        local_tenant_id = network['tenant_id']
        purge_output =\
            os.popen('neutron --insecure purge %s --tenant-id=%s' %
                     (local_tenant_id,
                      tenant['tenant']['id'])).read().strip()
        self.assertEqual(purge_output, '')
        os.environ['OS_USERNAME'] = CONF.auth.admin_username
        os.environ['OS_TENANT_NAME'] = CONF.auth.admin_project_name
        os.environ['OS_PASSWORD'] = CONF.auth.admin_password
        admin_tenant_id = os.popen(
            "openstack --insecure project list | grep admin | awk '{print $2}'")\
            .read()
        purge_output =\
            os.popen('neutron --insecure purge %s --tenant-id=%s' %
                     (local_tenant_id, admin_tenant_id)).read().strip()
        self.assertIn('Purging resources: 100% complete', purge_output)

    @test.idempotent_id('77ec7045-f8f0-4aa1-8e1d-68c0647fda89')
    def test_project_delete_no_resource_for_deletion(self):
        name = data_utils.rand_name('tenant-delete-')
        network_client = self.admin_manager.networks_client
        create_kwargs = dict(name=name)
        network = network_client.create_network(**create_kwargs)
        network_client.delete_network(network['network']['id'])
        uri = CONF.identity.uri
        os.environ['OS_AUTH_URL'] = uri
        os.environ['OS_REGION_NAME'] = 'nova'
        os.environ['OS_USERNAME'] = CONF.auth.admin_username
        os.environ['OS_TENANT_NAME'] = CONF.auth.admin_project_name
        os.environ['OS_PASSWORD'] = CONF.auth.admin_password
        local_tenant_id = network['network']['tenant_id']
        admin_tenant_id = os.popen(
            "openstack --insecure project list | grep admin | awk '{print $2}'")\
            .read()
        purge_output =\
            os.popen('neutron --insecure purge %s --tenant-id=%s' %
                     (local_tenant_id, admin_tenant_id)).read().strip()
        purge_output =\
            os.popen('neutron --insecure purge %s --tenant-id=%s' %
                     (local_tenant_id, admin_tenant_id)).read().strip()
        LOG.debug("create VLAN network: %s", (purge_output))
        check_output = 'Tenant has no supported resources'
        self.assertIn(check_output, purge_output)
        LOG.debug("Testcase run completed")

    @test.idempotent_id('38bf4e22-c67a-42db-9e9d-a087369207d4')
    def test_project_delete_with_all_resorces_deleted(self):
        name = data_utils.rand_name('tenant-delete-')
        security_client = self.admin_manager.security_groups_client
        create_kwargs = dict(name=name)
        sec_group = security_client.create_security_group(**create_kwargs)
        network_name = name
        resp = self.create_network(network_name)
        network = resp.get('network', resp)
        routers_client = self.admin_manager.routers_client
        create_kwargs = dict(name=name)
        router = routers_client.create_router(**create_kwargs)
        floatingip_client = self.admin_manager.floating_ips_client
        create_kwargs = {'floating_network_id': CONF.network.public_network_id}
        floatingip = floatingip_client.create_floatingip(**create_kwargs)
        uri = CONF.identity.uri
        os.environ['OS_AUTH_URL'] = uri
        os.environ['OS_REGION_NAME'] = 'nova'
        os.environ['OS_USERNAME'] = CONF.auth.admin_username
        os.environ['OS_TENANT_NAME'] = CONF.auth.admin_project_name
        os.environ['OS_PASSWORD'] = CONF.auth.admin_password
        self.admin_networks_client
        local_tenant_id = network['tenant_id']
        admin_tenant_id = os.popen(
            "openstack --insecure project list | grep admin | awk '{print $2}'")\
            .read()
        purge_output =\
            os.popen('neutron --insecure purge %s --tenant-id=%s' %
                     (local_tenant_id, admin_tenant_id)).read().strip()
        LOG.debug("create VLAN network: %s", (purge_output))
        check_output = ("Deleted 2 security_groups, 1 router, 1 network, "
                        "1 floatingip")
        self.assertIn(check_output, purge_output)
        list_of_sec_groups = security_client.list_security_groups()
        self.assertNotIn(sec_group['security_group']['id'], list_of_sec_groups)
        list_of_networks = self.admin_manager.networks_client.list_networks()
        self.assertNotIn(network['id'], list_of_networks)
        list_of_routers = routers_client.list_routers()
        self.assertNotIn(router['router']['id'], list_of_routers)
        list_of_floatingips = floatingip_client.list_floatingips()
        self.assertNotIn(floatingip['floatingip']['id'], list_of_floatingips)
        LOG.debug("Testcase run completed")

    @test.idempotent_id('d617d637-5b2d-4ac8-93ce-80060d495bb2')
    def test_project_delete_with_some_resources_left(self):
        network_name = data_utils.rand_name('tenant-delete-')
        resp = self.create_network(network_name)
        network = resp.get('network', resp)
        net_id = network['id']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_network, net_id)
        resp = self.create_subnet(network,
                                  name=network_name,
                                  cidr=None,
                                  cidr_offset=0)
        subnet = resp.get('subnet', resp)
        resp = self.show_network(net_id)
        s_network = resp.get('network', resp)
        net_subnets = s_network['subnets']
        self.assertIn(subnet['id'], net_subnets)
        uri = CONF.identity.uri
        os.environ['OS_AUTH_URL'] = uri
        os.environ['OS_REGION_NAME'] = 'nova'
        os.environ['OS_USERNAME'] = CONF.auth.admin_username
        os.environ['OS_TENANT_NAME'] = CONF.auth.admin_project_name
        os.environ['OS_PASSWORD'] = CONF.auth.admin_password
        self.admin_networks_client
        local_tenant_id = network['tenant_id']
        cmd = ("openstack --insecure project list |"
               " grep admin | awk '{print $2}'")
        admin_tenant_id = os.popen(cmd).read()
        purge_output =\
            os.popen('neutron --insecure purge %s --tenant-id=%s' %
                     (local_tenant_id, admin_tenant_id)).read().strip()
        check_output = 'Deleted 1 security_group, 1 network'
        self.assertIn(check_output, purge_output)
        check_output = 'The following resources could not be deleted: 1 port'
        self.assertIn(check_output, purge_output)
        list_of_subnets = self.admin_manager.subnets_client.list_subnets()
        self.assertNotIn(subnet['id'], list_of_subnets)
        list_of_networks = self.admin_manager.networks_client.list_networks()
        self.assertNotIn(network['id'], list_of_networks)
        LOG.debug("create VLAN network: %s", (purge_output))
