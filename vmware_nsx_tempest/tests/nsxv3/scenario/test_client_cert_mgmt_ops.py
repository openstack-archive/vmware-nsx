# Copyright 2017 VMware, Inc.
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


from oslo_log import log as logging

from tempest import config
from tempest import test

from tempest.lib import decorators

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils

from vmware_nsx_tempest.services import nsxv3_client
from vmware_nsx_tempest.services.qos import base_qos
from vmware_nsx_tempest.tests.scenario import manager

authorizationField = ''
CONF = config.CONF
LOG = logging.getLogger(__name__)


class TestCertificateMgmt(manager.NetworkScenarioTest):

    error_message = ("Principal 'admin' from group 'superusers' attempts\
 to delete or modify an object it doesn't own")

    @classmethod
    def skip_checks(cls):
        super(TestCertificateMgmt, cls).skip_checks()
        if not (CONF.network.project_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be true, or\
                public_network_id must be defined.')
            raise cls.skipException(msg)
        if not test.is_extension_enabled('qos', 'network'):
            msg = "q-qos extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(TestCertificateMgmt, cls).setup_credentials()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
            CONF.nsxv3.nsx_user, CONF.nsxv3.nsx_password)

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(TestCertificateMgmt, cls).resource_setup()
        cls.admin_mgr = cls.get_client_manager('admin')
        cls.adm_qos_client = base_qos.BaseQosClient(cls.admin_mgr)
        cls.policies_created = []

    def _create_subnet(self, network, cidr, subnets_client=None, **kwargs):
        client = subnets_client or self.subnets_client
        body = client.create_subnet(
            name=data_utils.rand_name('subnet-default1'),
            network_id=network['id'], tenant_id=network['tenant_id'],
            cidr=cidr, ip_version=4, **kwargs)
        subnet = body.get('subnet', body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        client.delete_subnet, subnet['id'])
        return subnet

    def _create_router(self, router_name=None, admin_state_up=True,
                       external_network_id=None, enable_snat=None,
                       **kwargs):
        ext_gw_info = {}
        if external_network_id:
            ext_gw_info['network_id'] = external_network_id
        if enable_snat is not None:
            ext_gw_info['enable_snat'] = enable_snat
        body = self.routers_client.create_router(
            name=router_name, external_gateway_info=ext_gw_info,
            admin_state_up=admin_state_up, **kwargs)
        router = body.get('router', body)
        self.addCleanup(self._delete_router, router)
        return router

    def _delete_router(self, router):
        body = self.ports_client.list_ports(device_id=router['id'])
        interfaces = body['ports']
        for i in interfaces:
            test_utils.call_and_ignore_notfound_exc(
                self.routers_client.remove_router_interface, router['id'],
                subnet_id=i['fixed_ips'][0]['subnet_id'])
        self.routers_client.delete_router(router['id'])

    @classmethod
    def create_qos_policy(cls, name='test-policy',
                          description='test policy desc',
                          shared=False,
                          qos_client=None, **kwargs):
        """create qos policy."""
        qos_client = qos_client if qos_client else cls.adm_qos_client
        policy = qos_client.create_policy(
            name=name, description=description,
            shared=shared, **kwargs)
        cls.policies_created.append(policy)
        return policy

    def parse_response(self, response):
        """
        Parse response from NSX backend to check if NSX
        is unable to delete or modify openstack entities
        """
        msg = 'Error: NSX admin is able to modify/delete'
        self.assertIn(self.error_message,
            response.json()['error_message'], msg)
        LOG.info('NSX admin is unable to modify/delete the openstack object')

    def ca_topo(self):
        """
        Create a topology consisting of network attached to a router
        and a logical port attached to the network
        """
        self.network = self._create_network(namestart="net-ca")
        self.subnet = self._create_subnet(self.network,
            cidr=CONF.network.project_network_cidr)
        self.port = self._create_port(network_id=self.network['id'],
            namestart='ca')
        msg = 'Logical Port %s not found' % self.port['name']
        self.assertIsNotNone(self.nsx.get_logical_port(
            self.port['name']), msg)
        data = self.nsx.get_logical_port(self.port['name'])
        return data


class TestCertificateMgmtOps(TestCertificateMgmt):
    openstack_tag = 'com.vmware.nsx.openstack'

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('6cb32a2b-048a-47a3-b0ed-f6337b81377f')
    def test_certificate_backend(self):
        """
        verify if NSX backend shows self-signed certificate
        """
        msg = 'Error: Openstack client certificate not registered with backend'
        self.assertIsNotNone(self.nsx.get_openstack_client_certificate(), msg)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('25bb1af7-6190-42d5-a590-4df9fb5592f0')
    def test_prevention_modification_openstack_network(self):
        """
        Create a network
        Verify if NSX shows network is created by openstack
        Verify if NSX admin is unable to modify this network
        """
        self.network = self._create_network()
        self.subnet = self._create_subnet(self.network,
            cidr=CONF.network.project_network_cidr)
        #check backend if the network was created
        msg = 'network %s not found' % self.network['name']
        self.assertIsNotNone(self.nsx.get_logical_switch(
            self.network['name'], self.network['id']), msg)
        data = self.nsx.get_logical_switch(self.network['name'],
            self.network['id'])
        """
        Check if backend shows openstack
        as the create user for the object
        """
        self.assertEqual(data['_create_user'], self.openstack_tag,
            'Incorrect tag for the create user')
        #try to update network name as NSX admin
        data.update({"display_name": "nsx_modified_switch"})
        response = self.nsx.ca_put_request(component='logical-switches',
            comp_id=data['id'], body=data)
        self.parse_response(response)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('3e9a4d5b-5a14-44a5-bf9f-8999148b9329')
    def test_prevention_modification_openstack_router(self):
        """
        Create a router
        Verify if backend shows router is created by openstack
        Verify if NSX admin can not modify this router
        Verify if NSX admin can not delete this router
        """
        self.network = self._create_network()
        self.subnet = self._create_subnet(self.network,
            cidr=CONF.network.project_network_cidr)
        #create router and add an interface
        self.router = self._create_router(
            router_name=data_utils.rand_name('router-cert-mgmt'),
            external_network_id=CONF.network.public_network_id)
        self.routers_client.add_router_interface(
            self.router['id'], subnet_id=self.subnet['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        self.router['id'], subnet_id=self.subnet['id'])
        #check backend if the router was created
        msg = 'router %s not found' % self.router['name']
        self.assertIsNotNone(self.nsx.get_logical_router(
            self.router['name'], self.router['id']), msg)
        data = self.nsx.get_logical_router(self.router['name'],
            self.router['id'])
        """
        Check if backend shows openstack
        as the create user for the object
        """
        self.assertEqual(data['_create_user'], self.openstack_tag,
            'Incorrect tag for the create user')
        #Obtain any router port corresponding to the logical router
        rtr_ports = self.nsx.get_logical_router_ports(data)
        #try to update router name as NSX admin
        data.update({"display_name": "nsx_modified_router"})
        response = self.nsx.ca_put_request(component='logical-routers',
            comp_id=data['id'], body=data)
        self.parse_response(response)
        #try to delete logical router port as NSX admin
        if len(rtr_ports) != 0:
            response = self.nsx.ca_delete_request(
                component='logical-router-ports',
                comp_id=rtr_ports[0]['id'])
            self.parse_response(response)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('141af4cb-52f0-4764-b817-5b0529dbbc73')
    def test_prevention_modification_qos_policy(self):
        """
        Create a qos policy
        Verify if backend shows switching profile is created by openstack
        Verify if NSX admin can not modify the profile
        Verify if NSX admin can not  delete the profile
        """
        policy = self.create_qos_policy(name='test-qos-policy-cert-mgmt',
                                        description='dscp_rule and bw_rule',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #obtain all switching profiles at the backend
        qos_policies = self.nsx.get_switching_profiles()
        nsx_policy = self.nsx.get_nsx_resource_by_name(qos_policies,
            policy['name'])
        #check backend if the qos policy was created
        msg = 'Qos policy %s not found' % policy['name']
        self.assertIsNotNone(self.nsx.get_switching_profile(
            nsx_policy['id']), msg)
        data = self.nsx.get_switching_profile(nsx_policy['id'])
        """
        Check if backend shows openstack
        as the create user for the object
        """
        self.assertEqual(data['_create_user'], self.openstack_tag,
            'Incorrect tag for the create user')
        #try to update qos policy  as NSX admin
        data.update({"display_name": "nsx_modified_qos-policy"})
        response = self.nsx.ca_put_request(component='switching-profiles',
            comp_id=data['id'], body=data)
        self.parse_response(response)
        #try to delete qos policy as NSX admin
        response = self.nsx.ca_delete_request(component='switching-profiles',
            comp_id=data['id'])
        self.parse_response(response)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('2b232060-dc42-4b2d-8185-64bd12e46e55')
    def test_prevention_modification_security_group(self):
        """
        Create a security group
        Verify if backend shows firewall is created by openstack
        Verify if NSX admin can not modify the firewall
        Verify if NSX admin can not delete the firewall
        """
        self.security_group = self._create_security_group()
        #check backend if the firewall section was created
        msg = 'Security group %s not found' % self.security_group['name']
        self.assertIsNotNone(self.nsx.get_firewall_section(
            self.security_group['name'], self.security_group['id']), msg)
        data = self.nsx.get_firewall_section(self.security_group['name'],
            self.security_group['id'])
        """
        Check if backend shows openstack
        as the create user for the object
        """
        self.assertEqual(data['_create_user'], self.openstack_tag,
            'Incorrect tag for the create user')
        #obtain firewall rules related to the security group
        fw_rules = self.nsx.get_firewall_section_rules(data)
        #try to update security group as NSX admin
        data.update({"display_name": "nsx_modified_security_group"})
        response = self.nsx.ca_put_request(component='firewall/sections',
            comp_id=data['id'], body=data)
        self.parse_response(response)
        #try to delete logical firewall rule as NSX admin
        if len(fw_rules) != 0:
            component = 'firewall/sections/' + data['id'] + '/rules/'
            response = self.nsx.ca_delete_request(component=component,
                comp_id=fw_rules[0]['id'])
            self.parse_response(response)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('b10d5ede-d1c7-47a0-9d55-b9aabc8f0af1')
    def test_prevention_modification_port(self):
        """
        Create a port
        Verify if backend shows logical port is created by openstack
        Verify if NSX admin can not modify the port
        Verify if NSX admin can not delete the port
        Check if backend shows openstack
        as the create user for the object
        """
        data = self.ca_topo()
        self.assertEqual(data['_create_user'], self.openstack_tag,
            'Incorrect tag for the create user')
        #try to update logical port as NSX admin
        data.update({"display_name": "nsx_modified_logical_port"})
        response = self.nsx.ca_put_request(component='logical-ports',
            comp_id=data['id'], body=data)
        self.parse_response(response)
        #try to delete logical port as NSX admin
        response = self.nsx.ca_delete_request(component='logical-ports',
                comp_id=data['id'])
        self.parse_response(response)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('280cdcc6-5bd0-472c-a8a9-954dd612a0a6')
    def test_port_modification_super_admin(self):
        """
        Verify if super admin can override openstack entity
        and delete openstack logical port
        """
        data = self.ca_topo()
        self.assertEqual(data['_create_user'], self.openstack_tag,
            'Incorrect tag for the create user')
        #try to delete logical port as NSX admin
        endpoint = ("/%s/%s" % ('logical-ports',
            data['id']))
        response = self.nsx.delete_super_admin(endpoint=endpoint)
        self.assertEqual(response.status_code, 200,
            "Superadmin unable to delete the logical port")

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('a874d78b-eb7a-4df6-a01b-dc0a22422dc2')
    def test_cert_removed_post_unstack(self):
        """
        verify if backend unregisters the self-signed certificate
        post unstack
        """
        msg = ('Error: Openstack certificate is still registered with backend')
        self.assertIsNone(self.nsx.get_openstack_client_certificate(), msg)
