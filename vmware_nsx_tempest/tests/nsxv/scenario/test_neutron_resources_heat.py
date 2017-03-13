# Copyright 2017 VMware Inc
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
import re
import yaml

from oslo_log import log as logging

from tempest.api.orchestration import base
from tempest.common.utils import data_utils
from tempest import config
from tempest.lib import decorators
from tempest.scenario import manager
from tempest import test

from vmware_nsx_tempest.services import nsxv_client


CONF = config.CONF

LOG = logging.getLogger(__name__)
DIR_PATH = '/opt/stack/vmware-nsx/vmware_nsx_tempest/tests/'


class HeatSmokeTest(base.BaseOrchestrationTest,
                    manager.NetworkScenarioTest):

    """Deploy and Test Neutron Resources using HEAT.

       The script load the neutron resources from template and fully
    validates successful deployment of all resources from the template.
    The template consists of two toplogies with Shared and Exclusive router.
    Tests will be common to toplogies (pls refer template for topo info)and
    will be as below :
            1. verify created resources from template
            2. verify all created resouces from template
              -->neutronDB-->NSXbackend
            3. check same network connectivity
            4. check cross network connectivity
    """

    def setUp(self):
        super(HeatSmokeTest, self).setUp()
        self.external_network = CONF.scenario.outside_world_servers

    @classmethod
    def read_template(cls, name, ext='yaml'):
        loc = ["templates", "%s.%s" % (name, ext)]
        filepath = os.path.join(DIR_PATH, *loc)
        if os.path.isfile(filepath):
            with open(filepath, "r") as f:
                content = f.read()
                return content
        else:
            raise IOError("File %s not found " % filepath)

    @classmethod
    def load_template(cls, name, ext='yaml'):
        loc = ["templates", "%s.%s" % (name, ext)]
        filepath = os.path.join(DIR_PATH, *loc)
        if os.path.isfile(filepath):
            with open(filepath, "r") as f:
                return yaml.safe_load(f)
        else:
            raise IOError("File %s not found " % filepath)

    @classmethod
    def resource_setup(cls):
        super(HeatSmokeTest, cls).resource_setup()
        cls.stack_name = data_utils.rand_name('heat')
        try:
            cls.neutron_basic_template = cls.load_template(
                'nsxv_neutron_smoke')
            template = cls.read_template('nsxv_neutron_smoke')
        except IOError as e:
            LOG.exception(("file nsxv_neutron_smoke.yaml not found %(rsp)s") %
                          {'rsp': e})
        cls.stack_identifier = cls.create_stack(cls.stack_name, template)
        cls.client.wait_for_stack_status(cls.stack_identifier,
                                         'CREATE_COMPLETE')
        cls.stack_id = cls.stack_identifier.split('/')[1]
        cls.resources = (cls.client.list_resources(cls.stack_identifier)
                         ['resources'])
        cls.test_resources = {}
        for resource in cls.resources:
            cls.test_resources[resource['logical_resource_id']] = resource

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(HeatSmokeTest, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        super(HeatSmokeTest, cls).setup_clients()
        cls.routers_client = cls.os.routers_client
        cls.subnets_client = cls.os.subnets_client
        manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                               CONF.nsxv.manager_uri).group(0)
        cls.vsm = nsxv_client.VSMClient(
            manager_ip, CONF.nsxv.user, CONF.nsxv.password)

    def _resource_list_check(self, resource):
        # sorts out the resources and returns resource id
        if resource == 'networks':
            body = self.networks_client.list_networks()
            component = 'OS::Neutron::Net'
        elif resource == 'routers':
            body = self.routers_client.list_routers()
            component = 'OS::Neutron::Router'
            print(body)
        elif resource == 'servers':
            body = self.servers_client.list_servers()
            component = 'OS::Nova::Server'
        resource_list_id = [res_list['id'] for res_list in body[resource]]
        test_resource_list_id = []
        for _, resource in self.test_resources.items():
            if resource['resource_type'] == component:
                test_resource_list_id.append(resource['physical_resource_id'])
        for resource_id in test_resource_list_id:
            self.assertIn(resource_id, resource_list_id)
        return test_resource_list_id

    def _check_server_connectivity(self, floating_ip, address_list,
                                   should_connect=True):
        # checks server connectivity
        private_key = self.get_stack_output(self.stack_identifier,
                                            'private_key')
        ssh_source = self.get_remote_client(floating_ip,
                                            private_key=private_key)
        for remote_ip in address_list:
            if should_connect:
                msg = ("Timed out waiting for %s to become "
                       "reachable") % remote_ip
            else:
                msg = "ip address %s is reachable" % remote_ip
            try:
                self.assertTrue(self._check_remote_connectivity
                                (ssh_source, remote_ip, should_connect),
                                msg)
            except Exception:
                LOG.exception(("Unable to access %(dest)s via ssh to "
                               "floating-ip %(src)s") %
                              {'dest': remote_ip, 'src': floating_ip})
                raise

    @decorators.idempotent_id('f693a425-b018-4cde-96ab-cdd5b858e15c')
    @test.attr(type=["smoke"])
    def test_created_resources(self):
        """Verifies created resources from template ."""
        for resource in self.resources:
            msg = 'resource %s not create successfully' \
                  % resource['logical_resource_id']
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'],
                             msg)
            self.assertIsInstance(resource, dict)

    @decorators.idempotent_id('3c3ccfcb-e50b-4372-82dc-d5b473acd506')
    @test.attr(type=["smoke"])
    def test_created_network(self):
        """Verifies created neutron networks."""
        network_id_list = self._resource_list_check(resource='networks')
        for network_id in network_id_list:
            body = self.networks_client.show_network(network_id)
            self.assertEqual('True', str(body['network']['admin_state_up']))
            msg = 'newtwork %s not found' % body['network']['name']
            self.assertIsNotNone(self.vsm.get_logical_switch(network_id), msg)

    @decorators.idempotent_id('b3b103a7-69b2-42ea-a1b8-aa11cc551df9')
    @test.attr(type=["smoke"])
    def test_created_router(self):
        """Verifies created router."""
        router_id_list = self._resource_list_check(resource='routers')
        for router_id in router_id_list:
            body = self.routers_client.show_router(router_id)
            self.assertEqual('True', str(body['router']['admin_state_up']))
            if (body['router']['router_type']) != 'shared':
                router_edge_name = "%s-%s" % (
                    body['router']['name'], body['router']['id'])
                exc_edge = self.vsm.get_edge(router_edge_name)
                msg = 'exc edge %s not found' % body['router']['name']
                self.assertTrue(exc_edge is not None, msg)

    @decorators.idempotent_id('2b29dfef-6d9f-4a70-9377-af432100ef10')
    @test.attr(type=["smoke"])
    def test_created_server(self):
        """Verifies created sever."""
        server_id_list = self._resource_list_check(resource='servers')
        for server_id in server_id_list:
            server = self.servers_client.show_server(server_id)['server']
            msg = 'server %s not active ' % (server)
            self.assertEqual('ACTIVE', str(server['status']), msg)

    @decorators.idempotent_id('d937a607-aa5e-4cf1-bbf9-00044cbe7190')
    @test.attr(type=["smoke"])
    def test_topo1_same_network_connectivity_(self):
        """Verifies same network connnectivity for Topology 1 """
        address_list = []
        topo1_server1_floatingip = self.get_stack_output(self.stack_identifier,
                                                   'topo1_server1_floatingip')
        server4_private_ip = self.get_stack_output(self.stack_identifier,
                                                   'topo1_server4_private_ip')
        address_list.append(server4_private_ip)
        LOG.info((" floating ip :%(rsp)s and private ip list : %(rsp1)s") %
                 {"rsp": topo1_server1_floatingip, "rsp1": address_list})
        self._check_server_connectivity(topo1_server1_floatingip, address_list,
                                        should_connect=True)

    @decorators.idempotent_id('fdbc8b1a-755a-4b37-93e7-0a268e422f05')
    @test.attr(type=["smoke"])
    def test_topo1_cross_network_connectivity(self):
        """Verifies cross network connnectivity for Topology 1 """
        address_list = []
        topo1_server1_floatingip = self.get_stack_output(
            self.stack_identifier, 'topo1_server1_floatingip')
        server2_private_ip = self.get_stack_output(self.stack_identifier,
                                                   'topo1_server2_private_ip')
        server3_private_ip = self.get_stack_output(self.stack_identifier,
                                                   'topo1_server3_private_ip')
        address_list.append(server2_private_ip)
        address_list.append(server3_private_ip)
        LOG.info(("floating ip :%(rsp)s and private ip list : %(rsp1)s") %
                 {"rsp": topo1_server1_floatingip, "rsp1": address_list})
        self._check_server_connectivity(topo1_server1_floatingip, address_list,
                                        should_connect=True)

    @decorators.idempotent_id('bcefd117-c55e-499d-a34b-653b8981f1c5')
    @test.attr(type=["smoke"])
    def test_topo1_cross_external_connectivity(self):
        """Verifies external network connnectivity for Topology 1 """
        address_list = []
        topo1_server1_floatingip = self.get_stack_output(self.stack_identifier,
                                                   'topo1_server1_floatingip')
        external_network = self.external_network[0]
        address_list.append(external_network)
        LOG.info(("floating ip :%(rsp)s and external ip : %(rsp1)s") %
                 {"rsp": topo1_server1_floatingip, "rsp1": address_list})
        self._check_server_connectivity(topo1_server1_floatingip, address_list,
                                        should_connect=True)
