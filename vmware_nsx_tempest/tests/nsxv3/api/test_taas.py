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

from oslo_log import log as logging

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest import test

from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest._i18n import _LW
from vmware_nsx_tempest.services import nsxv3_client
from vmware_nsx_tempest.services import taas_client

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TaaSJsonTest(base.BaseNetworkTest):

    """Tap Service and Tap Flow API's can be accessed using the TaaS Client .

    Tap Service is created by associating floating ip to the destination
    port and Tap Flow is created by binding the Tap Service created with the
    source port .

    CRUD Operations for Tap Service and Tap Flow are covered .

    """

    @classmethod
    def skip_checks(cls):
        super(TaaSJsonTest, cls).skip_checks()
        if not test.is_extension_enabled('taas', 'network'):
            msg = "taas extension not enabled."
            raise cls.skipException(msg)
        if not CONF.network.public_network_id:
            msg = "Public network id not found."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TaaSJsonTest, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id
        # Create the topology to test TaaS Client
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(data_utils.rand_name('router-'),
                                       external_network_id=cls.ext_net_id)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        for i in range(4):
            cls.create_port(cls.network)

    @classmethod
    def setup_clients(cls):
        super(TaaSJsonTest, cls).setup_clients()
        try:
            cls.tclient = taas_client.get_client(cls.manager)
            cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                               CONF.nsxv3.nsx_user,
                                               CONF.nsxv3.nsx_password)
        except AttributeError as attribute_err:
            LOG.warning(
                _LW("Failed to locate the attribute, Error: %(err_msg)s") %
                {"err_msg": attribute_err.__str__()})

    def _create_floating_ip(self, port_index):
        # Create and associates floating ip to the port based on port index
        create_body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[int(port_index)]['id'])
        fip = create_body['floatingip']
        return fip

    def _create_tap_service_env(self, port_index):
        """
         Creates floating ip and device_tap_service dict for
         Tap service environment
        """
        fip = self._create_floating_ip(port_index)
        tap_service_name = data_utils.rand_name('tapservice-ch')
        device_tap_service = {
            "description": 'TAP1', "name": tap_service_name,
            "port_id": self.ports[port_index]['id'],
            "tenant_id": self.ports[0]['tenant_id']
        }
        return fip, device_tap_service

    def _create_tap_flow_env(self, tap_service_id, tap_flow_direction,
                             src_port_index):
        # Creates device_tap_flow dict for tap flow environment
        tap_flow_name = data_utils.rand_name('tapflow-ch')
        device_tap_flow = {
            "description": 'tapflow1', "direction": tap_flow_direction,
            "name": tap_flow_name, "source_port": self.ports[src_port_index][
                'id'], "tap_service_id": tap_service_id,
            "tenant_id": self.ports[0]['tenant_id']
        }
        return device_tap_flow

    def _resource_cleanup(self, fip, tapservice_id, tapflow_id):
        # Cleans Tap Service and Tap Flow resources after each test
        if fip != 'null':
            self.addCleanup(self.floating_ips_client.delete_floatingip,
                            fip['id'])
        if tapflow_id != 'null':
            self.tclient.delete_tap_flow(tapflow_id)
        if tapservice_id != 'null':
            self.tclient.delete_tap_service(tapservice_id)

    @test.attr(type='nsxv3')
    @test.idempotent_id('dc5c1ec6-8c18-11e6-ae22-56b6b6499611')
    def test_create_tap_service(self):
        """
         Tap service create api is tested , Tap Service is created with
         destination port associated with floating ip
        """
        LOG.info(_LI(
            "Testing Tap Service Create api with floating ip associated to "
            "destination port"))
        # Create tap service env
        fip, device_tap_service = self._create_tap_service_env(port_index=0)
        # Create Tap Service
        rsp = self.tclient.create_tap_service(**device_tap_service)
        LOG.info(_LI("response from tap serive create : %(rsp)s") %
                 {"rsp": rsp})
        self.assertEqual('201',
                         rsp.response["status"],
                         "Response code is not 201 ")
        self.assertIn(self.ports[0]['id'], rsp['tap_service']['port_id'])
        self._resource_cleanup(fip, rsp['tap_service']['id'], 'null')

    @test.attr(type='nsxv3')
    @test.idempotent_id('dc5c21f0-8c18-11e6-ae22-56b6b6499611')
    def test_list_tap_service(self):
        """
         Tap Service List api is tested
        """
        LOG.info(_LI(
            "Testing Tap Service List api with floating ip associated "
            "to destination port "))
        # Create tap service env
        fip, device_tap_service = self._create_tap_service_env(port_index=0)
        # Create Tap Service
        rsp_create = self.tclient.create_tap_service(**device_tap_service)
        # List Tap Service
        rsp_list = self.tclient.list_tap_service()
        LOG.info(_LI("response from tap list : %(rsp)s") % {"rsp": rsp_list})
        self.assertEqual('200',
                         rsp_list.response["status"],
                         "Response code is not 200 ")
        self.assertIn(device_tap_service['name'],
                      rsp_list['tap_services'][0]['name'])
        self.assertIn(self.ports[0]['id'], rsp_list[
            'tap_services'][0]['port_id'])
        self._resource_cleanup(fip, rsp_create['tap_service']['id'], 'null')

    @test.attr(type='nsxv3')
    @test.idempotent_id('dc5c2394-8c18-11e6-ae22-56b6b6499611')
    def test_show_tap_service(self):
        """
         Tap Service Show api is tested
        """
        LOG.info(_LI(
            "Testing Tap Service Show api with floating ip associated to "
            "destination port "))
        # Create tap service env
        fip, device_tap_service = self._create_tap_service_env(port_index=0)
        # Create Tap Service
        rsp_create = self.tclient.create_tap_service(**device_tap_service)
        # Show Tap Service
        rsp_show = self.tclient.show_tap_service(
            rsp_create['tap_service']['id'])
        LOG.info(_LI("response from tap list : %(rsp)s") % {"rsp": rsp_show})
        self.assertEqual('200',
                         rsp_show.response["status"],
                         "Response code is not 200 ")
        self.assertIn(device_tap_service['name'],
                      rsp_show['tap_service']['name'])
        self.assertIn(self.ports[0]['id'],
                      rsp_show['tap_service']['port_id'])
        self._resource_cleanup(fip, rsp_create['tap_service']['id'], 'null')

    @test.attr(type='nsxv3')
    @test.idempotent_id('dc5c2538-8c18-11e6-ae22-56b6b6499611')
    def test_delete_tap_service(self):
        """
         Tap Service Delete api is tested
        """
        LOG.info(
            _LI(
                "Testing Tap delete api with floating ip associated "
                "to destination port "))
        # Create tap service env
        fip, device_tap_service = self._create_tap_service_env(port_index=0)
        # Create Tap Service
        rsp_create = self.tclient.create_tap_service(**device_tap_service)
        LOG.info(_LI("response from tap list : %(rsp)s") % {"rsp": rsp_create})
        self.assertEqual('201',
                         rsp_create.response["status"],
                         "Response code is not 201 ")
        # Delete Tap Service
        rsp_delete = self.tclient.delete_tap_service(
            rsp_create['tap_service']['id'])
        self.assertEqual('204',
                         rsp_delete.response["status"],
                         "Response code is not 204 ")
        rsp_list = self.tclient.list_tap_service()
        LOG.info(_LI("response from tap list : %(rsp)s") % {"rsp": rsp_list})
        self._resource_cleanup(fip, 'null', 'null')

    @test.attr(type='nsxv3')
    @test.idempotent_id('dc5c2a7e-8c18-11e6-ae22-56b6b6499611')
    def test_create_tap_flow(self):
        """
         Tap flow create api is tested , Tap Service is created with
         destination port associated with floating ip
        """
        LOG.info(_LI(
            "Testing Tap flow create api with direction BOTH and  "
            "floating ip associated to destination port "))
        # Create tap service env
        fip, device_tap_service = self._create_tap_service_env(port_index=0)
        # Create Tap Service
        rsp_tap_service = self.tclient.create_tap_service(**device_tap_service)
        LOG.info(_LI("response from tap service : %(rsp)s") %
                 {"rsp": rsp_tap_service})
        self.assertEqual('201',
                         rsp_tap_service.response["status"],
                         "Response code is not 201 ")
        # Create Tap Flow env
        device_tap_flow = self._create_tap_flow_env(
            tap_service_id=rsp_tap_service['tap_service']['id'],
            tap_flow_direction='BOTH', src_port_index=1)
        # Create Tap flow
        rsp_tap_flow = self.tclient.create_tap_flow(**device_tap_flow)
        LOG.info(_LI("response from flow : %(rsp)s") % {"rsp": rsp_tap_flow})
        # NSX backend check for Switch Profile
        nsx_switch_profiles = self.nsx.get_logical_switch_profiles()
        switch_profile = []
        for ls in nsx_switch_profiles:
            if ls['display_name'] == device_tap_flow['name']:
                self.assertIn(ls['direction'], 'BIDIRECTIONAL')
                self.assertIn(ls['destinations'][0],
                              fip['floating_ip_address'])
                switch_profile = [ls]
        self.assertNotEqual(len(switch_profile), 0, "Port mirror profile is "
                            "not found in NSX ")
        self.assertEqual('201',
                         rsp_tap_flow.response["status"],
                         "Response code is not 201 ")
        self.assertIn(self.ports[1]['id'], rsp_tap_flow[
            'tap_flow']['source_port'])
        self.assertEqual(device_tap_flow['name'], rsp_tap_flow['tap_flow'][
            'name'])
        self.assertEqual(device_tap_flow['direction'], rsp_tap_flow[
            'tap_flow']['direction'])
        self.assertEqual(rsp_tap_service['tap_service'][
                         'id'], rsp_tap_flow['tap_flow']['tap_service_id'])
        self._resource_cleanup(fip, rsp_tap_service['tap_service'][
            'id'], rsp_tap_flow['tap_flow']['id'])

    @test.attr(type='nsxv3')
    @test.idempotent_id('dc5c2c5e-8c18-11e6-ae22-56b6b6499611')
    def test_create_tap_flow_multiple(self):
        """
         Multiple Tap flow's are created in with 'IN' and 'OUT' , Tap Service
         is created with destination port associated with floating ip's for
         each Tap Flow
        """
        LOG.info(_LI(
            "Multiple Tap flow's created  with direction IN and OUT and"
            "floating ip associated to destination port "))
        # Create tap service env
        fip1, device_tap_service1 = self._create_tap_service_env(port_index=0)
        # Create tap service env
        fip2, device_tap_service2 = self._create_tap_service_env(port_index=1)
        # Create Tap Service 1 and Tap Service 2
        rsp_tap_service1 = self.tclient.create_tap_service(
            **device_tap_service1)
        rsp_tap_service2 = self.tclient.create_tap_service(
            **device_tap_service2)
        LOG.info(_LI(
            "response from tap service1 and tap service2  : %(rsp1)s  "
            "%(rsp2)s ") % {
            "rsp1": rsp_tap_service1, "rsp2": rsp_tap_service2
        })
        # Create Tap Flow env
        device_tap_flow1 = self._create_tap_flow_env(
            tap_service_id=rsp_tap_service1['tap_service']['id'],
            tap_flow_direction='IN', src_port_index=2)
        # Create Tap Flow env
        device_tap_flow2 = self._create_tap_flow_env(
            tap_service_id=rsp_tap_service2['tap_service']['id'],
            tap_flow_direction='OUT', src_port_index=3)
        # Create Tap Flow1 and Tap Flow2
        rsp_tap_flow1 = self.tclient.create_tap_flow(**device_tap_flow1)
        rsp_tap_flow2 = self.tclient.create_tap_flow(**device_tap_flow2)
        LOG.info(_LI(
            "response from tap flow1 and tap flow2  : %(rsp1)s  %(rsp2)s ") % {
            "rsp1": rsp_tap_flow1,
            "rsp2": rsp_tap_flow2
        })
        # NSX backend check for Switch Profile
        nsx_switch_profiles = self.nsx.get_logical_switch_profiles()
        profile_count = 0
        for ls in nsx_switch_profiles:
            if ls['display_name'].startswith('tapflow-ch-'):
                if ls['direction'] == 'INGRESS' or 'EGRESS':
                    profile_count += 1
        self.assertEqual(profile_count, 2, "Port mirror profile is "
                         "not found in NSX ")
        self.assertEqual(device_tap_flow1['name'], rsp_tap_flow1['tap_flow'][
            'name'])
        self.assertEqual(device_tap_flow2['name'], rsp_tap_flow2['tap_flow'][
            'name'])
        self.assertEqual(device_tap_flow1['direction'], rsp_tap_flow1[
            'tap_flow']['direction'])
        self.assertEqual(device_tap_flow2['direction'], rsp_tap_flow2[
            'tap_flow']['direction'])
        self._resource_cleanup(fip1, rsp_tap_service1['tap_service'][
            'id'], rsp_tap_flow1['tap_flow']['id'])
        self._resource_cleanup(fip2, rsp_tap_service2['tap_service'][
            'id'], rsp_tap_flow2['tap_flow']['id'])

    @test.attr(type='nsxv3')
    @test.idempotent_id('dc5c2dda-8c18-11e6-ae22-56b6b6499611')
    def test_list_tap_flow(self):
        """
         Tap flow list api is tested , Tap Service is created with
         destination port associated with floating ip
        """
        LOG.info(
            _LI(
                "Testing Tap Flow list api with floating ip associated to "
                "destination port "))
        # Create tap service env
        fip, device_tap_service = self._create_tap_service_env(port_index=0)
        # Create Tap Service
        rsp_tap_service = self.tclient.create_tap_service(**device_tap_service)
        LOG.info(_LI("response from tap service : %(rsp)s") %
                 {"rsp": rsp_tap_service})
        self.assertEqual('201',
                         rsp_tap_service.response["status"],
                         "Response code is not 201 ")
        # Create Tap Flow env
        device_tap_flow = self._create_tap_flow_env(
            tap_service_id=rsp_tap_service['tap_service']['id'],
            tap_flow_direction='BOTH', src_port_index=1)
        # Create Tap flow
        rsp_tap_flow = self.tclient.create_tap_flow(**device_tap_flow)
        LOG.info(_LI("response from flow : %(rsp)s") % {"rsp": rsp_tap_flow})
        self.assertEqual('201',
                         rsp_tap_flow.response["status"],
                         "Response code is not 201 ")
        self.assertIn(self.ports[1]['id'], rsp_tap_flow[
            'tap_flow']['source_port'])
        self.assertEqual(device_tap_flow['name'], rsp_tap_flow['tap_flow'][
            'name'])
        self.assertEqual(device_tap_flow['direction'], rsp_tap_flow[
            'tap_flow']['direction'])
        self.assertEqual(rsp_tap_service['tap_service'][
                         'id'], rsp_tap_flow['tap_flow']['tap_service_id'])
        # List Tap Flow
        rsp_tap_list_flow = self.tclient.list_tap_flow()
        LOG.info(_LI("response from tap list : %(rsp)s") %
                 {"rsp": rsp_tap_list_flow})
        self.assertEqual('200',
                         rsp_tap_list_flow.response["status"],
                         "Response code is not 200 ")
        self.assertIn(device_tap_flow['name'], rsp_tap_list_flow[
            'tap_flows'][0][
            'name'])
        self.assertIn(self.ports[1]['id'], rsp_tap_list_flow[
            'tap_flows'][0]['source_port'])
        self._resource_cleanup(fip, rsp_tap_service['tap_service'][
            'id'], rsp_tap_flow['tap_flow']['id'])

    @test.attr(type='nsxv3')
    @test.idempotent_id('dc5c2f6a-8c18-11e6-ae22-56b6b6499611')
    def test_show_tap_flow(self):
        """
         Tap flow show api is tested , Tap Service is created with
         destination port associated with floating ip
        """
        LOG.info(_LI(
            "Testing Tap Service Show api with floating ip associated "
            "to destination port "))
        # Create tap service env
        fip, device_tap_service = self._create_tap_service_env(port_index=0)
        # Create Tap Service
        rsp_tap_service = self.tclient.create_tap_service(**device_tap_service)
        LOG.info(_LI("response from tap service : %(rsp)s") %
                 {"rsp": rsp_tap_service})
        self.assertEqual('201',
                         rsp_tap_service.response["status"],
                         "Response code is not 201 ")
        # Create Tap Flow env
        device_tap_flow = self._create_tap_flow_env(
            tap_service_id=rsp_tap_service['tap_service']['id'],
            tap_flow_direction='BOTH', src_port_index=1)
        # Create Tap flow
        rsp_tap_flow = self.tclient.create_tap_flow(**device_tap_flow)
        # Show Tap Flow
        rsp_tap_flow_show = self.tclient.show_tap_flow(
            rsp_tap_flow['tap_flow']['id'])
        LOG.info(_LI("response from tap list : %(rsp)s") %
                 {"rsp": rsp_tap_flow_show})
        self.assertEqual('200',
                         rsp_tap_flow_show.response["status"],
                         "Response code is not 200 ")
        self.assertIn(device_tap_flow['name'], rsp_tap_flow_show['tap_flow'][
            'name'])
        self.assertIn(self.ports[1]['id'], rsp_tap_flow_show[
            'tap_flow']['source_port'])
        self._resource_cleanup(fip, rsp_tap_service['tap_service'][
            'id'], rsp_tap_flow['tap_flow']['id'])

    @test.attr(type='nsxv3')
    @test.idempotent_id('dc5c310e-8c18-11e6-ae22-56b6b6499611')
    def test_delete_tap_flow(self):
        """
         Tap flow delete api is tested , Tap Service is created with
         destination port associated with floating ip
        """
        LOG.info(_LI(
            "Testing Tap flow delete api with floating ip associated to "
            "destination port "))
        # Create tap service env
        fip, device_tap_service = self._create_tap_service_env(port_index=0)
        # Create Tap Service
        rsp_tap_service = self.tclient.create_tap_service(**device_tap_service)
        LOG.info(_LI("response from tap service : %(rsp)s") %
                 {"rsp": rsp_tap_service})
        self.assertEqual('201',
                         rsp_tap_service.response["status"],
                         "Response code is not 201 ")
        # Create Tap Flow env
        device_tap_flow = self._create_tap_flow_env(
            tap_service_id=rsp_tap_service['tap_service']['id'],
            tap_flow_direction='BOTH', src_port_index=1)
        # Create Tap flow
        rsp_tap_flow = self.tclient.create_tap_flow(**device_tap_flow)

        LOG.info(_LI("response from flow : %(rsp)s") % {"rsp": rsp_tap_flow})
        self.assertEqual('201',
                         rsp_tap_flow.response["status"],
                         "Response code is not 201 ")
        self.assertIn(self.ports[1]['id'], rsp_tap_flow[
            'tap_flow']['source_port'])
        self.assertEqual(device_tap_flow['name'], rsp_tap_flow['tap_flow'][
            'name'])
        self.assertEqual(device_tap_flow['direction'], rsp_tap_flow[
            'tap_flow']['direction'])
        self.assertEqual(rsp_tap_service['tap_service'][
                         'id'], rsp_tap_flow['tap_flow']['tap_service_id'])
        rsp_tap_flow_delete = self.tclient.delete_tap_flow(
            rsp_tap_flow['tap_flow']['id'])
        LOG.info(_LI("response from tap list : %(rsp)s") %
                 {"rsp": rsp_tap_flow_delete})
        self.assertEqual('204',
                         rsp_tap_flow_delete.response["status"],
                         "Response code is not 204 ")
        rsp_tap_list_flow = self.tclient.list_tap_flow()
        LOG.info(_LI("response from tap list : %(rsp)s") %
                 {"rsp": rsp_tap_list_flow})
        self._resource_cleanup(fip, rsp_tap_service[
            'tap_service']['id'], 'null')

    @test.attr(type='nsxv3')
    @test.idempotent_id('dc5c328a-8c18-11e6-ae22-56b6b6499611')
    def test_create_tap_flow_negative_nofloatingip(self):
        """
         Tap flow create api is tested , Tap Service is created with
         destination port associated to non floating ip
        """
        LOG.info(_LI(
            "Testing Tap flow create api with non floating ip "
            "associated to destination port "))
        tap_service_name = data_utils.rand_name('tapservice-ch')
        device_tap_service = {
            "description": 'tapservice1', "name": tap_service_name,
            "port_id": self.ports[0]['id'],
            "tenant_id": self.ports[0]['tenant_id']
        }
        # Create Tap Service
        rsp_tap_service = self.tclient.create_tap_service(**device_tap_service)
        LOG.info(_LI("response from tap service : %(rsp)s") %
                 {"rsp": rsp_tap_service})
        self.assertEqual('201',
                         rsp_tap_service.response["status"],
                         "Response code is not 201 ")
        tap_flow_name = data_utils.rand_name('tapflow-ch')
        device_tap_flow = {
            "description": 'tapflow1', "direction": "BOTH",
            "name": tap_flow_name, "source_port": self.ports[1]['id'],
            "tap_service_id": rsp_tap_service['tap_service']['id'],
            "tenant_id": self.ports[0]['tenant_id']
        }
        # Create Tap Flow with a non floating ip associated to destination port
        try:
            self.tclient.create_tap_flow(**device_tap_flow)
        except Exception as e:
            LOG.info(_LI("response from exception  %(rsp)s") % {"rsp": e})
            self._resource_cleanup('null', rsp_tap_service[
                'tap_service']['id'], 'null')

    @test.attr(type='nsxv3')
    @test.idempotent_id('dc5c3802-8c18-11e6-ae22-56b6b6499611')
    def test_create_tap_flow_negative_nosrcport(self):
        """
         Tap flow create api is tested with non existent src port
        """
        LOG.info(
            _LI("Testing Tap flow create api with non existent src port  "))
        tap_service_name = data_utils.rand_name('tapservice-ch')
        device_tap_service = {
            "description": 'tapservice1', "name": tap_service_name,
            "port_id": self.ports[0]['id'],
            "tenant_id": self.ports[0]['tenant_id']
        }
        # Create Tap Service
        rsp_tap_service = self.tclient.create_tap_service(**device_tap_service)
        LOG.info(_LI("response from tap service : %(rsp)s") %
                 {"rsp": rsp_tap_service})
        self.assertEqual('201',
                         rsp_tap_service.response["status"],
                         "Response code is not 201 ")
        tap_flow_name = data_utils.rand_name('tapflow-ch')
        device_tap_flow = {
            "description": 'tapflow1', "direction": "BOTH",
            "name": tap_flow_name,
            "source_port": '2ad76061-252e-xxxx-9d0f-dd94188be9cc',
            "tap_service_id": rsp_tap_service['tap_service']['id'],
            "tenant_id": self.ports[0]['tenant_id']
        }
        # Create Tap Flow with a dummy non existent source port
        try:
            self.tclient.create_tap_flow(**device_tap_flow)
        except Exception as e:
            LOG.info(_LI("response from  exception  %(rsp)s") % {"rsp": e})
            self._resource_cleanup('null', rsp_tap_service[
                'tap_service']['id'], 'null')
