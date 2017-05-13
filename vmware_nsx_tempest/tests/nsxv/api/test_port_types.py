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

import base_provider as base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as ex
from tempest import test

from oslo_log import log as logging

CONF = config.CONF

LOG = logging.getLogger(__name__)


class PortTypeTest(base.BaseAdminNetworkTest):
    """NSX-V OpenStack port types test

       Positive
       - Create direct port
       - Enable port direct vnic-type
       - Delete direct port
       - List ports with direct port
       - Create, update, delete direct port
       Negative
       - Create direct port without flat network with port configs
       - Create direct port with flat network without port configs
       - Update direct port with flat network without port configs
       - Update direct port without flat network with port configs
    """

    @classmethod
    def setup_clients(cls):
        super(PortTypeTest, cls).setup_clients()

    @classmethod
    def resource_setup(cls):
        super(PortTypeTest, cls).resource_setup()

    def _create_flat_network(self, _auto_clean_up=True, network_name=None,
                             **kwargs):
        network_name = network_name or data_utils.rand_name('flat-net')
        post_body = {'name': network_name,
                     'provider:network_type': 'flat'}
        post_body.update(kwargs)
        LOG.debug("create FLAT network: %s", str(post_body))
        body = self.admin_networks_client.create_network(**post_body)
        network = body['network']
        self.networks.append(network)
        if _auto_clean_up:
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.delete_network, network['id'])
        return network

    def _create_direct_port(self, network_id, _auto_clean_up=True,
                            port_name=None, **kwargs):
        dir_port_name = port_name or data_utils.rand_name('direct-port')
        post_body = {'name': dir_port_name,
                     'port_security_enabled': 'False',
                     'security_groups': [],
                     'binding:vnic_type': 'direct'}
        post_body.update(kwargs)
        LOG.debug("create DIRECT port: %s", str(post_body))
        body = self.create_port(network_id=network_id, **post_body)
        dir_port = body['port']
        if _auto_clean_up:
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.delete_port, dir_port['id'])
        return dir_port

    @test.attr(type='nsxv')
    @decorators.idempotent_id('ebb15f36-79bd-4461-91b5-84a57616730c')
    def test_create_direct_port(self):
        """
        Test create a direct openstack port. After creation, check
        OpenStack for the port vnic-type.
        """
        test_flat_net = self._create_flat_network()
        dir_port = self._create_direct_port(network_id=test_flat_net['id'])
        self.assertEqual(dir_port['binding:vnic_type'], 'direct',
                         "Created port type is not DIRECT")

    @test.attr(type='nsxv')
    @decorators.idempotent_id('2eaa0014-3265-479c-9012-c110df566ef1')
    def test_enable_port_direct(self):
        """
        Test updating a port to be a direct openstack port.
        After updating, check nsx_v backend for the port type.
        """
        test_flat_net = self._create_flat_network()
        test_port_name = data_utils.rand_name('test-port-')
        orig_post = {'name': test_port_name,
                     'port_security_enabled': 'False',
                     'security_groups': []}
        LOG.debug("create NORMAL port: %s", str(orig_post))
        test_port = self.create_port(network_id=test_flat_net['id'],
                                     **orig_post)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_port, test_port['port']['id'])
        post_body = {'binding:vnic_type': 'direct'}
        LOG.debug("update port to be DIRECT: %s", str(orig_post))
        self.assertEqual(test_port['port']['binding:vnic_type'], 'normal',
                         "Port vnic-type is not NORMAL")
        updated_port = self.update_port(test_port['port']['id'], **post_body)
        self.assertEqual(updated_port['port']['binding:vnic_type'], 'direct',
                         "Port vnic-type was not updated to DIRECT")

    @test.attr(type='nsxv')
    @decorators.idempotent_id('d77125af-7e8f-4dcf-a3a4-7956b3eaa2d2')
    def test_delete_direct_port(self):
        """
        Test create, then delete a direct openstack port.
        Verify port type and port delete.
        """
        test_flat_net = self._create_flat_network()
        dir_port = self._create_direct_port(network_id=test_flat_net['id'])
        self.assertEqual(dir_port['binding:vnic_type'], 'direct',
                         "Port type is not DIRECT")
        self.assertFalse(self.delete_port(dir_port['id']),
                         "Delete of Direct port was not successful")

    @test.attr(type='nsxv')
    @decorators.idempotent_id('b69f5ff1-7e86-4790-9392-434cd9ab808f')
    def test_list_direct_ports(self):
        """
        Create one each of a normal and direct port.
        Verify that both ports are included in port-list output.
        """
        test_list_ports = []
        test_flat_net = self._create_flat_network()
        dir_port = self._create_direct_port(network_id=test_flat_net['id'])
        test_list_ports.append(dir_port)
        vanilla_port_name = data_utils.rand_name('vanilla-port-')
        vanilla_post = {'name': vanilla_port_name}
        body = self.create_port(network_id=test_flat_net['id'],
                                **vanilla_post)
        test_port = body['port']
        test_list_ports.append(test_port)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_port, test_port['id'])
        body = self.admin_ports_client.list_ports(
            network_id=test_flat_net['id'])
        ports_list = body['ports']
        pids_list = [p['id'] for p in ports_list]
        ports_not_listed = []
        for port in test_list_ports:
            if port['id'] not in pids_list:
                ports_not_listed.append(port['id'])
        self.assertEmpty(ports_not_listed, "These ports not listed: %s"
                         % ports_not_listed)

    @test.attr(type='nsxv')
    @decorators.idempotent_id('9b7ec966-f4e4-4087-9789-96a3aa669fa2')
    def test_create_update_delete_direct_port(self):
        """
        Create, update, delete direct port. Verify port type and update
        operation.
        """
        test_flat_net = self._create_flat_network()
        dir_port = self._create_direct_port(network_id=test_flat_net['id'])
        self.assertEqual(dir_port['binding:vnic_type'], 'direct',
                         "Port VNIC_TYPE should be set to DIRECT")
        updated_port_name = data_utils.rand_name('update-port-')
        updated_post = {'name': updated_port_name}
        updated_port = self.update_port(dir_port['id'], **updated_post)['port']
        self.assertEqual(updated_port['binding:vnic_type'], 'direct',
                         "VNIC_TYPE is not correct type, should be DIRECT")
        self.assertEqual(updated_port['name'], updated_port_name,
                         "Port name should be updated to %s"
                         % updated_port_name)

    @test.attr(type='nsxv')
    @test.attr(type='negative')
    @decorators.idempotent_id('e661ba70-0ab4-4f91-8d84-c5c102ec5793')
    def test_create_direct_port_without_flat_network_negative(self):
        """
        Create a network. Create a direct openstack port.
        Creation should fail on a bad request since flat net prereq is not met
        """
        net_name = data_utils.rand_name('test-net')
        net_body = self.create_network(name=net_name)
        test_net = net_body['network']
        self.assertRaises(ex.BadRequest, self._create_direct_port,
                          network_id=test_net['id'])

    @test.attr(type='nsxv')
    @test.attr(type='negative')
    @decorators.idempotent_id('ee87287f-4ec6-4502-9bc1-855fa7c93e90')
    def test_create_direct_port_w_flat_net_wout_port_settings_negative(self):
        """
        Create a flat network. Create a direct openstack port without required
        port settings.
        """
        test_flat_net = self._create_flat_network()
        test_port_name = data_utils.rand_name('test-port-')
        orig_post = {'name': test_port_name, 'binding:vnic_type': 'direct'}
        LOG.debug("create DIRECT port: %s", str(orig_post))
        self.assertRaises(ex.BadRequest,
                          self.create_port, network_id=test_flat_net['id'],
                          **orig_post)

    @test.attr(type='nsxv')
    @test.attr(type='negative')
    @decorators.idempotent_id('03e0065e-6d76-45d5-9192-ce89853dfa9e')
    def test_update_direct_port_w_flat_net_wout_port_configs_negative(self):
        """
        Create a flat network. Create an openstack port with vnic-type normal.
        Update port to set vnic-type to direct, without required port settings.
        Update should fail on a bad request since prereq is not met.
        """
        test_flat_net = self._create_flat_network()
        test_port_name = data_utils.rand_name('test-port-')
        orig_post = {'name': test_port_name}
        LOG.debug("create NORMAL port: %s", str(orig_post))
        test_port = self.create_port(network_id=test_flat_net['id'],
                                     **orig_post)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_port, test_port['port']['id'])
        post_body = {'binding:vnic_type': 'direct'}
        LOG.debug("update port to be DIRECT: %s", str(orig_post))
        self.assertEqual(test_port['port']['binding:vnic_type'], 'normal',
                         "Orig port should be vnic-type NORMAL")
        self.assertRaises(ex.BadRequest, self.update_port,
                          test_port['port']['id'], **post_body)

    @test.attr(type='nsxv')
    @test.attr(type='negative')
    @decorators.idempotent_id('d3e75ed7-f3e5-4395-9ab0-063e7a8c141c')
    def test_update_direct_port_wout_flat_net_with_port_configs_negative(self):
        """
        Create a network. Create a normal openstack port. Update port to direct
        vnic-type. Update should fail since flat net prereq is not met
        """
        net_name = data_utils.rand_name('test-net')
        net_body = self.create_network(name=net_name)
        test_net = net_body['network']
        test_port_name = data_utils.rand_name('test-port-')
        orig_post = {'name': test_port_name}
        LOG.debug("create NORMAL port: %s", str(orig_post))
        test_port = self.create_port(network_id=test_net['id'],
                                     **orig_post)
        post_body = {'port_security_enabled': 'False',
                     'security_groups': [],
                     'binding:vnic_type': 'direct'}
        self.assertRaises(ex.BadRequest, self.update_port,
                          test_port['port']['id'], **post_body)
