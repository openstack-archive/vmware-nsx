# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log as logging

from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions
from tempest import test

from vmware_nsx_tempest.tests.nsxv.api.lbaas import base

CONF = config.CONF

LOG = logging.getLogger(__name__)


class ListenersTest(base.BaseTestCase):

    """Tests the following operations in the Neutron-LBaaS API

    using the REST client for Listeners:

        list listeners
        create listener
        get listener
        update listener
        delete listener
    """

    @classmethod
    def resource_setup(cls):
        super(ListenersTest, cls).resource_setup()
        cls.create_lb_kwargs = {'tenant_id': cls.subnet['tenant_id'],
                                'vip_subnet_id': cls.subnet['id']}
        cls.load_balancer = cls._create_active_load_balancer(
            **cls.create_lb_kwargs)
        cls.protocol = 'HTTP'
        cls.port = 80
        cls.load_balancer_id = cls.load_balancer['id']
        cls.create_listener_kwargs = {'loadbalancer_id': cls.load_balancer_id,
                                      'protocol': cls.protocol,
                                      'protocol_port': cls.port}
        cls.listener = cls._create_listener(**cls.create_listener_kwargs)
        cls.listener_id = cls.listener['id']

    @test.attr(type='smoke')
    @test.idempotent_id('32ae6156-d809-49fc-a45b-55269660651c')
    def test_get_listener(self):
        """Test get listener"""
        listener = self._show_listener(self.listener_id)
        self.assertEqual(self.listener, listener)
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='smoke')
    @test.idempotent_id('4013ab83-924a-4c53-982e-83388d7ad4d9')
    def test_list_listeners(self):
        """Test get listeners with one listener"""
        listeners = self._list_listeners()
        self.assertEqual(len(listeners), 1)
        self.assertIn(self.listener, listeners)
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='smoke')
    @test.idempotent_id('04f58729-3f93-4616-bb9d-8baaff3542b2')
    def test_list_listeners_two(self):
        """Test get listeners with two listeners"""
        create_new_listener_kwargs = self.create_listener_kwargs
        create_new_listener_kwargs['protocol_port'] = 8080
        new_listener = self._create_listener(
            **create_new_listener_kwargs)
        new_listener_id = new_listener['id']
        self.addCleanup(self._delete_listener, new_listener_id)
        self._check_status_tree(
            load_balancer_id=self.load_balancer_id,
            listener_ids=[self.listener_id, new_listener_id])
        listeners = self._list_listeners()
        self.assertEqual(len(listeners), 2)
        self.assertIn(self.listener, listeners)
        self.assertIn(new_listener, listeners)
        self.assertNotEqual(self.listener, new_listener)

    @test.attr(type='smoke')
    @test.idempotent_id('7989096b-95c2-4b26-86b1-5aec0a2d8386')
    def test_create_listener(self):
        """Test create listener"""
        create_new_listener_kwargs = self.create_listener_kwargs
        create_new_listener_kwargs['protocol_port'] = 8081
        new_listener = self._create_listener(
            **create_new_listener_kwargs)
        new_listener_id = new_listener['id']
        self.addCleanup(self._delete_listener, new_listener_id)
        self._check_status_tree(
            load_balancer_id=self.load_balancer_id,
            listener_ids=[self.listener_id, new_listener_id])
        listener = self._show_listener(new_listener_id)
        self.assertEqual(new_listener, listener)
        self.assertNotEqual(self.listener, new_listener)

    @test.attr(type='negative')
    @test.idempotent_id('f7ef7f56-b791-48e8-9bbe-838a3ed94519')
    def test_create_listener_missing_field_loadbalancer(self):
        """Test create listener with a missing required field loadbalancer"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          protocol_port=self.port,
                          protocol=self.protocol)
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('c392301c-3d9a-4123-85c3-124e4e3253f6')
    def test_create_listener_missing_field_protocol(self):
        """Test create listener with a missing required field protocol"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          loadbalancer_id=self.load_balancer_id,
                          protocol_port=self.port)
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('12c1c5b5-81a9-4384-811e-7131f65f3b1b')
    def test_create_listener_missing_field_protocol_port(self):
        """Test create listener with a missing required field protocol_port"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          loadbalancer_id=self.load_balancer_id,
                          protocol=self.protocol)
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='smoke')
    @test.idempotent_id('214a7acc-eacb-4828-ad27-b7f4774947cf')
    def test_create_listener_missing_admin_state_up(self):
        """Test create listener with a missing admin_state_up field"""
        create_new_listener_kwargs = self.create_listener_kwargs
        create_new_listener_kwargs['protocol_port'] = 8083
        new_listener = self._create_listener(
            **create_new_listener_kwargs)
        new_listener_id = new_listener['id']
        self.addCleanup(self._delete_listener, new_listener_id)
        self._check_status_tree(
            load_balancer_id=self.load_balancer_id,
            listener_ids=[self.listener_id, new_listener_id])
        listener = self._show_listener(new_listener_id)
        self.assertEqual(new_listener, listener)
        self.assertTrue(new_listener['admin_state_up'])

    @test.attr(type='negative')
    @test.idempotent_id('86d892dd-9025-4051-a160-8bf1bbb8c64d')
    def test_create_listener_invalid_load_balancer_id(self):
        """Test create listener with an invalid load_balancer_id"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          loadbalancer_id="234*",
                          protocol_port=self.port,
                          protocol=self.protocol)
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('fb430d68-e68d-4bd0-b43d-f1175ad5a819')
    def test_create_listener_invalid_protocol(self):
        """Test create listener with an invalid protocol"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          loadbalancer_id=self.load_balancer_id,
                          protocol_port=self.port,
                          protocol="UDP")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('8e472e7e-a5c2-4dba-ac5c-993f6e6bb229')
    def test_create_listener_invalid_protocol_port(self):
        """Test create listener with an invalid protocol_port"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          loadbalancer_id=self.load_balancer_id,
                          protocol_port="9999999",
                          protocol=self.protocol)
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('57fc90f4-95e4-4f3c-8f53-32c7282b956e')
    def test_create_listener_invalid_admin_state_up(self):
        """Test update listener with an invalid admin_state_up"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          protocol_port=self.port,
                          protocol=self.protocol,
                          admin_state_up="abc123")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('556e1ab9-051c-4e9c-aaaa-f11d15de070b')
    def test_create_listener_invalid_tenant_id(self):
        """Test create listener with an invalid tenant id"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          loadbalancer_id=self.load_balancer_id,
                          protocol_port=self.port,
                          protocol=self.protocol,
                          tenant_id="&^%123")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @decorators.skip_because(bug="1637877")
    @test.idempotent_id('59d32fd7-06f6-4466-bdd4-0be23b15970c')
    def test_create_listener_invalid_name(self):
        """Test create listener with an invalid name"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          loadbalancer_id=self.load_balancer_id,
                          protocol_port=self.port,
                          protocol=self.protocol,
                          name='a' * 256)
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @decorators.skip_because(bug="1637877")
    @test.idempotent_id('95457f70-2c1a-4c14-aa80-db8e803d78a9')
    def test_create_listener_invalid_description(self):
        """Test create listener with an invalid description"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          loadbalancer_id=self.load_balancer_id,
                          protocol_port=self.port,
                          protocol=self.protocol,
                          description='a' * 256)
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('177d337f-fe0c-406c-92f1-a25c0103bd0f')
    def test_create_listener_invalid_connection_limit(self):
        """Test create listener_ids

        with an invalid value for connection _limit field
        """
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          loadbalancer_id=self.load_balancer_id,
                          protocol_port=self.port,
                          protocol=self.protocol,
                          connection_limit="&^%123")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('8af7b033-8ff7-4bdb-8949-76809745d8a9')
    def test_create_listener_empty_load_balancer_id(self):
        """Test create listener with an empty load_balancer_id"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          loadbalancer_id="",
                          protocol_port=self.port,
                          protocol=self.protocol)
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('242af61b-ce50-46e2-926a-6801600dcee4')
    def test_create_listener_empty_protocol(self):
        """Test create listener with an empty protocol"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          loadbalancer_id=self.load_balancer_id,
                          protocol_port=self.port,
                          protocol="")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('4866af4c-2b91-4bce-af58-af77f19d9119')
    def test_create_listener_empty_protocol_port(self):
        """Test create listener with an empty protocol_port"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          loadbalancer_id=self.load_balancer_id,
                          protocol_port="",
                          protocol=self.protocol)
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('09636ad1-a9d5-4c03-92db-ae5d9847993d')
    def test_create_listener_empty_admin_state_up(self):
        """Test update listener with an empty  admin_state_up"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          protocol_port=self.port,
                          protocol=self.protocol,
                          admin_state_up="")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @decorators.skip_because(bug="1638701")
    @test.idempotent_id('46fc3784-d676-42f7-953b-a23c1d62323d')
    def test_create_listener_empty_tenant_id(self):
        """Test create listener with an empty tenant id"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          loadbalancer_id=self.load_balancer_id,
                          protocol_port=self.port,
                          protocol=self.protocol,
                          tenant_id="")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='smoke')
    @test.idempotent_id('b4120626-a47e-4b4e-9b64-017e595c4daf')
    def test_create_listener_empty_name(self):
        """Test create listener with an empty name"""
        create_new_listener_kwargs = self.create_listener_kwargs
        create_new_listener_kwargs['protocol_port'] = 8081
        create_new_listener_kwargs['name'] = ""
        new_listener = self._create_listener(
            **create_new_listener_kwargs)
        new_listener_id = new_listener['id']
        self.addCleanup(self._delete_listener, new_listener_id)
        self._check_status_tree(
            load_balancer_id=self.load_balancer_id,
            listener_ids=[self.listener_id, new_listener_id])
        listener = self._show_listener(new_listener_id)
        self.assertEqual(new_listener, listener)

    @test.attr(type='smoke')
    @test.idempotent_id('af067d00-d496-4f02-87d6-40624c34d492')
    def test_create_listener_empty_description(self):
        """Test create listener with an empty description"""
        create_new_listener_kwargs = self.create_listener_kwargs
        create_new_listener_kwargs['protocol_port'] = 8082
        create_new_listener_kwargs['description'] = ""
        new_listener = self._create_listener(
            **create_new_listener_kwargs)
        new_listener_id = new_listener['id']
        self.addCleanup(self._delete_listener, new_listener_id)
        self._check_status_tree(
            load_balancer_id=self.load_balancer_id,
            listener_ids=[self.listener_id, new_listener_id])
        listener = self._show_listener(new_listener_id)
        self.assertEqual(new_listener, listener)

    @test.attr(type='negative')
    @test.idempotent_id('dd271757-c447-4579-a417-f9d0871b145c')
    def test_create_listener_empty_connection_limit(self):
        """Test create listener with an empty connection _limit field"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          loadbalancer_id=self.load_balancer_id,
                          protocol_port=self.port,
                          protocol=self.protocol,
                          connection_limit="")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('a1602217-e1b4-4f85-8a5e-d474477333f3')
    def test_create_listener_incorrect_attribute(self):
        """Test create a listener withan extra, incorrect field"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_listener,
                          incorrect_attribute="incorrect_attribute",
                          **self.create_listener_kwargs)
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='smoke')
    @test.idempotent_id('27c443ff-3aee-4ae6-8b9a-6abf3d5443bf')
    def test_update_listener(self):
        """Test update listener"""
        self._update_listener(self.listener_id,
                              name='new_name')
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])
        listener = self._show_listener(self.listener_id)
        self.assertEqual(listener.get('name'), 'new_name')

    @test.attr(type='negative')
    @test.idempotent_id('a709e4da-01ef-4dda-a336-f5e37268b5ea')
    def test_update_listener_invalid_tenant_id(self):
        """Test update listener with an invalid tenant id"""
        self.assertRaises(exceptions.BadRequest,
                          self._update_listener,
                          listener_id=self.listener_id,
                          tenant_id="&^%123")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('d88dd3d5-a52f-4306-ba53-e8f6f4e1b399')
    def test_update_listener_invalid_admin_state_up(self):
        """Test update a listener with an invalid admin_state_up"""
        self.assertRaises(exceptions.BadRequest,
                          self._update_listener,
                          listener_id=self.listener_id,
                          admin_state_up="$23")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @decorators.skip_because(bug="1637877")
    @test.idempotent_id('7c0efb63-90d9-43d0-b959-eb841ef39832')
    def test_update_listener_invalid_name(self):
        """Test update a listener with an invalid name"""
        self.assertRaises(exceptions.BadRequest,
                          self._update_listener,
                          listener_id=self.listener_id,
                          name='a' * 256)
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @decorators.skip_because(bug="1637877")
    @test.idempotent_id('ba9bfad8-dbb0-4cbc-b2e3-52bf72bc1fc5')
    def test_update_listener_invalid_description(self):
        """Test update a listener with an invalid description"""
        self.assertRaises(exceptions.BadRequest,
                          self._update_listener,
                          listener_id=self.listener_id,
                          description='a' * 256)
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('dcafa50b-cece-4904-bcc9-a0dd1ac99a7e')
    def test_update_listener_invalid_connection_limit(self):
        """Test update a listener with an invalid connection_limit"""
        self.assertRaises(exceptions.BadRequest,
                          self._update_listener,
                          listener_id=self.listener_id,
                          connection_limit="$23")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('27e009c5-3c79-414d-863d-24b731f03123')
    def test_update_listener_incorrect_attribute(self):
        """Test update a listener with an extra, incorrect field"""
        self.assertRaises(exceptions.BadRequest,
                          self._update_listener,
                          listener_id=self.listener_id,
                          name="listener_name123",
                          description="listener_description123",
                          admin_state_up=True,
                          connection_limit=10,
                          vip_subnet_id="123321123")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='smoke')
    @test.idempotent_id('e8bdd948-7bea-494b-8a4a-e730b70f2882')
    def test_update_listener_missing_name(self):
        """Test update listener with a missing name"""
        old_listener = self._show_listener(self.listener_id)
        old_name = old_listener['name']
        self._update_listener(self.listener_id,
                              description='updated')
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])
        listener = self._show_listener(self.listener_id)
        self.assertEqual(listener.get('name'), old_name)

    @test.attr(type='smoke')
    @test.idempotent_id('7e0194b8-9315-452d-9de5-d48f227b626f')
    def test_update_listener_missing_description(self):
        """Test update listener with a missing description"""
        old_listener = self._show_listener(self.listener_id)
        old_description = old_listener['description']
        self._update_listener(self.listener_id,
                              name='updated_name')
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])
        listener = self._show_listener(self.listener_id)
        self.assertEqual(listener.get('description'), old_description)

    @test.attr(type='smoke')
    @test.idempotent_id('285dd3f2-fcb8-4ccb-b9ce-d6207b29a2f8')
    def test_update_listener_missing_admin_state_up(self):
        """Test update listener with a missing admin_state_up"""
        old_listener = self._show_listener(self.listener_id)
        old_admin_state_up = old_listener['admin_state_up']
        self._update_listener(self.listener_id,
                              name='updated_name')
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])
        listener = self._show_listener(self.listener_id)
        self.assertEqual(listener.get('admin_state_up'), old_admin_state_up)

    @test.attr(type='smoke')
    @test.idempotent_id('5c510338-0f8a-4d1e-805b-f8458f2e80ee')
    def test_update_listener_missing_connection_limit(self):
        """Test update listener with a missing connection_limit"""
        old_listener = self._show_listener(self.listener_id)
        old_connection_limit = old_listener['connection_limit']
        self._update_listener(self.listener_id,
                              name='updated_name')
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])
        listener = self._show_listener(self.listener_id)
        self.assertEqual(listener.get('connection_limit'),
                         old_connection_limit)

    @test.attr(type='negative')
    @test.idempotent_id('677205d9-9d97-4232-a8e3-d17ebf42ff05')
    def test_update_listener_empty_tenant_id(self):
        """Test update listener with an empty tenant id"""
        self.assertRaises(exceptions.BadRequest,
                          self._update_listener,
                          listener_id=self.listener_id,
                          tenant_id="")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='negative')
    @test.idempotent_id('6e9f8fdb-48b0-4c4e-9b29-460576b125ff')
    def test_update_listener_empty_admin_state_up(self):
        """Test update a listener with an empty admin_state_up"""
        self.assertRaises(exceptions.BadRequest,
                          self._update_listener,
                          listener_id=self.listener_id,
                          admin_state_up="")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='smoke')
    @test.idempotent_id('cf619b8d-1916-4144-85c7-e5a34e0d7a2b')
    def test_update_listener_empty_name(self):
        """Test update a listener with an empty name"""
        self._update_listener(self.listener_id,
                              name="")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])
        listener = self._show_listener(self.listener_id)
        self.assertEqual(listener.get('name'), "")

    @test.attr(type='smoke')
    @test.idempotent_id('a9b6f721-c3c1-4d22-a3e5-7e89b58fa3a7')
    def test_update_listener_empty_description(self):
        """Test update a listener with an empty description"""
        self._update_listener(self.listener_id,
                              description="")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])
        listener = self._show_listener(self.listener_id)
        self.assertEqual(listener.get('description'), "")

    @test.attr(type='negative')
    @test.idempotent_id('7ddcf46b-068b-449c-9dde-ea4021dd76bf')
    def test_update_listener_empty_connection_limit(self):
        """Test update a listener with an empty connection_limit"""
        self.assertRaises(exceptions.BadRequest,
                          self._update_listener,
                          listener_id=self.listener_id,
                          connection_limit="")
        self._check_status_tree(load_balancer_id=self.load_balancer_id,
                                listener_ids=[self.listener_id])

    @test.attr(type='smoke')
    @test.idempotent_id('c891c857-fa89-4775-92d8-5320321b86cd')
    def test_delete_listener(self):
        """Test delete listener"""
        create_new_listener_kwargs = self.create_listener_kwargs
        create_new_listener_kwargs['protocol_port'] = 8083
        new_listener = self._create_listener(**create_new_listener_kwargs)
        new_listener_id = new_listener['id']
        self._check_status_tree(
            load_balancer_id=self.load_balancer_id,
            listener_ids=[self.listener_id, new_listener_id])
        listener = self._show_listener(new_listener_id)
        self.assertEqual(new_listener, listener)
        self.assertNotEqual(self.listener, new_listener)
        self._delete_listener(new_listener_id)
        self.assertRaises(exceptions.NotFound,
                          self._show_listener,
                          new_listener_id)
