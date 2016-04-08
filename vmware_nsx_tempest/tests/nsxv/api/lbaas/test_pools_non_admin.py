# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from tempest.lib import decorators
from tempest.lib import exceptions as ex
from tempest import test

from vmware_nsx_tempest.tests.nsxv.api.lbaas import base

PROTOCOL_PORT = 80


class TestPools(base.BaseTestCase):

    """Tests the following operations in the Neutron-LBaaS API

    using the REST client for Pools:

        list pools
        create pool
        get pool
        update pool
        delete pool
    """

    @classmethod
    def resource_setup(cls):
        super(TestPools, cls).resource_setup()
        cls.load_balancer = cls._create_load_balancer(
            tenant_id=cls.subnet.get('tenant_id'),
            vip_subnet_id=cls.subnet.get('id'),
            wait=True)
        cls.listener = cls._create_listener(
            loadbalancer_id=cls.load_balancer.get('id'),
            protocol='HTTP', protocol_port=80)

    def increment_protocol_port(self):
        global PROTOCOL_PORT
        PROTOCOL_PORT += 1

    def _prepare_and_create_pool(self, protocol=None, lb_algorithm=None,
                                 listener_id=None, cleanup=True, **kwargs):
        self._wait_for_load_balancer_status(self.load_balancer.get('id'))
        self.increment_protocol_port()
        if not protocol:
            protocol = 'HTTP'
        if not lb_algorithm:
            lb_algorithm = 'ROUND_ROBIN'
        if not listener_id:
            listener = self._create_listener(
                loadbalancer_id=self.load_balancer.get('id'),
                protocol='HTTP', protocol_port=PROTOCOL_PORT,
                wait=True)
            listener_id = listener.get('id')
        response = self._create_pool(protocol=protocol,
                                     lb_algorithm=lb_algorithm,
                                     listener_id=listener_id,
                                     wait=True,
                                     **kwargs)
        if cleanup:
            self.addCleanup(self._delete_pool, response['id'])
        return response

    @test.attr(type='smoke')
    @test.idempotent_id('99154002-e598-4277-b6d8-bf0fe10f276f')
    def test_list_pools_empty(self):
        """Test get pools when empty"""
        pools = self._list_pools()
        self.assertEqual([], pools)

    @test.attr(type='smoke')
    @test.idempotent_id('4f09b544-8e82-4313-b452-8fe3ca5ad14e')
    def test_list_pools_one(self):
        """Test get pools with one pool"""
        new_pool = self._prepare_and_create_pool()
        new_pool = self._show_pool(new_pool['id'])
        pools = self._list_pools()
        self.assertEqual(1, len(pools))
        self.assertIn(new_pool, pools)

    @test.attr(type='smoke')
    @test.idempotent_id('7562b846-a685-49ea-9d41-afcaff418bae')
    def test_list_pools_two(self):
        """Test get pools with two pools"""
        new_pool1 = self._prepare_and_create_pool()
        new_pool2 = self._prepare_and_create_pool()
        pools = self._list_pools()
        self.assertEqual(2, len(pools))
        self.assertIn(new_pool1, pools)
        self.assertIn(new_pool2, pools)

    @test.attr(type='smoke')
    @test.idempotent_id('0cf61c6a-efd5-4859-9d92-da204f5ec1ed')
    def test_get_pool(self):
        """Test get pool"""
        new_pool = self._prepare_and_create_pool()
        pool = self._show_pool(new_pool.get('id'))
        self.assertEqual(new_pool, pool)

    @test.attr(type='smoke')
    @test.idempotent_id('7fc310a0-7640-4f7c-8cdb-53b6ae23bd52')
    def test_create_pool(self):
        """Test create pool"""
        new_pool = self._prepare_and_create_pool()
        pool = self._show_pool(new_pool.get('id'))
        self.assertEqual(new_pool, pool)

    @test.attr(type='negative')
    @test.idempotent_id('5f414612-4f8c-4f48-ac99-286356870fae')
    def test_create_pool_missing_required_fields(self):
        """Test create pool with a missing required fields"""
        tenant_id = self.subnet.get('tenant_id')
        self.assertRaises(ex.BadRequest, self._create_pool,
                          tenant_id=tenant_id,
                          lb_algorithm='ROUND_ROBIN')

    @test.attr(type='smoke')
    @test.idempotent_id('7fe53b0c-d7b8-4283-aeb3-eeeb3219e42f')
    def test_create_pool_missing_tenant_field(self):
        """Test create pool with a missing required tenant field"""
        tenant_id = self.subnet.get('tenant_id')
        new_pool = self._prepare_and_create_pool(
            protocol='HTTP',
            lb_algorithm='ROUND_ROBIN')
        pool = self._show_pool(new_pool.get('id'))
        pool_tenant = pool['tenant_id']
        self.assertEqual(tenant_id, pool_tenant)

    @test.attr(type='negative')
    @test.idempotent_id('7d17e507-99c2-4e8f-a403-27b630b403a2')
    def test_create_pool_missing_protocol_field(self):
        """Test create pool with a missing required protocol field"""
        self.increment_protocol_port()
        listener = self._create_listener(
            loadbalancer_id=self.load_balancer.get('id'),
            protocol='HTTP', protocol_port=PROTOCOL_PORT)
        self.addCleanup(self._delete_listener, listener['id'])
        self._wait_for_load_balancer_status(self.load_balancer.get('id'))
        listener_id = listener.get('id')
        tenant_id = self.subnet.get('tenant_id')
        self.assertRaises(ex.BadRequest, self._create_pool,
                          tenant_id=tenant_id,
                          listener_id=listener_id,
                          lb_algorithm='ROUND_ROBIN')

    @test.attr(type='negative')
    @test.idempotent_id('99051cc6-bf51-4af0-b530-edbfb7d4b7ab')
    def test_create_pool_missing_lb_algorithm_field(self):
        """Test create pool with a missing required lb algorithm field"""
        self.increment_protocol_port()
        listener = self._create_listener(
            loadbalancer_id=self.load_balancer.get('id'),
            protocol='HTTP', protocol_port=PROTOCOL_PORT)
        self.addCleanup(self._delete_listener, listener['id'])
        self._wait_for_load_balancer_status(self.load_balancer.get('id'))
        listener_id = listener.get('id')
        tenant_id = self.subnet.get('tenant_id')
        self.assertRaises(ex.BadRequest, self._create_pool,
                          tenant_id=tenant_id,
                          listener_id=listener_id,
                          protocol='HTTP')

    @test.attr(type='negative')
    @test.idempotent_id('d04b75fe-688b-4713-83d1-f0ac29005391')
    def test_create_pool_missing_listener_id_field(self):
        """Test create pool with a missing required listener id field"""
        tenant_id = self.subnet.get('tenant_id')
        self.assertRaises(ex.BadRequest, self._create_pool,
                          tenant_id=tenant_id,
                          lb_algorithm='ROUND_ROBIN',
                          protocol='HTTP')

    @test.attr(type='smoke')
    @test.idempotent_id('378c56b4-cf61-448b-8460-1ffb1a091ea5')
    def test_create_pool_missing_description_field(self):
        """Test create pool with missing description field"""
        self._wait_for_load_balancer_status(self.load_balancer.get('id'))
        new_pool = self._prepare_and_create_pool()
        pool_initial = self._show_pool(new_pool.get('id'))
        desc = pool_initial.get('description')
        self.assertEqual(desc, "")

    @test.attr(type='smoke')
    @test.idempotent_id('f73ff259-7fbb-41ac-ab92-c6eef0213e20')
    def test_create_pool_missing_name_field(self):
        """Test create pool with a missing name field"""
        new_pool = self._prepare_and_create_pool()
        pool_initial = self._show_pool(new_pool.get('id'))
        name = pool_initial.get('name')
        self.assertEqual(name, "")

    @test.attr(type='smoke')
    @test.idempotent_id('37957c70-6979-4e15-a316-8c29cb7e724e')
    def test_create_pool_missing_admin_state_up_field(self):
        """Test create pool with a missing admin_state_up field"""
        new_pool = self._prepare_and_create_pool()
        pool_initial = self._show_pool(new_pool.get('id'))
        state = pool_initial.get('admin_state_up')
        self.assertEqual(state, True)

    @test.attr(type='smoke')
    @test.idempotent_id('d1e41b4b-fe79-4bec-bc94-5934995c6e05')
    def test_create_pool_missing_session_pers_field(self):
        """Test create pool with a missing session_pers field"""
        new_pool = self._prepare_and_create_pool()
        pool_initial = self._show_pool(new_pool.get('id'))
        sess = pool_initial.get('session_persistence')
        self.assertIsNone(sess)

    @test.attr(type='negative')
    @test.idempotent_id('440b3975-b7c8-4cff-85a5-a0a02ad6b8f9')
    def test_create_pool_invalid_protocol(self):
        """Test create pool with an invalid protocol"""
        self.assertRaises(ex.BadRequest, self._create_pool,
                          protocol='UDP',
                          lb_algorithm='ROUND_ROBIN',
                          listener_id=self.listener['id'])

    @test.attr(type='negative')
    @test.idempotent_id('a0b322b1-629c-483c-9136-397fc9100e48')
    def test_create_pool_invalid_session_persistence_field(self):
        """Test create pool with invalid session persistance field"""
        self.assertRaises(ex.BadRequest, self._create_pool,
                          protocol='HTTP',
                          session_persistence={'type': 'HTTP'},
                          lb_algorithm='ROUND_ROBIN',
                          listener_id=self.listener['id'])

    @test.attr(type='negative')
    @test.idempotent_id('53cd9427-29fa-4a55-adb8-9cb6388b9548')
    def test_create_pool_invalid_algorithm(self):
        """Test create pool with an invalid algorithm"""
        self.assertRaises(ex.BadRequest, self._create_pool,
                          protocol='HTTP',
                          lb_algorithm='LEAST_CON',
                          listener_id=self.listener['id'])

    @test.attr(type='negative')
    @test.idempotent_id('26e6bb34-4b0f-4650-a5dc-87484fa55038')
    def test_create_pool_invalid_admin_state_up(self):
        """Test create pool with an invalid admin state up field"""
        self.assertRaises(ex.BadRequest, self._create_pool,
                          protocol='HTTP',
                          admin_state_up="$!1%9823",
                          lb_algorithm='ROUND_ROBIN',
                          listener_id=self.listener['id'])

    @test.attr(type='negative')
    @test.idempotent_id('8df02129-2b9c-4628-a390-805967107090')
    def test_create_pool_invalid_listener_field(self):
        """Test create pool with invalid listener field"""
        tenant_id = self.subnet.get('tenant_id')
        self.assertRaises(ex.BadRequest, self._create_pool,
                          tenant_id=tenant_id,
                          lb_algorithm='ROUND_ROBIN',
                          protocol='HTTP',
                          listener_id="$@5$%$7863")

    @test.attr(type='negative')
    @test.idempotent_id('94949cd4-ebc1-4af5-a220-9ebb32772fbc')
    def test_create_pool_invalid_tenant_id_field(self):
        """Test create pool with invalid tenant_id field"""
        self.increment_protocol_port()
        listener = self._create_listener(
            loadbalancer_id=self.load_balancer.get('id'),
            protocol='HTTP', protocol_port=PROTOCOL_PORT)
        self.addCleanup(self._delete_listener, listener['id'])
        self._wait_for_load_balancer_status(self.load_balancer.get('id'))
        listener_id = listener.get('id')
        self.assertRaises(ex.BadRequest, self._create_pool,
                          tenant_id="*&7653^%&",
                          lb_algorithm='ROUND_ROBIN',
                          protocol='HTTP',
                          listener_id=listener_id)

    @test.attr(type='negative')
    @test.idempotent_id('e335db64-ad16-4e23-bd60-c72c37c7b188')
    def test_create_pool_incorrect_attribute(self):
        """Test create a pool with an extra, incorrect field"""
        self.assertRaises(ex.BadRequest, self._create_pool,
                          protocol='HTTP',
                          lb_algorithm='ROUND_ROBIN',
                          protocol_port=80,
                          listener_id=self.listener['id'])

    @test.attr(type='negative')
    @test.idempotent_id('390053c1-adc9-4b1a-8eb0-dbdb9085cf0f')
    def test_create_pool_empty_listener_field(self):
        """Test create pool with empty listener field"""
        tenant_id = self.subnet.get('tenant_id')
        self.assertRaises(ex.BadRequest, self._create_pool,
                          tenant_id=tenant_id,
                          lb_algorithm='ROUND_ROBIN',
                          protocol='HTTP',
                          listener_id="")

    @test.attr(type='smoke')
    @test.idempotent_id('8b25defa-8efc-47f5-a43d-3d299d7b9752')
    def test_create_pool_empty_description_field(self):
        """Test create pool with empty description field"""
        new_pool = self._prepare_and_create_pool(description="")
        pool = self._show_pool(new_pool.get('id'))
        pool_desc = pool.get('description')
        self.assertEqual(pool_desc, '')

    @test.attr(type='smoke')
    @test.idempotent_id('c8cd496c-7698-4c0e-bbed-fe9ef6c910de')
    def test_create_pool_empty_name_field(self):
        """Test create pool with empty name field"""
        new_pool = self._prepare_and_create_pool(name="")
        pool = self._show_pool(new_pool.get('id'))
        pool_name = pool.get('name')
        self.assertEqual(pool_name, '')

    @test.attr(type='negative')
    @test.idempotent_id('b7997d71-84ea-43d2-8ce0-eea4156cc952')
    def test_create_pool_empty_protocol(self):
        """Test create pool with an empty protocol"""
        self.assertRaises(ex.BadRequest, self._create_pool,
                          protocol="",
                          lb_algorithm='ROUND_ROBIN',
                          listener_id=self.listener['id'])

    @test.attr(type='negative')
    @test.idempotent_id('bffe50bb-8be5-4ed9-aea6-a15b40342599')
    def test_create_pool_empty_session_persistence_field(self):
        """Test create pool with empty session persistence field"""
        self.assertRaises(ex.BadRequest, self._create_pool,
                          session_persistence="",
                          protocol='HTTP',
                          lb_algorithm='ROUND_ROBIN',
                          listener_id=self.listener['id'])

    @test.attr(type='negative')
    @test.idempotent_id('4cfd301a-baae-462d-8041-84c337e95d16')
    def test_create_pool_empty_algorithm(self):
        """Test create pool with an empty algorithm"""
        self.assertRaises(ex.BadRequest, self._create_pool,
                          protocol='HTTP',
                          lb_algorithm="",
                          listener_id=self.listener['id'])

    @test.attr(type='negative')
    @test.idempotent_id('814de2e3-a536-4ab1-a80f-9506b11c7bc8')
    def test_create_pool_empty_admin_state_up(self):
        """Test create pool with an invalid admin state up field"""
        self.assertRaises(ex.BadRequest, self._create_pool,
                          protocol='HTTP',
                          admin_state_up="",
                          lb_algorithm='ROUND_ROBIN')

    @test.attr(type='negative')
    @test.idempotent_id('0f230e6d-057d-4da8-a42d-f32464ae1c47')
    def test_create_pool_empty_tenant_field(self):
        """Test create pool with empty tenant field"""
        self.assertRaises(ex.BadRequest, self._create_pool,
                          protocol='HTTP',
                          tenant_id="",
                          lb_algorithm='ROUND_ROBIN',
                          listener_id=self.listener['id'])

    @test.attr(type='negative')
    @test.idempotent_id('4a0e711a-b4da-4226-b265-f87b04ee4977')
    def test_create_pool_for_other_tenant_field(self):
        """Test create pool for other tenant field"""
        tenant = 'deffb4d7c0584e89a8ec99551565713c'
        self.assertRaises(ex.BadRequest, self._create_pool,
                          protocol='HTTP',
                          tenant_id=tenant,
                          lb_algorithm='ROUND_ROBIN',
                          listener_id=self.listener['id'])

    @test.attr(type='negative')
    @test.idempotent_id('cb564af8-89aa-40ca-850e-55418da0f235')
    @decorators.skip_because(bug="1637877")
    def test_create_pool_invalid_name_field(self):
        """known bug with

        input more than 255 chars Test create pool with invalid name field
        """
        self.assertRaises(ex.BadRequest, self._create_pool,
                          protocol='HTTP',
                          lb_algorithm='ROUND_ROBIN',
                          listener_id=self.listener['id'],
                          name='n' * 256)

    @test.attr(type='negative')
    @decorators.skip_because(bug="1637877")
    @test.idempotent_id('7f4472be-feb7-4ab7-9fb9-97e08f1fa787')
    def test_create_pool_invalid_desc_field(self):
        """known bug with

        input more than 255 chars Test create pool with invalid desc field
        """
        self.assertRaises(ex.BadRequest, self._prepare_and_create_pool,
                          protocol='HTTP',
                          lb_algorithm='ROUND_ROBIN',
                          listener_id=self.listener['id'],
                          description='d' * 256)

    @test.attr(type='negative')
    @test.idempotent_id('b09b14dc-029d-4132-94dd-e713c9bfa0ee')
    def test_create_pool_with_session_persistence_unsupported_type(self):
        """Test create a pool

        with an incorrect type value for session persistence
        """
        self.assertRaises(ex.BadRequest, self._create_pool,
                          session_persistence={'type': 'UNSUPPORTED'},
                          protocol='HTTP',
                          lb_algorithm='ROUND_ROBIN',
                          listener_id=self.listener['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('b5af574a-d05f-4db0-aece-58676cdbf440')
    def test_create_pool_with_session_persistence_http_cookie(self):
        """Test create a pool with session_persistence type=HTTP_COOKIE"""
        new_pool = self._prepare_and_create_pool(
            session_persistence={'type': 'HTTP_COOKIE'})
        pool = self._show_pool(new_pool.get('id'))
        self.assertEqual(new_pool, pool)

    @test.attr(type='smoke')
    @test.idempotent_id('2d6b6667-e38b-4e7f-8443-8dc7ee63ea87')
    def test_create_pool_with_session_persistence_app_cookie(self):
        """Test create a pool with session_persistence type=APP_COOKIE"""
        new_pool = self._prepare_and_create_pool(
            session_persistence={'type': 'APP_COOKIE',
                                 'cookie_name': 'sessionId'})
        pool = self._show_pool(new_pool.get('id'))
        self.assertEqual(new_pool, pool)

    @test.attr(type='negative')
    @test.idempotent_id('9ac450fc-24c5-4b5c-a781-b23e5713f172')
    def test_create_pool_with_session_persistence_redundant_cookie_name(self):
        """Test create a pool

        with session_persistence with cookie_name for type=HTTP_COOKIE
        """
        self.assertRaises(ex.BadRequest, self._create_pool,
                          session_persistence={'type': 'HTTP_COOKIE',
                                               'cookie_name': 'sessionId'},
                          protocol='HTTP',
                          lb_algorithm='ROUND_ROBIN',
                          listener_id=self.listener['id'])

    @test.attr(type='negative')
    @test.idempotent_id('7783ebd0-5bd9-43f0-baf2-a43212ba2617')
    def test_create_pool_with_session_persistence_without_cookie_name(self):
        """Test create a pool

        with session_persistence without cookie_name for type=APP_COOKIE
        """
        self.assertRaises(ex.BadRequest, self._create_pool,
                          session_persistence={'type': 'APP_COOKIE'},
                          protocol='HTTP',
                          lb_algorithm='ROUND_ROBIN',
                          listener_id=self.listener['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('767ed26e-7114-402a-bdee-443d52009a73')
    def test_update_pool(self):
        """Test update pool"""
        new_pool = self._prepare_and_create_pool()
        desc = 'testing update with new description'
        pool = self._update_pool(new_pool.get('id'),
                                 description=desc,
                                 wait=True)
        self.assertEqual(desc, pool.get('description'))

    @test.attr(type='smoke')
    @test.idempotent_id('5cbc4dac-13fc-44de-b98f-41ca369a6e0f')
    def test_update_pool_missing_name(self):
        """Test update pool with missing name"""
        new_pool = self._prepare_and_create_pool()
        pool_initial = self._show_pool(new_pool.get('id'))
        name = pool_initial.get('name')
        pool = self._update_pool(new_pool.get('id'))
        self._wait_for_load_balancer_status(self.load_balancer.get('id'))
        self.assertEqual(name, pool.get('name'))

    @test.attr(type='smoke')
    @test.idempotent_id('af9c2f8e-b0e3-455b-83f0-222f8d692185')
    def test_update_pool_missing_description(self):
        """Test update pool with missing description"""
        new_pool = self._prepare_and_create_pool()
        pool_initial = self._show_pool(new_pool.get('id'))
        desc = pool_initial.get('description')
        pool = self._update_pool(new_pool.get('id'))
        self._wait_for_load_balancer_status(self.load_balancer.get('id'))
        self.assertEqual(desc, pool.get('description'))

    @test.attr(type='smoke')
    @test.idempotent_id('3b41e855-edca-42c1-a1c6-07421f87704d')
    def test_update_pool_missing_admin_state_up(self):
        """Test update pool with missing admin state up field"""
        new_pool = self._prepare_and_create_pool()
        pool_initial = self._show_pool(new_pool.get('id'))
        admin = pool_initial.get('admin_state_up')
        pool = self._update_pool(new_pool.get('id'))
        self._wait_for_load_balancer_status(self.load_balancer.get('id'))
        self.assertEqual(admin, pool.get('admin_state_up'))

    @test.attr(type='smoke')
    @test.idempotent_id('8b49ecc3-4694-4482-9b2d-dc928576e161')
    def test_update_pool_missing_session_persistence(self):
        """Test update pool with missing session persistence"""
        new_pool = self._prepare_and_create_pool()
        pool_initial = self._show_pool(new_pool.get('id'))
        sess_pers = pool_initial.get('session_persistence')
        pool = self._update_pool(new_pool.get('id'))
        self.assertAlmostEqual(sess_pers, pool.get('session_persistence'))

    @test.attr(type='negative')
    @decorators.skip_because(bug="1637877")
    @test.idempotent_id('23a9dbaf-105b-450e-95cf-050203b28366')
    def test_update_pool_invalid_name(self):
        """Test update pool with invalid name"""
        new_pool = self._prepare_and_create_pool()
        self.assertRaises(ex.BadRequest, self._update_pool,
                          new_pool.get('id'), name='n' * 256)

    @test.attr(type='negative')
    @decorators.skip_because(bug="1637877")
    @test.idempotent_id('efeeb827-5cb0-4349-8272-b2dbcbf42d22')
    def test_update_pool_invalid_desc(self):
        """Test update pool with invalid desc"""
        new_pool = self._prepare_and_create_pool()
        self.assertRaises(ex.BadRequest, self._update_pool,
                          new_pool.get('id'),
                          description='d' * 256)

    @test.attr(type='negative')
    @test.idempotent_id('a91c1380-0d36-43a1-bf64-8fe9078e2bbd')
    def test_update_pool_invalid_admin_state_up(self):
        """Test update pool with an invalid admin_state_up"""
        new_pool = self._prepare_and_create_pool()
        self.assertRaises(ex.BadRequest, self._update_pool,
                          new_pool.get('id'), admin_state_up='hello')

    @test.attr(type='negative')
    @test.idempotent_id('5d45b0e3-7d7f-4523-8504-9ccfd6ecec81')
    def test_update_pool_invalid_session_persistence(self):
        """Test update pool with an invalid session pers. field"""
        new_pool = self._prepare_and_create_pool()
        self.assertRaises(ex.BadRequest, self._update_pool,
                          new_pool.get('id'),
                          session_persistence={'type': 'Hello'})

    @test.attr(type='smoke')
    @test.idempotent_id('3ddec9b1-fc7a-4073-9451-e73316237763')
    def test_update_pool_empty_name(self):
        """Test update pool with empty name"""
        new_pool = self._prepare_and_create_pool()
        pool = self._update_pool(new_pool.get('id'), name="")
        self._wait_for_load_balancer_status(self.load_balancer.get('id'))
        self.assertEqual(pool.get('name'), "")

    @test.attr(type='smoke')
    @test.idempotent_id('171e1153-9898-467d-80ed-d6deed430342')
    def test_update_pool_empty_description(self):
        """Test update pool with empty description"""
        new_pool = self._prepare_and_create_pool()
        pool = self._update_pool(new_pool.get('id'),
                                 description="")
        self._wait_for_load_balancer_status(self.load_balancer.get('id'))
        self.assertEqual(pool.get('description'), "")

    @test.attr(type='negative')
    @test.idempotent_id('397bd0ec-0e82-4421-a672-b7a2c4e84b56')
    def test_update_pool_empty_admin_state_up(self):
        """Test update pool with empty admin state up"""
        new_pool = self._prepare_and_create_pool()
        self.assertRaises(ex.BadRequest, self._update_pool,
                          new_pool.get('id'), admin_state_up="")

    @test.attr(type='negative')
    @test.idempotent_id('f68a6ed5-4577-44f1-81c8-6dd30d8a874d')
    def test_update_pool_empty_session_persistence(self):
        """Test update pool with empty session persistence field"""
        new_pool = self._prepare_and_create_pool()
        self.assertRaises(ex.BadRequest, self._update_pool,
                          new_pool.get('id'),
                          session_persistence="")

    @test.attr(type='negative')
    @test.idempotent_id('d8027ea2-6912-41f7-bf5a-f2eb3d0901b1')
    def test_update_pool_invalid_attribute(self):
        """Test update pool with an invalid attribute"""
        new_pool = self._prepare_and_create_pool()
        self.assertRaises(ex.BadRequest, self._update_pool,
                          new_pool.get('id'), lb_algorithm='ROUNDED')

    @test.attr(type='negative')
    @test.idempotent_id('a58822ee-56fc-4b96-bb28-47cd07ae9cb8')
    def test_update_pool_incorrect_attribute(self):
        """Test update a pool with an extra, incorrect field"""
        new_pool = self._prepare_and_create_pool()
        self.assertRaises(ex.BadRequest, self._update_pool,
                          new_pool.get('id'), protocol='HTTPS')

    @test.attr(type='smoke')
    @test.idempotent_id('4839f03e-2439-4619-8546-411ca883066d')
    def test_delete_pool(self):
        """Test delete pool"""
        new_pool = self._prepare_and_create_pool(cleanup=False)
        pool = self._show_pool(new_pool.get('id'))
        self.assertEqual(new_pool, pool)
        self._delete_pool(new_pool.get('id'))
        self.assertRaises(ex.NotFound, self._show_pool,
                          new_pool.get('id'))

    @test.attr(type='smoke')
    @test.idempotent_id('cd30962a-12ce-4ae9-89de-db007aebbd9f')
    def test_delete_invalid_pool(self):
        """Test delete pool that doesn't exist"""
        new_pool = self._prepare_and_create_pool(cleanup=False)
        pool = self._show_pool(new_pool.get('id'))
        self.assertEqual(new_pool, pool)
        self._delete_pool(new_pool.get('id'))
        self.assertRaises(ex.NotFound, self._delete_pool,
                          new_pool.get('id'))
