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

from tempest.lib import decorators
from tempest.lib import exceptions as ex
from tempest import test

from vmware_nsx_tempest.tests.nsxv.api.lbaas import base


class TestHealthMonitors(base.BaseTestCase):

    """Tests the following operations in the Neutron-LBaaS API

    using the REST client for Health Monitors:
        list pools
        create pool
        get pool
        update pool
        delete pool
    """

    @classmethod
    def resource_setup(cls):
        super(TestHealthMonitors, cls).resource_setup()
        cls.load_balancer = cls._create_load_balancer(
            tenant_id=cls.subnet.get('tenant_id'),
            vip_subnet_id=cls.subnet.get('id'))
        cls.listener = cls._create_listener(
            loadbalancer_id=cls.load_balancer.get('id'),
            protocol='HTTP', protocol_port=80)
        cls.pool = cls._create_pool(
            protocol='HTTP', lb_algorithm='ROUND_ROBIN',
            listener_id=cls.listener.get('id'))
        cls.create_basic_hm_kwargs = {'type': 'HTTP', 'delay': 3,
                                      'max_retries': 10, 'timeout': 5,
                                      'pool_id': cls.pool.get('id')}

    # possible cause is bug#1638601: can not delete health monitor
    # temparary solution
    def remove_existing_health_monitors(self):
        """remove all existing hm because one pool can only one hm

        During testing, because bug#163860 and
        one pool can only have one health_monitor,
        we delete hm before testing -- acutally not very effective.

        hm_list = self._list_health_monitors()
        for hm in hm_list:
            test_utils.call_and_igonre_not_found_exc(
                self._delete_health_monitor,
                hm.get('id'))
        """
        return None

    @test.attr(type='smoke')
    @test.idempotent_id('3c223a4d-3733-4daa-a6e3-69a31f9e7304')
    def test_list_health_monitors_empty(self):
        hm_list = self._list_health_monitors()
        self.assertEmpty(hm_list)

    @test.attr(type='smoke')
    @test.idempotent_id('76880edd-b01c-4b80-ba4d-1d10f35aaeb7')
    def test_list_health_monitors_one(self):
        hm = self._create_health_monitor(**self.create_basic_hm_kwargs)
        hm_list = self._list_health_monitors()
        self.assertIn(hm, hm_list)

    @test.attr(type='smoke')
    @test.idempotent_id('22b984d5-8284-4f7c-90c4-407d0e872ea8')
    def test_list_health_monitors_two(self):
        hm1 = self._create_health_monitor(**self.create_basic_hm_kwargs)
        new_listener = self._create_listener(
            loadbalancer_id=self.load_balancer.get('id'),
            protocol='HTTP', protocol_port=88)
        self.addCleanup(self._delete_listener, new_listener.get('id'))
        new_pool = self._create_pool(
            protocol='HTTP', lb_algorithm='ROUND_ROBIN',
            listener_id=new_listener.get('id'))
        self.addCleanup(self._delete_pool, new_pool.get('id'))
        hm2 = self._create_health_monitor(
            type='HTTP', max_retries=10, delay=3, timeout=5,
            pool_id=new_pool.get('id'))
        hm_list = self._list_health_monitors()
        self.assertEqual(2, len(hm_list))
        self.assertIn(hm1, hm_list)
        self.assertIn(hm2, hm_list)

    @test.attr(type='smoke')
    @test.idempotent_id('ca49b640-259c-49ee-be9c-b425a4bbd2cf')
    def test_get_health_monitor(self):
        hm = self._create_health_monitor(**self.create_basic_hm_kwargs)
        hm_test = self._show_health_monitor(hm.get('id'))
        self.assertEqual(hm, hm_test)

    @test.attr(type='smoke')
    @test.idempotent_id('80ded4c2-2277-4e19-8280-3519b22a999e')
    def test_create_health_monitor(self):
        new_hm = self._create_health_monitor(**self.create_basic_hm_kwargs)
        hm = self._show_health_monitor(new_hm.get('id'))
        self.assertEqual(new_hm, hm)

    @test.attr(type='smoke')
    @test.idempotent_id('387f669b-7a02-4ab3-880d-719dd79ff853')
    def test_create_health_monitor_missing_attribute(self):
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10,
                          pool_id=self.pool.get('id'))

    @test.attr(type=['smoke', 'negative'])
    @test.idempotent_id('bf2ec88e-91d3-48f5-b9f2-be3dab21445c')
    def test_create_health_monitor_missing_required_field_type(self):
        """Test if a non_admin user can

        create a health monitor with type missing
        """
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          delay=3, max_retries=10, timeout=5,
                          pool_id=self.pool.get('id'))

    @test.attr(type=['smoke', 'negative'])
    @test.idempotent_id('85110a81-d905-40f1-92c0-7dafb1617915')
    def test_create_health_monitor_missing_required_field_delay(self):
        """Test if a non_admin user can

        create a health monitor with delay missing
        """
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', max_retries=10, timeout=5,
                          pool_id=self.pool.get('id'))

    @test.attr(type=['smoke', 'negative'])
    @test.idempotent_id('10ed9396-271a-4edd-948d-93ad44df2713')
    def test_create_health_monitor_missing_required_field_timeout(self):
        """Test if a non_admin user can

        create a health monitor with timeout missing
        """
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10,
                          pool_id=self.pool.get('id'))

    @test.attr(type=['smoke', 'negative'])
    @test.idempotent_id('69614cb5-9078-4b93-8dfa-45d59ac240f8')
    def test_create_health_monitor_missing_required_field_max_retries(self):
        """Test if a non_admin user

        can create a health monitor with max_retries missing
        """
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, timeout=5,
                          pool_id=self.pool.get('id'))

    @test.attr(type=['smoke', 'negative'])
    @test.idempotent_id('543d1f68-1b3a-49c8-bc6c-3eb8123b6e9a')
    def test_create_health_monitor_missing_required_field_pool_id(self):
        """Test if a non_admin user

        can create a health monitor with pool_id missing
        """
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10, timeout=5)

    @test.attr(type='smoke')
    @test.idempotent_id('4f8d17d2-3e52-4e34-83c7-4398b328c559')
    def test_create_health_monitor_missing_admin_state_up(self):
        """Test if a non_admin user

        can create a health monitor with admin_state_up missing
        """
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))

        hm_test = self._show_health_monitor(hm.get('id'))
        self.assertEqual(hm, hm_test)
        self.assertEqual(True, hm_test.get('admin_state_up'))

    @test.attr(type='smoke')
    @test.idempotent_id('6e1066d3-f358-446e-a574-5d4ceaf0b51d')
    def test_create_health_monitor_missing_http_method(self):
        """Test if a non_admin user

        can create a health monitor with http_method missing
        """
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))

        hm_test = self._show_health_monitor(hm.get('id'))
        self.assertEqual(hm, hm_test)
        self.assertEqual('GET', hm_test.get('http_method'))

    @test.attr(type='smoke')
    @test.idempotent_id('9b25196f-7476-4ed7-9542-1f22a76b79f8')
    def test_create_health_monitor_missing_url_path(self):
        """Test if a non_admin user

        can create a health monitor with url_path missing
        """
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))

        hm_test = self._show_health_monitor(hm.get('id'))
        self.assertEqual(hm, hm_test)
        self.assertEqual('/', hm_test.get('url_path'))

    @test.attr(type='smoke')
    @test.idempotent_id('c69da922-1c46-4b9b-8b8b-2e700d506a9c')
    def test_create_health_monitor_missing_expected_codes(self):
        """Test if a non_admin user

        can create a health monitor with expected_codes missing
        """
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))

        hm_test = self._show_health_monitor(hm.get('id'))
        self.assertEqual(hm, hm_test)
        self.assertEqual('200', hm_test.get('expected_codes'))

    @test.attr(type='negative')
    @test.idempotent_id('a00cb8e0-cd0b-44d0-85b0-5935a0297e37')
    def test_create_health_monitor_invalid_tenant_id(self):
        """Test create health monitor with invalid tenant_id"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          tenant_id='blah',
                          type='HTTP', delay=3, max_retries=10, timeout=5,
                          pool_id=self.pool.get('id'))

    @test.attr(type='negative')
    @test.idempotent_id('fcd93a6d-1fec-4031-9c18-611f4f3b270e')
    def test_create_health_monitor_invalid_type(self):
        """Test create health monitor with invalid type"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='blah', delay=3, max_retries=10, timeout=5,
                          pool_id=self.pool.get('id'))

    @test.attr(type='negative')
    @test.idempotent_id('3c2829d9-5d51-4bcc-b83e-f28f6e6d0bc3')
    def test_create_health_monitor_invalid_delay(self):
        """Test create health monitor with invalid delay"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay='blah', max_retries=10,
                          timeout=5, pool_id=self.pool.get('id'))

    @test.attr(type='negative')
    @test.idempotent_id('7155e366-72a2-47a0-9fcf-25e38a3ef7f7')
    def test_create_health_monitor_invalid_max_retries(self):
        """Test create health monitor with invalid max_retries"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries='blah',
                          timeout=5, pool_id=self.pool.get('id'))

    @test.attr(type='negative')
    @test.idempotent_id('fb5d0016-5ea6-4697-8049-e80473e67880')
    def test_create_health_monitor_invalid_timeout(self):
        """Test create health monitor with invalid timeout"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10,
                          timeout='blah', pool_id=self.pool.get('id'))

    @test.attr(type='negative')
    @test.idempotent_id('7f3e6e95-3eac-4a46-983a-ba1fd3b0afdf')
    def test_create_health_monitor_invalid_pool_id(self):
        """Test create health monitor with invalid pool id"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10, timeout=5,
                          pool_id='blah')

    @test.attr(type='negative')
    @test.idempotent_id('f5aacc27-3573-4749-9cb9-3261fcabf1e9')
    def test_create_health_monitor_invalid_admin_state_up(self):
        """Test if a non_admin user

        can create a health monitor with invalid admin_state_up
        """
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10, timeout=5,
                          pool_id=self.pool.get('id'),
                          admin_state_up='blah')

    @test.attr(type='negative')
    @test.idempotent_id('0f9f2488-aefb-44c9-a08b-67b715e63091')
    def test_create_health_monitor_invalid_expected_codes(self):
        """Test if a non_admin user

        can create a health monitor with invalid expected_codes
        """
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10, timeout=5,
                          pool_id=self.pool.get('id'),
                          expected_codes='blah')

    @test.attr(type='negative')
    @test.idempotent_id('0d637b7f-52ea-429f-8f97-584a5a9118aa')
    @decorators.skip_because(bug="1641652")
    def test_create_health_monitor_invalid_url_path(self):
        """Test if a non_admin user

        can create a health monitor with invalid url_path
        """
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10, timeout=5,
                          pool_id=self.pool.get('id'), url_path='blah')

    @test.attr(type='negative')
    @test.idempotent_id('7d4061c4-1fbc-43c3-81b5-2d099a120297')
    @decorators.skip_because(bug="1641643")
    def test_create_health_monitor_invalid_http_method(self):
        """Test if a non_admin user

        can create a health monitor with invalid http_method
        """
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10, timeout=5,
                          pool_id=self.pool.get('id'), http_method='blah')

    @test.attr(type='negative')
    @test.idempotent_id('b655cee7-df0d-4531-bd98-a4918d2e752a')
    def test_create_health_monitor_empty_type(self):
        """Test create health monitor with empty type"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='', delay=3, max_retries=10, timeout=5,
                          pool_id=self.pool.get('id'))

    @test.attr(type='negative')
    @test.idempotent_id('d843c9f4-507e-462f-8f2b-319af23029db')
    def test_create_health_monitor_empty_delay(self):
        """Test create health monitor with empty delay"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay='', max_retries=10, timeout=5,
                          pool_id=self.pool.get('id'))

    @test.attr(type='negative')
    @test.idempotent_id('bb9cb2b0-2684-4f4d-b344-6e7b0c58b019')
    def test_create_health_monitor_empty_timeout(self):
        """Test create health monitor with empty timeout"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10, timeout='',
                          pool_id=self.pool.get('id'))

    @test.attr(type='negative')
    @test.idempotent_id('3b52441d-5e8a-4d17-b772-bd261d0c2656')
    def test_create_health_monitor_empty_max_retries(self):
        """Test create health monitor with empty max_retries"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries='', timeout=5,
                          pool_id=self.pool.get('id'))

    @test.attr(type='negative')
    @test.idempotent_id('397aa201-25c1-4828-8c60-9cee5c4d89ab')
    # NSX-v does reject empty pool_id
    def test_create_health_monitor_empty_max_pool_id(self):
        """Test create health monitor with empty pool_id"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10, timeout=5,
                          pool_id='')

    @test.attr(type='negative')
    @test.idempotent_id('e806c916-877c-41dc-bacb-aabd9684a540')
    # NSX-v does reject empty admin_state_up
    def test_create_health_monitor_empty_max_admin_state_up(self):
        """Test create health monitor with empty admin_state_up"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10, timeout=5,
                          pool_id=self.pool.get('id'), admin_state_up='')

    @test.attr(type='negative')
    @test.idempotent_id('9c8e8fe8-a3a2-481b-9ac8-eb9ecccd8330')
    @decorators.skip_because(bug="1639340")
    def test_create_health_monitor_empty_max_http_method(self):
        """Test create health monitor with empty http_method"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10, timeout=5,
                          pool_id=self.pool.get('id'), http_method='')

    @test.attr(type='negative')
    @test.idempotent_id('9016c846-fc7c-4063-9f01-61fad37c435d')
    @decorators.skip_because(bug="1639340")
    def test_create_health_monitor_empty_max_url_path(self):
        """Test create health monitor with empty url_path"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10, timeout=5,
                          pool_id=self.pool.get('id'), url_path='')

    @test.attr(type='negative')
    @test.idempotent_id('5df60d27-55ec-42a9-96cd-3affa611c8b1')
    # NSX-v does reject empty expected_codes
    def test_create_health_monitor_empty_expected_codes(self):
        """Test create health monitor with empty expected_codes"""
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10, timeout=5,
                          pool_id=self.pool.get('id'), expected_codes='')

    @test.attr(type='negative')
    @test.idempotent_id('da63bd3a-89d5-40dd-b920-420263cbfd93')
    def test_create_health_monitor_invalid_attribute(self):
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries='twenty one',
                          pool_id=self.pool.get('id'))

    @test.attr(type='negative')
    @test.idempotent_id('2005ded4-7d26-4946-8d22-e05bf026bd44')
    def test_create_health_monitor_extra_attribute(self):
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10,
                          pool_id=self.pool.get('id'), subnet_id=10)

    @test.attr(type='smoke')
    @test.idempotent_id('79b4a4f9-1d2d-4df0-a11b-dd97f973dff2')
    def test_update_health_monitor(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        max_retries = 1
        new_hm = self._update_health_monitor(
            hm.get('id'), max_retries=max_retries)
        self.assertEqual(max_retries, new_hm.get('max_retries'))

    @test.attr(type='smoke')
    @test.idempotent_id('9496ba1f-e917-4972-883b-432e44f3cf19')
    def test_update_health_monitor_missing_admin_state_up(self):
        """Test update health monitor with missing admin state field"""
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))

        new_hm = self._update_health_monitor(hm.get('id'))
        self.assertEqual(True, new_hm.get('admin_state_up'))

    @test.attr(type='smoke')
    @test.idempotent_id('88570f22-cb68-47b4-a020-52b75af818d3')
    def test_update_health_monitor_missing_delay(self):
        """Test update health monitor with missing delay field"""
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))

        new_hm = self._update_health_monitor(hm.get('id'))
        self.assertEqual(hm.get('delay'), new_hm.get('delay'))

    @test.attr(type='smoke')
    @test.idempotent_id('45ace70d-28a5-405d-95cd-b2c92ccaa593')
    def test_update_health_monitor_missing_timeout(self):
        """Test update health monitor with missing timeout field"""
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))

        new_hm = self._update_health_monitor(hm.get('id'))
        self.assertEqual(hm.get('timeout'), new_hm.get('timeout'))

    @test.attr(type='smoke')
    @test.idempotent_id('269af536-2352-4772-bf35-268df9f4542c')
    def test_update_health_monitor_missing_max_retries(self):
        """Test update health monitor with missing max retries field"""
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))

        new_hm = self._update_health_monitor(hm.get('id'))
        self.assertEqual(hm.get('max_retries'), new_hm.get('max_retries'))

    @test.attr(type='smoke')
    @test.idempotent_id('318d972f-9cd1-42ef-9b8b-2f91ba785ac7')
    def test_update_health_monitor_missing_http_method(self):
        """Test update health monitor with missing http_method field"""
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))

        new_hm = self._update_health_monitor(hm.get('id'))
        self.assertEqual(hm.get('http_method'), new_hm.get('http_method'))

    @test.attr(type='smoke')
    @test.idempotent_id('4b97ab67-889d-480c-bedc-f06d86479bb5')
    def test_update_health_monitor_missing_url_path(self):
        """Test update health monitor with missing url_path field"""
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))

        new_hm = self._update_health_monitor(hm.get('id'))
        self.assertEqual(hm.get('url_path'), new_hm.get('url_path'))

    @test.attr(type='smoke')
    @test.idempotent_id('095cdb91-0937-4ae1-8b46-5edd10f00a1e')
    def test_update_health_monitor_missing_expected_codes(self):
        """Test update health monitor with missing expected_codes field"""
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))

        new_hm = self._update_health_monitor(hm.get('id'))
        self.assertEqual(hm.get('expected_codes'),
                         new_hm.get('expected_codes'))

    @test.attr(type='negative')
    @test.idempotent_id('646d74ed-9afe-4710-a677-c36f85482731')
    def test_update_health_monitor_invalid_attribute(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), max_retries='blue')

    @test.attr(type='negative')
    @test.idempotent_id('9d717551-82ab-4073-a269-8b05b67d8306')
    def test_update_health_monitor_invalid_admin_state_up(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), admin_state_up='blah')

    @test.attr(type='negative')
    @test.idempotent_id('b865dc8a-695b-4f15-891c-e73b7402ddeb')
    def test_update_health_monitor_invalid_delay(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), delay='blah')

    @test.attr(type='negative')
    @test.idempotent_id('813c8bc1-7ba6-4ae5-96f3-1fdb10ae7be3')
    def test_update_health_monitor_invalid_timeout(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), timeout='blah')

    @test.attr(type='negative')
    @test.idempotent_id('05456473-5014-43ae-97a2-3790e4987526')
    def test_update_health_monitor_invalid_max_retries(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), max_retries='blah')

    @test.attr(type='negative')
    @test.idempotent_id('1e2fb718-de77-46a3-8897-6f5aff6cab5e')
    @decorators.skip_because(bug="1641643")
    def test_update_health_monitor_invalid_http_method(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), http_method='blah')

    @test.attr(type='negative')
    @test.idempotent_id('07d62a55-18b3-4b74-acb2-b73a0b5e4364')
    @decorators.skip_because(bug="1641652")
    def test_update_health_monitor_invalid_url_path(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), url_path='blah')

    @test.attr(type='negative')
    @test.idempotent_id('47c96e10-4863-4635-8bc6-371d460f61bc')
    def test_update_health_monitor_invalid_expected_codes(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), expected_codes='blah')

    @test.attr(type='negative')
    @test.idempotent_id('8594b3a3-70e8-4dfa-8928-18bc1cc7ab4a')
    def test_update_health_monitor_empty_admin_state_up(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), admin_state_up='')

    @test.attr(type='negative')
    @test.idempotent_id('1e1b761d-5114-4931-935d-1069d66e2bb1')
    def test_update_health_monitor_empty_delay(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), empty_delay='')

    @test.attr(type='negative')
    @test.idempotent_id('e6e4a6b7-50b4-465d-be02-44fd5f258bb6')
    def test_update_health_monitor_empty_timeout(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), timeout='')

    @test.attr(type='negative')
    @test.idempotent_id('65d05adf-a399-4457-bd83-92c43c1eca01')
    def test_update_health_monitor_empty_max_retries(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), max_retries='')

    @test.attr(type='negative')
    @test.idempotent_id('0c464bb3-ff84-4816-9237-4583e4da9881')
    @decorators.skip_because(bug="1639340")
    def test_update_health_monitor_empty_empty_http_method(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), http_method='')

    @test.attr(type='negative')
    @test.idempotent_id('3e87c0a8-ef15-457c-a58f-270de8c5c76c')
    @decorators.skip_because(bug="1639340")
    def test_update_health_monitor_empty_url_path(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), url_path='')

    @test.attr(type='negative')
    @test.idempotent_id('d45189e6-db9f-44d1-b5ad-8b7691e781ee')
    def test_update_health_monitor_empty_expected_codes(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), expected_codes='')

    @test.attr(type=['smoke', 'negative'])
    @test.idempotent_id('cf70e44e-8060-494a-b577-d656726ba3d8')
    def test_update_health_monitor_extra_attribute(self):
        hm = self._create_health_monitor(type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self.assertRaises(ex.BadRequest,
                          self._update_health_monitor,
                          hm.get('id'), protocol='UDP')

    @test.attr(type=['smoke', 'negative'])
    @test.idempotent_id('fe44e0d9-957b-44cf-806b-af7819444864')
    @decorators.skip_because(bug="1639340")
    def test_delete_health_monitor(self):
        hm = self._create_health_monitor(cleanup=False, type='HTTP', delay=3,
                                         max_retries=10, timeout=5,
                                         pool_id=self.pool.get('id'))
        self._delete_health_monitor(hm.get('id'))
        self.assertRaises(ex.NotFound,
                          self._show_health_monitor,
                          hm.get('id'))
