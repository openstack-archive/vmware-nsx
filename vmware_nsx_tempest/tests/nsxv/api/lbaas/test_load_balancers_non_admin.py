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

import netaddr

from oslo_log import log as logging

from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions
from tempest import test

from vmware_nsx_tempest.tests.nsxv.api.lbaas import base

CONF = config.CONF

LOG = logging.getLogger(__name__)


class LoadBalancersTest(base.BaseTestCase):

    """Tests the following operations in the Neutron-LBaaS API

     using the REST client for Load Balancers with default credentials:

        list load balancers
        create load balancer
        get load balancer
        update load balancer
        delete load balancer
    """

    @classmethod
    def resource_setup(cls):
        super(LoadBalancersTest, cls).resource_setup()
        cls.create_lb_kwargs = {'tenant_id': cls.subnet['tenant_id'],
                                'vip_subnet_id': cls.subnet['id']}
        cls.load_balancer = \
            cls._create_active_load_balancer(**cls.create_lb_kwargs)
        cls.load_balancer_id = cls.load_balancer['id']

    @test.attr(type='smoke')
    @test.idempotent_id('b7ea6c09-e077-4a67-859b-b2cd01e3b46b')
    def test_list_load_balancers(self):
        """Test list load balancers with one load balancer"""
        load_balancers = self._list_load_balancers()
        self.assertEqual(len(load_balancers), 1)
        self.assertIn(self.load_balancer, load_balancers)

    @test.attr(type='smoke')
    @test.idempotent_id('8c2302df-ca94-4950-9826-eb996630a392')
    def test_list_load_balancers_two(self):
        """Test list load balancers with two load balancers"""
        new_load_balancer = self._create_active_load_balancer(
            **self.create_lb_kwargs)
        new_load_balancer_id = new_load_balancer['id']
        self.addCleanup(self._delete_load_balancer, new_load_balancer_id)
        load_balancers = self._list_load_balancers()
        self.assertEqual(len(load_balancers), 2)
        self.assertIn(self.load_balancer, load_balancers)
        self.assertIn(new_load_balancer, load_balancers)
        self.assertNotEqual(self.load_balancer, new_load_balancer)

    @test.attr(type='smoke')
    @test.idempotent_id('56345a78-1d53-4c05-9d7b-3e5cf34c22aa')
    def test_get_load_balancer(self):
        """Test get load balancer"""
        load_balancer = self._show_load_balancer(
            self.load_balancer_id)
        self.assertEqual(self.load_balancer, load_balancer)

    @test.attr(type='smoke')
    @test.idempotent_id('5bf80330-d908-4025-9467-bca1727525c8')
    def test_create_load_balancer(self):
        """Test create load balancer"""
        new_load_balancer = self._create_active_load_balancer(
            **self.create_lb_kwargs)
        new_load_balancer_id = new_load_balancer['id']
        self.addCleanup(self._delete_load_balancer, new_load_balancer_id)
        load_balancer = self._show_load_balancer(
            new_load_balancer_id)
        self.assertEqual(new_load_balancer, load_balancer)
        self.assertNotEqual(self.load_balancer, new_load_balancer)

    @test.attr(type='negative')
    @test.idempotent_id('66bf5390-154f-4627-af61-2c1c30325d6f')
    def test_create_load_balancer_missing_vip_subnet_id_field(self):
        """Test create load balancer

         with a missing required vip_subnet_id field
        """
        self.assertRaises(exceptions.BadRequest,
                          self._create_load_balancer,
                          wait=False,
                          tenant_id=self.subnet['tenant_id'])

    @test.attr(type='negative')
    @test.idempotent_id('8e78a7e6-2da3-4f79-9f66-fd1447277883')
    def test_create_load_balancer_empty_provider_field(self):
        """Test create load balancer with an empty provider field"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_load_balancer,
                          wait=False,
                          provider="")

    @test.attr(type='smoke')
    @test.idempotent_id('def37122-3f9a-47f5-b7b5-b5c0d5e7e5ca')
    def test_create_load_balancer_empty_description_field(self):
        """Test create load balancer with an empty description field"""
        load_balancer = self._create_active_load_balancer(
            vip_subnet_id=self.subnet['id'], description="")
        self.addCleanup(self._delete_load_balancer, load_balancer['id'])
        self.assertEqual(load_balancer.get('description'), "")

    @test.attr(type='negative')
    @test.idempotent_id('69944c74-3ea1-4c06-8d28-82120721a13e')
    def test_create_load_balancer_empty_vip_address_field(self):
        """Test create load balancer with empty vip_address field"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_load_balancer,
                          wait=False,
                          vip_subnet_id=self.subnet['id'],
                          vip_address="")

    @test.attr(type='smoke')
    @test.idempotent_id('63bbe788-f3a6-444f-89b3-8c740425fc39')
    def test_create_load_balancer_missing_admin_state_up(self):
        """Test create load balancer with a missing admin_state_up field"""
        load_balancer = self._create_active_load_balancer(
            vip_subnet_id=self.subnet['id'])
        self.addCleanup(self._delete_load_balancer, load_balancer['id'])
        self.assertEqual(load_balancer.get('admin_state_up'), True)

    @test.attr(type='negative')
    @test.idempotent_id('499f164a-e926-47a6-808a-14f3c29d04c9')
    def test_create_load_balancer_empty_admin_state_up_field(self):
        """Test create load balancer with empty admin_state_up field"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_load_balancer,
                          wait=False,
                          vip_subnet_id=self.subnet['id'],
                          admin_state_up="")

    @test.attr(type='smoke')
    @test.idempotent_id('e4511356-0e78-457c-a310-8515b2dedad4')
    def test_create_load_balancer_missing_name(self):
        """Test create load balancer with a missing name field"""
        load_balancer = self._create_load_balancer(
            vip_subnet_id=self.subnet['id'])
        self.addCleanup(self._delete_load_balancer, load_balancer['id'])
        self.assertEqual(load_balancer.get('name'), '')
        self._wait_for_load_balancer_status(load_balancer['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('6bd4a92c-7498-4b92-aeae-bce0b74608e3')
    def test_create_load_balancer_empty_name(self):
        """Test create load balancer with an empty name field"""
        load_balancer = self._create_load_balancer(
            vip_subnet_id=self.subnet['id'], name="")
        self.addCleanup(self._delete_load_balancer, load_balancer['id'])
        self.assertEqual(load_balancer.get('name'), "")
        self._wait_for_load_balancer_status(load_balancer['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('e605b1ea-5179-4035-8100-c24d0164a5a5')
    def test_create_load_balancer_missing_description(self):
        """Test create load balancer with a missing description field"""
        load_balancer = self._create_load_balancer(
            vip_subnet_id=self.subnet['id'])
        self.addCleanup(self._delete_load_balancer, load_balancer['id'])
        self.assertEqual(load_balancer.get('description'), '')
        self._wait_for_load_balancer_status(load_balancer['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('9f718024-340b-405f-817f-311392353c32')
    def test_create_load_balancer_missing_vip_address(self):
        """Test create load balancer

        with a missing vip_address field,checks for
        ipversion and actual ip address
        """
        load_balancer = self._create_active_load_balancer(
            vip_subnet_id=self.subnet['id'])
        self.addCleanup(self._delete_load_balancer, load_balancer['id'])
        load_balancer_ip_initial = load_balancer['vip_address']
        ip = netaddr.IPAddress(load_balancer_ip_initial)
        self.assertEqual(ip.version, 4)
        load_balancer = self._show_load_balancer(
            load_balancer['id'])
        load_balancer_final = load_balancer['vip_address']
        self.assertEqual(load_balancer_ip_initial, load_balancer_final)

    @test.attr(type='smoke')
    @test.idempotent_id('f599ccbd-73e8-4e27-96a5-d9e0e3419a9f')
    def test_create_load_balancer_missing_provider_field(self):
        """Test create load balancer with a missing provider field"""
        load_balancer = self._create_active_load_balancer(
            vip_subnet_id=self.subnet['id'])
        self.addCleanup(self._delete_load_balancer, load_balancer['id'])
        load_balancer_initial = load_balancer['provider']
        load_balancer = self._show_load_balancer(
            load_balancer['id'])
        load_balancer_final = load_balancer['provider']
        self.assertEqual(load_balancer_initial, load_balancer_final)

    @test.attr(type='negative')
    @test.idempotent_id('377166eb-f581-4383-bc2e-54fdeed73e42')
    def test_create_load_balancer_invalid_vip_subnet_id(self):
        """Test create load balancer with an invalid vip subnet id"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_load_balancer,
                          wait=False,
                          vip_subnet_id="abc123")

    @test.attr(type='negative')
    @test.idempotent_id('512bec06-5259-4e93-b482-7ec3346c794a')
    def test_create_load_balancer_empty_vip_subnet_id(self):
        """Test create load balancer with an empty vip subnet id"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_load_balancer,
                          wait=False,
                          vip_subnet_id="")

    @test.attr(type='negative')
    @test.idempotent_id('02bd6d0e-820e-46fb-89cb-1d335e7aaa02')
    def test_create_load_balancer_invalid_tenant_id(self):
        """Test create load balancer with an invalid tenant id"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_load_balancer,
                          wait=False,
                          tenant_id="&^%123")

    @test.attr(type='negative')
    @decorators.skip_because(bug="1637877")
    @test.idempotent_id('b8c56e4a-9644-4119-8fc9-130841caf662')
    def test_create_load_balancer_invalid_name(self):
        """Test create load balancer with an invalid name"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_load_balancer,
                          wait=False,
                          tenant_id=self.subnet['tenant_id'],
                          vip_subnet_id=self.subnet['id'],
                          name='n' * 256)

    @test.attr(type='negative')
    @decorators.skip_because(bug="1637877")
    @test.idempotent_id('d638ae60-7de5-45da-a7d9-53eca4998980')
    def test_create_load_balancer_invalid_description(self):
        """Test create load balancer with an invalid description"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_load_balancer,
                          wait=False,
                          tenant_id=self.subnet['tenant_id'],
                          vip_subnet_id=self.subnet['id'],
                          description='d' * 256)

    @test.attr(type='negative')
    @test.idempotent_id('56768aa6-b26e-48aa-8118-956c62930d79')
    def test_create_load_balancer_incorrect_attribute(self):
        """Test create a load balancer with an extra, incorrect field"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_load_balancer,
                          wait=False,
                          tenant_id=self.subnet['tenant_id'],
                          vip_subnet_id=self.subnet['id'],
                          protocol_port=80)

    @test.attr(type='smoke')
    @test.idempotent_id('a130e70f-9d76-4bff-89de-3e564952b244')
    def test_create_load_balancer_missing_tenant_id_field(self):
        """Test create load balancer with a missing tenant id field"""
        load_balancer = self._create_load_balancer(
            vip_subnet_id=self.subnet['id'])
        self.addCleanup(self._delete_load_balancer, load_balancer['id'])
        self.assertEqual(load_balancer.get('tenant_id'),
                         self.subnet['tenant_id'])
        self._wait_for_load_balancer_status(load_balancer['id'])

    @test.attr(type='negative')
    @test.idempotent_id('25261cca-0c38-4dc8-bb40-f7692035740f')
    def test_create_load_balancer_empty_tenant_id_field(self):
        """Test create load balancer with empty tenant_id field"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_load_balancer,
                          vip_subnet_id=self.subnet['id'],
                          wait=False,
                          tenant_id="")

    @test.attr(type='negative')
    @test.idempotent_id('10de328d-c754-484b-841f-313307f92935')
    def test_create_load_balancer_other_tenant_id_field(self):
        """Test create load balancer for other tenant"""
        tenant = 'deffb4d7c0584e89a8ec99551565713c'
        self.assertRaises(exceptions.BadRequest,
                          self._create_load_balancer,
                          wait=False,
                          vip_subnet_id=self.subnet['id'],
                          tenant_id=tenant)

    @test.attr(type='negative')
    @test.idempotent_id('9963cbf5-97d0-4ab9-96e5-6cbd65c98714')
    # TODO(akang): upstream is exceptions.NotFound
    def test_create_load_balancer_invalid_flavor_field(self):
        """Test create load balancer with an invalid flavor field"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_load_balancer,
                          vip_subnet_id=self.subnet['id'],
                          flavor_id="NO_SUCH_FLAVOR")

    @test.attr(type='negative')
    @test.idempotent_id('f7319e32-0fad-450e-8f53-7567f56e8223')
    # TODO(akang): upstream is exceptions.Conflict
    def test_create_load_balancer_provider_flavor_conflict(self):
        """Test create load balancer with both a provider and a flavor"""
        self.assertRaises(exceptions.BadRequest,
                          self._create_load_balancer,
                          vip_subnet_id=self.subnet['id'],
                          flavor_id="NO_SUCH_FLAVOR",
                          provider="NO_SUCH_PROVIDER")

    @test.attr(type='smoke')
    @test.idempotent_id('1d92d98f-550f-4f05-a246-cdf4525459a2')
    def test_update_load_balancer(self):
        """Test update load balancer"""
        self._update_load_balancer(self.load_balancer_id,
                                   name='new_name')
        load_balancer = self._show_load_balancer(
            self.load_balancer_id)
        self.assertEqual(load_balancer.get('name'), 'new_name')

    @test.attr(type='smoke')
    @test.idempotent_id('474ca200-8dea-4d20-8468-abc0169a445b')
    def test_update_load_balancer_empty_name(self):
        """Test update load balancer with empty name"""
        self._update_load_balancer(self.load_balancer_id,
                                   name="")
        load_balancer = self._show_load_balancer(
            self.load_balancer_id)
        self.assertEqual(load_balancer.get('name'), "")

    @test.attr(type='negative')
    @decorators.skip_because(bug="1637877")
    @test.idempotent_id('551be885-215d-4941-8870-651cbc871162')
    def test_update_load_balancer_invalid_name(self):
        """Test update load balancer with invalid name"""
        self.assertRaises(exceptions.BadRequest,
                          self._update_load_balancer,
                          load_balancer_id=self.load_balancer_id,
                          wait=False,
                          name='a' * 256)

    @test.attr(type='smoke')
    @test.idempotent_id('62eef0ba-3859-4c8f-9e6a-8d6918754597')
    def test_update_load_balancer_missing_name(self):
        """Test update load balancer with missing name"""
        loadbalancer = self._show_load_balancer(
            self.load_balancer_id)
        load_balancer_initial = loadbalancer['name']
        self._update_load_balancer(self.load_balancer_id)
        load_balancer = self._show_load_balancer(
            self.load_balancer_id)
        load_balancer_new = load_balancer['name']
        self.assertEqual(load_balancer_initial, load_balancer_new)

    @test.attr(type='negative')
    @decorators.skip_because(bug="1637877")
    @test.idempotent_id('ab3550c6-8b21-463c-bc5d-e79cbae3432f')
    def test_update_load_balancer_invalid_description(self):
        """Test update load balancer with invalid description"""
        self.assertRaises(exceptions.BadRequest,
                          self._update_load_balancer,
                          load_balancer_id=self.load_balancer_id,
                          wait=False,
                          description='a' * 256)

    @test.attr(type='smoke')
    @test.idempotent_id('157ebdbf-4ad2-495d-b880-c1b1a8edc46d')
    def test_update_load_balancer_empty_description(self):
        """Test update load balancer with empty description"""
        self._update_load_balancer(self.load_balancer_id,
                                   description="")
        load_balancer = self._show_load_balancer(
            self.load_balancer_id)
        self.assertEqual(load_balancer.get('description'), "")

    @test.attr(type='smoke')
    @test.idempotent_id('d13fa2f5-e8df-4d53-86a8-68583941200c')
    def test_update_load_balancer_missing_description(self):
        """Test update load balancer with missing description"""
        loadbalancer = self._show_load_balancer(
            self.load_balancer_id)
        load_balancer_initial = loadbalancer['description']
        self._update_load_balancer(self.load_balancer_id)
        load_balancer = self._show_load_balancer(
            self.load_balancer_id)
        load_balancer_new = load_balancer['description']
        self.assertEqual(load_balancer_initial, load_balancer_new)

    @test.attr(type='negative')
    @test.idempotent_id('96e46a1a-62e7-47f1-98c5-9983f89e622f')
    def test_update_load_balancer_invalid_admin_state_up_field(self):
        """Test update load balancer with an invalid admin_state_up"""
        self.assertRaises(exceptions.BadRequest,
                          self._update_load_balancer,
                          load_balancer_id=self.load_balancer_id,
                          wait=False,
                          admin_state_up="a&^%$jbc123")

    @test.attr(type='negative')
    @test.idempotent_id('48f1e227-8b15-4389-a050-7ce76f4b4d46')
    def test_update_load_balancer_empty_admin_state_up_field(self):
        """Test update load balancer with an empty admin_state_up"""
        self.assertRaises(exceptions.BadRequest,
                          self._update_load_balancer,
                          load_balancer_id=self.load_balancer_id,
                          wait=False,
                          admin_state_up="")

    @test.attr(type='smoke')
    @test.idempotent_id('a9182e53-ddaa-4f41-af54-585d983279ba')
    def test_update_load_balancer_missing_admin_state_up(self):
        """Test update load balancer with missing admin state field"""
        loadbalancer = self._show_load_balancer(
            self.load_balancer_id)
        load_balancer_initial = loadbalancer['admin_state_up']
        self._update_load_balancer(self.load_balancer_id)
        self.assertEqual(load_balancer_initial, True)

    @test.attr(type='negative')
    @test.idempotent_id('bfbe9339-d083-4a88-b6d6-015522809c3a')
    def test_update_load_balancer_incorrect_attribute(self):
        """Test update a load balancer with an extra, invalid attribute"""
        self.assertRaises(exceptions.BadRequest,
                          self._update_load_balancer,
                          load_balancer_id=self.load_balancer_id,
                          wait=False,
                          name="lb_name",
                          description="lb_name_description",
                          admin_state_up=True,
                          port=80)

    @test.attr(type='smoke')
    @test.idempotent_id('d2258984-6e9a-41d6-bffa-0543c8b1f2b0')
    def test_get_load_balancer_status_tree(self):
        """Test get load balancer status tree"""
        statuses = self._show_load_balancer_status_tree(
            self.load_balancer_id)
        load_balancer = statuses['loadbalancer']
        self.assertEqual("ONLINE", load_balancer['operating_status'])
        self.assertEqual("ACTIVE", load_balancer['provisioning_status'])
        self.assertEqual([], load_balancer['listeners'])

    @test.attr(type='smoke')
    @test.idempotent_id('a23677a9-b770-4894-8be9-cd66590c228b')
    def test_get_load_balancer_stats(self):
        """Test get load balancer stats"""
        stats = self._show_load_balancer_stats(
            self.load_balancer_id)
        self.assertEqual(0, stats['bytes_in'])
        self.assertEqual(0, stats['bytes_out'])
        self.assertEqual(0, stats['total_connections'])
        self.assertEqual(0, stats['active_connections'])

    @test.attr(type='smoke')
    @test.idempotent_id('f289f8df-a867-45cd-bee3-7ff08f5e96e0')
    def test_delete_load_balancer(self):
        """Test delete load balancer"""
        new_load_balancer = self._create_active_load_balancer(
            **self.create_lb_kwargs)
        new_load_balancer_id = new_load_balancer['id']
        load_balancer = self._show_load_balancer(
            new_load_balancer_id)
        self.assertEqual(new_load_balancer, load_balancer)
        self.assertNotEqual(self.load_balancer, new_load_balancer)
        self._delete_load_balancer(new_load_balancer_id)
        self.assertRaises(exceptions.NotFound,
                          self._show_load_balancer,
                          new_load_balancer_id)
