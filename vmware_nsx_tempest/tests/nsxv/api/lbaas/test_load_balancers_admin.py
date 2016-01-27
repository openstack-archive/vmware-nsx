# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log as logging

from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions as ex
from tempest import test

from vmware_nsx_tempest.tests.nsxv.api.lbaas import base

CONF = config.CONF

LOG = logging.getLogger(__name__)


class LoadBalancersTest(base.BaseAdminTestCase):

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
    @decorators.skip_because(bug="1641902")
    @test.idempotent_id('0008ae1e-77a2-45d9-b81e-0e3119b5a26d')
    def test_create_load_balancer_missing_tenant_id_field_for_admin(self):
        """Test create load balancer with a missing tenant id field.

        Verify tenant_id matches when creating loadbalancer vs.
        load balancer(admin tenant)
        """
        load_balancer = self._create_load_balancer(
            vip_subnet_id=self.subnet['id'])
        self.addCleanup(self._delete_load_balancer, load_balancer['id'])
        admin_lb = self._show_load_balancer(
            load_balancer.get('id'))
        self.assertEqual(load_balancer.get('tenant_id'),
                         admin_lb.get('tenant_id'))
        self._wait_for_load_balancer_status(load_balancer['id'])

    @test.attr(type='smoke')
    @decorators.skip_because(bug="1638571")
    @test.idempotent_id('37620941-47c1-40b2-84d8-db17ff823ebc')
    def test_create_load_balancer_missing_tenant_id_for_other_tenant(self):
        """Test create load balancer with a missing tenant id field.

        Verify tenant_id does not match of subnet(non-admin tenant) vs.
        load balancer(admin tenant)
        """
        load_balancer = self._create_load_balancer(
            vip_subnet_id=self.subnet['id'])
        self.addCleanup(self._delete_load_balancer, load_balancer['id'])
        self.assertNotEqual(load_balancer.get('tenant_id'),
                            self.subnet['tenant_id'])
        self._wait_for_load_balancer_status(load_balancer['id'])

    @test.attr(type='negative')
    @decorators.skip_because(bug="1638148")
    # Empty tenant_id causing ServerFault
    @test.idempotent_id('5bf483f5-ae28-47f5-8805-642da0ffcb40')
    def test_create_load_balancer_empty_tenant_id_field(self):
        """Test create load balancer with empty tenant_id field should fail"""
        self.assertRaises(ex.BadRequest,
                          self._create_load_balancer,
                          vip_subnet_id=self.subnet['id'],
                          wait=False,
                          tenant_id="")

    @test.attr(type='smoke')
    @decorators.skip_because(bug="1638571")
    @test.idempotent_id('19fc8a44-1280-49f3-be5b-0d30e6e43363')
    # 2nd tenant_id at the same subnet not supported; got serverFault
    def test_create_load_balancer_for_another_tenant(self):
        """Test create load balancer for other tenant"""
        tenant = 'deffb4d7c0584e89a8ec99551565713c'
        load_balancer = self._create_load_balancer(
            vip_subnet_id=self.subnet['id'],
            tenant_id=tenant)
        self.addCleanup(self._delete_load_balancer, load_balancer['id'])
        self.assertEqual(load_balancer.get('tenant_id'), tenant)
        self._wait_for_load_balancer_status(load_balancer['id'])
