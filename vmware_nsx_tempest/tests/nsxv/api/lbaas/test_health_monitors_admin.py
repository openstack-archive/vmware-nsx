# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log as logging
from oslo_utils import uuidutils

from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions as ex
from tempest import test

from vmware_nsx_tempest.tests.nsxv.api.lbaas import base

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestHealthMonitors(base.BaseAdminTestCase):

    """Tests the following operations in the Neutron-LBaaS API

    using the REST client for Health Monitors with ADMIN role:

        create health monitor with missing tenant_id
        create health monitor with empty tenant id
        create health monitor with another tenant_id
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

    @classmethod
    def resource_cleanup(cls):
        super(TestHealthMonitors, cls).resource_cleanup()

    @test.attr(type='smoke')
    @test.idempotent_id('24cf7da4-b829-4df5-a133-b6cef97ec560')
    def test_create_health_monitor_missing_tenant_id_field(self):
        """Test if admin user can

        create health monitor with a missing tenant id field.
        """
        hm = self._create_health_monitor(type='HTTP', delay=3, max_retries=10,
                                         timeout=5,
                                         pool_id=self.pool.get('id'))

        admin_hm = self._show_health_monitor(hm.get('id'))
        admin_tenant_id = admin_hm.get('tenant_id')
        hm_tenant_id = hm.get('tenant_id')
        self.assertEqual(admin_tenant_id, hm_tenant_id)

    @test.attr(type='negative')
    @decorators.skip_because(bug="1638148")
    @test.idempotent_id('acbff982-15d6-43c5-a015-e72b7df30998')
    def test_create_health_monitor_empty_tenant_id_field(self):
        """Test with admin user

        creating health monitor with an empty tenant id field should fail.
        """
        self.assertRaises(ex.BadRequest, self._create_health_monitor,
                          type='HTTP', delay=3, max_retries=10,
                          timeout=5,
                          pool_id=self.pool.get('id'),
                          tenant_id="")

    @test.attr(type='smoke')
    @test.idempotent_id('a318d351-a72e-46dc-a094-8a751e4fa7aa')
    def test_create_health_monitor_for_another_tenant_id_field(self):
        """Test with admin user

        create health Monitors for another tenant id.
        """

        tenantid = uuidutils.generate_uuid()
        hm = self._create_health_monitor(type='HTTP', delay=3, max_retries=10,
                                         timeout=5,
                                         pool_id=self.pool.get('id'),
                                         tenant_id=tenantid)

        self.assertEqual(hm.get('tenant_id'), tenantid)
        self.assertNotEqual(hm.get('tenant_id'),
                            self.subnet.get('tenant_id'))
