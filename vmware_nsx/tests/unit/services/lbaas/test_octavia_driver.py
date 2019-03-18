# Copyright 2018 VMware, Inc.
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

import decorator
import mock
import testtools

from oslo_utils import uuidutils

from octavia_lib.api.drivers import data_models

code_ok = True
# Skip duplications between Octavia & Neutron configurations and missing
# configuration groups
with mock.patch('oslo_config.cfg.ConfigOpts.import_group'),\
    mock.patch('oslo_config.cfg.ConfigOpts.__getattr__'):
    try:
        from vmware_nsx.services.lbaas.octavia import octavia_driver as driver
    except ImportError:
        # Octavia code not found
        # this can happen as Octavia is not in the requirements yet
        code_ok = False

DRIVER = 'vmware_nsx.services.lbaas.octavia.octavia_driver.NSXOctaviaDriver'


class TestNsxProviderDriver(testtools.TestCase):
    """Test the NSX Octavia driver

    Make sure all the relevant data is translated and sent to the listener
    """
    def setUp(self):
        super(TestNsxProviderDriver, self).setUp()
        global code_ok
        if not code_ok:
            return
        # init the NSX driver without the RPC & certificate
        with mock.patch(DRIVER + '._init_rpc_messaging'), \
            mock.patch(DRIVER + '._init_rpc_listener'), \
            mock.patch(DRIVER + '._init_cert_manager'):
            self.driver = driver.NSXOctaviaDriver()
            self.driver.client = mock.Mock()

        self.loadbalancer_id = uuidutils.generate_uuid()
        self.vip_address = '192.0.2.10'
        self.vip_network_id = uuidutils.generate_uuid()
        self.vip_port_id = uuidutils.generate_uuid()
        self.vip_subnet_id = uuidutils.generate_uuid()
        self.listener_id = uuidutils.generate_uuid()
        self.pool_id = uuidutils.generate_uuid()
        self.member_id = uuidutils.generate_uuid()
        self.member_subnet_id = uuidutils.generate_uuid()
        self.healthmonitor_id = uuidutils.generate_uuid()
        self.l7policy_id = uuidutils.generate_uuid()
        self.l7rule_id = uuidutils.generate_uuid()
        self.project_id = uuidutils.generate_uuid()
        self.default_tls_container_ref = uuidutils.generate_uuid()
        self.sni_container_ref_1 = uuidutils.generate_uuid()
        self.sni_container_ref_2 = uuidutils.generate_uuid()

        self.ref_member = data_models.Member(
            address='198.51.100.4',
            admin_state_up=True,
            member_id=self.member_id,
            monitor_address='203.0.113.2',
            monitor_port=66,
            name='jacket',
            pool_id=self.pool_id,
            protocol_port=99,
            subnet_id=self.member_subnet_id,
            weight=55)

        self.ref_healthmonitor = data_models.HealthMonitor(
            admin_state_up=False,
            delay=2,
            expected_codes="500",
            healthmonitor_id=self.healthmonitor_id,
            http_method='TRACE',
            max_retries=1,
            max_retries_down=0,
            name='doc',
            pool_id=self.pool_id,
            timeout=3,
            type='PHD',
            url_path='/index.html')

        self.ref_pool = data_models.Pool(
            admin_state_up=True,
            description='Olympic swimming pool',
            healthmonitor=self.ref_healthmonitor,
            lb_algorithm='A_Fast_One',
            loadbalancer_id=self.loadbalancer_id,
            members=[self.ref_member],
            name='Osborn',
            pool_id=self.pool_id,
            protocol='avian',
            session_persistence={'type': 'glue'})

        self.ref_l7rule = data_models.L7Rule(
            admin_state_up=True,
            compare_type='store_brand',
            invert=True,
            key='board',
            l7policy_id=self.l7policy_id,
            l7rule_id=self.l7rule_id,
            type='strict',
            value='gold')

        self.ref_l7policy = data_models.L7Policy(
            action='packed',
            admin_state_up=False,
            description='Corporate policy',
            l7policy_id=self.l7policy_id,
            listener_id=self.listener_id,
            name='more_policy',
            position=1,
            redirect_pool_id=self.pool_id,
            redirect_url='/hr',
            rules=[self.ref_l7rule])

        self.ref_listener = data_models.Listener(
            admin_state_up=False,
            connection_limit=5,
            default_pool=self.ref_pool,
            default_pool_id=self.pool_id,
            default_tls_container_data='default_cert_data',
            default_tls_container_ref=self.default_tls_container_ref,
            description='The listener',
            insert_headers={'X-Forwarded-For': 'true'},
            l7policies=[self.ref_l7policy],
            listener_id=self.listener_id,
            loadbalancer_id=self.loadbalancer_id,
            name='super_listener',
            protocol='avian',
            protocol_port=42,
            sni_container_data=['sni_cert_data_1', 'sni_cert_data_2'],
            sni_container_refs=[self.sni_container_ref_1,
                                self.sni_container_ref_2])

        self.ref_lb = data_models.LoadBalancer(
            admin_state_up=False,
            description='One great load balancer',
            flavor={'cake': 'chocolate'},
            listeners=[self.ref_listener],
            loadbalancer_id=self.loadbalancer_id,
            name='favorite_lb',
            project_id=self.project_id,
            vip_address=self.vip_address,
            vip_network_id=self.vip_network_id,
            vip_port_id=self.vip_port_id,
            vip_subnet_id=self.vip_subnet_id)

        # start DB mocks
        mock.patch('octavia.db.api.get_session').start()
        mock.patch("octavia.api.drivers.utils.db_pool_to_provider_pool",
                   return_value=self.ref_pool).start()

    @decorator.decorator
    def skip_no_octavia(f, *args, **kwargs):
        global code_ok
        if not code_ok:
            obj = args[0]
            return obj.skipTest('Octavia code not found')
        return f(*args, **kwargs)

    @skip_no_octavia
    def test_loadbalancer_create(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.loadbalancer_create(self.ref_lb)
            cast_method.assert_called_with({}, 'loadbalancer_create',
                                           loadbalancer=mock.ANY)
            driver_obj = cast_method.call_args[1]['loadbalancer']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)
            self.assertIn('admin_state_up', driver_obj)
            self.assertIn('name', driver_obj)
            self.assertIn('listeners', driver_obj)
            self.assertEqual(1, len(driver_obj['listeners']))
            self.assertEqual(self.ref_lb.vip_address,
                             driver_obj['vip_address'])
            self.assertEqual(self.ref_lb.vip_network_id,
                             driver_obj['vip_network_id'])
            self.assertEqual(self.ref_lb.vip_port_id,
                             driver_obj['vip_port_id'])
            self.assertEqual(self.ref_lb.vip_subnet_id,
                             driver_obj['vip_subnet_id'])

    @skip_no_octavia
    def test_loadbalancer_delete(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.loadbalancer_delete(self.ref_lb)
            cast_method.assert_called_with({}, 'loadbalancer_delete',
                                           cascade=False,
                                           loadbalancer=mock.ANY)
            driver_obj = cast_method.call_args[1]['loadbalancer']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)

    @skip_no_octavia
    def test_loadbalancer_update(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.loadbalancer_update(self.ref_lb, self.ref_lb)
            cast_method.assert_called_with({}, 'loadbalancer_update',
                                           old_loadbalancer=mock.ANY,
                                           new_loadbalancer=mock.ANY)
            driver_obj = cast_method.call_args[1]['new_loadbalancer']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)

    @skip_no_octavia
    def test_listener_create(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.listener_create(self.ref_listener)
            cast_method.assert_called_with({}, 'listener_create', cert=None,
                                           listener=mock.ANY)
            driver_obj = cast_method.call_args[1]['listener']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)
            self.assertIn('admin_state_up', driver_obj)
            self.assertIn('name', driver_obj)
            self.assertIn('loadbalancer_id', driver_obj)
            self.assertIn('loadbalancer', driver_obj)
            self.assertEqual(self.ref_listener.protocol,
                             driver_obj['protocol'])
            self.assertEqual(self.ref_listener.protocol_port,
                             driver_obj['protocol_port'])
            self.assertEqual(self.ref_listener.connection_limit,
                             driver_obj['connection_limit'])
            self.assertIn('l7policies', driver_obj)
            #TODO(asarfaty) add after the driver is fixed
            #self.assertIn('default_tls_container_id', driver_obj)

    @skip_no_octavia
    def test_listener_delete(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.listener_delete(self.ref_listener)
            cast_method.assert_called_with({}, 'listener_delete',
                                           listener=mock.ANY)
            driver_obj = cast_method.call_args[1]['listener']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)

    @skip_no_octavia
    def test_listener_update(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.listener_update(self.ref_listener, self.ref_listener)
            cast_method.assert_called_with({}, 'listener_update', cert=None,
                                           old_listener=mock.ANY,
                                           new_listener=mock.ANY)
            driver_obj = cast_method.call_args[1]['new_listener']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)

    @skip_no_octavia
    def test_pool_create(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.pool_create(self.ref_pool)
            cast_method.assert_called_with({}, 'pool_create', pool=mock.ANY)
            driver_obj = cast_method.call_args[1]['pool']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)
            self.assertIn('admin_state_up', driver_obj)
            self.assertIn('name', driver_obj)
            self.assertIn('loadbalancer_id', driver_obj)
            self.assertIn('listener', driver_obj)
            self.assertIn('listeners', driver_obj)
            self.assertEqual(self.ref_pool.lb_algorithm,
                             driver_obj['lb_algorithm'])
            self.assertEqual(self.ref_pool.session_persistence,
                             driver_obj['session_persistence'])
            self.assertIn('members', driver_obj)

    @skip_no_octavia
    def test_pool_delete(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.pool_delete(self.ref_pool)
            cast_method.assert_called_with({}, 'pool_delete', pool=mock.ANY)
            driver_obj = cast_method.call_args[1]['pool']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)

    @skip_no_octavia
    def test_pool_update(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.pool_update(self.ref_pool, self.ref_pool)
            cast_method.assert_called_with({}, 'pool_update',
                                           old_pool=mock.ANY,
                                           new_pool=mock.ANY)
            driver_obj = cast_method.call_args[1]['new_pool']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)

    @skip_no_octavia
    def test_member_create(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.member_create(self.ref_member)
            cast_method.assert_called_with({}, 'member_create',
                                           member=mock.ANY)
            driver_obj = cast_method.call_args[1]['member']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)
            self.assertIn('admin_state_up', driver_obj)
            self.assertIn('name', driver_obj)
            self.assertEqual(self.pool_id, driver_obj['pool_id'])
            self.assertIn('pool', driver_obj)
            self.assertIn('loadbalancer', driver_obj['pool'])
            #TODO(asarfaty) add when the driver is fixed
            #self.assertIn('listener', driver_obj['pool'])
            self.assertEqual(self.ref_member.subnet_id,
                             driver_obj['subnet_id'])
            self.assertEqual(self.ref_member.address,
                             driver_obj['address'])
            self.assertEqual(self.ref_member.protocol_port,
                             driver_obj['protocol_port'])
            self.assertEqual(self.ref_member.weight,
                             driver_obj['weight'])

    @skip_no_octavia
    def test_member_delete(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.member_delete(self.ref_member)
            cast_method.assert_called_with({}, 'member_delete',
                                           member=mock.ANY)
            driver_obj = cast_method.call_args[1]['member']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)

    @skip_no_octavia
    def test_member_update(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.member_update(self.ref_member, self.ref_member)
            cast_method.assert_called_with({}, 'member_update',
                                           old_member=mock.ANY,
                                           new_member=mock.ANY)
            driver_obj = cast_method.call_args[1]['old_member']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)

    @skip_no_octavia
    def test_health_monitor_create(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.health_monitor_create(self.ref_healthmonitor)
            cast_method.assert_called_with({}, 'healthmonitor_create',
                                           healthmonitor=mock.ANY)
            driver_obj = cast_method.call_args[1]['healthmonitor']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)
            self.assertIn('admin_state_up', driver_obj)
            self.assertIn('name', driver_obj)
            self.assertEqual(self.ref_healthmonitor.type,
                             driver_obj['type'])
            self.assertEqual(self.ref_healthmonitor.url_path,
                             driver_obj['url_path'])
            self.assertEqual(self.ref_healthmonitor.delay,
                             driver_obj['delay'])
            self.assertEqual(self.ref_healthmonitor.timeout,
                             driver_obj['timeout'])
            self.assertEqual(self.ref_healthmonitor.max_retries,
                             driver_obj['max_retries'])
            self.assertEqual(self.ref_healthmonitor.http_method,
                             driver_obj['http_method'])
            self.assertIn('pool', driver_obj)
            self.assertEqual(self.pool_id,
                             driver_obj['pool']['id'])
            self.assertEqual(self.loadbalancer_id,
                             driver_obj['pool']['loadbalancer_id'])

    @skip_no_octavia
    def test_health_monitor_delete(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.health_monitor_delete(self.ref_healthmonitor)
            cast_method.assert_called_with({}, 'healthmonitor_delete',
                                           healthmonitor=mock.ANY)
            driver_obj = cast_method.call_args[1]['healthmonitor']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)

    @skip_no_octavia
    def test_health_monitor_update(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.health_monitor_update(self.ref_healthmonitor,
                                              self.ref_healthmonitor)
            cast_method.assert_called_with({}, 'healthmonitor_update',
                                           old_healthmonitor=mock.ANY,
                                           new_healthmonitor=mock.ANY)
            driver_obj = cast_method.call_args[1]['new_healthmonitor']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)

    @skip_no_octavia
    def test_l7policy_create(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.l7policy_create(self.ref_l7policy)
            cast_method.assert_called_with({}, 'l7policy_create',
                                           l7policy=mock.ANY)
            driver_obj = cast_method.call_args[1]['l7policy']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)
            self.assertIn('admin_state_up', driver_obj)
            self.assertIn('name', driver_obj)
            self.assertIn('listener', driver_obj)
            self.assertEqual(self.listener_id, driver_obj['listener_id'])
            self.assertIn('rules', driver_obj)
            self.assertIn('position', driver_obj)
            self.assertEqual(self.ref_l7policy.action, driver_obj['action'])
            self.assertEqual(self.ref_l7policy.redirect_url,
                             driver_obj['redirect_url'])
            self.assertEqual(self.ref_l7policy.redirect_pool_id,
                             driver_obj['redirect_pool_id'])

    @skip_no_octavia
    def test_l7policy_delete(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.l7policy_delete(self.ref_l7policy)
            cast_method.assert_called_with({}, 'l7policy_delete',
                                           l7policy=mock.ANY)
            driver_obj = cast_method.call_args[1]['l7policy']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)

    @skip_no_octavia
    def test_l7policy_update(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.l7policy_update(self.ref_l7policy, self.ref_l7policy)
            cast_method.assert_called_with({}, 'l7policy_update',
                                           old_l7policy=mock.ANY,
                                           new_l7policy=mock.ANY)
            driver_obj = cast_method.call_args[1]['new_l7policy']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)

    @skip_no_octavia
    def test_l7rule_create(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.l7rule_create(self.ref_l7rule)
            cast_method.assert_called_with({}, 'l7rule_create',
                                           l7rule=mock.ANY)
            driver_obj = cast_method.call_args[1]['l7rule']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)
            self.assertIn('admin_state_up', driver_obj)
            self.assertIn('name', driver_obj)
            self.assertIn('policy', driver_obj)
            self.assertIn('rules', driver_obj['policy'])
            self.assertEqual(self.ref_l7rule.type, driver_obj['type'])
            self.assertEqual(self.ref_l7rule.value, driver_obj['value'])
            self.assertEqual(self.ref_l7rule.invert, driver_obj['invert'])

    @skip_no_octavia
    def test_l7rule_delete(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.l7rule_delete(self.ref_l7rule)
            cast_method.assert_called_with({}, 'l7rule_delete',
                                           l7rule=mock.ANY)
            driver_obj = cast_method.call_args[1]['l7rule']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)

    @skip_no_octavia
    def test_l7rule_update(self):
        with mock.patch.object(self.driver.client, 'cast') as cast_method:
            self.driver.l7rule_update(self.ref_l7rule, self.ref_l7rule)
            cast_method.assert_called_with({}, 'l7rule_update',
                                           old_l7rule=mock.ANY,
                                           new_l7rule=mock.ANY)
            driver_obj = cast_method.call_args[1]['new_l7rule']
            self.assertIn('id', driver_obj)
            self.assertIn('project_id', driver_obj)
