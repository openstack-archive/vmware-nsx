# Copyright 2017 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from collections import namedtuple
import contextlib

import mock
from oslo_utils import uuidutils

from neutron.db import l3_db
from neutron.db.models import l3 as l3_models
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib import context as n_ctx
from neutron_lib.plugins import directory
from neutron_vpnaas.db.vpn import vpn_models  # noqa
from neutron_vpnaas.tests import base

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_driver
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_validator
from vmware_nsx.tests.unit.nsx_v3 import test_plugin

_uuid = uuidutils.generate_uuid

FAKE_TENANT = _uuid()
FAKE_ROUTER_ID = "aaaaaa-bbbbb-ccc"
FAKE_ROUTER = {'id': FAKE_ROUTER_ID,
               'name': 'fake router',
               'tenant_id': FAKE_TENANT,
               'admin_state_up': True,
               'status': 'ACTIVE',
               'gw_port_id': _uuid(),
               'enable_snat': False,
               l3_db.EXTERNAL_GW_INFO: {'network_id': _uuid()}}
FAKE_SUBNET_ID = _uuid()
FAKE_SUBNET = {'cidr': '1.1.1.0/24', 'id': FAKE_SUBNET_ID}
FAKE_VPNSERVICE_ID = _uuid()
FAKE_VPNSERVICE = {'id': FAKE_VPNSERVICE_ID,
                   'name': 'vpn_service',
                   'description': 'dummy',
                   'router': FAKE_ROUTER,
                   'router_id': FAKE_ROUTER_ID,
                   'subnet': FAKE_SUBNET,
                   'subnet_id': FAKE_SUBNET_ID,
                   'tenant_id': FAKE_TENANT,
                   'admin_state_up': True}
FAKE_IKE_POLICY_ID = _uuid()
FAKE_IKE_POLICY = {'id': FAKE_IKE_POLICY_ID,
                   'name': 'ike_dummy',
                   'description': 'ike_dummy',
                   'auth_algorithm': 'sha1',
                   'encryption_algorithm': 'aes-128',
                   'phase1_negotiation_mode': 'main',
                   'lifetime': {
                       'units': 'seconds',
                       'value': 3600},
                   'ike_version': 'v1',
                   'pfs': 'group14',
                   'tenant_id': FAKE_TENANT}
FAKE_IPSEC_POLICY_ID = _uuid()
FAKE_IPSEC_POLICY = {'id': FAKE_IPSEC_POLICY_ID,
                     'name': 'ipsec_dummy',
                     'description': 'myipsecpolicy1',
                     'auth_algorithm': 'sha1',
                     'encryption_algorithm': 'aes-128',
                     'encapsulation_mode': 'tunnel',
                     'lifetime': {
                         'units': 'seconds',
                         'value': 3600},
                     'transform_protocol': 'esp',
                     'pfs': 'group14',
                     'tenant_id': FAKE_TENANT}
FAKE_IPSEC_CONNECTION_ID = _uuid()
FAKE_IPSEC_CONNECTION = {'vpnservice_id': FAKE_VPNSERVICE_ID,
                         'ikepolicy_id': FAKE_IKE_POLICY_ID,
                         'ipsecpolicy_id': FAKE_IPSEC_POLICY_ID,
                         'name': 'VPN connection',
                         'description': 'VPN connection',
                         'id': FAKE_IPSEC_CONNECTION_ID,
                         'peer_address': '192.168.1.10',
                         'peer_id': '192.168.1.10',
                         'peer_cidrs': '192.168.1.0/24',
                         'mtu': 1500,
                         'psk': 'abcd',
                         'initiator': 'bi-directional',
                         'dpd': {
                             'action': 'hold',
                             'interval': 30,
                             'timeout': 120},
                         'admin_state_up': True,
                         'tenant_id': FAKE_TENANT}
FAKE_NEW_CONNECTION = {'vpnservice_id': FAKE_VPNSERVICE_ID,
                       'ikepolicy_id': FAKE_IKE_POLICY_ID,
                       'ipsecpolicy_id': FAKE_IPSEC_POLICY_ID,
                       'name': 'VPN connection',
                       'description': 'VPN connection',
                       'id': FAKE_IPSEC_CONNECTION_ID,
                       'peer_address': '192.168.1.10',
                       'peer_id': '192.168.1.10',
                       'peer_cidrs': '192.168.2.0/24',
                       'mtu': 1500,
                       'psk': 'abcd',
                       'initiator': 'bi-directional',
                       'dpd': {
                           'action': 'hold',
                           'interval': 30,
                           'timeout': 120},
                       'admin_state_up': True,
                       'tenant_id': FAKE_TENANT}


class TestDriverValidation(base.BaseTestCase):

    def setUp(self):
        super(TestDriverValidation, self).setUp()
        self.context = n_ctx.Context('some_user', 'some_tenant')
        self.service_plugin = mock.Mock()
        driver = mock.Mock()
        driver.service_plugin = self.service_plugin
        with mock.patch("neutron_lib.plugins.directory.get_plugin"):
            self.validator = ipsec_validator.IPsecV3Validator(driver)
            self.validator._l3_plugin = mock.Mock()
            self.validator._core_plugin = mock.Mock()

        self.vpn_service = {'router_id': 'dummy_router',
                            'subnet_id': 'dummy_subnet'}
        self.peer_address = '10.10.10.10'
        self.peer_cidr = '10.10.11.0/20'

    def _test_lifetime_not_in_seconds(self, validation_func):
        policy_info = {'lifetime': {'units': 'kilobytes', 'value': 1000}}
        self.assertRaises(nsx_exc.NsxVpnValidationError,
                          validation_func,
                          self.context, policy_info)

    def test_ike_lifetime_not_in_seconds(self):
        self._test_lifetime_not_in_seconds(
            self.validator.validate_ike_policy)

    def test_ipsec_lifetime_not_in_seconds(self):
        self._test_lifetime_not_in_seconds(
            self.validator.validate_ipsec_policy)

    def _test_lifetime_seconds_values_at_limits(self, validation_func):
        policy_info = {'lifetime': {'units': 'seconds', 'value': 21600}}
        validation_func(self.context, policy_info)
        policy_info = {'lifetime': {'units': 'seconds', 'value': 86400}}
        validation_func(self.context, policy_info)

        policy_info = {'lifetime': {'units': 'seconds', 'value': 10}}
        self.assertRaises(nsx_exc.NsxVpnValidationError,
                          validation_func,
                          self.context, policy_info)

    def test_ike_lifetime_seconds_values_at_limits(self):
        self._test_lifetime_seconds_values_at_limits(
            self.validator.validate_ike_policy)

    def test_ipsec_lifetime_seconds_values_at_limits(self):
        self._test_lifetime_seconds_values_at_limits(
            self.validator.validate_ipsec_policy)

    def _test_auth_algorithm(self, validation_func):
        auth_algorithm = {'auth_algorithm': 'sha384'}
        self.assertRaises(nsx_exc.NsxVpnValidationError,
                          validation_func,
                          self.context, auth_algorithm)

        auth_algorithm = {'auth_algorithm': 'sha512'}
        self.assertRaises(nsx_exc.NsxVpnValidationError,
                          validation_func,
                          self.context, auth_algorithm)

        auth_algorithm = {'auth_algorithm': 'sha1'}
        validation_func(self.context, auth_algorithm)

        auth_algorithm = {'auth_algorithm': 'sha256'}
        validation_func(self.context, auth_algorithm)

    def test_ipsec_auth_algorithm(self):
        self._test_auth_algorithm(self.validator.validate_ipsec_policy)

    def test_ike_auth_algorithm(self):
        self._test_auth_algorithm(self.validator.validate_ike_policy)

    def _test_encryption_algorithm(self, validation_func):
        auth_algorithm = {'encryption_algorithm': 'aes-192'}
        self.assertRaises(nsx_exc.NsxVpnValidationError,
                          validation_func,
                          self.context, auth_algorithm)

        auth_algorithm = {'encryption_algorithm': 'aes-128'}
        validation_func(self.context, auth_algorithm)

        auth_algorithm = {'encryption_algorithm': 'aes-256'}
        validation_func(self.context, auth_algorithm)

    def test_ipsec_encryption_algorithm(self):
        self._test_encryption_algorithm(self.validator.validate_ipsec_policy)

    def test_ike_encryption_algorithm(self):
        self._test_encryption_algorithm(self.validator.validate_ike_policy)

    def test_ike_negotiation_mode(self):
        policy_info = {'phase1-negotiation-mode': 'aggressive'}
        self.assertRaises(nsx_exc.NsxVpnValidationError,
                          self.validator.validate_ike_policy,
                          self.context, policy_info)

        policy_info = {'phase1-negotiation-mode': 'main'}
        self.validator.validate_ike_policy(self.context, policy_info)

    def _test_pfs(self, validation_func):
        policy_info = {'pfs': 'group15'}
        self.assertRaises(nsx_exc.NsxVpnValidationError,
                          validation_func,
                          self.context, policy_info)

        policy_info = {'pfs': 'group14'}
        validation_func(self.context, policy_info)

    def test_ipsec_pfs(self):
        self._test_pfs(self.validator.validate_ipsec_policy)

    def test_ike_pfs(self):
        self._test_pfs(self.validator.validate_ike_policy)

    def test_ipsec_encap_mode(self):
        policy_info = {'encapsulation_mode': 'transport'}
        self.assertRaises(nsx_exc.NsxVpnValidationError,
                          self.validator.validate_ipsec_policy,
                          self.context, policy_info)

        policy_info = {'encapsulation_mode': 'tunnel'}
        self.validator.validate_ipsec_policy(self.context, policy_info)

    def test_ipsec_transform_protocol(self):
        policy_info = {'transform_protocol': 'ah'}
        self.assertRaises(nsx_exc.NsxVpnValidationError,
                          self.validator.validate_ipsec_policy,
                          self.context, policy_info)

        policy_info = {'transform_protocol': 'esp'}
        self.validator.validate_ipsec_policy(self.context, policy_info)

    def test_vpn_service_validation_router(self):
        db_router = l3_models.Router()
        nsx_router = {'high_availability_mode': 'ACITVE_ACTIVE'}
        db_router.enable_snat = False
        with mock.patch.object(self.validator.nsxlib.logical_router, 'get',
                               return_value=nsx_router):
            self.assertRaises(nsx_exc.NsxVpnValidationError,
                              self.validator.validate_vpnservice,
                              self.context, self.vpn_service)

        nsx_router = {'high_availability_mode': 'ACTIVE_STANDBY'}
        db_router.enable_snat = True
        with mock.patch.object(self.validator.nsxlib.logical_router, 'get',
                               return_value=nsx_router),\
            mock.patch.object(self.validator._core_plugin, '_get_router',
                              return_value=db_router):
            self.assertRaises(nsx_exc.NsxVpnValidationError,
                              self.validator.validate_vpnservice,
                              self.context, self.vpn_service)

        nsx_router = {'high_availability_mode': 'ACTIVE_STANDBY'}
        db_router.enable_snat = False
        with mock.patch.object(self.validator.nsxlib.logical_router, 'get',
                               return_value=nsx_router),\
            mock.patch.object(self.validator._core_plugin, '_get_router',
                              return_value=db_router):
            self.validator.validate_vpnservice(self.context, self.vpn_service)

    def _test_conn_validation(self, conn_params=None, success=True,
                              connections=None, service_subnets=None,
                              router_subnets=None):
        if connections is None:
            connections = []
        if router_subnets is None:
            router_subnets = []

        def mock_get_routers(context, filters=None, fields=None):
            return [{'id': 'no-snat',
                     'external_gateway_info': {'enable_snat': False}}]

        def mock_get_service(context, service_id):
            if service_subnets:
                # option to give the test a different subnet per service
                subnet_cidr = service_subnets[int(service_id) - 1]
            else:
                subnet_cidr = '5.5.5.0/2%s' % service_id
            return {'id': service_id,
                    'router_id': service_id,
                    'subnet_id': 'dummy_subnet',
                    'external_v4_ip': '1.1.1.%s' % service_id,
                    'subnet': {'id': 'dummy_subnet',
                               'cidr': subnet_cidr}}

        def mock_get_connections(context, filters=None, fields=None):
            if filters and 'peer_address' in filters:
                return [conn for conn in connections
                        if conn['peer_address'] == filters['peer_address'][0]]
            else:
                return connections

        with mock.patch.object(self.validator.vpn_plugin, '_get_vpnservice',
                               side_effect=mock_get_service),\
            mock.patch.object(self.validator._core_plugin, 'get_routers',
                              side_effect=mock_get_routers),\
            mock.patch.object(self.validator._core_plugin,
                              '_find_router_subnets_cidrs',
                              return_value=router_subnets),\
            mock.patch.object(self.validator.vpn_plugin,
                              'get_ipsec_site_connections',
                              side_effect=mock_get_connections):
                ipsec_sitecon = {'id': '1',
                                 'vpnservice_id': '1',
                                 'mtu': 1500,
                                 'peer_address': self.peer_address,
                                 'peer_cidrs': [self.peer_cidr]}
                if conn_params:
                    ipsec_sitecon.update(conn_params)
                if success:
                    self.validator.validate_ipsec_site_connection(
                        self.context, ipsec_sitecon)
                else:
                    self.assertRaises(
                        nsx_exc.NsxVpnValidationError,
                        self.validator.validate_ipsec_site_connection,
                        self.context, ipsec_sitecon)

    def test_dpd_validation(self):
        params = {'dpd': {'action': 'hold',
                          'timeout': 120}}
        self._test_conn_validation(conn_params=params, success=True)

        params = {'dpd': {'action': 'clear',
                          'timeout': 120}}
        self._test_conn_validation(conn_params=params, success=False)

        params = {'dpd': {'action': 'hold',
                          'timeout': 2}}
        self._test_conn_validation(conn_params=params, success=False)

    def test_check_unique_addresses(self):
        # this test runs with non-overlapping local subnets on
        # different routers
        subnets = ['5.5.5.0/20', '6.6.6.0/20']

        # same service/router gw & peer address - should fail
        connections = [{'id': '2',
                        'status': 'ACTIVE',
                        'vpnservice_id': '1',
                        'peer_address': self.peer_address,
                        'peer_cidrs': [self.peer_cidr]}]
        self._test_conn_validation(success=False,
                                   connections=connections,
                                   service_subnets=subnets)

        # different service/router gw - ok
        connections = [{'id': '2',
                        'status': 'ACTIVE',
                        'vpnservice_id': '2',
                        'peer_address': self.peer_address,
                        'peer_cidrs': ['6.6.6.6']}]
        self._test_conn_validation(success=True,
                                   connections=connections,
                                   service_subnets=subnets)

        # different peer address - ok
        connections = [{'id': '2',
                        'status': 'ACTIVE',
                        'vpnservice_id': '1',
                        'peer_address': '7.7.7.1',
                        'peer_cidrs': ['7.7.7.7']}]
        self._test_conn_validation(success=True,
                                   connections=connections,
                                   service_subnets=subnets)

        # ignoring non-active connections
        connections = [{'id': '2',
                        'status': 'ERROR',
                        'vpnservice_id': '1',
                        'peer_address': self.peer_address,
                        'peer_cidrs': [self.peer_cidr]}]
        self._test_conn_validation(success=True,
                                   connections=connections,
                                   service_subnets=subnets)

    def test_overlapping_rules(self):
        # peer-cidr overlapping with new one, same subnet - should fail
        connections = [{'id': '2',
                        'status': 'ACTIVE',
                        'vpnservice_id': '1',
                        'peer_address': '9.9.9.9',
                        'peer_cidrs': ['10.10.11.1/19']}]
        self._test_conn_validation(success=False,
                                   connections=connections)

        # same peer-cidr, overlapping subnets - should fail
        connections = [{'id': '2',
                        'status': 'ACTIVE',
                        'vpnservice_id': '2',
                        'peer_address': '9.9.9.9',
                        'peer_cidrs': [self.peer_cidr]}]
        self._test_conn_validation(success=False,
                                   connections=connections)

        # non overlapping peer-cidr, same subnet - ok
        connections = [{'id': '2',
                        'status': 'ACTIVE',
                        'vpnservice_id': '1',
                        'peer_address': '7.7.7.1',
                        'peer_cidrs': ['7.7.7.7']}]
        self._test_conn_validation(success=True,
                                   connections=connections)

        # ignoring non-active connections
        connections = [{'id': '2',
                        'status': 'ERROR',
                        'vpnservice_id': '1',
                        'peer_address': '9.9.9.9',
                        'peer_cidrs': ['10.10.11.1/19']}]
        self._test_conn_validation(success=True,
                                   connections=connections)

    def test_advertisment(self):
        # different routers, same subnet - should fail
        subnets = ['5.5.5.0/20', '5.5.5.0/20']
        connections = [{'id': '2',
                        'status': 'ACTIVE',
                        'vpnservice_id': '2',
                        'peer_address': self.peer_address,
                        'peer_cidrs': ['6.6.6.6']}]
        self._test_conn_validation(success=False,
                                   connections=connections,
                                   service_subnets=subnets)

        # different routers, overlapping subnet - should fail
        subnets = ['5.5.5.0/20', '5.5.5.0/21']
        connections = [{'id': '2',
                        'status': 'ACTIVE',
                        'vpnservice_id': '2',
                        'peer_address': self.peer_address,
                        'peer_cidrs': ['6.6.6.6']}]
        self._test_conn_validation(success=False,
                                   connections=connections,
                                   service_subnets=subnets)

        # different routers, non overlapping subnet - ok
        subnets = ['5.5.5.0/20', '50.5.5.0/21']
        connections = [{'id': '2',
                        'status': 'ACTIVE',
                        'vpnservice_id': '2',
                        'peer_address': self.peer_address,
                        'peer_cidrs': ['6.6.6.6']}]
        self._test_conn_validation(success=True,
                                   connections=connections,
                                   service_subnets=subnets)

        # no-snat router with overlapping subnet to the service subnet - fail
        subnets = ['5.5.5.0/21', '1.1.1.0/20']
        connections = [{'id': '2',
                        'status': 'ACTIVE',
                        'vpnservice_id': '2',
                        'peer_address': self.peer_address,
                        'peer_cidrs': ['6.6.6.6']}]
        self._test_conn_validation(success=False,
                                   connections=connections,
                                   router_subnets=subnets)

        # no-snat router with non overlapping subnet to the service subnet - ok
        service_subnets = ['5.5.5.0/20', '6.6.6.0/20']
        router_subnets = ['50.5.5.0/21', '1.1.1.0/20']
        connections = [{'id': '2',
                        'status': 'ACTIVE',
                        'vpnservice_id': '2',
                        'peer_address': self.peer_address,
                        'peer_cidrs': ['6.6.6.6']}]
        self._test_conn_validation(success=True,
                                   connections=connections,
                                   service_subnets=service_subnets,
                                   router_subnets=router_subnets)


class TestVpnaasDriver(test_plugin.NsxV3PluginTestCaseMixin):

    def setUp(self):
        super(TestVpnaasDriver, self).setUp()
        self.context = n_ctx.get_admin_context()
        self.service_plugin = mock.Mock()
        self.validator = mock.Mock()
        self.driver = ipsec_driver.NSXv3IPsecVpnDriver(self.service_plugin)
        self.plugin = directory.get_plugin()
        self.nsxlib_vpn = self.plugin.nsxlib.vpn_ipsec
        self.l3plugin = self.plugin

    @contextlib.contextmanager
    def router(self, name='vpn-test-router', tenant_id=_uuid(),
               admin_state_up=True, **kwargs):
        request = {'router': {'tenant_id': tenant_id,
                              'name': name,
                              'admin_state_up': admin_state_up}}
        for arg in kwargs:
            request['router'][arg] = kwargs[arg]
        router = self.l3plugin.create_router(self.context, request)
        yield router

    def test_create_ipsec_site_connection(self):
        with mock.patch.object(self.service_plugin, 'get_ikepolicy',
                               return_value=FAKE_IKE_POLICY),\
            mock.patch.object(self.service_plugin, 'get_ipsecpolicy',
                              return_value=FAKE_IPSEC_POLICY),\
            mock.patch.object(self.service_plugin, '_get_vpnservice',
                              return_value=FAKE_VPNSERVICE),\
            mock.patch.object(self.service_plugin, 'get_vpnservices',
                              return_value=[FAKE_VPNSERVICE]),\
            mock.patch.object(self.plugin, 'get_router',
                              return_value=FAKE_ROUTER),\
            mock.patch.object(self.plugin, 'get_subnet',
                              return_value=FAKE_SUBNET),\
            mock.patch("vmware_nsx.db.db.add_nsx_vpn_connection_mapping"),\
            mock.patch.object(self.plugin.nsxlib.logical_router,
                              'update_advertisement_rules') as update_adv,\
            mock.patch.object(self.nsxlib_vpn.ike_profile,
                              'create') as create_ike,\
            mock.patch.object(self.nsxlib_vpn.tunnel_profile,
                              'create') as create_ipsec,\
            mock.patch.object(self.nsxlib_vpn.dpd_profile,
                              'create') as create_dpd,\
            mock.patch.object(self.nsxlib_vpn.session,
                              'create') as create_sesson:
            self.driver.create_ipsec_site_connection(self.context,
                                                     FAKE_IPSEC_CONNECTION)
            create_ike.assert_called_once()
            create_ipsec.assert_called_once()
            create_dpd.assert_called_once()
            create_sesson.assert_called_once()
            update_adv.assert_called_once()

    def test_update_ipsec_site_connection(self):
        with mock.patch.object(self.service_plugin, '_get_vpnservice',
                               return_value=FAKE_VPNSERVICE),\
            mock.patch.object(self.plugin, 'get_router',
                              return_value=FAKE_ROUTER),\
            mock.patch.object(self.plugin,
                              'update_router_firewall') as update_fw,\
            mock.patch.object(self.nsxlib_vpn.session,
                              'update') as update_sesson,\
            mock.patch("vmware_nsx.db.db.get_nsx_vpn_connection_mapping"):
            self.driver.update_ipsec_site_connection(self.context,
                                                     FAKE_IPSEC_CONNECTION,
                                                     FAKE_NEW_CONNECTION)
            update_sesson.assert_called_once()
            update_fw.assert_called_once()

    def test_delete_ipsec_site_connection(self):
        with mock.patch.object(self.service_plugin, 'get_ikepolicy',
                               return_value=FAKE_IKE_POLICY),\
            mock.patch.object(self.service_plugin, 'get_ipsecpolicy',
                              return_value=FAKE_IPSEC_POLICY),\
            mock.patch.object(self.service_plugin, '_get_vpnservice',
                              return_value=FAKE_VPNSERVICE),\
            mock.patch.object(self.service_plugin, 'get_vpnservices',
                              return_value=[FAKE_VPNSERVICE]),\
            mock.patch.object(self.plugin, 'get_router',
                              return_value=FAKE_ROUTER),\
            mock.patch.object(self.plugin, 'get_subnet',
                              return_value=FAKE_SUBNET),\
            mock.patch.object(self.plugin.nsxlib.logical_router,
                              'update_advertisement_rules') as update_adv,\
            mock.patch("vmware_nsx.db.db.get_nsx_vpn_connection_mapping"),\
            mock.patch.object(self.nsxlib_vpn.ike_profile,
                              'delete') as delete_ike,\
            mock.patch.object(self.nsxlib_vpn.tunnel_profile,
                              'delete') as delete_ipsec,\
            mock.patch.object(self.nsxlib_vpn.dpd_profile,
                              'delete') as delete_dpd,\
            mock.patch.object(self.nsxlib_vpn.session,
                              'delete') as delete_sesson:
            self.driver.delete_ipsec_site_connection(self.context,
                                                     FAKE_IPSEC_CONNECTION)
            delete_ike.assert_called_once()
            delete_ipsec.assert_called_once()
            delete_dpd.assert_called_once()
            delete_sesson.assert_called_once()
            update_adv.assert_called_once()

    def test_create_vpn_service_legal(self):
        """Create a legal vpn service"""
        # create an external network with a subnet, and a router
        providernet_args = {extnet_apidef.EXTERNAL: True}
        router_db = namedtuple("Router", FAKE_ROUTER.keys())(
            *FAKE_ROUTER.values())
        tier0_uuid = 'tier-0'
        with self.network(name='ext-net',
                          providernet_args=providernet_args,
                          arg_list=(extnet_apidef.EXTERNAL, )) as ext_net,\
            self.subnet(ext_net),\
            mock.patch.object(self.plugin, '_get_tier0_uuid_by_router',
                              return_value=tier0_uuid),\
            self.router(external_gateway_info={'network_id':
                        ext_net['network']['id']}) as router,\
            self.subnet(cidr='1.1.0.0/24') as sub:
            # add an interface to the router
            self.l3plugin.add_router_interface(
                self.context,
                router['id'],
                {'subnet_id': sub['subnet']['id']})
            # create the service
            dummy_port = {'id': 'dummy_port',
                          'fixed_ips': [{'ip_address': '1.1.1.1'}]}
            tier0_rtr = {'high_availability_mode': 'ACTIVE_STANDBY'}
            with mock.patch.object(self.service_plugin, '_get_vpnservice',
                                   return_value=FAKE_VPNSERVICE),\
                mock.patch.object(self.nsxlib_vpn.service,
                                  'create') as create_service,\
                mock.patch.object(self.l3plugin, '_get_router',
                                  return_value=router_db),\
                mock.patch.object(self.plugin, 'get_router',
                                  return_value=FAKE_ROUTER),\
                mock.patch.object(self.plugin, 'get_ports',
                                  return_value=[dummy_port]),\
                mock.patch.object(self.plugin.nsxlib.logical_router, 'get',
                                  return_value=tier0_rtr):
                self.driver.create_vpnservice(self.context, FAKE_VPNSERVICE)
                create_service.assert_called_once()
                # Delete the service
                nsx_services = [{'logical_router_id': tier0_uuid,
                                 'id': 'xxx'}]
                with mock.patch.object(
                    self.nsxlib_vpn.service, 'list',
                    return_value={'results': nsx_services}),\
                    mock.patch.object(self.service_plugin, 'get_vpnservices',
                                      return_value=[]),\
                    mock.patch.object(self.nsxlib_vpn.service,
                                      'delete') as delete_service:
                    self.driver.delete_vpnservice(
                        self.context, FAKE_VPNSERVICE)
                    delete_service.assert_called_once()

    def test_create_another_vpn_service(self):
        # make sure another backend service is not created
        providernet_args = {extnet_apidef.EXTERNAL: True}
        router_db = namedtuple("Router", FAKE_ROUTER.keys())(
            *FAKE_ROUTER.values())
        tier0_rtr_id = _uuid()
        with self.network(name='ext-net',
                          providernet_args=providernet_args,
                          arg_list=(extnet_apidef.EXTERNAL, )) as ext_net,\
            self.subnet(ext_net),\
            mock.patch.object(self.plugin, '_get_tier0_uuid_by_router',
                              return_value=tier0_rtr_id),\
            self.router(external_gateway_info={'network_id':
                        ext_net['network']['id']}) as router,\
            self.subnet(cidr='1.1.0.0/24') as sub:
            # add an interface to the router
            self.l3plugin.add_router_interface(
                self.context,
                router['id'],
                {'subnet_id': sub['subnet']['id']})
            # create the service
            dummy_port = {'id': 'dummy_port',
                          'fixed_ips': [{'ip_address': '1.1.1.1'}]}
            tier0_rtr = {'id': tier0_rtr_id,
                         'high_availability_mode': 'ACTIVE_STANDBY'}
            nsx_srv = {'logical_router_id': tier0_rtr_id,
                       'id': _uuid(),
                       'enabled': True}
            with mock.patch.object(self.service_plugin, '_get_vpnservice',
                                   return_value=FAKE_VPNSERVICE),\
                mock.patch.object(self.nsxlib_vpn.service,
                                  'create') as create_service,\
                mock.patch.object(
                    self.nsxlib_vpn.service, 'list',
                    return_value={'results': [nsx_srv]}) as create_service,\
                mock.patch.object(self.l3plugin, '_get_router',
                                  return_value=router_db),\
                mock.patch.object(self.plugin, 'get_router',
                                  return_value=FAKE_ROUTER),\
                mock.patch.object(self.plugin, 'get_ports',
                                  return_value=[dummy_port]),\
                mock.patch.object(self.plugin.nsxlib.logical_router, 'get',
                                  return_value=tier0_rtr):
                self.driver.create_vpnservice(self.context, FAKE_VPNSERVICE)
                create_service.assert_called_once()

                # now delete both
                nsx_services = [{'logical_router_id': tier0_rtr_id,
                                 'id': 'xxx'}]
                with mock.patch.object(
                    self.nsxlib_vpn.service, 'list',
                    return_value={'results': nsx_services}),\
                    mock.patch.object(self.nsxlib_vpn.service,
                                      'delete') as delete_service:
                    self.driver.delete_vpnservice(
                        self.context, FAKE_VPNSERVICE)
                    delete_service.assert_not_called()

                with mock.patch.object(
                    self.nsxlib_vpn.service, 'list',
                    return_value={'results': nsx_services}),\
                    mock.patch.object(self.service_plugin, 'get_vpnservices',
                                      return_value=[]),\
                    mock.patch.object(self.nsxlib_vpn.service,
                                      'delete') as delete_service:
                    self.driver.delete_vpnservice(
                        self.context, FAKE_VPNSERVICE)
                    delete_service.assert_called_once()

        pass
