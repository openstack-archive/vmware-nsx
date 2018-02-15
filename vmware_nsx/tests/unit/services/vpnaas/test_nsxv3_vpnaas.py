# Copyright 2013, Nachi Ueno, NTT I3, Inc.
# All Rights Reserved.
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
import mock

from neutron.db.models import l3 as l3_models
from neutron_lib import context as n_ctx
from neutron_vpnaas.tests import base

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_validator


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


# TODO(asarfaty): add tests for the driver
