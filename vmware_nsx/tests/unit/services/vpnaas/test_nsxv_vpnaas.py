# Copyright 2016 VMware, Inc.
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

import contextlib

import mock
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_vpnaas.db.vpn import vpn_models  # noqa
from oslo_utils import uuidutils

from vmware_nsx.common import exceptions as nsxv_exc
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as vcns_exc
from vmware_nsx.services.vpnaas.nsxv import ipsec_driver
from vmware_nsx.tests.unit.nsx_v import test_plugin


_uuid = uuidutils.generate_uuid

DRIVER_PATH = "vmware_nsx.services.vpnaas.nsxv.ipsec_driver.NSXvIPsecVpnDriver"
VALI_PATH = "vmware_nsx.services.vpnaas.nsxv.ipsec_validator.IPsecValidator"
FAKE_ROUTER_ID = "aaaaaa-bbbbb-ccc"
FAKE_VPNSERVICE_ID = _uuid()
FAKE_IPSEC_CONNECTION = {"vpnservice_id": FAKE_VPNSERVICE_ID,
                         "id": _uuid()}
FAKE_EDGE_ID = _uuid()
FAKE_IPSEC_VPN_SITE = {"peerIp": "192.168.1.1"}
FAKE_VCNSAPIEXC = {"status": "fail",
                   "head": "fake_head",
                   "response": "error"}
FAKE_NEW_CONNECTION = {"peer_cidrs": "192.168.1.0/24"}


class TestVpnaasDriver(test_plugin.NsxVPluginV2TestCase):

    def setUp(self):
        super(TestVpnaasDriver, self).setUp()
        self.context = context.get_admin_context()
        self.service_plugin = mock.Mock()
        self.validator = mock.Mock()
        self.driver = ipsec_driver.NSXvIPsecVpnDriver(self.service_plugin)
        self.plugin = directory.get_plugin()
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

    @mock.patch('%s.validate_ipsec_conn' % VALI_PATH)
    @mock.patch('%s._convert_ipsec_conn' % DRIVER_PATH)
    @mock.patch('%s._get_router_edge_id' % DRIVER_PATH)
    @mock.patch('%s._generate_new_sites' % DRIVER_PATH)
    @mock.patch('%s._update_ipsec_config' % DRIVER_PATH)
    @mock.patch('%s._update_status' % DRIVER_PATH)
    @mock.patch('%s._update_firewall_rules' % DRIVER_PATH)
    def test_create_ipsec_site_connection(self, mock_update_fw,
                                          mock_update_status,
                                          mock_update_ipsec, mock_gen_new,
                                          mock_get_id,
                                          mock_conv_ipsec,
                                          mock_val_conn):
        mock_get_id.return_value = (FAKE_ROUTER_ID, FAKE_EDGE_ID)
        mock_conv_ipsec.return_value = FAKE_IPSEC_VPN_SITE
        mock_gen_new.return_value = FAKE_IPSEC_VPN_SITE
        self.driver.create_ipsec_site_connection(self.context,
                                                 FAKE_IPSEC_CONNECTION)
        mock_val_conn.assert_called_with(self.context,
                                         FAKE_IPSEC_CONNECTION)
        mock_conv_ipsec.assert_called_with(self.context,
                                           FAKE_IPSEC_CONNECTION)
        mock_get_id.assert_called_with(self.context, FAKE_VPNSERVICE_ID)
        mock_gen_new.assert_called_with(FAKE_EDGE_ID, FAKE_IPSEC_VPN_SITE)
        mock_update_ipsec.assert_called_with(FAKE_EDGE_ID,
                                             FAKE_IPSEC_VPN_SITE,
                                             enabled=True)
        mock_update_fw.assert_called_with(self.context, FAKE_VPNSERVICE_ID)
        mock_update_status.assert_called_with(
            self.context,
            FAKE_IPSEC_CONNECTION["vpnservice_id"],
            FAKE_IPSEC_CONNECTION["id"],
            "ACTIVE")

    @mock.patch('%s.validate_ipsec_conn' % VALI_PATH)
    @mock.patch('%s._convert_ipsec_conn' % DRIVER_PATH)
    @mock.patch('%s._get_router_edge_id' % DRIVER_PATH)
    @mock.patch('%s._generate_new_sites' % DRIVER_PATH)
    @mock.patch('%s._update_ipsec_config' % DRIVER_PATH)
    @mock.patch('%s._update_status' % DRIVER_PATH)
    def test_create_ipsec_site_connection_fail(self,
                                               mock_update_status,
                                               mock_update_ipsec,
                                               mock_gen_new, mock_get_id,
                                               mock_conv_ipsec,
                                               mock_val_conn):
        mock_get_id.return_value = (FAKE_ROUTER_ID, FAKE_EDGE_ID)
        mock_conv_ipsec.return_value = FAKE_IPSEC_VPN_SITE
        mock_gen_new.return_value = FAKE_IPSEC_VPN_SITE
        mock_update_ipsec.side_effect = (
            vcns_exc.VcnsApiException(**FAKE_VCNSAPIEXC))
        self.assertRaises(nsxv_exc.NsxPluginException,
                          self.driver.create_ipsec_site_connection,
                          self.context, FAKE_IPSEC_CONNECTION)
        mock_val_conn.assert_called_with(self.context, FAKE_IPSEC_CONNECTION)
        mock_conv_ipsec.assert_called_with(self.context, FAKE_IPSEC_CONNECTION)
        mock_get_id.assert_called_with(self.context, FAKE_VPNSERVICE_ID)
        mock_gen_new.assert_called_with(FAKE_EDGE_ID, FAKE_IPSEC_VPN_SITE)
        mock_update_ipsec.assert_called_with(FAKE_EDGE_ID,
                                             FAKE_IPSEC_VPN_SITE,
                                             enabled=True)
        mock_update_status.assert_called_with(
            self.context,
            FAKE_IPSEC_CONNECTION["vpnservice_id"],
            FAKE_IPSEC_CONNECTION["id"],
            "ERROR")

    @mock.patch('%s.validate_ipsec_conn' % VALI_PATH)
    @mock.patch('%s._convert_ipsec_conn' % DRIVER_PATH)
    @mock.patch('%s._get_router_edge_id' % DRIVER_PATH)
    @mock.patch('%s._generate_new_sites' % DRIVER_PATH)
    @mock.patch('%s._update_ipsec_config' % DRIVER_PATH)
    @mock.patch('%s._update_status' % DRIVER_PATH)
    @mock.patch('%s._update_firewall_rules' % DRIVER_PATH)
    def test_update_fw_fail(self, mock_update_fw, mock_update_status,
                            mock_update_ipsec, mock_gen_new,
                            mock_get_id, mock_conv_ipsec, mock_val_conn):
        mock_get_id.return_value = (FAKE_ROUTER_ID, FAKE_EDGE_ID)
        mock_conv_ipsec.return_value = FAKE_IPSEC_VPN_SITE
        mock_gen_new.return_value = FAKE_IPSEC_VPN_SITE
        mock_update_fw.side_effect = (
            vcns_exc.VcnsApiException(**FAKE_VCNSAPIEXC))
        self.assertRaises(nsxv_exc.NsxPluginException,
                          self.driver.create_ipsec_site_connection,
                          self.context, FAKE_IPSEC_CONNECTION)
        mock_val_conn.assert_called_with(self.context, FAKE_IPSEC_CONNECTION)
        mock_conv_ipsec.assert_called_with(self.context, FAKE_IPSEC_CONNECTION)
        mock_get_id.assert_called_with(self.context, FAKE_VPNSERVICE_ID)
        mock_gen_new.assert_called_with(FAKE_EDGE_ID, FAKE_IPSEC_VPN_SITE)
        mock_update_ipsec.assert_called_with(FAKE_EDGE_ID,
                                             FAKE_IPSEC_VPN_SITE,
                                             enabled=True)
        mock_update_fw.assert_called_with(self.context, FAKE_VPNSERVICE_ID)
        mock_update_status.assert_called_with(
            self.context,
            FAKE_IPSEC_CONNECTION["vpnservice_id"],
            FAKE_IPSEC_CONNECTION["id"],
            "ERROR")

    @mock.patch('%s._get_router_edge_id' % DRIVER_PATH)
    @mock.patch('%s._update_site_dict' % DRIVER_PATH)
    @mock.patch('%s._update_ipsec_config' % DRIVER_PATH)
    @mock.patch('%s._update_firewall_rules' % DRIVER_PATH)
    def test_update_ipsec(self, mock_update_fw, mock_update_ipsec,
                          mock_update_sites, mock_get_id):
        mock_get_id.return_value = (FAKE_ROUTER_ID, FAKE_EDGE_ID)
        mock_update_sites.return_value = FAKE_IPSEC_VPN_SITE
        self.driver.update_ipsec_site_connection(self.context,
                                                 FAKE_IPSEC_CONNECTION,
                                                 FAKE_NEW_CONNECTION)
        mock_update_sites.assert_called_with(self.context, FAKE_EDGE_ID,
                                             FAKE_IPSEC_CONNECTION,
                                             FAKE_NEW_CONNECTION)
        mock_update_ipsec.assert_called_with(FAKE_EDGE_ID, FAKE_IPSEC_VPN_SITE)
        mock_update_fw.assert_called_with(self.context, FAKE_VPNSERVICE_ID)

    @mock.patch('%s._get_router_edge_id' % DRIVER_PATH)
    @mock.patch('%s._update_site_dict' % DRIVER_PATH)
    @mock.patch('%s._update_ipsec_config' % DRIVER_PATH)
    @mock.patch('%s._update_firewall_rules' % DRIVER_PATH)
    def test_update_ipsec_fail_with_notfound(self, mock_update_fw,
                                             mock_update_ipsec,
                                             mock_update_sites, mock_get_id):
        mock_get_id.return_value = (FAKE_ROUTER_ID, FAKE_EDGE_ID)
        mock_update_sites.return_value = {}
        self.assertRaises(nsxv_exc.NsxIPsecVpnMappingNotFound,
                          self.driver.update_ipsec_site_connection,
                          self.context, FAKE_IPSEC_CONNECTION,
                          FAKE_NEW_CONNECTION)
        mock_update_sites.assert_called_with(self.context,
                                             FAKE_EDGE_ID,
                                             FAKE_IPSEC_CONNECTION,
                                             FAKE_NEW_CONNECTION)

    @mock.patch('%s._get_router_edge_id' % DRIVER_PATH)
    @mock.patch('%s._update_site_dict' % DRIVER_PATH)
    @mock.patch('%s._update_ipsec_config' % DRIVER_PATH)
    @mock.patch('%s._update_firewall_rules' % DRIVER_PATH)
    def test_update_ipsec_fail_with_fw_fail(self, mock_update_fw,
                                            mock_update_ipsec,
                                            mock_update_sites, mock_get_id):
        mock_get_id.return_value = (FAKE_ROUTER_ID, FAKE_EDGE_ID)
        mock_update_fw.side_effect = (
            vcns_exc.VcnsApiException(**FAKE_VCNSAPIEXC))
        self.assertRaises(nsxv_exc.NsxPluginException,
                          self.driver.update_ipsec_site_connection,
                          self.context, FAKE_IPSEC_CONNECTION,
                          FAKE_NEW_CONNECTION)
        mock_update_sites.assert_called_with(self.context, FAKE_EDGE_ID,
                                             FAKE_IPSEC_CONNECTION,
                                             FAKE_NEW_CONNECTION)
        mock_update_fw.assert_called_with(self.context, FAKE_VPNSERVICE_ID)

    @mock.patch('%s._get_router_edge_id' % DRIVER_PATH)
    @mock.patch('%s._update_site_dict' % DRIVER_PATH)
    @mock.patch('%s._update_ipsec_config' % DRIVER_PATH)
    @mock.patch('%s._update_status' % DRIVER_PATH)
    def test_update_ipsec_fail_with_site_fail(self, mock_update_status,
                                              mock_update_ipsec,
                                              mock_update_sites, mock_get_id):
        mock_get_id.return_value = (FAKE_ROUTER_ID, FAKE_EDGE_ID)
        mock_update_sites.return_value = FAKE_IPSEC_VPN_SITE
        mock_update_ipsec.side_effect = (
            vcns_exc.VcnsApiException(**FAKE_VCNSAPIEXC))
        self.assertRaises(nsxv_exc.NsxPluginException,
                          self.driver.update_ipsec_site_connection,
                          self.context,
                          FAKE_IPSEC_CONNECTION,
                          FAKE_NEW_CONNECTION)
        mock_update_sites.assert_called_with(self.context, FAKE_EDGE_ID,
                                             FAKE_IPSEC_CONNECTION,
                                             FAKE_NEW_CONNECTION)
        mock_update_ipsec.assert_called_with(FAKE_EDGE_ID,
                                             FAKE_IPSEC_VPN_SITE)
        mock_update_status.assert_called_with(
            self.context,
            FAKE_IPSEC_CONNECTION["vpnservice_id"],
            FAKE_IPSEC_CONNECTION["id"],
            "ERROR")

    def test_create_vpn_service_on_shared_router(self):
        with self.router(router_type='shared') as router, self.subnet():
            vpnservice = {'router_id': router['id'],
                          'id': _uuid()}
            self.assertRaises(n_exc.InvalidInput,
                              self.driver.create_vpnservice,
                              self.context, vpnservice)
