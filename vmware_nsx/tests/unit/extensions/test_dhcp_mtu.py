# Copyright 2016 VMware, Inc.
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

from neutron.tests.unit.db import test_db_base_plugin_v2 as test_db
from neutron_lib.db import api as db_api

from vmware_nsx.db import nsxv_db
from vmware_nsx.extensions import dhcp_mtu as ext_dhcp_mtu
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.tests.unit.nsx_v import test_plugin
from vmware_nsx.tests.unit.nsx_v.vshield import fake_vcns

PLUGIN_NAME = 'vmware_nsx.plugin.NsxVPlugin'


class DhcpMtuExtensionManager(object):

    def get_resources(self):
        return []

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []

    def get_extended_resources(self, version):
        return ext_dhcp_mtu.get_extended_resources(version)


class DhcpMtuExtensionTestCase(test_plugin.NsxVPluginV2TestCase):
    """Test API extension dhcp-mtu attribute of subnets."""

    @mock.patch.object(edge_utils.EdgeManager, '_deploy_edge')
    def setUp(self, plugin=PLUGIN_NAME):
        ext_mgr = DhcpMtuExtensionManager()
        # This feature is enabled only since 6.2.3
        with mock.patch.object(fake_vcns.FakeVcns,
                               'get_version',
                               return_value="6.2.3"):
            super(DhcpMtuExtensionTestCase, self).setUp(ext_mgr=ext_mgr)

    def _create_subnet_with_dhcp_mtu(self, dhcp_mtu):
        with self.network() as net:
            tenant_id = net['network']['tenant_id']
            net_id = net['network']['id']
            data = {'subnet': {'network_id': net_id,
                               'cidr': '10.0.0.0/24',
                               'ip_version': 4,
                               'name': 'test-mtu-subnet',
                               'tenant_id': tenant_id,
                               'dhcp_mtu': dhcp_mtu}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            return res

    def test_subnet_create_with_dhcp_mtu(self):
        for mtu in (68, 2000, 65535):
            res = self._create_subnet_with_dhcp_mtu(mtu)
            sub = self.deserialize(self.fmt, res)
            self.assertEqual(mtu, sub['subnet']['dhcp_mtu'])

    def test_subnet_create_with_invalid_dhcp_mtu_fail(self):
        res = self._create_subnet_with_dhcp_mtu(67)
        self.assertEqual(400, res.status_int)

        res = self._create_subnet_with_dhcp_mtu(100000)
        self.assertEqual(400, res.status_int)

    def test_subnet_update_with_dhcp_mtu(self):
        res = self._create_subnet_with_dhcp_mtu(2000)
        sub = self.deserialize(self.fmt, res)
        data = {'subnet': {'dhcp_mtu': 3000}}
        req = self.new_update_request('subnets', data, sub['subnet']['id'])
        updated_sub = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertEqual(3000, updated_sub['subnet']['dhcp_mtu'])

    def _create_subnet_with_dhcp_mtu_and_dns(self, dhcp_mtu,
                                             dns_search_domain):
        with self.network() as net:
            tenant_id = net['network']['tenant_id']
            net_id = net['network']['id']
            data = {'subnet': {'network_id': net_id,
                               'cidr': '10.0.0.0/24',
                               'ip_version': 4,
                               'name': 'test-mtu-subnet',
                               'tenant_id': tenant_id,
                               'dhcp_mtu': dhcp_mtu,
                               'dns_search_domain': dns_search_domain}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            return res

    def test_subnet_create_with_dhcp_mtu_and_dns(self):
        res = self._create_subnet_with_dhcp_mtu_and_dns(2000, 'vmware.com')
        sub = self.deserialize(self.fmt, res)
        self.assertEqual(2000, sub['subnet']['dhcp_mtu'])
        self.assertEqual('vmware.com', sub['subnet']['dns_search_domain'])

    def test_subnet_update_with_dhcp_mtu_and_dns(self):
        res = self._create_subnet_with_dhcp_mtu_and_dns(2000, 'vmware.com')
        sub = self.deserialize(self.fmt, res)
        data = {'subnet': {'dhcp_mtu': 3000,
                'dns_search_domain': 'eng.vmware.com'}}
        req = self.new_update_request('subnets', data, sub['subnet']['id'])
        updated_sub = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertEqual(3000, updated_sub['subnet']['dhcp_mtu'])
        self.assertEqual('eng.vmware.com',
                         updated_sub['subnet']['dns_search_domain'])


class DhcpMtuDBTestCase(test_db.NeutronDbPluginV2TestCase):

    def setUp(self):
        super(DhcpMtuDBTestCase, self).setUp()
        self.session = db_api.get_writer_session()

    def test_get_nsxv_subnet_ext_attributes_no_dhcp_mtu(self):
        with self.subnet() as sub:
            sub_binding = nsxv_db.get_nsxv_subnet_ext_attributes(
                session=self.session, subnet_id=sub['subnet']['id'])
            self.assertIsNone(sub_binding)

    def test_add_nsxv_subnet_ext_attributes_dhcp_mtu(self):
        with self.subnet() as sub:
            nsxv_db.add_nsxv_subnet_ext_attributes(
                session=self.session,
                subnet_id=sub['subnet']['id'],
                dhcp_mtu=2000)
            sub_binding = nsxv_db.get_nsxv_subnet_ext_attributes(
                session=self.session, subnet_id=sub['subnet']['id'])
            self.assertEqual(2000, sub_binding.dhcp_mtu)
            self.assertEqual(sub['subnet']['id'], sub_binding.subnet_id)

    def test_update_nsxv_subnet_ext_attributes_dhcp_mtu(self):
        with self.subnet() as sub:
            nsxv_db.add_nsxv_subnet_ext_attributes(
                session=self.session,
                subnet_id=sub['subnet']['id'],
                dhcp_mtu=2000)
            sub_binding = nsxv_db.update_nsxv_subnet_ext_attributes(
                session=self.session,
                subnet_id=sub['subnet']['id'],
                dhcp_mtu=3000)
            self.assertEqual(3000, sub_binding.dhcp_mtu)

    def test_add_nsxv_subnet_ext_attributes_dhcp_mtu_and_dns(self):
        with self.subnet() as sub:
            nsxv_db.add_nsxv_subnet_ext_attributes(
                session=self.session,
                subnet_id=sub['subnet']['id'],
                dhcp_mtu=2000,
                dns_search_domain='eng.vmware.com')
            sub_binding = nsxv_db.get_nsxv_subnet_ext_attributes(
                session=self.session, subnet_id=sub['subnet']['id'])
            self.assertEqual(2000, sub_binding.dhcp_mtu)
            self.assertEqual('eng.vmware.com', sub_binding.dns_search_domain)
            self.assertEqual(sub['subnet']['id'], sub_binding.subnet_id)

    def test_update_nsxv_subnet_ext_attributes_dhcp_mtu_and_dns(self):
        with self.subnet() as sub:
            nsxv_db.add_nsxv_subnet_ext_attributes(
                session=self.session,
                subnet_id=sub['subnet']['id'],
                dhcp_mtu=2000,
                dns_search_domain='eng.vmware.com')
            sub_binding = nsxv_db.update_nsxv_subnet_ext_attributes(
                session=self.session,
                subnet_id=sub['subnet']['id'],
                dhcp_mtu=3000,
                dns_search_domain='nsx.vmware.com')
            self.assertEqual(3000, sub_binding.dhcp_mtu)
            self.assertEqual('nsx.vmware.com', sub_binding.dns_search_domain)
