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
from vmware_nsx.extensions import dns_search_domain as ext_dns_search_domain
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.tests.unit.nsx_v import test_plugin

PLUGIN_NAME = 'vmware_nsx.plugin.NsxVPlugin'


class DnsSearchDomainExtensionManager(object):

    def get_resources(self):
        return []

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []

    def get_extended_resources(self, version):
        return ext_dns_search_domain.get_extended_resources(version)


class DnsSearchDomainExtensionTestCase(test_plugin.NsxVPluginV2TestCase):
    """Test API extension dns-search-domain attribute."""

    @mock.patch.object(edge_utils.EdgeManager, '_deploy_edge')
    def setUp(self, plugin=PLUGIN_NAME):
        ext_mgr = DnsSearchDomainExtensionManager()
        super(DnsSearchDomainExtensionTestCase, self).setUp(ext_mgr=ext_mgr)

    def _create_subnet_with_dns_search_domain(self, dns_search_domain):
        with self.network() as net:
            tenant_id = net['network']['tenant_id']
            net_id = net['network']['id']
            data = {'subnet': {'network_id': net_id,
                               'cidr': '10.0.0.0/24',
                               'ip_version': 4,
                               'name': 'test-dns-search-domain-subnet',
                               'tenant_id': tenant_id,
                               'dns_search_domain': dns_search_domain}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            return res

    def test_subnet_create_with_dns_search_domain(self):
        res = self._create_subnet_with_dns_search_domain('vmware.com')
        sub = self.deserialize(self.fmt, res)
        self.assertEqual('vmware.com', sub['subnet']['dns_search_domain'])

    def test_subnet_create_with_invalid_dns_search_domain_fail(self):
        res = self._create_subnet_with_dns_search_domain('vmw@re.com')
        self.assertEqual(400, res.status_int)

    def test_subnet_update_with_dns_search_domain(self):
        res = self._create_subnet_with_dns_search_domain('vmware.com')
        sub = self.deserialize(self.fmt, res)
        data = {'subnet': {'dns_search_domain': 'eng.vmware.com'}}
        req = self.new_update_request('subnets', data, sub['subnet']['id'])
        updated_sub = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertEqual('eng.vmware.com',
                         updated_sub['subnet']['dns_search_domain'])


class DnsSearchDomainDBTestCase(test_db.NeutronDbPluginV2TestCase):

    def setUp(self):
        super(DnsSearchDomainDBTestCase, self).setUp()
        self.session = db_api.get_writer_session()

    def test_get_nsxv_subnet_ext_attributes_no_dns_search_domain(self):
        with self.subnet() as sub:
            sub_binding = nsxv_db.get_nsxv_subnet_ext_attributes(
                session=self.session, subnet_id=sub['subnet']['id'])
            self.assertIsNone(sub_binding)

    def test_add_nsxv_subnet_ext_attributes_dns_search_domain(self):
        with self.subnet() as sub:
            nsxv_db.add_nsxv_subnet_ext_attributes(
                session=self.session,
                subnet_id=sub['subnet']['id'],
                dns_search_domain='eng.vmware.com')
            sub_binding = nsxv_db.get_nsxv_subnet_ext_attributes(
                session=self.session, subnet_id=sub['subnet']['id'])
            self.assertEqual('eng.vmware.com', sub_binding.dns_search_domain)
            self.assertEqual(sub['subnet']['id'], sub_binding.subnet_id)

    def test_update_nsxv_subnet_ext_attributes_dns_search_domain(self):
        with self.subnet() as sub:
            nsxv_db.add_nsxv_subnet_ext_attributes(
                session=self.session,
                subnet_id=sub['subnet']['id'],
                dns_search_domain='eng.vmware.com')
            sub_binding = nsxv_db.update_nsxv_subnet_ext_attributes(
                session=self.session,
                subnet_id=sub['subnet']['id'],
                dns_search_domain='nsx.vmware.com')
            self.assertEqual('nsx.vmware.com', sub_binding.dns_search_domain)
