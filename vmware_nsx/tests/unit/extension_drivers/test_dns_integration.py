# Copyright 2017 VMware, Inc.
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

from neutron_lib.api.definitions import dns
from neutron_lib import context
from neutron_lib.plugins import directory
from oslo_config import cfg

from vmware_nsx.extension_drivers import dns_integration
from vmware_nsx.tests.unit.nsx_v import test_plugin as test_v_plugin
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_v3_plugin


NETWORK_DOMAIN_NAME = 'net-domain.com.'
NEW_NETWORK_DOMAIN_NAME = 'new-net-domain.com.'
PORT_DNS_NAME = 'port-dns-name'
NEW_PORT_DNS_NAME = 'new-port-dns-name'


class NsxDNSIntegrationTestCase(object):
    _domain = 'domain.com.'
    dns_integration.DNS_DRIVER = None

    def test_create_network_dns_domain(self):
        with self.network(dns_domain=NETWORK_DOMAIN_NAME,
                          arg_list=(dns.DNSDOMAIN,)) as network:
            self.assertEqual(NETWORK_DOMAIN_NAME,
                             network['network'][dns.DNSDOMAIN])

    def test_update_network_dns_domain(self):
        with self.network(dns_domain=NETWORK_DOMAIN_NAME,
                          arg_list=(dns.DNSDOMAIN,)) as network:
            update_data = {'network': {dns.DNSDOMAIN: NEW_NETWORK_DOMAIN_NAME}}
            updated_network = directory.get_plugin().update_network(
                context.get_admin_context(), network['network']['id'],
                update_data)
            self.assertEqual(NEW_NETWORK_DOMAIN_NAME,
                             updated_network[dns.DNSDOMAIN])

    def test_create_port_dns_name(self):
        with self.port(dns_name=PORT_DNS_NAME,
                       arg_list=(dns.DNSNAME,)) as port:
            port_data = port['port']
            dns_assignment = port_data[dns.DNSASSIGNMENT][0]
            self.assertEqual(PORT_DNS_NAME, port_data[dns.DNSNAME])
            self.assertEqual(PORT_DNS_NAME, dns_assignment['hostname'])
            self.assertEqual(port_data['fixed_ips'][0]['ip_address'],
                             dns_assignment['ip_address'])
            self.assertEqual(PORT_DNS_NAME + '.' + self._domain,
                             dns_assignment['fqdn'])

    def test_update_port_dns_name_ip(self):
        with self.subnet(cidr='10.0.0.0/24') as subnet:
            fixed_ips = [{'subnet_id': subnet['subnet']['id'],
                          'ip_address': '10.0.0.3'}]
            with self.port(subnet=subnet, fixed_ips=fixed_ips,
                           dns_name=PORT_DNS_NAME,
                           arg_list=(dns.DNSNAME,)) as port:
                update_data = {'port': {
                    dns.DNSNAME: NEW_PORT_DNS_NAME,
                    'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                                   'ip_address': '10.0.0.4'}]}}
                updated_port = directory.get_plugin().update_port(
                    context.get_admin_context(), port['port']['id'],
                    update_data)
                dns_assignment = updated_port[dns.DNSASSIGNMENT][0]
                self.assertEqual(NEW_PORT_DNS_NAME, updated_port[dns.DNSNAME])
                self.assertEqual(NEW_PORT_DNS_NAME, dns_assignment['hostname'])
                self.assertEqual(updated_port['fixed_ips'][0]['ip_address'],
                                 dns_assignment['ip_address'])
                self.assertEqual(NEW_PORT_DNS_NAME + '.' + self._domain,
                                 dns_assignment['fqdn'])


class NsxVDNSIntegrationTestCase(NsxDNSIntegrationTestCase,
                                 test_v_plugin.NsxVPluginV2TestCase):

    def setUp(self):
        cfg.CONF.set_override('nsx_extension_drivers', ['vmware_nsxv_dns'])
        cfg.CONF.set_override('dns_domain', self._domain)
        super(NsxVDNSIntegrationTestCase, self).setUp()


class NsxV3DNSIntegrationTestCase(NsxDNSIntegrationTestCase,
                                  test_v3_plugin.NsxV3PluginTestCaseMixin):

    def setUp(self):
        cfg.CONF.set_override('nsx_extension_drivers', ['vmware_nsxv3_dns'])
        cfg.CONF.set_override('dns_domain', self._domain, 'nsx_v3')
        super(NsxV3DNSIntegrationTestCase, self).setUp()

    def test_create_port_dns_domain_name(self):
        with self.network(dns_domain=NETWORK_DOMAIN_NAME,
                          arg_list=(dns.DNSDOMAIN,)) as network,\
            self.subnet(network=network, cidr='10.0.0.0/24') as subnet,\
            self.port(subnet=subnet, dns_name=PORT_DNS_NAME,
                      arg_list=(dns.DNSNAME,)) as port:
            port_data = port['port']
            dns_assignment = port_data[dns.DNSASSIGNMENT][0]
            self.assertEqual(PORT_DNS_NAME, port_data[dns.DNSNAME])
            self.assertEqual(PORT_DNS_NAME, dns_assignment['hostname'])
            self.assertEqual(port_data['fixed_ips'][0]['ip_address'],
                             dns_assignment['ip_address'])
            self.assertEqual(PORT_DNS_NAME + '.' + NETWORK_DOMAIN_NAME,
                             dns_assignment['fqdn'])
