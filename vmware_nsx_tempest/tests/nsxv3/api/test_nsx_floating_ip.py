# Copyright 2016 VMware Inc
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

from oslo_log import log as logging

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest import test

from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF

LOG = logging.getLogger(__name__)


class NSXv3FloatingIPTest(base.BaseNetworkTest):

    @classmethod
    def skip_checks(cls):
        super(NSXv3FloatingIPTest, cls).skip_checks()
        if not test.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)
        if not CONF.network.public_network_id:
            msg = "Public network id not found."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(NSXv3FloatingIPTest, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id
        # Create the topology to test floating IP
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(data_utils.rand_name('router-'),
                                       external_network_id=cls.ext_net_id)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        for i in range(2):
            cls.create_port(cls.network)
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)

    @test.attr(type='nsxv3')
    @test.idempotent_id('593e4e51-9ea2-445b-b789-eff2b0b7a503')
    def test_create_floating_ip(self):
        # Create a floating ip
        create_body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[0]['id'])
        fip = create_body['floatingip']
        port_ip = self.ports[0]['fixed_ips'][0]['ip_address']
        LOG.debug("Port IP address: %s", port_ip)
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        fip['id'])
        nsx_router = self.nsx.get_logical_router(self.router['name'],
                                                 self.router['id'])
        LOG.debug("NSX router on backend: %s", nsx_router)
        nat_rules = self.nsx.get_logical_router_nat_rules(nsx_router)
        LOG.debug("NAT rules on NSX router %(router)s: %(rules)s",
                  {'router': nsx_router, 'rules': nat_rules})
        dnat_rules = [(rule['translated_network'],
                       rule['match_destination_network']) for rule in nat_rules
                      if 'match_destination_network' in rule]
        snat_rules = [(rule['translated_network'],
                       rule['match_source_network']) for rule in nat_rules
                      if 'match_source_network' in rule]
        LOG.debug("snat_rules: %(snat)s; dnat_rules: %(dnat)s",
                  {'snat': snat_rules, 'dnat': dnat_rules})
        self.assertIsNotNone(fip['id'])
        self.assertEqual(fip['fixed_ip_address'], port_ip)
        self.assertIn((fip['floating_ip_address'], port_ip), snat_rules)
        self.assertIn((port_ip, fip['floating_ip_address']), dnat_rules)

    @test.attr(type='nsxv3')
    @test.idempotent_id('48d8cda8-dfc3-4d84-8f91-4bad6cc7d452')
    def test_update_floating_ip(self):
        # Create a floating ip
        create_body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[0]['id'])
        fip = create_body['floatingip']
        port1_ip = self.ports[0]['fixed_ips'][0]['ip_address']
        port2_ip = self.ports[1]['fixed_ips'][0]['ip_address']
        LOG.debug("Port1 IP address: %(port1)s, port2 IP address %(port2)s",
                  {'port1': port1_ip, 'port2': port2_ip})
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        fip['id'])
        nsx_router = self.nsx.get_logical_router(self.router['name'],
                                                 self.router['id'])
        self.assertEqual(fip['fixed_ip_address'], port1_ip)
        self.assertEqual(fip['router_id'], self.router['id'])
        # Update the floating ip
        update_body = self.floating_ips_client.update_floatingip(
            fip['id'], port_id=self.ports[1]['id'])
        updated_fip = update_body['floatingip']
        nat_rules = self.nsx.get_logical_router_nat_rules(nsx_router)
        LOG.debug("NAT rules on NSX router %(router)s: %(rules)s",
                  {'router': nsx_router, 'rules': nat_rules})
        dnat_rules = [(rule['translated_network'],
                       rule['match_destination_network']) for rule in nat_rules
                      if 'match_destination_network' in rule]
        snat_rules = [(rule['translated_network'],
                       rule['match_source_network']) for rule in nat_rules
                      if 'match_source_network' in rule]
        LOG.debug("snat_rules: %(snat)s; dnat_rules: %(dnat)s",
                  {'snat': snat_rules, 'dnat': dnat_rules})
        self.assertEqual(updated_fip['fixed_ip_address'], port2_ip)
        self.assertEqual(updated_fip['floating_ip_address'],
                         fip['floating_ip_address'])
        self.assertIn((updated_fip['floating_ip_address'], port2_ip),
                      snat_rules)
        self.assertIn((port2_ip, updated_fip['floating_ip_address']),
                      dnat_rules)

    @test.attr(type='nsxv3')
    @test.idempotent_id('6e5a87fe-b40e-4c62-94b8-07431493cc3d')
    def test_delete_floating_ip(self):
        # Create a floating ip
        create_body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[0]['id'])
        fip = create_body['floatingip']
        port_ip = self.ports[0]['fixed_ips'][0]['ip_address']
        LOG.debug("Port IP address: %s", port_ip)
        nsx_router = self.nsx.get_logical_router(self.router['name'],
                                                 self.router['id'])
        LOG.debug("NSX router on backend: %s", nsx_router)
        self.assertIsNotNone(fip['id'])
        # Delete the floating ip and backend nat rules
        self.floating_ips_client.delete_floatingip(fip['id'])
        nat_rules = self.nsx.get_logical_router_nat_rules(nsx_router)
        LOG.debug("NAT rules on NSX router %(router)s: %(rules)s",
                  {'router': nsx_router, 'rules': nat_rules})
        dnat_rules = [(rule['translated_network'],
                       rule['match_destination_network']) for rule in nat_rules
                      if 'match_destination_network' in rule]
        snat_rules = [(rule['translated_network'],
                       rule['match_source_network']) for rule in nat_rules
                      if 'match_source_network' in rule]
        LOG.debug("snat_rules: %(snat)s; dnat_rules: %(dnat)s",
                  {'snat': snat_rules, 'dnat': dnat_rules})
        self.assertNotIn((fip['floating_ip_address'], port_ip), snat_rules)
        self.assertNotIn((port_ip, fip['floating_ip_address']), dnat_rules)
