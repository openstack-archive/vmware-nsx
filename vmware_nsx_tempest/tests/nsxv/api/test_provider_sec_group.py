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
import re

from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions
from tempest import test

from vmware_nsx_tempest.services import nsxv_client
from vmware_nsx_tempest.tests.nsxv.api import base_provider as base

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ProviderSecGroup(base.BaseAdminNetworkTest):
    """Test Provider Security Group

    1. Only Admin can create provider security group.
    2. Tenants can not create provider security-group.
    3. Check Provider sec group at beckend in firewall section
    4. Check the priority of provider sec groups at beckend
    5. Check non-admin tenant can't create provider security group
    6. Check multiple rules under provider sec group
    """

    @classmethod
    def skip_checks(cls):
        super(ProviderSecGroup, cls).skip_checks()
        if not test.is_extension_enabled('provider-security-group', 'network'):
            msg = "Extension provider-security-group is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(ProviderSecGroup, cls).setup_clients()
        cls.cmgr_pri = cls.get_client_manager('primary')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(ProviderSecGroup, cls).resource_setup()
        manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                               CONF.nsxv.manager_uri).group(0)
        cls.vsm = nsxv_client.VSMClient(
            manager_ip, CONF.nsxv.user, CONF.nsxv.password)

    def delete_security_group(self, sg_client, sg_id):
        sg_client.delete_security_group(sg_id)

    def create_security_provider_group(self, cmgr=None,
                                       project_id=None, provider=False):
        cmgr = cmgr or self.cmgr_adm
        sg_client = cmgr.security_groups_client
        sg_dict = dict(name=data_utils.rand_name('provider-sec-group'))
        if project_id:
            sg_dict['tenant_id'] = project_id
        if provider:
            sg_dict['provider'] = True
        sg = sg_client.create_security_group(**sg_dict)
        sg = sg.get('security_group', sg)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_security_group,
                        sg_client, sg.get('id'))
        return sg

    def update_security_provider_group(self, security_group_id,
                                       new_policy_id, cmgr=None):
        cmgr = cmgr or self.cmgr_adm
        sg_client = cmgr.security_groups_client
        sg = sg_client.update_security_group(security_group_id,
                                             policy=new_policy_id)
        return sg.get('security_group', sg)

    def create_security_group_rule(self, security_group_id,
                                   cmgr=None, project_id=None,
                                   protocol=None):
        cmgr = cmgr or self.cmgr_adm
        sgr_client = cmgr.security_group_rules_client
        sgr_dict = dict(security_group_id=security_group_id,
                        direction='ingress', protocol=protocol)
        if project_id:
            sgr_dict['tenant_id'] = project_id
        sgr = sgr_client.create_security_group_rule(**sgr_dict)
        return sgr.get('security_group_rule', sgr)

    def show_security_provider_group(self, security_group_id, cmgr=None):
        cmgr = cmgr or self.cmgr_adm
        sg_client = cmgr.security_groups_client
        sg = sg_client.show_security_group(security_group_id)
        return sg.get('security_group', sg)

    def get_default_security_group_policy(self, cmgr=None):
        cmgr = cmgr or self.cmgr_adm
        sg_client = cmgr.security_groups_client
        sg_list = sg_client.list_security_groups()
        # why list twice, see bug#1772424
        sg_list = sg_client.list_security_groups(name='default')
        sg_list = sg_list.get('security_groups', sg_list)
        return sg_list[0]

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('5480d96e-287b-4e59-9ee3-d1bcf451dfc9')
    def test_provider_security_group_crud(self):
        sg_desc = "crud provider-security-group"
        sg_client = self.cmgr_adm.security_groups_client
        sg = self.create_security_provider_group(self.cmgr_adm, provider=True)
        sg_id = sg.get('id')
        show_sec_group = sg_client.show_security_group(sg_id)
        self.assertEqual(True, show_sec_group['security_group']['provider'])
        sg_show = sg_client.update_security_group(sg_id, description=sg_desc)
        self.assertEqual(sg_desc, sg_show['security_group'].get('description'))
        self.delete_security_group(sg_client, sg_id)
        sg_list = sg_client.list_security_groups(id=sg_id)
        sg_list = sg_list.get('security_groups', sg_list)
        self.assertEqual(len(sg_list), 0)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('6e48a2ed-8035-4986-a5c6-903c49ae26a2')
    def test_admin_can_create_provider_security_group_for_tenant(self):
        project_id = self.cmgr_alt.networks_client.tenant_id
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 project_id=project_id,
                                                 provider=True)
        self.assertEqual(True, sg.get('provider'))

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('95ce76a4-a125-411b-95d7-7a66addf0efc')
    def test_tenant_provider_sec_group_with_no_rules(self):
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 provider=True)
        self.assertEmpty(sg.get('security_group_rules'))

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('5e6237ca-033a-4bee-b5fb-8f225ed00b0c')
    def test_admin_can_create_security_group_rule(self):
        sg_client = self.cmgr_adm.security_groups_client
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 provider=True)
        sg_id = sg.get('id')
        self.create_security_group_rule(sg_id, cmgr=self.cmgr_adm,
                                        protocol='icmp')
        show_sec_group = sg_client.show_security_group(sg_id)
        self.assertEqual('ingress',
                         show_sec_group['security_group']
                         ['security_group_rules']
                         [0]['direction'])
        self.assertEqual('icmp',
                         show_sec_group['security_group']
                         ['security_group_rules']
                         [0]['protocol'])

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('18737e13-4bca-4f62-b993-f021795a7dbf')
    def test_provider_security_group_rule_at_beckend(self):
        sg = self.create_security_provider_group(self.cmgr_adm, provider=True)
        sg_id = sg.get('id')
        sg_name = sg.get('name')
        sg_rule = self.create_security_group_rule(sg_id, cmgr=self.cmgr_adm,
                                                  protocol='icmp')
        sg_rule.get('id')
        firewall_section = self.vsm.get_firewall()
        for i in (0, len(firewall_section)):
            if (sg_name in firewall_section['layer3Sections']
                    ['layer3Sections'][i]['name']):
                for rule in firewall_section.\
                        get('layer3Sections')['layer3Sections'][i]['rules']:
                    for rule_proto in rule['services']['serviceList']:
                        self.assertIn('ICMP', rule_proto['protocolName'])
                        self.assertIn('deny', rule['action'], "Provider "
                                      "security Group applied")

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('b179a32b-e012-43ec-9d2d-f9e5801c97c6')
    def test_provider_security_group_predence_at_beckend(self):
        sg = self.create_security_provider_group(self.cmgr_adm, provider=True)
        sg_name = sg.get('name')
        firewall_section = self.vsm.get_firewall()
        count = 0
        for i in (0, len(firewall_section)):
            if (count == 0):
                self.assertIn(sg_name, firewall_section['layer3Sections']
                              ['layer3Sections'][i]['name'],
                              "Provider security Group applied at the beckend"
                              " and has higher predence over default sec "
                              "group")
                self.assertEqual(0, count)
                break
            count += count
        self.assertEqual(0, count)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('38b21ea8-7822-4b1a-b923-cd00fa57ca4d')
    def test_provider_security_group_at_port_level(self):
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 provider=True)
        sg_id = sg.get('id')
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network'}
        network = net_client.create_network(**body)
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id'],
                "admin_state_up": 'true'}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.create_port(**body)
        ss = port_client.show_port(port_id['port']['id'])
        self.assertEqual([sg_id], ss['port']['provider_security_groups'])
        body = {"id": port_id}
        port_client.delete_port(port_id['port']['id'])
        net_client.delete_network(network['network']['id'])

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('b1e904fb-a70a-400e-a757-d772aab152eb')
    def test_provider_sec_group_with_multiple_rules(self):
        project_id = self.cmgr_adm.networks_client.tenant_id
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 project_id=project_id)
        sg_rule1 = self.create_security_group_rule(sg.get('id'),
                                                   cmgr=self.cmgr_adm,
                                                   project_id=project_id,
                                                   protocol='icmp')
        sg_rule1_id = sg_rule1.get('id')
        sg_rule2 = self.create_security_group_rule(sg.get('id'),
                                                   cmgr=self.cmgr_adm,
                                                   project_id=project_id,
                                                   protocol='tcp')
        sg_rule2_id = sg_rule2.get('id')
        self.assertNotEqual(sg_rule1_id, sg_rule2_id)

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('edd94f8c-53b7-4286-9350-0ddc0af3213b')
    def test_clear_provider_sec_group_from_port(self):
        project_id = self.cmgr_adm.networks_client.tenant_id
        self.create_security_provider_group(self.cmgr_adm,
                                            project_id=project_id,
                                            provider=True)
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network'}
        network = net_client.create_network(**body)
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id'],
                "provider_security_groups": []}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.create_port(**body)
        ss = port_client.show_port(port_id['port']['id'])
        self.assertEmpty(ss['port']['provider_security_groups'])
        port_client.delete_port(port_id['port']['id'])
        net_client.delete_network(network['network']['id'])

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('6c1e6728-b84a-47f9-9021-ff3e3f88a933')
    def test_tenant_cannot_delete_admin_provider_security_group(self):
        project_id = self.cmgr_adm.networks_client.tenant_id
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 project_id=project_id,
                                                 provider=True)
        sg_id = sg.get('id')
        sg_client = self.cmgr_alt.security_groups_client
        try:
            self.delete_security_group(sg_client, sg_id)
        except Exception:
            LOG.debug("Non Admin tenant can't see admin"
                      "provider security group")
            pass

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('94e06ee2-82ed-4203-ac9b-421a298bdba4')
    def test_tenant_cannot_create_provider_sec_group(self):
        project_id = self.cmgr_alt.networks_client.tenant_id
        self.assertRaises(exceptions.Forbidden,
                          self.create_security_provider_group,
                          self.cmgr_alt, project_id=project_id,
                          provider=True)
        LOG.debug("Non-Admin Tenant cannot create provider sec group")

    @decorators.attr(type='nsxv')
    @decorators.idempotent_id('01f00a36-7576-40e0-a397-b43860a9c122')
    def test_update_port_with_psg(self):
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network'}
        network = net_client.create_network(**body)
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id'],
                "provider_security_groups": []}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.create_port(**body)
        ss = port_client.show_port(port_id['port']['id'])
        self.assertEmpty(ss['port']['provider_security_groups'])
        project_id = self.cmgr_adm.networks_client.tenant_id
        sg = self.create_security_provider_group(self.cmgr_adm,
                                                 project_id=project_id,
                                                 provider=True)
        sg_id = sg.get('id')
        body = {"provider_security_groups": ["%s" % sg_id]}
        port_client.update_port(port_id['port']['id'], **body)
        ss = port_client.show_port(port_id['port']['id'])
        self.assertIsNotNone(ss['port']['provider_security_groups'])
        port_client.delete_port(port_id['port']['id'])
        net_client.delete_network(network['network']['id'])
