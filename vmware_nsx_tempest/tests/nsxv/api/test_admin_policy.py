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

import testtools

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions
from tempest import test

from vmware_nsx_tempest.tests.nsxv.api import base_provider as base

CONF = config.CONF


class AdminPolicyTest(base.BaseAdminNetworkTest):
    """Provides organization to policy traffic using NSX security policy

    When security-group-policy extension is enabled:

    1. Only Admin can create secuiry-group-policy.
    2. Tenants can not create security-group.
    3. No security rules can be added to security-group-policy.
    4. Only Admin can update security-group-policy.

    If tests failed, check vmware/nsx.ini and neutron/policy.json to make
    sure correct settings are being applied.

    ATTENTIONS:
        if allow_tenant_rules_with_policy=True
            run test_tenant_create_security_group_if_allowed
        if allow_tenant_rules_with_policy=False
            run test_tenant_cannot_create_security_group (negative test)

    WARNING: Tempest scenario tests, tenants will create security-groups,
             and failures should be expected. So when run scenario tests,
             set allow_tenant_rules_with_policy to True.
    """

    @classmethod
    def skip_checks(cls):
        super(AdminPolicyTest, cls).skip_checks()
        if not test.is_extension_enabled('security-group-policy', 'network'):
            msg = "Extension security-group-policy is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(AdminPolicyTest, cls).setup_clients()
        cls.cmgr_pri = cls.get_client_manager('primary')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(AdminPolicyTest, cls).resource_setup()
        cls.default_policy_id = CONF.nsxv.default_policy_id
        cls.alt_policy_id = CONF.nsxv.alt_policy_id
        if not (cls.default_policy_id and
                cls.default_policy_id.startswith("policy-")):
            msg = "default_policy_id is not defined in session nsxv"
            raise cls.skipException(msg)

    def delete_security_group(self, sg_client, sg_id):
        sg_client.delete_security_group(sg_id)

    def create_security_group(self, sg_client, sg_name=None, desc=None,
                              tenant_id=None):
        name = sg_name or data_utils.rand_name('security-group')
        desc = desc or "OS security-group %s" % name
        sg_dict = dict(name=name, description=desc)
        if tenant_id:
            sg_dict['tenant_id'] = tenant_id
        sg = sg_client.create_security_group(**sg_dict)
        sg = sg.get('security_group', sg)
        return sg

    def create_security_group_policy(self, cmgr=None, policy_id=None,
                                     tenant_id=None, provider=False):
        cmgr = cmgr or self.cmgr_adm
        policy_id = policy_id or self.default_policy_id
        sg_client = cmgr.security_groups_client
        sg_dict = dict(policy=policy_id,
                       name=data_utils.rand_name('admin-policy'))
        if tenant_id:
            sg_dict['tenant_id'] = tenant_id
        if provider:
            sg_dict['provider'] = True
        sg = sg_client.create_security_group(**sg_dict)
        sg = sg.get('security_group', sg)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_security_group,
                        sg_client, sg.get('id'))
        return sg

    def update_security_group_policy(self, security_group_id,
                                     new_policy_id, cmgr=None):
        cmgr = cmgr or self.cmgr_adm
        sg_client = cmgr.security_groups_client
        sg = sg_client.update_security_group(security_group_id,
                                             policy=new_policy_id)
        return sg.get('security_group', sg)

    def create_security_group_rule(self, security_group_id,
                                   cmgr=None, tenant_id=None):
        cmgr = cmgr or self.cmgr_adm
        sgr_client = cmgr.security_group_rules_client
        sgr_dict = dict(security_group_id=security_group_id,
                        direction='ingress', protocol='icmp')
        if tenant_id:
            sgr_dict['tenant_id'] = tenant_id
        sgr = sgr_client.create_security_group_rule(**sgr_dict)
        return sgr.get('security_group_rule', sgr)

    def get_default_security_group_policy(self, cmgr=None):
        cmgr = cmgr or self.cmgr_adm
        sg_client = cmgr.security_groups_client
        sg_list = sg_client.list_security_groups()
        # why list twice, see bug#1772424
        sg_list = sg_client.list_security_groups(name='default')
        sg_list = sg_list.get('security_groups', sg_list)
        return sg_list[0]

    def show_security_group_policy(self, security_group_id, cmgr=None):
        cmgr = cmgr or self.cmgr_adm
        sg_client = cmgr.security_groups_client
        sg = sg_client.show_security_group(security_group_id)
        return sg.get('security_group', sg)

    @test.idempotent_id('825d0270-6649-44f2-ac0c-a3b5566d0d2a')
    def test_admin_can_crud_policy(self):
        sg_desc = "crud security-group-policy"
        sg_client = self.cmgr_adm.security_groups_client
        sg = self.create_security_group_policy(self.cmgr_adm)
        sg_id = sg.get('id')
        self.assertEqual(self.default_policy_id, sg.get('policy'))
        sg_client.update_security_group(sg_id, description=sg_desc)
        sg_show = self.show_security_group_policy(sg_id)
        self.assertEqual(sg_desc, sg_show.get('description'))
        self.delete_security_group(sg_client, sg_id)
        sg_list = sg_client.list_security_groups(id=sg_id)
        sg_list = sg_list.get('security_groups', sg_list)
        self.assertEqual(len(sg_list), 0)

    @test.idempotent_id('809d72be-c2d8-4e32-b538-09a5003630c0')
    def test_admin_can_create_policy_for_tenant(self):
        tenant_id = self.cmgr_alt.networks_client.tenant_id
        sg = self.create_security_group_policy(self.cmgr_adm,
                                               tenant_id=tenant_id)
        self.assertEqual(self.default_policy_id, sg.get('policy'))

    @test.idempotent_id('1ab540b0-2a56-46cd-bbaa-607a655b4688')
    def test_admin_can_create_provider_policy(self):
        tenant_id = self.cmgr_pri.networks_client.tenant_id
        sg = self.create_security_group_policy(self.cmgr_adm,
                                               tenant_id=tenant_id,
                                               provider=True)
        self.assertEqual(self.default_policy_id, sg.get('policy'))
        self.assertEqual(sg.get('provider'), True)

    @test.idempotent_id('1d31ea7a-37f1-40db-b917-4acfbf565ae2')
    def test_tenant_has_default_policy(self):
        sg = self.get_default_security_group_policy(self.cmgr_pri)
        self.assertEqual(self.default_policy_id, sg.get('policy'))

    @testtools.skipIf(not CONF.nsxv.alt_policy_id.startswith('policy-'),
                      "nsxv.alt_policy_id not defined.")
    @test.idempotent_id('6784cf25-6b50-4349-b96b-85076111dbf4')
    def test_admin_change_tenant_policy(self):
        tenant_id = self.cmgr_alt.networks_client.tenant_id
        sg = self.create_security_group_policy(tenant_id=tenant_id)
        sg_id = sg.get('id')
        self.update_security_group_policy(sg_id, self.alt_policy_id)
        sg = self.show_security_group_policy(sg_id, self.cmgr_alt)
        self.assertEqual(self.alt_policy_id, sg.get('policy'))

    @testtools.skipIf(not CONF.nsxv.allow_tenant_rules_with_policy,
                      "skip because tenant is not allowed to create SG.")
    @test.idempotent_id('4abf29bd-22ae-46b4-846b-e7c28f318159')
    def test_tenant_create_security_group_if_allowed(self):
        """test if allow_tenant_rules_with_policy=True"""
        sg_client = self.cmgr_pri.security_groups_client
        sg_name = data_utils.rand_name('security-group')
        sg = self.create_security_group(sg_client, sg_name)
        self.assertEqual(sg.get('name'), sg_name)

    @test.attr(type=['negative'])
    @test.idempotent_id('5099604c-637a-4b25-8756-c6fc0929f963')
    def test_add_rules_to_policy_disallowed(self):
        tenant_id = self.cmgr_pri.networks_client.tenant_id
        sg = self.create_security_group_policy(self.cmgr_adm,
                                               tenant_id=tenant_id)
        self.assertRaises(exceptions.BadRequest,
            self.create_security_group_rule, sg.get('id'),
            cmgr=self.cmgr_adm, tenant_id=tenant_id)

    @test.attr(type=['negative'])
    @test.idempotent_id('9a604036-ace6-4ced-92b8-be732eee310f')
    def test_cannot_create_policy_with_invalid_policy_id(self):
        self.assertRaises(exceptions.BadRequest,
                          self.create_security_group_policy,
                          self.cmgr_adm, "invalid-policy-id")

    @test.attr(type=['negative'])
    @test.idempotent_id('4d383d3c-f1e6-47e3-906e-3c171146965a')
    def test_tenant_cannot_delete_its_policy(self):
        tenant_cmgr = self.cmgr_alt
        tenant_id = tenant_cmgr.networks_client.tenant_id
        sg = self.create_security_group_policy(cmgr=self.cmgr_adm,
                                               tenant_id=tenant_id)
        sg_id = sg.get('id')
        tenant_sg_client = tenant_cmgr.security_groups_client
        self.assertRaises(exceptions.Forbidden,
                          self.delete_security_group,
                          tenant_sg_client, sg_id)

    @test.attr(type=['negative'])
    @test.idempotent_id('154985cd-26b2-468d-af6d-b6144ef2d378')
    def test_tenant_cannot_update_its_policy(self):
        tenant_cmgr = self.cmgr_alt
        tenant_id = tenant_cmgr.networks_client.tenant_id
        sg = self.create_security_group_policy(cmgr=self.cmgr_adm,
                                               tenant_id=tenant_id)
        sg_id = sg.get('id')
        self.assertRaises(exceptions.Forbidden,
                          self.update_security_group_policy,
                          sg_id, self.alt_policy_id, self.cmgr_alt)

    @test.attr(type=['negative'])
    @test.idempotent_id('d6d8c918-d488-40c4-83dc-8ce1a565e54f')
    def test_tenant_cannot_create_policy(self):
        self.assertRaises(exceptions.Forbidden,
                          self.create_security_group_policy,
                          self.cmgr_pri)

    @test.attr(type=['negative'])
    @testtools.skipIf(CONF.nsxv.allow_tenant_rules_with_policy,
                      "skip because tenant is allowed to create SG.")
    @test.idempotent_id('82aa02ee-8008-47a9-90ea-ba7840bfb932')
    def test_tenant_cannot_create_security_group(self):
        """Only valid if allow_tenant_rules_with_policy=True

           If test fail, check nsx.ini and vmware_nsx_tempest/config.py
           to make sure they are the same value.

           Exception is BadRequest, not Forbideen as the message is
           edited first before integration check.

           counter part test is:
              test_tenant_create_security_group_if_allowed()
        """
        sg_client = self.cmgr_pri.security_groups_client
        sg_name = data_utils.rand_name('security-group')
        self.assertRaises(exceptions.BadRequest,
                          self.create_security_group,
                          sg_client, sg_name)
