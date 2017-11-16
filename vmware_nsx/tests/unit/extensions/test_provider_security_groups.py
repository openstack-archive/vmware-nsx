# Copyright 2016 VMware, Inc.
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
import mock
import webob.exc

from neutron.api.v2 import attributes as attr
from neutron.db import api as db_api
from neutron.db import db_base_plugin_v2
from neutron.db import securitygroups_db
from neutron.tests.unit.extensions import test_securitygroup
from neutron_lib import context

from vmware_nsx.db import extended_security_group
from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.tests.unit.nsx_v import test_plugin as test_nsxv_plugin
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_nsxv3_plugin


PLUGIN_NAME = ('vmware_nsx.tests.unit.extensions.'
               'test_provider_security_groups.ProviderSecurityGroupTestPlugin')


# FIXME(arosen): make common mixin for extended_security_group_properties and
# security_group_db_minxin.
class ProviderSecurityGroupTestPlugin(
    db_base_plugin_v2.NeutronDbPluginV2,
    extended_security_group.ExtendedSecurityGroupPropertiesMixin,
    securitygroups_db.SecurityGroupDbMixin):

    supported_extension_aliases = ["security-group",
                                   "provider-security-group"]

    def create_security_group(self, context, security_group, default_sg=False):
        secgroup = security_group['security_group']
        with db_api.context_manager.writer.using(context):
            # NOTE(arosen): a neutron security group by default adds rules
            # that allow egress traffic. We do not want this behavior for
            # provider security_groups
            if secgroup.get(provider_sg.PROVIDER) is True:
                secgroup_db = self.create_provider_security_group(
                    context, security_group)
            else:
                secgroup_db = (
                    super(ProviderSecurityGroupTestPlugin, self
                          ).create_security_group(context, security_group,
                                                  default_sg))

            self._process_security_group_properties_create(context,
                                                           secgroup_db,
                                                           secgroup,
                                                           default_sg)
        return secgroup_db

    def create_port(self, context, port, l2gw_port_check=False):
        port_data = port['port']

        with db_api.context_manager.writer.using(context):
            self._ensure_default_security_group_on_port(context, port)
            (sgids, provider_groups) = self._get_port_security_groups_lists(
                context, port)

            port_db = super(ProviderSecurityGroupTestPlugin, self).create_port(
                context, port)
            port_data.update(port_db)

            # handle adding security groups to port
            self._process_port_create_security_group(
                context, port_db, sgids)

            # handling adding provider security group to port if there are any
            self._process_port_create_provider_security_group(
                context, port_data, provider_groups)
        return port_data

    def update_port(self, context, id, port):
        with db_api.context_manager.writer.using(context):
            original_port = super(ProviderSecurityGroupTestPlugin,
                                  self).get_port(context, id)
            updated_port = super(ProviderSecurityGroupTestPlugin,
                                 self).update_port(context, id, port)

            self.update_security_group_on_port(context, id, port,
                                               original_port, updated_port)
            self._process_port_update_provider_security_group(
                context, port, original_port, updated_port)
            return self.get_port(context, id)

    def _make_port_dict(self, port, fields=None, process_extensions=True):
        port_data = super(
            ProviderSecurityGroupTestPlugin, self)._make_port_dict(
            port, fields=fields,
            process_extensions=process_extensions)
        self._remove_provider_security_groups_from_list(port_data)
        return port_data

    def delete_security_group(self, context, id):
        self._prevent_non_admin_delete_provider_sg(context, id)
        super(ProviderSecurityGroupTestPlugin,
              self).delete_security_group(context, id)

    def delete_security_group_rule(self, context, id):
        rule_db = self._get_security_group_rule(context, id)
        sg_id = rule_db['security_group_id']
        self._prevent_non_admin_delete_provider_sg(context, sg_id)
        return super(ProviderSecurityGroupTestPlugin,
                     self).delete_security_group_rule(context, id)

    def create_security_group_rule(self, context, security_group_rule):
        id = security_group_rule['security_group_rule']['security_group_id']
        self._prevent_non_admin_delete_provider_sg(context, id)
        return super(ProviderSecurityGroupTestPlugin,
                     self).create_security_group_rule(context,
                                                      security_group_rule)


class ProviderSecurityGroupExtTestCase(
        test_securitygroup.SecurityGroupDBTestCase):
    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None):
        super(ProviderSecurityGroupExtTestCase, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr)
        self._tenant_id = 'foobar'
        # add provider group attributes
        attr.RESOURCE_ATTRIBUTE_MAP['security_groups'].update(
            provider_sg.EXTENDED_ATTRIBUTES_2_0['security_groups'])

        attr.RESOURCE_ATTRIBUTE_MAP['ports'].update(
            provider_sg.EXTENDED_ATTRIBUTES_2_0['ports'])

    def tearDown(self):
        # remove provider security group attributes
        del attr.RESOURCE_ATTRIBUTE_MAP['security_groups']['provider']
        del attr.RESOURCE_ATTRIBUTE_MAP['ports']['provider_security_groups']
        super(ProviderSecurityGroupExtTestCase, self).tearDown()

    def _create_provider_security_group(self):
        body = {'security_group': {'name': 'provider-deny',
                                   'tenant_id': self._tenant_id,
                                   'description': 'foobarzzkk',
                                   'provider': True}}
        security_group_req = self.new_create_request('security-groups', body)
        return self.deserialize(self.fmt,
                                security_group_req.get_response(self.ext_api))

    def test_create_provider_security_group(self):
        # confirm this attribute is true
        provider_secgroup = self._create_provider_security_group()
        self.assertTrue(provider_secgroup['security_group']['provider'])

        # provider security groups have no rules by default which is different
        # from normal neutron security groups which by default include a rule
        # to allow egress traffic. We confirm this here.
        self.assertEqual(
            provider_secgroup['security_group']['security_group_rules'], [])

    def test_create_provider_security_groups_same_tenant(self):
        provider_secgroup = self._create_provider_security_group()
        self.assertTrue(provider_secgroup['security_group']['provider'])

        # Verify that another one can also be created for the same tenant
        provider_secgroup2 = self._create_provider_security_group()
        self.assertTrue(provider_secgroup2['security_group']['provider'])

    def test_create_port_gets_provider_sg(self):
        # need to create provider security group first.
        provider_secgroup = self._create_provider_security_group()
        with self.port(tenant_id=self._tenant_id) as p:
            # check that the provider security group is on port resource.
            self.assertEqual(1, len(p['port']['provider_security_groups']))
            self.assertEqual(provider_secgroup['security_group']['id'],
                             p['port']['provider_security_groups'][0])

            # confirm there is still a default security group.
            self.assertEqual(len(p['port']['security_groups']), 1)

    def test_create_port_gets_multi_provider_sg(self):
        # need to create provider security groups first.
        provider_secgroup1 = self._create_provider_security_group()
        provider_secgroup2 = self._create_provider_security_group()
        with self.port(tenant_id=self._tenant_id) as p:
            # check that the provider security group is on port resource.
            self.assertEqual(2, len(p['port']['provider_security_groups']))
            self.assertIn(provider_secgroup1['security_group']['id'],
                          p['port']['provider_security_groups'])
            self.assertIn(provider_secgroup2['security_group']['id'],
                          p['port']['provider_security_groups'])

            # confirm there is still a default security group.
            self.assertEqual(len(p['port']['security_groups']), 1)

    def test_create_port_with_no_provider_sg(self):
        self._create_provider_security_group()
        with self.port(tenant_id=self._tenant_id,
                       arg_list=('provider_security_groups', ),
                       provider_security_groups=[]) as p1:
            self.assertEqual([], p1['port']['provider_security_groups'])
        with self.port(tenant_id=self._tenant_id,
                       arg_list=('provider_security_groups', ),
                       provider_security_groups=None) as p1:
            self.assertEqual([], p1['port']['provider_security_groups'])

    def test_update_port_remove_provider_sg_with_empty_list(self):
        # need to create provider security group first.
        self._create_provider_security_group()
        with self.port(tenant_id=self._tenant_id) as p:
            body = {'port': {'provider_security_groups': []}}
            req = self.new_update_request('ports', body, p['port']['id'])
            port = self.deserialize(self.fmt, req.get_response(self.api))
            # confirm that the group has been removed.
            self.assertEqual([], port['port']['provider_security_groups'])

    def test_update_port_remove_provider_sg_with_none(self):
        # need to create provider security group first.
        self._create_provider_security_group()
        with self.port(tenant_id=self._tenant_id) as p:
            body = {'port': {'provider_security_groups': None}}
            req = self.new_update_request('ports', body, p['port']['id'])
            port = self.deserialize(self.fmt, req.get_response(self.api))
            # confirm that the group has been removed.
            self.assertEqual([], port['port']['provider_security_groups'])

    def test_cannot_update_port_with_provider_group_as_sec_group(self):
        with self.port(tenant_id=self._tenant_id) as p:
            provider_secgroup = self._create_provider_security_group()
            sg_id = provider_secgroup['security_group']['id']
            body = {'port': {'security_groups': [sg_id]}}
            req = self.new_update_request('ports', body, p['port']['id'])
            res = req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_cannot_update_port_with_sec_group_as_provider(self):
        with self.security_group() as sg1:
            with self.port(tenant_id=self._tenant_id) as p:
                sg_id = sg1['security_group']['id']
                body = {'port': {'provider_security_groups': [sg_id]}}
                req = self.new_update_request('ports', body, p['port']['id'])
                res = req.get_response(self.api)
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_cannot_update_port_with_different_tenant_provider_secgroup(self):
        with self.port(tenant_id=self._tenant_id) as p:
            tmp_tenant_id = self._tenant_id
            self._tenant_id += "-alt"
            pvd_sg = self._create_provider_security_group()
            self._tenant_id = tmp_tenant_id
            body = {'port': {'provider_security_groups': [
                pvd_sg['security_group']['id']]}}

            ctx = context.Context('', self._tenant_id)
            req = self.new_update_request('ports', body,
                                          p['port']['id'], context=ctx)
            res = req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_update_port_security_groups_only(self):
        # We want to make sure that modifying security-groups on the port
        # doesn't impact the provider security-group on this port.
        provider_secgroup = self._create_provider_security_group()
        with self.security_group() as sg1:
            with self.port(tenant_id=self._tenant_id) as p:
                sg_id = sg1['security_group']['id']
                body = {'port': {'security_groups': [sg_id]}}
                req = self.new_update_request('ports', body, p['port']['id'])
                port = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertEqual(
                    [provider_secgroup['security_group']['id']],
                    port['port']['provider_security_groups'])

    def test_update_port_security_groups(self):
        with self.security_group() as sg1:
            with self.port(tenant_id=self._tenant_id) as p:
                # Port created before provider secgroup is created, so the port
                # would not be associated with the pvd secgroup at this point.
                provider_secgroup = self._create_provider_security_group()
                pvd_sg_id = provider_secgroup['security_group']['id']
                sg_id = sg1['security_group']['id']
                body = {'port': {
                    'security_groups': [sg_id],
                    'provider_security_groups': [pvd_sg_id]}
                }
                req = self.new_update_request('ports', body, p['port']['id'])
                port = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertEqual([pvd_sg_id],
                                 port['port']['provider_security_groups'])
                self.assertEqual([sg_id], port['port']['security_groups'])

    def test_non_admin_cannot_delete_provider_sg_and_admin_can(self):
        provider_secgroup = self._create_provider_security_group()
        pvd_sg_id = provider_secgroup['security_group']['id']

        # Try deleting the request as the normal tenant returns forbidden
        # as a tenant is not allowed to delete this.
        ctx = context.Context('', self._tenant_id)
        self._delete('security-groups', pvd_sg_id,
                     expected_code=webob.exc.HTTPForbidden.code,
                     neutron_context=ctx)
        # can be deleted though as admin
        self._delete('security-groups', pvd_sg_id,
                     expected_code=webob.exc.HTTPNoContent.code)

    def test_non_admin_cannot_delete_provider_sg_rule(self):
        provider_secgroup = self._create_provider_security_group()
        pvd_sg_id = provider_secgroup['security_group']['id']

        data = {'security_group_rule': {'security_group_id': pvd_sg_id,
                                        'direction': 'ingress',
                                        'protocol': 'tcp',
                                        'ethertype': 'IPv4',
                                        'tenant_id': self._tenant_id}}

        req = self.new_create_request('security-group-rules', data)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))

        sg_rule_id = res['security_group_rule']['id']

        # Try deleting the request as the normal tenant returns forbidden
        # as a tenant is not allowed to delete this.
        ctx = context.Context('', self._tenant_id)
        self._delete('security-group-rules', sg_rule_id,
                     expected_code=webob.exc.HTTPForbidden.code,
                     neutron_context=ctx)
        # can be deleted though as admin
        self._delete('security-group-rules', sg_rule_id,
                     expected_code=webob.exc.HTTPNoContent.code)

    def test_non_admin_cannot_add_provider_sg_rule(self):
        provider_secgroup = self._create_provider_security_group()
        pvd_sg_id = provider_secgroup['security_group']['id']

        data = {'security_group_rule': {'security_group_id': pvd_sg_id,
                                        'direction': 'ingress',
                                        'protocol': 'tcp',
                                        'ethertype': 'IPv4',
                                        'tenant_id': self._tenant_id}}

        req = self.new_create_request(
            'security-group-rules', data)
        req.environ['neutron.context'] = context.Context('', self._tenant_id)
        res = req.get_response(self.ext_api)
        self.assertEqual(webob.exc.HTTPForbidden.code, res.status_int)


class TestNSXv3ProviderSecurityGrp(test_nsxv3_plugin.NsxV3PluginTestCaseMixin,
                                   ProviderSecurityGroupExtTestCase):

    def test_update_port_remove_provider_sg(self):
        # need to create provider security group first.
        self._create_provider_security_group()
        with self.port(tenant_id=self._tenant_id) as p:
            body = {'port': {'provider_security_groups': []}}
            req = self.new_update_request('ports', body, p['port']['id'])
            port = self.deserialize(self.fmt, req.get_response(self.api))
            # confirm that the group has been removed.
            self.assertEqual([], port['port']['provider_security_groups'])
            # make sure that the security groups did not contain the provider
            # security group
            self.assertEqual(p['port']['security_groups'],
                             port['port']['security_groups'])


class TestNSXvProviderSecurityGroup(test_nsxv_plugin.NsxVPluginV2TestCase,
                                    ProviderSecurityGroupExtTestCase):
    def test_create_provider_security_group(self):
        _create_section_tmp = self.fc2.create_section

        def _create_section(*args, **kwargs):
            return _create_section_tmp(*args, **kwargs)

        with mock.patch.object(self.fc2, 'create_section',
                               side_effect=_create_section) as create_sec_mock:
            super(TestNSXvProviderSecurityGroup,
                  self).test_create_provider_security_group()
            create_sec_mock.assert_called_with('ip', mock.ANY,
                                               insert_top=True,
                                               insert_before=mock.ANY)

    def test_create_provider_security_group_rule(self):
        provider_secgroup = self._create_provider_security_group()
        sg_id = provider_secgroup['security_group']['id']
        _create_nsx_rule_tmp = self.plugin._create_nsx_rule

        def m_create_nsx_rule(*args, **kwargs):
            return _create_nsx_rule_tmp(*args, **kwargs)

        with mock.patch.object(self.plugin, '_create_nsx_rule',
                               side_effect=m_create_nsx_rule) as create_rule_m:
            with self.security_group_rule(security_group_id=sg_id):
                create_rule_m.assert_called_with(mock.ANY, mock.ANY,
                                                 logged=mock.ANY,
                                                 action='deny')
