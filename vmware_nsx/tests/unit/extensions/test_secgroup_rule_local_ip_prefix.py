# Copyright 2015 VMware, Inc.
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

from oslo_utils import uuidutils

from neutron.api.v2 import attributes
from neutron.db import db_base_plugin_v2
from neutron.db import securitygroups_db
from neutron import manager
from neutron.tests.unit.extensions import test_securitygroup
from neutron_lib import constants as const

from vmware_nsx.db import extended_security_group_rule as ext_rule_db
from vmware_nsx.extensions import secgroup_rule_local_ip_prefix as ext_loip
from vmware_nsx.plugins.nsx_v.vshield import securitygroup_utils
from vmware_nsx.tests.unit.nsx_v import test_plugin as test_nsxv_plugin


PLUGIN_NAME = ('vmware_nsx.tests.unit.extensions.'
               'test_secgroup_rule_local_ip_prefix.ExtendedRuleTestPlugin')

_uuid = uuidutils.generate_uuid


class ExtendedRuleTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                             ext_rule_db.ExtendedSecurityGroupRuleMixin,
                             securitygroups_db.SecurityGroupDbMixin):

    supported_extension_aliases = ["security-group",
                                   "secgroup-rule-local-ip-prefix"]

    def create_security_group_rule(self, context, security_group_rule):
        rule = security_group_rule['security_group_rule']
        rule['id'] = _uuid()
        self._check_local_ip_prefix(context, rule)
        with context.session.begin(subtransactions=True):
            res = super(ExtendedRuleTestPlugin,
                        self).create_security_group_rule(
                            context, security_group_rule)
            self._save_extended_rule_properties(context, rule)
            self._get_security_group_rule_properties(context, res)
        return res


class LocalIPPrefixExtTestCase(test_securitygroup.SecurityGroupDBTestCase):
    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None):
        super(LocalIPPrefixExtTestCase, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr)
        attributes.RESOURCE_ATTRIBUTE_MAP['security_group_rules'].update(
            ext_loip.RESOURCE_ATTRIBUTE_MAP['security_group_rules'])

    def tearDown(self):
        # Remove attributes which were written to global attr map, they may
        # interfer with tests for other plugins which doesn't support this
        # extension.
        del attributes.RESOURCE_ATTRIBUTE_MAP[
            'security_group_rules']['local_ip_prefix']
        super(LocalIPPrefixExtTestCase, self).tearDown()

    def _build_ingress_rule_with_local_ip_prefix(self, security_group_id,
                                                 local_ip_prefix,
                                                 remote_ip_prefix,
                                                 direction='ingress'):
        rule = self._build_security_group_rule(
            security_group_id, remote_ip_prefix=remote_ip_prefix,
            direction=direction, proto=const.PROTO_NAME_UDP)
        rule['security_group_rule']['local_ip_prefix'] = local_ip_prefix
        return rule

    def test_raise_rule_not_ingress_when_local_ip_specified(self):
        local_ip_prefix = '239.255.0.0/16'
        remote_ip_prefix = '10.0.0.0/24'
        with self.security_group() as sg:
            rule = self._build_ingress_rule_with_local_ip_prefix(
                sg['security_group']['id'], local_ip_prefix,
                remote_ip_prefix, direction='egress')
            res = self._create_security_group_rule(self.fmt, rule)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_rule_with_local_ip_prefix(self):
        local_ip_prefix = '239.255.0.0/16'
        remote_ip_prefix = '10.0.0.0/24'
        with self.security_group() as sg:
            rule = self._build_ingress_rule_with_local_ip_prefix(
                sg['security_group']['id'], local_ip_prefix, remote_ip_prefix)
            res = self._make_security_group_rule(self.fmt, rule)
            self.assertEqual(local_ip_prefix,
                             res['security_group_rule']['local_ip_prefix'])


class TestNsxVExtendedSGRule(test_nsxv_plugin.NsxVSecurityGroupsTestCase,
                             LocalIPPrefixExtTestCase):
    def test_create_rule_with_local_ip_prefix(self):
        sg_utils = securitygroup_utils.NsxSecurityGroupUtils(None)
        local_ip_prefix = '239.255.0.0/16'
        plugin = manager.NeutronManager.get_plugin()
        dest = {'type': 'Ipv4Address', 'value': local_ip_prefix}

        def _assert_destination_as_expected(*args, **kwargs):
            self.assertEqual(dest, kwargs['destination'])
            return sg_utils.get_rule_config(*args, **kwargs)

        plugin.nsx_sg_utils.get_rule_config = mock.Mock(
            side_effect=sg_utils.get_rule_config)
        super(TestNsxVExtendedSGRule,
              self).test_create_rule_with_local_ip_prefix()
        plugin.nsx_sg_utils.get_rule_config.assert_called_with(
            destination=dest, applied_to_ids=mock.ANY, name=mock.ANY,
            services=mock.ANY, source=mock.ANY, flags=mock.ANY)
