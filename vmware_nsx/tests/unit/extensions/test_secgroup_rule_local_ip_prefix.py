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

from neutron.db import db_base_plugin_v2
from neutron.db import securitygroups_db
from neutron.extensions import securitygroup as ext_sg
from neutron.tests.unit.extensions import test_securitygroup
from neutron_lib import constants as const
from neutron_lib.db import api as db_api
from neutron_lib.plugins import directory

from vmware_nsx.db import extended_security_group_rule as ext_rule_db
from vmware_nsx.extensions import secgroup_rule_local_ip_prefix as ext_loip
from vmware_nsx.plugins.nsx_v.vshield import securitygroup_utils
from vmware_nsx.tests.unit.nsx_p import test_plugin as test_nsxp_plugin
from vmware_nsx.tests.unit.nsx_v import test_plugin as test_nsxv_plugin
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_nsxv3_plugin


PLUGIN_NAME = ('vmware_nsx.tests.unit.extensions.'
               'test_secgroup_rule_local_ip_prefix.ExtendedRuleTestPlugin')

_uuid = uuidutils.generate_uuid


class ExtendedRuleTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                             ext_rule_db.ExtendedSecurityGroupRuleMixin,
                             securitygroups_db.SecurityGroupDbMixin):

    supported_extension_aliases = ["security-group",
                                   ext_loip.ALIAS]

    def create_security_group_rule(self, context, security_group_rule):
        rule = security_group_rule['security_group_rule']
        self._check_local_ip_prefix(context, rule)
        with db_api.CONTEXT_WRITER.using(context):
            res = super(ExtendedRuleTestPlugin,
                        self).create_security_group_rule(
                            context, security_group_rule)
            self._process_security_group_rule_properties(context, res, rule)
        return res


class LocalIPPrefixExtTestCase(test_securitygroup.SecurityGroupDBTestCase):
    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None):
        super(LocalIPPrefixExtTestCase, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr)
        ext_sg.Securitygroup().update_attributes_map(
            ext_loip.RESOURCE_ATTRIBUTE_MAP)

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
        plugin = directory.get_plugin()
        dest = {'type': 'Ipv4Address', 'value': local_ip_prefix}

        plugin.nsx_sg_utils.get_rule_config = mock.Mock(
            side_effect=sg_utils.get_rule_config)
        super(TestNsxVExtendedSGRule,
              self).test_create_rule_with_local_ip_prefix()
        plugin.nsx_sg_utils.get_rule_config.assert_called_with(
            source=mock.ANY, destination=dest, services=mock.ANY,
            name=mock.ANY, applied_to_ids=mock.ANY, flags=mock.ANY,
            logged=mock.ANY, action=mock.ANY, tag=mock.ANY, notes=mock.ANY)


class TestNSXv3ExtendedSGRule(test_nsxv3_plugin.NsxV3PluginTestCaseMixin,
                              LocalIPPrefixExtTestCase):
    def test_create_rule_with_local_ip_prefix(self):
        sg_rules = [
            {'tenant_id': mock.ANY,
             'project_id': mock.ANY,
             'id': mock.ANY,
             'port_range_min': None,
             'local_ip_prefix': '239.255.0.0/16',
             'ethertype': 'IPv4',
             'protocol': u'udp', 'remote_ip_prefix': '10.0.0.0/24',
             'port_range_max': None,
             'security_group_id': mock.ANY,
             'remote_group_id': None, 'direction': u'ingress',
             'description': ''}]

        with mock.patch(
            "vmware_nsxlib.v3.security.NsxLibFirewallSection."
            "create_section_rules",
            side_effect=test_nsxv3_plugin._mock_create_firewall_rules,
        ) as mock_rule:

            super(TestNSXv3ExtendedSGRule,
                  self).test_create_rule_with_local_ip_prefix()

            mock_rule.assert_called_with(
                mock.ANY,  # firewall_section_id
                mock.ANY,  # ns_group_id
                False,  # logging
                'ALLOW',  # action
                sg_rules,  # sg_rules
                mock.ANY)  # ruleid_2_remote_nsgroup_map

    def test_create_rule_with_remote_ip_prefix(self):
        remote_ip_prefix = '0.0.0.0/0'
        with self.security_group() as sg:
            rule = self._build_security_group_rule(
                sg['security_group']['id'], remote_ip_prefix=remote_ip_prefix,
                direction='ingress', proto=const.PROTO_NAME_UDP)
            res = self._make_security_group_rule(self.fmt, rule)
            self.assertEqual(remote_ip_prefix,
                             res['security_group_rule']['remote_ip_prefix'])

    def test_create_nsx_rule_with_remote_ip_prefix_zeros(self):
        sg_rules = [
            {'tenant_id': mock.ANY,
             'project_id': mock.ANY,
             'id': mock.ANY,
             'port_range_min': None,
             'local_ip_prefix': None,
             'ethertype': 'IPv4',
             'protocol': u'udp',
             'remote_ip_prefix': None,
             'port_range_max': None,
             'security_group_id': mock.ANY,
             'remote_group_id': None,
             'direction': u'ingress',
             'description': ''}]

        with mock.patch(
            "vmware_nsxlib.v3.security.NsxLibFirewallSection."
            "create_section_rules",
            side_effect=test_nsxv3_plugin._mock_create_firewall_rules,
        ) as mock_rule:
            self.test_create_rule_with_remote_ip_prefix()
            mock_rule.assert_called_with(
                mock.ANY,  # firewall_section_id
                mock.ANY,  # ns_group_id
                False,  # logging
                'ALLOW',  # action
                sg_rules,  # sg_rules
                mock.ANY)  # ruleid_2_remote_nsgroup_map


class TestNSXpExtendedSGRule(test_nsxp_plugin.NsxPPluginTestCaseMixin,
                             LocalIPPrefixExtTestCase):
    pass
