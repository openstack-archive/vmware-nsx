# Copyright (c) 2014 VMware, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from neutron.tests.unit.api.v2 import test_base
from neutron_lib import constants
from neutron_lib import exceptions

from vmware_nsx.nsxlib import mh as nsxlib
from vmware_nsx.nsxlib.mh import secgroup as secgrouplib
from vmware_nsx.tests.unit.nsxlib.mh import base

_uuid = test_base._uuid


class SecurityProfileTestCase(base.NsxlibTestCase):

    def test_create_and_get_security_profile(self):
        sec_prof = secgrouplib.create_security_profile(
            self.fake_cluster, _uuid(), 'pippo', {'name': 'test'})
        sec_prof_res = nsxlib.do_request(
            secgrouplib.HTTP_GET,
            nsxlib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])
        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_egress_rules']), 1)
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 2)

    def test_create_and_get_default_security_profile(self):
        sec_prof = secgrouplib.create_security_profile(
            self.fake_cluster, _uuid(), 'pippo', {'name': 'default'})
        sec_prof_res = nsxlib.do_request(
            secgrouplib.HTTP_GET,
            nsxlib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])
        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_egress_rules']), 3)
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 2)

    def test_update_security_profile_raise_not_found(self):
        self.assertRaises(exceptions.NotFound,
                          secgrouplib.update_security_profile,
                          self.fake_cluster,
                          _uuid(), 'tatore_magno(the great)')

    def test_update_security_profile(self):
        tenant_id = 'foo_tenant_uuid'
        secgroup_id = 'foo_secgroup_uuid'
        old_sec_prof = secgrouplib.create_security_profile(
            self.fake_cluster, tenant_id, secgroup_id,
            {'name': 'tatore_magno'})
        new_sec_prof = secgrouplib.update_security_profile(
            self.fake_cluster, old_sec_prof['uuid'], 'aaron_magno')
        self.assertEqual('aaron_magno', new_sec_prof['display_name'])

    def test_update_security_profile_rules(self):
        sec_prof = secgrouplib.create_security_profile(
            self.fake_cluster, _uuid(), 'pippo', {'name': 'test'})
        ingress_rule = {'ethertype': 'IPv4'}
        egress_rule = {'ethertype': 'IPv4', 'profile_uuid': 'xyz'}
        new_rules = {'logical_port_egress_rules': [egress_rule],
                     'logical_port_ingress_rules': [ingress_rule]}
        secgrouplib.update_security_group_rules(
            self.fake_cluster, sec_prof['uuid'], new_rules)
        sec_prof_res = nsxlib.do_request(
            nsxlib.HTTP_GET,
            nsxlib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])
        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_egress_rules']), 2)
        self.assertIn(egress_rule,
                      sec_prof_res['logical_port_egress_rules'])
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 1)
        self.assertIn(ingress_rule,
                      sec_prof_res['logical_port_ingress_rules'])

    def test_update_security_profile_rules_noingress(self):
        sec_prof = secgrouplib.create_security_profile(
            self.fake_cluster, _uuid(), 'pippo', {'name': 'test'})
        hidden_ingress_rule = {'ethertype': 'IPv4',
                               'ip_prefix': '127.0.0.1/32'}
        egress_rule = {'ethertype': 'IPv4', 'profile_uuid': 'xyz'}
        new_rules = {'logical_port_egress_rules': [egress_rule],
                     'logical_port_ingress_rules': []}
        secgrouplib.update_security_group_rules(
            self.fake_cluster, sec_prof['uuid'], new_rules)
        sec_prof_res = nsxlib.do_request(
            nsxlib.HTTP_GET,
            nsxlib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])
        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_egress_rules']), 2)
        self.assertIn(egress_rule,
                      sec_prof_res['logical_port_egress_rules'])
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 1)
        self.assertIn(hidden_ingress_rule,
                      sec_prof_res['logical_port_ingress_rules'])

    def test_update_security_profile_rules_summarize_port_range(self):
        sec_prof = secgrouplib.create_security_profile(
            self.fake_cluster, _uuid(), 'pippo', {'name': 'test'})
        ingress_rule = [{'ethertype': 'IPv4'}]
        egress_rules = [
            {'ethertype': 'IPv4', 'protocol': constants.PROTO_NUM_UDP,
             'port_range_min': 1, 'port_range_max': 65535}]
        new_rules = {'logical_port_egress_rules': egress_rules,
                     'logical_port_ingress_rules': [ingress_rule]}
        egress_rules_summarized = [{'ethertype': 'IPv4',
                                    'protocol': constants.PROTO_NUM_UDP}]
        secgrouplib.update_security_group_rules(
            self.fake_cluster, sec_prof['uuid'], new_rules)
        sec_prof_res = nsxlib.do_request(
            nsxlib.HTTP_GET,
            nsxlib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])

        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 1)
        self.assertEqual(sec_prof_res['logical_port_egress_rules'],
                         egress_rules_summarized)
        self.assertIn(ingress_rule,
                      sec_prof_res['logical_port_ingress_rules'])

    def test_update_security_profile_rules_summarize_ip_prefix(self):
        sec_prof = secgrouplib.create_security_profile(
            self.fake_cluster, _uuid(), 'pippo', {'name': 'test'})
        ingress_rule = [{'ethertype': 'IPv4'}]
        egress_rules = [
            {'ethertype': 'IPv4', 'protocol': constants.PROTO_NUM_UDP,
             'ip_prefix': '0.0.0.0/0'},
            {'ethertype': 'IPv6', 'protocol': constants.PROTO_NUM_UDP,
             'ip_prefix': '::/0'}]
        new_rules = {'logical_port_egress_rules': egress_rules,
                     'logical_port_ingress_rules': [ingress_rule]}
        egress_rules_summarized = [
            {'ethertype': 'IPv4', 'protocol': constants.PROTO_NUM_UDP},
            {'ethertype': 'IPv6', 'protocol': constants.PROTO_NUM_UDP}]
        secgrouplib.update_security_group_rules(
            self.fake_cluster, sec_prof['uuid'], new_rules)
        sec_prof_res = nsxlib.do_request(
            nsxlib.HTTP_GET,
            nsxlib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])

        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 1)
        self.assertEqual(sec_prof_res['logical_port_egress_rules'],
                         egress_rules_summarized)
        self.assertIn(ingress_rule,
                      sec_prof_res['logical_port_ingress_rules'])

    def test_update_security_profile_rules_summarize_subset(self):
        sec_prof = secgrouplib.create_security_profile(
            self.fake_cluster, _uuid(), 'pippo', {'name': 'test'})
        ingress_rule = [{'ethertype': 'IPv4'}]
        egress_rules = [
            {'ethertype': 'IPv4', 'protocol': constants.PROTO_NUM_UDP,
             'port_range_min': 1, 'port_range_max': 1,
             'remote_ip_prefix': '1.1.1.1/20'},
            {'ethertype': 'IPv4', 'protocol': constants.PROTO_NUM_UDP,
             'port_range_min': 2, 'port_range_max': 2,
             'profile_uuid': 'xyz'},
            {'ethertype': 'IPv4', 'protocol': constants.PROTO_NUM_UDP}]
        new_rules = {'logical_port_egress_rules': egress_rules,
                     'logical_port_ingress_rules': [ingress_rule]}
        egress_rules_summarized = [
            {'ethertype': 'IPv4', 'protocol': constants.PROTO_NUM_UDP}]
        secgrouplib.update_security_group_rules(
            self.fake_cluster, sec_prof['uuid'], new_rules)
        sec_prof_res = nsxlib.do_request(
            nsxlib.HTTP_GET,
            nsxlib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])

        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 1)
        self.assertEqual(sec_prof_res['logical_port_egress_rules'],
                         egress_rules_summarized)
        self.assertIn(ingress_rule,
                      sec_prof_res['logical_port_ingress_rules'])

    def test_update_non_existing_securityprofile_raises(self):
        self.assertRaises(exceptions.NeutronException,
                          secgrouplib.update_security_group_rules,
                          self.fake_cluster, 'whatever',
                          {'logical_port_egress_rules': [],
                           'logical_port_ingress_rules': []})

    def test_delete_security_profile(self):
        sec_prof = secgrouplib.create_security_profile(
            self.fake_cluster, _uuid(), 'pippo', {'name': 'test'})
        secgrouplib.delete_security_profile(
            self.fake_cluster, sec_prof['uuid'])
        self.assertRaises(exceptions.NotFound,
                          nsxlib.do_request,
                          nsxlib.HTTP_GET,
                          nsxlib._build_uri_path(
                              'security-profile',
                              resource_id=sec_prof['uuid']),
                          cluster=self.fake_cluster)

    def test_delete_non_existing_securityprofile_raises(self):
        self.assertRaises(exceptions.NeutronException,
                          secgrouplib.delete_security_profile,
                          self.fake_cluster, 'whatever')
