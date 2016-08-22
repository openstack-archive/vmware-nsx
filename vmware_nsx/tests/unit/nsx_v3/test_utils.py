# Copyright (c) 2015 OpenStack Foundation.
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

from neutron import version
from neutron_lib import exceptions as n_exc

from vmware_nsx.common import utils
from vmware_nsx.tests.unit.nsx_v3 import test_plugin


class TestNsxV3Utils(test_plugin.NsxV3PluginTestCaseMixin):

    def test_build_v3_tags_payload(self):
        result = utils.build_v3_tags_payload(
            {'id': 'fake_id',
             'tenant_id': 'fake_tenant_id'},
            resource_type='os-neutron-net-id',
            project_name='fake_tenant_name')
        expected = [{'scope': 'os-neutron-net-id', 'tag': 'fake_id'},
                    {'scope': 'os-project-id', 'tag': 'fake_tenant_id'},
                    {'scope': 'os-project-name', 'tag': 'fake_tenant_name'},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()}]
        self.assertEqual(expected, result)

    def test_build_v3_tags_payload_internal(self):
        result = utils.build_v3_tags_payload(
            {'id': 'fake_id',
             'tenant_id': 'fake_tenant_id'},
            resource_type='os-neutron-net-id',
            project_name=None)
        expected = [{'scope': 'os-neutron-net-id', 'tag': 'fake_id'},
                    {'scope': 'os-project-id', 'tag': 'fake_tenant_id'},
                    {'scope': 'os-project-name', 'tag': 'NSX Neutron plugin'},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()}]
        self.assertEqual(expected, result)

    def test_build_v3_tags_payload_invalid_length(self):
        self.assertRaises(n_exc.InvalidInput,
                          utils.build_v3_tags_payload,
                          {'id': 'fake_id',
                           'tenant_id': 'fake_tenant_id'},
                          resource_type='os-neutron-maldini-rocks-id',
                          project_name='fake')

    def test_build_v3_api_version_tag(self):
        result = utils.build_v3_api_version_tag()
        expected = [{'scope': 'os-neutron-id',
                     'tag': 'NSX Neutron plugin'},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()}]
        self.assertEqual(expected, result)

    def test_is_internal_resource(self):
        project_tag = utils.build_v3_tags_payload(
            {'id': 'fake_id',
             'tenant_id': 'fake_tenant_id'},
            resource_type='os-neutron-net-id',
            project_name=None)
        internal_tag = utils.build_v3_api_version_tag()

        expect_false = utils.is_internal_resource({'tags': project_tag})
        self.assertFalse(expect_false)

        expect_true = utils.is_internal_resource({'tags': internal_tag})
        self.assertTrue(expect_true)

    def test_get_name_and_uuid(self):
        uuid = 'afc40f8a-4967-477e-a17a-9d560d1786c7'
        suffix = '_afc40...786c7'
        expected = 'maldini%s' % suffix
        short_name = utils.get_name_and_uuid('maldini', uuid)
        self.assertEqual(expected, short_name)

        name = 'X' * 255
        expected = '%s%s' % ('X' * (80 - len(suffix)), suffix)
        short_name = utils.get_name_and_uuid(name, uuid)
        self.assertEqual(expected, short_name)

    def test_build_v3_tags_max_length_payload(self):
        result = utils.build_v3_tags_payload(
            {'id': 'X' * 255,
             'tenant_id': 'X' * 255},
            resource_type='os-neutron-net-id',
            project_name='X' * 255)
        expected = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-name', 'tag': 'X' * 40},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()}]
        self.assertEqual(expected, result)

    def test_add_v3_tag(self):
        result = utils.add_v3_tag([], 'fake-scope', 'fake-tag')
        expected = [{'scope': 'fake-scope', 'tag': 'fake-tag'}]
        self.assertEqual(expected, result)

    def test_add_v3_tag_max_length_payload(self):
        result = utils.add_v3_tag([], 'fake-scope', 'X' * 255)
        expected = [{'scope': 'fake-scope', 'tag': 'X' * 40}]
        self.assertEqual(expected, result)

    def test_add_v3_tag_invalid_scope_length(self):
        self.assertRaises(n_exc.InvalidInput,
                          utils.add_v3_tag,
                          [],
                          'fake-scope-name-is-far-too-long',
                          'fake-tag')

    def test_update_v3_tags_addition(self):
        tags = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                {'scope': 'os-project-id', 'tag': 'Y' * 40},
                {'scope': 'os-project-name', 'tag': 'Z' * 40},
                {'scope': 'os-api-version',
                 'tag': version.version_info.release_string()}]
        resources = [{'scope': 'os-instance-uuid',
                      'tag': 'A' * 40}]
        tags = utils.update_v3_tags(tags, resources)
        expected = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-id', 'tag': 'Y' * 40},
                    {'scope': 'os-project-name', 'tag': 'Z' * 40},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()},
                    {'scope': 'os-instance-uuid',
                     'tag': 'A' * 40}]
        self.assertEqual(sorted(expected, key=lambda x: x.get('tag')),
                         sorted(tags, key=lambda x: x.get('tag')))

    def test_update_v3_tags_removal(self):
        tags = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                {'scope': 'os-project-id', 'tag': 'Y' * 40},
                {'scope': 'os-project-name', 'tag': 'Z' * 40},
                {'scope': 'os-api-version',
                 'tag': version.version_info.release_string()}]
        resources = [{'scope': 'os-neutron-net-id',
                      'tag': ''}]
        tags = utils.update_v3_tags(tags, resources)
        expected = [{'scope': 'os-project-id', 'tag': 'Y' * 40},
                    {'scope': 'os-project-name', 'tag': 'Z' * 40},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()}]
        self.assertEqual(sorted(expected, key=lambda x: x.get('tag')),
                         sorted(tags, key=lambda x: x.get('tag')))

    def test_update_v3_tags_update(self):
        tags = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                {'scope': 'os-project-id', 'tag': 'Y' * 40},
                {'scope': 'os-project-name', 'tag': 'Z' * 40},
                {'scope': 'os-api-version',
                 'tag': version.version_info.release_string()}]
        resources = [{'scope': 'os-project-id',
                      'tag': 'A' * 40}]
        tags = utils.update_v3_tags(tags, resources)
        expected = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-id', 'tag': 'A' * 40},
                    {'scope': 'os-project-name', 'tag': 'Z' * 40},
                    {'scope': 'os-api-version',
                     'tag': version.version_info.release_string()}]
        self.assertEqual(sorted(expected, key=lambda x: x.get('tag')),
                         sorted(tags, key=lambda x: x.get('tag')))

    def test_update_v3_tags_repetitive_scopes(self):
        tags = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                {'scope': 'os-project-id', 'tag': 'Y' * 40},
                {'scope': 'os-project-name', 'tag': 'Z' * 40},
                {'scope': 'os-security-group', 'tag': 'SG1'},
                {'scope': 'os-security-group', 'tag': 'SG2'}]
        tags_update = [{'scope': 'os-security-group', 'tag': 'SG3'},
                       {'scope': 'os-security-group', 'tag': 'SG4'}]
        tags = utils.update_v3_tags(tags, tags_update)
        expected = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-id', 'tag': 'Y' * 40},
                    {'scope': 'os-project-name', 'tag': 'Z' * 40},
                    {'scope': 'os-security-group', 'tag': 'SG3'},
                    {'scope': 'os-security-group', 'tag': 'SG4'}]
        self.assertEqual(sorted(expected, key=lambda x: x.get('tag')),
                         sorted(tags, key=lambda x: x.get('tag')))

    def test_update_v3_tags_repetitive_scopes_remove(self):
        tags = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                {'scope': 'os-project-id', 'tag': 'Y' * 40},
                {'scope': 'os-project-name', 'tag': 'Z' * 40},
                {'scope': 'os-security-group', 'tag': 'SG1'},
                {'scope': 'os-security-group', 'tag': 'SG2'}]
        tags_update = [{'scope': 'os-security-group', 'tag': None}]
        tags = utils.update_v3_tags(tags, tags_update)
        expected = [{'scope': 'os-neutron-net-id', 'tag': 'X' * 40},
                    {'scope': 'os-project-id', 'tag': 'Y' * 40},
                    {'scope': 'os-project-name', 'tag': 'Z' * 40}]
        self.assertEqual(sorted(expected, key=lambda x: x.get('tag')),
                         sorted(tags, key=lambda x: x.get('tag')))
