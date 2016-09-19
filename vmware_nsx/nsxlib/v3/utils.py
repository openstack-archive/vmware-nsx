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

import retrying

from neutron import version as n_version
from neutron_lib import exceptions
from oslo_log import log

from vmware_nsx._i18n import _
from vmware_nsx.nsxlib.v3 import exceptions as nsxlib_exceptions

LOG = log.getLogger(__name__)

MAX_RESOURCE_TYPE_LEN = 20
MAX_TAG_LEN = 40
NSX_NEUTRON_PLUGIN = 'NSX Neutron plugin'
OS_NEUTRON_ID_SCOPE = 'os-neutron-id'
DEFAULT_MAX_ATTEMPTS = 10


def is_internal_resource(nsx_resource):
    """
    Indicates whether the passed nsx-resource is owned by the plugin for
    internal use.
    """
    for tag in nsx_resource.get('tags', []):
        if tag['scope'] == OS_NEUTRON_ID_SCOPE:
            return tag['tag'] == NSX_NEUTRON_PLUGIN
    return False


def build_v3_api_version_tag():
    """
    Some resources are created on the manager that do not have a corresponding
    Neutron resource.
    """
    return [{'scope': OS_NEUTRON_ID_SCOPE,
             'tag': NSX_NEUTRON_PLUGIN},
            {'scope': "os-api-version",
             'tag': n_version.version_info.release_string()}]


def _validate_resource_type_length(resource_type):
    # Add in a validation to ensure that we catch this at build time
    if len(resource_type) > MAX_RESOURCE_TYPE_LEN:
        raise exceptions.InvalidInput(
            error_message=(_('Resource type cannot exceed %(max_len)s '
                             'characters: %(resource_type)s') %
                           {'max_len': MAX_RESOURCE_TYPE_LEN,
                            'resource_type': resource_type}))


def build_v3_tags_payload(resource, resource_type, project_name):
    """
    Construct the tags payload that will be pushed to NSX-v3
    Add <resource_type>:<resource-id>, os-project-id:<tenant-id>,
    os-project-name:<project_name> os-api-version:<neutron-api-version>
    """
    _validate_resource_type_length(resource_type)
    # There may be cases when the plugin creates the port, for example DHCP
    if not project_name:
        project_name = NSX_NEUTRON_PLUGIN
    tenant_id = resource.get('tenant_id', '')
    # If tenant_id is present in resource and set to None, explicitly set
    # the tenant_id in tags as ''.
    if tenant_id is None:
        tenant_id = ''
    return [{'scope': resource_type,
             'tag': resource.get('id', '')[:MAX_TAG_LEN]},
            {'scope': 'os-project-id',
             'tag': tenant_id[:MAX_TAG_LEN]},
            {'scope': 'os-project-name',
             'tag': project_name[:MAX_TAG_LEN]},
            {'scope': 'os-api-version',
             'tag': n_version.version_info.release_string()[:MAX_TAG_LEN]}]


def add_v3_tag(tags, resource_type, tag):
    _validate_resource_type_length(resource_type)
    tags.append({'scope': resource_type, 'tag': tag[:MAX_TAG_LEN]})
    return tags


def update_v3_tags(current_tags, tags_update):
    current_scopes = set([tag['scope'] for tag in current_tags])
    updated_scopes = set([tag['scope'] for tag in tags_update])

    tags = [{'scope': tag['scope'], 'tag': tag['tag']}
            for tag in (current_tags + tags_update)
            if tag['scope'] in (current_scopes ^ updated_scopes)]

    modified_scopes = current_scopes & updated_scopes
    for tag in tags_update:
        if tag['scope'] in modified_scopes:
            # If the tag value is empty or None, then remove the tag completely
            if tag['tag']:
                tag['tag'] = tag['tag'][:MAX_TAG_LEN]
                tags.append(tag)

    return tags


def retry_upon_exception(exc, delay=500, max_delay=2000,
                         max_attempts=DEFAULT_MAX_ATTEMPTS):
    return retrying.retry(retry_on_exception=lambda e: isinstance(e, exc),
                          wait_exponential_multiplier=delay,
                          wait_exponential_max=max_delay,
                          stop_max_attempt_number=max_attempts)


def list_match(list1, list2):
    # Check if list1 and list2 have identical elements, but relaxed on
    # dict elements where list1's dict element can be a subset of list2's
    # corresponding element.
    if (not isinstance(list1, list) or
        not isinstance(list2, list) or
        len(list1) != len(list2)):
        return False
    list1 = sorted(list1)
    list2 = sorted(list2)
    for (v1, v2) in zip(list1, list2):
        if isinstance(v1, dict):
            if not dict_match(v1, v2):
                return False
        elif isinstance(v1, list):
            if not list_match(v1, v2):
                return False
        elif v1 != v2:
            return False
    return True


def dict_match(dict1, dict2):
    # Check if dict1 is a subset of dict2.
    if not isinstance(dict1, dict) or not isinstance(dict2, dict):
        return False
    for k1, v1 in dict1.items():
        if k1 not in dict2:
            return False
        v2 = dict2[k1]
        if isinstance(v1, dict):
            if not dict_match(v1, v2):
                return False
        elif isinstance(v1, list):
            if not list_match(v1, v2):
                return False
        elif v1 != v2:
            return False
    return True


def get_name_and_uuid(name, uuid, tag=None, maxlen=80):
    short_uuid = '_' + uuid[:5] + '...' + uuid[-5:]
    maxlen = maxlen - len(short_uuid)
    if tag:
        maxlen = maxlen - len(tag) - 1
        return name[:maxlen] + '_' + tag + short_uuid
    else:
        return name[:maxlen] + short_uuid


class NsxLibApiBase(object):
    """Base class for nsxlib api """
    def __init__(self, client, max_attempts):
        self.client = client
        self.max_attempts = max_attempts
        super(NsxLibApiBase, self).__init__()

    def _update_resource_with_retry(self, resource, payload):
        #Using internal method so we can access max_attempts in the decorator
        @retry_upon_exception(nsxlib_exceptions.StaleRevision,
                             max_attempts=self.max_attempts)
        def do_update():
            revised_payload = self.client.get(resource)
            for key_name in payload.keys():
                revised_payload[key_name] = payload[key_name]
            return self.client.update(resource, revised_payload)

        return do_update()

    def _get_resource_by_name_or_id(self, name_or_id, resource):
        all_results = self.client.get(resource)['results']
        matched_results = []
        for rs in all_results:
            if rs.get('id') == name_or_id:
                # Matched by id - must be unique
                return name_or_id

            if rs.get('display_name') == name_or_id:
                # Matched by name - add to the list to verify it is unique
                matched_results.append(rs)

        if len(matched_results) == 0:
            err_msg = (_("Could not find %(resource)s %(name)s") %
                       {'name': name_or_id, 'resource': resource})
            # XXX improve exception handling...
            raise exceptions.ManagerError(details=err_msg)
        elif len(matched_results) > 1:
            err_msg = (_("Found multiple %(resource)s named %(name)s") %
                       {'name': name_or_id, 'resource': resource})
            # XXX improve exception handling...
            raise exceptions.ManagerError(details=err_msg)

        return matched_results[0].get('id')
