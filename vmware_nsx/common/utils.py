# Copyright 2013 VMware, Inc.
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

from distutils import version
import functools
import hashlib

import eventlet
from neutron import version as n_version
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib import exceptions
from oslo_config import cfg
from oslo_context import context as common_context
from oslo_log import log
import retrying
import six
import xml.etree.ElementTree as et

from vmware_nsx._i18n import _, _LE

LOG = log.getLogger(__name__)

MAX_DISPLAY_NAME_LEN = 40
MAX_RESOURCE_TYPE_LEN = 20
MAX_TAG_LEN = 40
NEUTRON_VERSION = n_version.version_info.release_string()
NSX_NEUTRON_PLUGIN = 'NSX Neutron plugin'
OS_NEUTRON_ID_SCOPE = 'os-neutron-id'
NSXV3_VERSION_1_1_0 = '1.1.0'


# Allowed network types for the NSX Plugin
class NetworkTypes(object):
    """Allowed provider network types for the NSX Plugin."""
    L3_EXT = 'l3_ext'
    STT = 'stt'
    GRE = 'gre'
    FLAT = 'flat'
    VLAN = 'vlan'
    BRIDGE = 'bridge'
    PORTGROUP = 'portgroup'


# Allowed network types for the NSX-v Plugin
class NsxVNetworkTypes(object):
    """Allowed provider network types for the NSX-v Plugin."""
    FLAT = 'flat'
    VLAN = 'vlan'
    VXLAN = 'vxlan'
    PORTGROUP = 'portgroup'


# Allowed network types for the NSXv3 Plugin
class NsxV3NetworkTypes(object):
    """Allowed provider network types for the NSXv3 Plugin."""
    FLAT = 'flat'
    VLAN = 'vlan'
    VXLAN = 'vxlan'


def is_nsx_version_1_1_0(nsx_version):
    return (version.LooseVersion(nsx_version) >=
            version.LooseVersion(NSXV3_VERSION_1_1_0))


def is_nsxv_version_6_2(nsx_version):
    return (version.LooseVersion(nsx_version) >=
            version.LooseVersion('6.2'))


def get_tags(**kwargs):
    tags = ([dict(tag=value, scope=key)
            for key, value in six.iteritems(kwargs)])
    tags.append({"tag": NEUTRON_VERSION, "scope": "quantum"})
    return sorted(tags, key=lambda x: x['tag'])


def device_id_to_vm_id(device_id, obfuscate=False):
    # device_id can be longer than 40 characters, for example
    # a device_id for a dhcp port is like the following:
    #
    # dhcp83b5fdeb-e3b4-5e18-ac5f-55161...80747326-47d7-46c2-a87a-cf6d5194877c
    #
    # To fit it into an NSX tag we need to hash it, however device_id
    # used for ports associated to VM's are small enough so let's skip the
    # hashing
    if len(device_id) > MAX_DISPLAY_NAME_LEN or obfuscate:
        return hashlib.sha1(device_id.encode()).hexdigest()
    else:
        return device_id or "N/A"


def check_and_truncate(display_name):
    if (validators.is_attr_set(display_name) and
            len(display_name) > MAX_DISPLAY_NAME_LEN):
        LOG.debug("Specified name:'%s' exceeds maximum length. "
                  "It will be truncated on NSX", display_name)
        return display_name[:MAX_DISPLAY_NAME_LEN]
    return display_name or ''


def is_internal_resource(nsx_resource):
    """
    Indicates whether the passed nsx-resource is owned by the plugin for
    internal use.
    """
    for tag in nsx_resource.get('tags', []):
        if tag['scope'] == OS_NEUTRON_ID_SCOPE:
            return tag['tag'] == NSX_NEUTRON_PLUGIN
    return False


def normalize_xml(data):
    data = data.encode('ascii', 'ignore')
    return et.fromstring(data)


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
        project_name = 'NSX Neutron plugin'
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

    # All tags scopes which are either completley new or arleady defined on the
    # resource are left in place, unless the tag value is empty, in that case
    # it is ignored.
    tags = [{'scope': tag['scope'], 'tag': tag['tag']}
            for tag in (current_tags + tags_update)
            if tag['tag'] and
            tag['scope'] in (current_scopes ^ updated_scopes)]

    modified_scopes = current_scopes & updated_scopes
    for tag in tags_update:
        if tag['scope'] in modified_scopes:
            # If the tag value is empty or None, then remove the tag completely
            if tag['tag']:
                tag['tag'] = tag['tag'][:MAX_TAG_LEN]
                tags.append(tag)

    return tags


def retry_upon_exception_nsxv3(exc, delay=500, max_delay=2000,
                               max_attempts=cfg.CONF.nsx_v3.retries):
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


def read_file(path):
    try:
        with open(path) as file:
            return file.read().strip()
    except IOError as e:
        LOG.error(_LE("Error while opening file "
                      "%(path)s: %(err)s"), {'path': path, 'err': str(e)})


def get_name_and_uuid(name, uuid, tag=None, maxlen=80):
    short_uuid = '_' + uuid[:5] + '...' + uuid[-5:]
    maxlen = maxlen - len(short_uuid)
    if tag:
        maxlen = maxlen - len(tag) - 1
        return name[:maxlen] + '_' + tag + short_uuid
    else:
        return name[:maxlen] + short_uuid


def is_ipv4_ip_address(addr):

    def _valid_part(part):
        try:
            int_part = int(part)
            if int_part < 0 or int_part > 255:
                return False
            return True
        except ValueError:
            return False

    parts = str(addr).split('.')
    if len(parts) != 4:
        return False

    for ip_part in parts:
        if not _valid_part(ip_part):
            return False
    return True


def is_port_dhcp_configurable(port):
    owner = port.get('device_owner')
    return (owner and
            not owner.startswith(constants.DEVICE_OWNER_NETWORK_PREFIX))


def spawn_n(func, *args, **kwargs):
    """Passthrough method for eventlet.spawn_n.

    This utility exists so that it can be stubbed for testing without
    interfering with the service spawns.

    It will also grab the context from the threadlocal store and add it to
    the store on the new thread.  This allows for continuity in logging the
    context when using this method to spawn a new thread.
    """
    _context = common_context.get_current()

    @functools.wraps(func)
    def context_wrapper(*args, **kwargs):
        # NOTE: If update_store is not called after spawn_n it won't be
        # available for the logger to pull from threadlocal storage.
        if _context is not None:
            _context.update_store()
        func(*args, **kwargs)

    eventlet.spawn_n(context_wrapper, *args, **kwargs)
