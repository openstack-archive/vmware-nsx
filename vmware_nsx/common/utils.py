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

import hashlib

from neutron.api.v2 import attributes
from neutron.common import exceptions
from neutron import version
from oslo_config import cfg
from oslo_log import log
import retrying
import six

from vmware_nsx._i18n import _, _LE

LOG = log.getLogger(__name__)
MAX_DISPLAY_NAME_LEN = 40
NEUTRON_VERSION = version.version_info.release_string()


# Allowed network types for the NSX Plugin
class NetworkTypes:
    """Allowed provider network types for the NSX Plugin."""
    L3_EXT = 'l3_ext'
    STT = 'stt'
    GRE = 'gre'
    FLAT = 'flat'
    VLAN = 'vlan'
    BRIDGE = 'bridge'


# Allowed network types for the NSX-v Plugin
class NsxVNetworkTypes:
    """Allowed provider network types for the NSX-v Plugin."""
    FLAT = 'flat'
    VLAN = 'vlan'
    VXLAN = 'vxlan'
    PORTGROUP = 'portgroup'


# Allowed network types for the NSXv3 Plugin
class NsxV3NetworkTypes:
    """Allowed provider network types for the NSXv3 Plugin."""
    FLAT = 'flat'
    VLAN = 'vlan'
    VXLAN = 'vxlan'


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
    if (attributes.is_attr_set(display_name) and
            len(display_name) > MAX_DISPLAY_NAME_LEN):
        LOG.debug("Specified name:'%s' exceeds maximum length. "
                  "It will be truncated on NSX", display_name)
        return display_name[:MAX_DISPLAY_NAME_LEN]
    return display_name or ''


def build_v3_api_version_tag():
    """
    Some resources are created on the manager that do not have a corresponding
    Neutron resource.
    """
    return [{'scope': 'os-neutron-id',
             'tag': 'NSX neutron plug-in'},
            {'scope': "os-api-version",
             'tag': version.version_info.release_string()}]


def build_v3_tags_payload(resource, resource_type):
    """
    Construct the tags payload that will be pushed to NSX-v3
    Add os-project-id:<tenant-id>, os-api-version:<neutron-api-version>,
        os-neutron-id:<resource-id>
    """
    # Add in a validation to ensure that we catch this at build time
    if len(resource_type) > 20:
        raise exceptions.InvalidInput(
            error_message=_('scope cannot exceed 20 characters'))

    return [{'scope': resource_type,
             'tag': resource.get('id', '')},
            {'scope': 'os-project-id',
             'tag': resource.get('tenant_id', '')},
            {'scope': 'os-api-version',
             'tag': version.version_info.release_string()}]


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


def get_name_and_uuid(name, uuid, maxlen=80):
    # TODO(garyk):the second '_' should be '...'. Pending backend support
    short_uuid = '_' + uuid[:5] + '_' + uuid[-5:]
    maxlen = maxlen - len(short_uuid)
    return name[:maxlen] + short_uuid
