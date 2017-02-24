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
import xml.etree.ElementTree as et

import eventlet
import six
import tenacity

from neutron import version as n_version
from neutron_lib.api import validators
from neutron_lib import constants
from oslo_context import context as common_context
from oslo_log import log

from vmware_nsxlib.v3 import nsx_constants as v3_const

LOG = log.getLogger(__name__)

MAX_DISPLAY_NAME_LEN = 40
NEUTRON_VERSION = n_version.version_info.release_string()
OS_NEUTRON_ID_SCOPE = 'os-neutron-id'


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
            version.LooseVersion(v3_const.NSX_VERSION_1_1_0))


def is_nsx_version_2_0_0(nsx_version):
    return (version.LooseVersion(nsx_version) >=
            version.LooseVersion(v3_const.NSX_VERSION_2_0_0))


def is_nsx_version_2_1_0(nsx_version):
    return (version.LooseVersion(nsx_version) >=
            version.LooseVersion(v3_const.NSX_VERSION_2_1_0))


def is_nsxv_version_6_2(nsx_version):
    return (version.LooseVersion(nsx_version) >=
            version.LooseVersion('6.2'))


def is_nsxv_version_6_3(nsx_version):
    return (version.LooseVersion(nsx_version) >=
            version.LooseVersion('6.3'))


def is_nsxv_dhcp_binding_supported(nsx_version):
    return ((version.LooseVersion(nsx_version) >=
             version.LooseVersion('6.3.3')) or
            (version.LooseVersion(nsx_version) >=
             version.LooseVersion('6.2.8') and
             version.LooseVersion(nsx_version) <
             version.LooseVersion('6.3')))


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


def normalize_xml(data):
    data = data.encode('ascii', 'ignore')
    return et.fromstring(data)


def _get_bad_request_error_code(e):
    """Get the error code out of the exception"""
    try:
        desc = normalize_xml(e.response)
        return int(desc.find('errorCode').text)
    except Exception:
        pass


def retry_upon_exception_exclude_error_codes(
    exc, excluded_errors, delay, max_delay, max_attempts):
    """Retry with the configured exponential delay, unless the exception error
    code is in the given list
    """
    def retry_if_not_error_codes(e):
        # return True only for BadRequests without error codes or with error
        # codes not in the exclude list
        if isinstance(e, exc):
            error_code = _get_bad_request_error_code(e)
            if error_code and error_code not in excluded_errors:
                return True
        return False

    return tenacity.retry(reraise=True,
                          retry=tenacity.retry_if_exception(
                                retry_if_not_error_codes),
                          wait=tenacity.wait_exponential(
                                multiplier=delay, max=max_delay),
                          stop=tenacity.stop_after_attempt(max_attempts))


def retry_upon_exception(exc, delay, max_delay, max_attempts):
    return tenacity.retry(reraise=True,
                          retry=tenacity.retry_if_exception_type(exc),
                          wait=tenacity.wait_exponential(
                                multiplier=delay, max=max_delay),
                          stop=tenacity.stop_after_attempt(max_attempts))


def read_file(path):
    try:
        with open(path) as file:
            return file.read().strip()
    except IOError as e:
        LOG.error("Error while opening file "
                  "%(path)s: %(err)s", {'path': path, 'err': str(e)})


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
