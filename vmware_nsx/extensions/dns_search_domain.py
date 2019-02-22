# Copyright 2016 VMware, Inc.  All rights reserved.
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

import re

from neutron_lib.api import extensions
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib.db import constants as db_const

from vmware_nsx._i18n import _

DNS_LABEL_MAX_LEN = 63
DNS_LABEL_REGEX = "[a-zA-Z0-9-]{1,%d}$" % DNS_LABEL_MAX_LEN


def _validate_dns_format(data):
    if not data:
        return
    try:
        # Allow values ending in period '.'
        trimmed = data if not data.endswith('.') else data[:-1]
        names = trimmed.split('.')
        for name in names:
            if not name:
                raise TypeError(_("Encountered an empty component"))
            if name.endswith('-') or name[0] == '-':
                raise TypeError(
                    _("Name '%s' must not start or end with a hyphen") % name)
            if not re.match(DNS_LABEL_REGEX, name):
                raise TypeError(
                    _("Name '%s' must be 1-63 characters long, each of "
                      "which can only be alphanumeric or a hyphen") % name)
        # RFC 1123 hints that a TLD can't be all numeric. last is a TLD if
        # it's an FQDN.
        if len(names) > 1 and re.match("^[0-9]+$", names[-1]):
            raise TypeError(_("TLD '%s' must not be all numeric") % names[-1])
    except TypeError as e:
        msg = _("'%(data)s' not a valid DNS search domain. Reason: "
                "%(reason)s") % {'data': data, 'reason': str(e)}
        return msg


def _validate_dns_search_domain(data, max_len=db_const.NAME_FIELD_SIZE):
    msg = validators.validate_string(data, max_len)
    if msg:
        return msg
    if not data:
        return
    msg = _validate_dns_format(data)
    if msg:
        return msg


validators.add_validator('dns_search_domain', _validate_dns_search_domain)


ALIAS = 'dns-search-domain'
DNS_SEARCH_DOMAIN = 'dns_search_domain'
EXTENDED_ATTRIBUTES_2_0 = {
    'subnets': {
        DNS_SEARCH_DOMAIN: {
            'allow_post': True, 'allow_put': True,
            'default': constants.ATTR_NOT_SPECIFIED,
            'validate': {'type:dns_search_domain': db_const.NAME_FIELD_SIZE},
            'is_visible': True},
    }
}


class Dns_search_domain(extensions.ExtensionDescriptor):
    """Extension class supporting dns search domains for subnets."""

    @classmethod
    def get_name(cls):
        return "DNS search Domains"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return "Enable the ability to add DNS search domain name for Subnets"

    @classmethod
    def get_updated(cls):
        return "2016-1-22T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        return {}
