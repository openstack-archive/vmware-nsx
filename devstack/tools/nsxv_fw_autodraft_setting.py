#!/usr/bin/env python
# Copyright 2016 VMware Inc
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

"""
Purpose: Configure distributed firewall autodraft setting

Usage:
    python nsxv_fw_autodraft_setting.py --vsm-ip <nsx-manager-ip>
                                  --username <nsx-manager-username>
                                  --password <nsx-manager-password>
                                  [--autodraft-disable]
                                  [--autodraft-enable]
"""

import base64
import optparse

from oslo_serialization import jsonutils
import requests

requests.packages.urllib3.disable_warnings()


GLOBAL_CONFIG_URI = 'api/4.0/firewall/config/globalconfiguration'
AUTO_DRAFT_DISABLED = 'autoDraftDisabled'


class NSXClient(object):

    def __init__(self, host, username, password, *args, **kwargs):
        self._host = host
        self._username = username
        self._password = password

    def _get_headers(self, format):
        auth_cred = self._username + ":" + self._password
        auth = base64.b64encode(auth_cred)
        headers = {}
        headers['Authorization'] = "Basic %s" % auth
        headers['Content-Type'] = "application/%s" % format
        headers['Accept'] = "application/%s" % format
        return headers

    def _get_url(self, uri):
        return 'https://%s/%s' % (self._host, uri)

    def _get(self, format, uri):
        headers = self._get_headers(format)
        url = self._get_url(uri)
        response = requests.get(url, headers=headers,
                                verify=False)
        return response

    def _put(self, format, uri, data):
        headers = self._get_headers(format)
        url = self._get_url(uri)
        response = requests.put(url, headers=headers,
                                verify=False, data=data)
        return response

    def disable_autodraft(self):
        self._set_autodraft(True)

    def enable_autodraft(self):
        self._set_autodraft(False)

    def _get_global_config(self):
        resp = self._get('json', GLOBAL_CONFIG_URI)
        global_conf = jsonutils.loads(resp.text)
        return global_conf

    def _set_autodraft(self, disabled):
        global_conf = self._get_global_config()
        global_conf[AUTO_DRAFT_DISABLED] = disabled
        self._put('json', GLOBAL_CONFIG_URI, jsonutils.dumps(global_conf))


if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("--vsm-ip", dest="vsm_ip", help="NSX Manager IP address")
    parser.add_option("-u", "--username", default="admin", dest="username",
                      help="NSX Manager username")
    parser.add_option("-p", "--password", default="default", dest="password",
                      help="NSX Manager password")
    parser.add_option("--disable-autodraft", action="store_true",
                      default=False, dest="disabled",
                      help="Disable the autodraft setting for NSX "
                      "distributed firewal.")
    parser.add_option("--enable-autodraft", action="store_true",
                      default=False, dest="enabled",
                      help="Enable the autodraft setting for NSX "
                      "distributed firewal.")
    (options, args) = parser.parse_args()
    print("vsm-ip: %s" % options.vsm_ip)
    print("username: %s" % options.username)
    print("password: %s" % options.password)

    if options.disabled and options.enabled:
        print("Please provide only one of the options: --disable-autodraft, "
              "--enable-autodraft.")

    nsx_client = NSXClient(options.vsm_ip, options.username,
                           options.password)
    if options.disabled:
        print("Disabling autodraft settings:")
        nsx_client.disable_autodraft()
        print("Autodraft is now disabled.")
    if options.enabled:
        print("Enabling autodraft settings:")
        nsx_client.enable_autodraft()
        print("Autodraft is now enabled.")
