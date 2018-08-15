#!/usr/bin/env python
# Copyright 2015 VMware Inc
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
Purpose: Configure edge resource limits

Usage:
    python nsxv_edge_resources.py --vsm-ip <nsx-manager-ip>
                                  --username <nsx-manager-username>
                                  --password <nsx-manager-password>
"""

import base64
import optparse
import xml.etree.ElementTree as et

from oslo_serialization import jsonutils
import requests
import six

requests.packages.urllib3.disable_warnings()


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

    def _get_tuning_configuration(self):
        response = self._get("json",
                             "/api/4.0/edgePublish/tuningConfiguration")
        return jsonutils.loads(response.text)

    def configure_reservations(self):
        config = self._get_tuning_configuration()
        # NSX only receive XML format for the resource allocation update
        tuning = et.Element('tuningConfiguration')
        for opt, val in six.iteritems(config):
            child = et.Element(opt)
            if (opt == 'edgeVCpuReservationPercentage' or
                opt == 'edgeMemoryReservationPercentage'):
                child.text = '0'
            elif opt == 'megaHertzPerVCpu':
                child.text = '1500'
            else:
                child.text = str(val)
            tuning.append(child)
        self._put("xml",
                  "/api/4.0/edgePublish/tuningConfiguration",
                  et.tostring(tuning))
        print("Edge resource limits set")


if __name__ == "__main__":

    parser = optparse.OptionParser()
    parser.add_option("--vsm-ip", dest="vsm_ip", help="NSX Manager IP address")
    parser.add_option("-u", "--username", default="admin", dest="username",
                      help="NSX Manager username")
    parser.add_option("-p", "--password", default="default", dest="password",
                      help="NSX Manager password")
    (options, args) = parser.parse_args()
    print("vsm-ip: %s" % options.vsm_ip)
    print("username: %s" % options.username)
    print("password: %s" % options.password)

    nsx_client = NSXClient(options.vsm_ip, options.username,
                           options.password)
    nsx_client.configure_reservations()
