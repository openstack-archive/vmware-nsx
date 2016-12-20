# Copyright 2013 VMware, Inc
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

import base64

import eventlet
from oslo_serialization import jsonutils
import six

from vmware_nsx.plugins.nsx_v.vshield.common import exceptions

httplib2 = eventlet.import_patched('httplib2')


def _xmldump(obj):
    """Sort of improved xml creation method.

    This converts the dict to xml with following assumptions:
    Keys starting with _(underscore) are to be used as attributes and not
    element keys starting with @ so that dict can be made.
    The keys are not part of any xml schema.
    """

    config = ""
    attr = ""
    if isinstance(obj, dict):
        for key, value in six.iteritems(obj):
            if (key.startswith('_')):
                attr += ' %s="%s"' % (key[1:], value)
            else:
                a, x = _xmldump(value)
                if (key.startswith('@')):
                    cfg = "%s" % (x)
                else:
                    cfg = "<%s%s>%s</%s>" % (key, a, x, key)

                config += cfg
    elif isinstance(obj, list):
        for value in obj:
            a, x = _xmldump(value)
            attr += a
            config += x
    else:
        config = obj

    return attr, config


def xmldumps(obj):
    attr, xml = _xmldump(obj)
    return xml


class VcnsApiHelper(object):
    errors = {
        303: exceptions.ResourceRedirect,
        400: exceptions.RequestBad,
        403: exceptions.Forbidden,
        404: exceptions.ResourceNotFound,
        409: exceptions.ServiceConflict,
        415: exceptions.MediaTypeUnsupport,
        503: exceptions.ServiceUnavailable
    }

    def __init__(self, address, user, password, format='json', ca_file=None,
                 insecure=True):
        self.authToken = base64.encodestring(six.b("%s:%s" % (user, password)))
        self.user = user
        self.passwd = password
        self.address = address
        self.format = format
        if format == 'json':
            self.encode = jsonutils.dumps
        else:
            self.encode = xmldumps
        self.ca_file = ca_file
        self.insecure = insecure

    def request(self, method, uri, params=None, headers=None,
                encodeparams=True):
        uri = self.address + uri
        http = httplib2.Http()
        if self.ca_file is not None:
            http.ca_certs = self.ca_file
            http.disable_ssl_certificate_validation = False
        else:
            http.disable_ssl_certificate_validation = self.insecure
        if headers is None:
            headers = {}

        headers['Content-Type'] = 'application/' + self.format
        headers['Accept'] = 'application/' + self.format,
        headers['Authorization'] = 'Basic ' + self.authToken

        if encodeparams is True:
            body = self.encode(params) if params else None
        else:
            body = params if params else None
        header, response = http.request(uri, method,
                                        body=body, headers=headers)
        status = int(header['status'])
        if 200 <= status < 300:
            return header, response
        if status in self.errors:
            cls = self.errors[status]
        else:
            cls = exceptions.VcnsApiException
        raise cls(uri=uri, status=status, header=header, response=response)
