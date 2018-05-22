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
import os
import xml.etree.ElementTree as et

from oslo_context import context as context_utils
from oslo_serialization import jsonutils
import requests
import six

from vmware_nsx.plugins.nsx_v.vshield.common import exceptions


def _xmldump(obj):
    """Sort of improved xml creation method.

    This converts the dict to xml with following assumptions:
    Keys starting with _(underscore) are to be used as attributes and not
    element keys starting with @ so that dict can be made.
    Keys starting with __(double underscore) are to be skipped and its
    value is processed.
    The keys are not part of any xml schema.
    """

    config = ""
    attr = ""
    if isinstance(obj, dict):
        for key, value in six.iteritems(obj):
            if key.startswith('__'):
                # Skip the key and evaluate it's value.
                a, x = _xmldump(value)
                config += x
            elif key.startswith('_'):
                attr += ' %s="%s"' % (key[1:], value)
            else:
                a, x = _xmldump(value)
                if key.startswith('@'):
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

    nsx_errors = {
        # firewall rule doesn't exists for deletion.
        100046: exceptions.ResourceNotFound,
        100029: exceptions.ResourceNotFound,
    }

    def __init__(self, address, user, password, format='json', ca_file=None,
                 insecure=True, timeout=None):
        # pylint: disable=deprecated-method
        encode_fn = base64.encodestring if six.PY2 else base64.encodebytes
        self.authToken = encode_fn(six.b("%s:%s" % (user, password)))
        self.user = user
        self.passwd = password
        self.address = address
        self.format = format
        self.timeout = timeout
        if format == 'json':
            self.encode = jsonutils.dumps
        else:
            self.encode = xmldumps

        if insecure:
            self.verify_cert = False
        else:
            if ca_file:
                self.verify_cert = ca_file
            else:
                self.verify_cert = True
        self._session = None
        self._pid = None

    @property
    def session(self):
        if self._session is None or self._pid != os.getpid():
            self._pid = os.getpid()
            self._session = requests.Session()
        return self._session

    def _get_nsx_errorcode(self, content):
        try:
            if self.format == 'xml':
                error = et.fromstring(content).find('errorCode')
                errcode = error is not None and int(error.text)
            else:  # json
                error = jsonutils.loads(content)
                errcode = int(error.get('errorCode'))
            return errcode
        except (TypeError, ValueError, et.ParseError):
            # We won't assume that integer error-code value is guaranteed.
            return None

    def _get_request_id(self):
        ctx = context_utils.get_current()
        if ctx:
            return ctx.__dict__.get('request_id')

    def request(self, method, uri, params=None, headers=None,
                encodeparams=True, timeout=None):
        uri = self.address + uri
        if timeout is None:
            timeout = self.timeout
        if headers is None:
            headers = {}

        auth_token = self.authToken.decode('ascii').strip()
        headers['Accept'] = 'application/' + self.format
        headers['Authorization'] = 'Basic ' + auth_token
        headers['Content-Type'] = 'application/' + self.format
        request_id = self._get_request_id()
        if request_id:
            headers['TicketNumber'] = request_id

        if params:
            if encodeparams is True:
                data = self.encode(params)
            else:
                data = params
        else:
            data = None

        try:
            response = self.session.request(method,
                                            uri,
                                            verify=self.verify_cert,
                                            data=data,
                                            headers=headers,
                                            timeout=timeout)
        except requests.exceptions.Timeout:
            raise exceptions.ResourceTimedOut(uri=uri)

        status = response.status_code

        if 200 <= status < 300:
            return response.headers, response.text

        nsx_errcode = self._get_nsx_errorcode(response.text)
        if nsx_errcode in self.nsx_errors:
            cls = self.nsx_errors[nsx_errcode]
        elif status in self.errors:
            cls = self.errors[status]
        else:
            cls = exceptions.VcnsApiException
        raise cls(uri=uri, status=status,
                  header=response.headers, response=response.text)
