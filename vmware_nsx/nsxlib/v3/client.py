# Copyright 2015 VMware, Inc.
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
#
import requests

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils

from vmware_nsx._i18n import _LW, _
from vmware_nsx.common import exceptions as nsx_exc

LOG = log.getLogger(__name__)

ERRORS = {requests.codes.NOT_FOUND: nsx_exc.ResourceNotFound,
          requests.codes.PRECONDITION_FAILED: nsx_exc.StaleRevision}


class RESTClient(object):

    _VERB_RESP_CODES = {
        'get': [requests.codes.ok],
        'post': [requests.codes.created, requests.codes.ok],
        'put': [requests.codes.ok],
        'delete': [requests.codes.ok]
    }

    def __init__(self, host_ip=None, user_name=None,
                 password=None, insecure=None,
                 url_prefix=None, default_headers=None,
                 cert_file=None):
        self._host_ip = host_ip
        self._user_name = user_name
        self._password = password
        self._insecure = insecure if insecure is not None else False
        self._url_prefix = url_prefix or ""
        self._default_headers = default_headers or {}
        self._cert_file = cert_file

        self._session = requests.Session()
        self._session.auth = (self._user_name, self._password)
        if not insecure and self._cert_file:
            self._session.cert = self._cert_file

    def new_client_for(self, *uri_segments):
        uri = "%s/%s" % (self._url_prefix, '/'.join(uri_segments))
        uri = uri.replace('//', '/')

        return self.__class__(
            host_ip=self._host_ip, user_name=self._user_name,
            password=self._password, insecure=self._insecure,
            url_prefix=uri,
            default_headers=self._default_headers,
            cert_file=self._cert_file)

    @property
    def validate_certificate(self):
        return not self._insecure

    def list(self, headers=None):
        return self.url_list('')

    def get(self, uuid, headers=None):
        return self.url_get(uuid, headers=headers)

    def delete(self, uuid, headers=None):
        return self.url_delete(uuid, headers=headers)

    def update(self, uuid, body=None, headers=None):
        return self.url_put(uuid, body, headers=headers)

    def create(self, body=None, headers=None):
        return self.url_post('', body, headers=headers)

    def url_list(self, url, headers=None):
        return self.url_get(url, headers=headers)

    def url_get(self, url, headers=None):
        return self._rest_call(url, method='GET', headers=headers)

    def url_delete(self, url, headers=None):
        return self._rest_call(url, method='DELETE', headers=headers)

    def url_put(self, url, body, headers=None):
        return self._rest_call(url, method='PUT', body=body, headers=headers)

    def url_post(self, url, body, headers=None):
        return self._rest_call(url, method='POST', body=body, headers=headers)

    def _validate_result(self, result, expected, operation):
        if result.status_code not in expected:
            result_msg = result.json() if result.content else ''
            LOG.warning(_LW("The HTTP request returned error code "
                            "%(result)d, whereas %(expected)s response "
                            "codes were expected. Response body %(body)s"),
                        {'result': result.status_code,
                         'expected': '/'.join([str(code)
                                               for code in expected]),
                         'body': result_msg})

            manager_error = ERRORS.get(
                result.status_code, nsx_exc.ManagerError)
            if type(result_msg) is dict:
                result_msg = result_msg.get('error_message', result_msg)
            raise manager_error(
                manager=self._host_ip,
                operation=operation,
                details=result_msg)

    @classmethod
    def merge_headers(cls, *headers):
        merged = {}
        for header in headers:
            if header:
                merged.update(header)
        return merged

    def _build_url(self, uri):
        uri = ("/%s/%s" % (self._url_prefix, uri)).replace('//', '/')
        return ("https://%s%s" % (self._host_ip, uri)).strip('/')

    def _rest_call(self, url, method='GET', body=None, headers=None):
        request_headers = headers.copy() if headers else {}
        request_headers.update(self._default_headers)
        request_url = self._build_url(url)

        do_request = getattr(self._session, method.lower())

        LOG.debug("REST call: %s %s\nHeaders: %s\nBody: %s",
                  method, request_url, request_headers, body)

        result = do_request(
            request_url,
            verify=self.validate_certificate,
            data=body,
            headers=request_headers,
            cert=self._cert_file)

        self._validate_result(
            result, RESTClient._VERB_RESP_CODES[method.lower()],
            _("%(verb)s %(url)s") % {'verb': method, 'url': request_url})
        return result


class JSONRESTClient(RESTClient):

    _DEFAULT_HEADERS = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    def __init__(self, host_ip=None, user_name=None,
                 password=None, insecure=None,
                 url_prefix=None, default_headers=None,
                 cert_file=None):

        super(JSONRESTClient, self).__init__(
            host_ip=host_ip, user_name=user_name,
            password=password, insecure=insecure,
            url_prefix=url_prefix,
            default_headers=RESTClient.merge_headers(
                JSONRESTClient._DEFAULT_HEADERS, default_headers),
            cert_file=cert_file)

    def _rest_call(self, *args, **kwargs):
        if kwargs.get('body') is not None:
            kwargs['body'] = jsonutils.dumps(kwargs['body'], sort_keys=True)
        result = super(JSONRESTClient, self)._rest_call(*args, **kwargs)
        return result.json() if result.content else result


class NSX3Client(JSONRESTClient):

    _NSX_V1_API_PREFIX = '/api/v1/'

    def __init__(self, host_ip=None, user_name=None,
                 password=None, insecure=None,
                 url_prefix=None, default_headers=None,
                 cert_file=None):

        url_prefix = url_prefix or NSX3Client._NSX_V1_API_PREFIX
        if (url_prefix and not url_prefix.startswith(
                NSX3Client._NSX_V1_API_PREFIX)):
            url_prefix = "%s/%s" % (NSX3Client._NSX_V1_API_PREFIX,
                                    url_prefix or '')
        host_ip = host_ip or cfg.CONF.nsx_v3.nsx_manager
        user_name = user_name or cfg.CONF.nsx_v3.nsx_user
        password = password or cfg.CONF.nsx_v3.nsx_password
        cert_file = cert_file or cfg.CONF.nsx_v3.ca_file
        insecure = (insecure if insecure is not None
                    else cfg.CONF.nsx_v3.insecure)

        super(NSX3Client, self).__init__(
            host_ip=host_ip, user_name=user_name,
            password=password, insecure=insecure,
            url_prefix=url_prefix,
            default_headers=default_headers,
            cert_file=cert_file)


# NOTE(boden): tmp until all refs use client class
def _get_client(client, *args, **kwargs):
    return client or NSX3Client(*args, **kwargs)


# NOTE(shihli): tmp until all refs use client class
def _get_manager_ip(client=None):
    # NOTE: In future this may return the IP address from a pool
    return (client._host_ip if client is not None
            else cfg.CONF.nsx_v3.nsx_manager)


# NOTE(boden): tmp until all refs use client class
def get_resource(resource, client=None):
    return _get_client(client).get(resource)


# NOTE(boden): tmp until all refs use client class
def create_resource(resource, data, client=None):
    return _get_client(client).url_post(resource, body=data)


# NOTE(boden): tmp until all refs use client class
def update_resource(resource, data, client=None):
    return _get_client(client).update(resource, body=data)


# NOTE(boden): tmp until all refs use client class
def delete_resource(resource, client=None):
    return _get_client(client).delete(resource)
