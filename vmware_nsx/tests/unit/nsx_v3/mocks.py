# Copyright (c) 2015 VMware, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import requests
import six.moves.urllib.parse as urlparse

from oslo_serialization import jsonutils
from oslo_utils import uuidutils
from vmware_nsx.common import nsx_constants


FAKE_NAME = "fake_name"
DEFAULT_TIER0_ROUTER_UUID = "efad0078-9204-4b46-a2d8-d4dd31ed448f"
NSX_BRIDGE_CLUSTER_NAME = 'default bridge cluster'
FAKE_MANAGER = "fake_manager_ip"


def make_fake_switch(switch_uuid=None, tz_uuid=None, name=FAKE_NAME):
    if not switch_uuid:
        switch_uuid = uuidutils.generate_uuid()
    if not tz_uuid:
        tz_uuid = uuidutils.generate_uuid()

    fake_switch = {
        "id": switch_uuid,
        "display_name": name,
        "resource_type": "LogicalSwitch",
        "address_bindings": [],
        "transport_zone_id": tz_uuid,
        "replication_mode": nsx_constants.MTEP,
        "admin_state": nsx_constants.ADMIN_STATE_UP,
        "vni": 50056,
        "switching_profile_ids": [
            {
                "value": "64814784-7896-3901-9741-badeff705639",
                "key": "IpDiscoverySwitchingProfile"
            },
            {
                "value": "fad98876-d7ff-11e4-b9d6-1681e6b88ec1",
                "key": "SpoofGuardSwitchingProfile"
            },
            {
                "value": "93b4b7e8-f116-415d-a50c-3364611b5d09",
                "key": "PortMirroringSwitchingProfile"
            },
            {
                "value": "fbc4fb17-83d9-4b53-a286-ccdf04301888",
                "key": "SwitchSecuritySwitchingProfile"
            },
            {
                "value": "f313290b-eba8-4262-bd93-fab5026e9495",
                "key": "QosSwitchingProfile"
            }
        ],
    }
    return fake_switch


def make_fake_dhcp_profile():
    return {"id": uuidutils.generate_uuid(),
            "edge_cluster_id": uuidutils.generate_uuid(),
            "edge_cluster_member_indexes": [0, 1]}


def make_fake_metadata_proxy():
    return {"id": uuidutils.generate_uuid(),
            "metadata_server_url": "http://1.2.3.4",
            "secret": "my secret",
            "edge_cluster_id": uuidutils.generate_uuid(),
            "edge_cluster_member_indexes": [0, 1]}


def get_resource(resource):
    return {'id': resource.split('/')[-1]}


def create_resource(resource, data):
    data['id'] = uuidutils.generate_uuid()
    return data


def update_resource(resource, data):
    return resource


def delete_resource(resource):
    pass


class MockRequestsResponse(object):
    def __init__(self, status_code, content=None):
        self.status_code = status_code
        self.content = content

    def json(self):
        return jsonutils.loads(self.content)


class MockRequestSessionApi(object):

    def __init__(self):
        self._store = {}

    def _format_uri(self, uri):
        uri = urlparse.urlparse(uri).path
        while uri.endswith('/'):
            uri = uri[:-1]
        while uri.startswith('/'):
            uri = uri[1:]
        if not self._is_uuid_uri(uri):
            uri = "%s/" % uri
        return uri

    def _is_uuid_uri(self, uri):
        return uuidutils.is_uuid_like(
            urlparse.urlparse(uri).path.split('/')[-1])

    def _query(self, search_key, copy=True):
        items = []
        for uri, obj in self._store.items():
            if uri.startswith(search_key):
                items.append(obj.copy() if copy else obj)
        return items

    def _build_response(self, url, content=None,
                        status=requests.codes.ok, **kwargs):
        if type(content) is list:
            content = {
                'result_count': len(content),
                'results': content
            }

        if (content is not None and kwargs.get('headers', {}).get(
                'Content-Type') == 'application/json'):
            content = jsonutils.dumps(content)

        return MockRequestsResponse(status, content=content)

    def _get_content(self, **kwargs):
        content = kwargs.get('data', None)
        if content and kwargs.get('headers', {}).get(
                'Content-Type') == 'application/json':
            content = jsonutils.loads(content)
        return content

    def get(self, url, **kwargs):
        url = self._format_uri(url)

        if self._is_uuid_uri(url):
            item = self._store.get(url)
            code = requests.codes.ok if item else requests.codes.not_found
            return self._build_response(
                url, content=item, status=code, **kwargs)

        return self._build_response(
            url, content=self._query(url), status=requests.codes.ok, **kwargs)

    def _create(self, url, content, **kwargs):
        resource_id = content.get('id')
        if resource_id and self._store.get("%s%s" % (url, resource_id)):
            return self._build_response(
                url, content=None, status=requests.codes.bad, **kwargs)

        resource_id = resource_id or uuidutils.generate_uuid()
        content['id'] = resource_id

        self._store["%s%s" % (url, resource_id)] = content.copy()
        return content

    def post(self, url, **kwargs):
        parsed_url = urlparse.urlparse(url)
        url = self._format_uri(url)

        if self._is_uuid_uri(url):
            if self._store.get(url) is None:
                return self._build_response(
                    url, content=None, status=requests.codes.bad, **kwargs)

        body = self._get_content(**kwargs)
        if body is None:
            return self._build_response(
                url, content=None, status=requests.codes.bad, **kwargs)

        response_content = None

        url_queries = urlparse.parse_qs(parsed_url.query)
        if 'create_multiple' in url_queries.get('action', []):
            response_content = {}
            for resource_name, resource_body in body.items():
                for new_resource in resource_body:
                    created_resource = self._create(
                        url, new_resource, **kwargs)
                    if response_content.get(resource_name, None) is None:
                        response_content[resource_name] = []
                    response_content[resource_name].append(created_resource)
        else:
            response_content = self._create(url, body, **kwargs)

        if isinstance(response_content, MockRequestsResponse):
            return response_content

        return self._build_response(
            url, content=response_content,
            status=requests.codes.created, **kwargs)

    def put(self, url, **kwargs):
        url = self._format_uri(url)

        item = {}
        if self._is_uuid_uri(url):
            item = self._store.get(url, None)
            if item is None:
                return self._build_response(
                    url, content=None,
                    status=requests.codes.not_found, **kwargs)

        body = self._get_content(**kwargs)
        if body is None:
            return self._build_response(
                url, content=None, status=requests.codes.bad, **kwargs)

        item.update(body)
        self._store[url] = item
        return self._build_response(
            url, content=item, status=requests.codes.ok, **kwargs)

    def delete(self, url, **kwargs):
        url = self._format_uri(url)

        if not self._store.get(url):
            return self._build_response(
                url, content=None, status=requests.codes.not_found, **kwargs)

        del self._store[url]
        return self._build_response(
            url, content=None, status=requests.codes.ok, **kwargs)
