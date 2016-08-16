# Copyright 2016 VMware, Inc.
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

from oslo_serialization import jsonutils

from tempest.lib.services.network import base


class BaseTagsClient(base.BaseNetworkClient):
    """Why base client for tags_client:

    https://bugs.launchpad.net/neutron/+bug/1606659
    tag-add is a CREATE operation; then expected resp_code is 201
    however it is using http PUT operation to accomplish it.
    """

    def update_resource(self, uri, post_data, resp_code=None):
        """allow different response code."""
        if resp_code:
            req_uri = self.uri_prefix + uri
            req_post_data = jsonutils.dumps(post_data)
            resp, body = self.put(req_uri, req_post_data)
            body = jsonutils.loads(body)
            self.expected_success(resp_code, resp.status)
            return base.rest_client.ResponseBody(
                resp, body)
        else:
            return super(BaseTagsClient, self).update_resource(
                uri, post_data)


class TagsClient(BaseTagsClient):
    resource_base_path = '/{resource_type}/{resource_id}/tags'
    resource_object_path = '/{resource_type}/{resource_id}/tags/{tag}'

    def add_tag(self, **kwargs):
        """add a tag to network resource.

        neutron tag-add
            --resource resource
            --resource-type network --tag TAG
        """
        uri = self.resource_object_path.format(
            **self._fix_args(**kwargs))
        # https://bugs.launchpad.net/neutron/+bug/1606659
        return self.update_resource(uri, None, 201)

    def remove_tag(self, **kwargs):
        """remove a tag from network resource.

        neutron tag-remove
           --resource resource
           --resource-type network --tag TAG
        """
        if 'all' in kwargs:
            return self.remove_all_tags(**kwargs)
        uri = self.resource_object_path.format(
            **self._fix_args(**kwargs))
        return self.delete_resource(uri)

    def remove_all_tags(self, **kwargs):
        """remove all tags from network resource.

        neutron tag-remove
            --resource resource
            --resource-type network --all
        """
        uri = self.resource_base_path.format(
            **self._fix_args(**kwargs))
        return self.delete_resource(uri)

    def replace_tag(self, **kwargs):
        """replace network resource's tag with list of tags.

        neutron tag-replace
            --resource resource
            --resource-type network --tag TAG
        """
        tag_list = kwargs.pop('tags', None)
        kwargs = self._fix_args(**kwargs)
        if 'tag' in kwargs:
            uri = self.resource_object_path.format(**kwargs)
        else:
            uri = self.resource_base_path.format(**kwargs)
        update_body = None if tag_list is None else {"tags": tag_list}
        return self.update_resource(uri, update_body)

    def _fix_args(self, **kwargs):
        """Fix key-value of input fields.

        resource can be name, to simplify the design, only ID accepted.
        """
        if 'resource' in kwargs and 'resource_id' not in kwargs:
            kwargs['resource_id'] = kwargs['resource']
        if 'resource_type' in kwargs:
            if kwargs['resource_type'][-1] != 's':
                kwargs['resource_type'] += "s"
        else:
            kwargs['resource_type'] = 'networks'
        return kwargs


def get_client(client_mgr,
               set_property=False, with_name="tags_client"):
    """create tags_client from networks_client.

    Create network tags_client from manager or networks_client.
    client = tags_client.get_client(manager)
    """
    manager = getattr(client_mgr, 'manager', client_mgr)
    net_client = getattr(manager, 'networks_client')
    try:
        _params = manager.default_params_with_timeout_values.copy()
    except Exception:
        _params = {}
    client = TagsClient(net_client.auth_provider,
                        net_client.service,
                        net_client.region,
                        net_client.endpoint_type,
                        **_params)
    if set_property:
        setattr(manager, with_name, client)
    return client
