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


from neutron.api.v2 import attributes
from neutron_lib.api import attributes as lib_attrs
from oslo_config import cfg
from oslo_utils import uuidutils
import webob.exc


def _fixup_res_dict(context, attr_name, res_dict, check_allow_post=True):
    # This method is a replacement of _fixup_res_dict which is used in
    # neutron.plugin.common.utils. All this mock does is insert a uuid
    # for the id field if one is not found ONLY if running in api_replay_mode.
    if cfg.CONF.api_replay_mode and 'id' not in res_dict:
        res_dict['id'] = uuidutils.generate_uuid()
    attr_info = attributes.RESOURCE_ATTRIBUTE_MAP[attr_name]
    attr_ops = lib_attrs.AttributeInfo(attr_info)
    try:
        attr_ops.populate_project_id(context, res_dict, True)
        lib_attrs.populate_project_info(attr_info)
        attr_ops.verify_attributes(res_dict)
    except webob.exc.HTTPBadRequest as e:
        # convert webob exception into ValueError as these functions are
        # for internal use. webob exception doesn't make sense.
        raise ValueError(e.detail)

    attr_ops.fill_post_defaults(res_dict, check_allow_post=check_allow_post)
    attr_ops.convert_values(res_dict)
    return res_dict
