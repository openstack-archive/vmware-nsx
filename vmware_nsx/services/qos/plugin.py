# Copyright 2015 VMware, Inc.
#
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

from oslo_log import log as logging
from oslo_utils import excutils

from neutron.db import db_base_plugin_common
from neutron.objects.qos import policy as policy_object
from neutron.services.qos import qos_plugin

from vmware_nsx._i18n import _LE, _LI
from vmware_nsx.common import utils
from vmware_nsx.nsxlib import v3 as nsxlib

LOG = logging.getLogger(__name__)


class NsxQosPlugin(qos_plugin.QoSPlugin):

    """Service plugin for VMware NSX to implement Neutron's Qos API."""

    supported_extension_aliases = ["qos"]

    def __init__(self):
        super(NsxQosPlugin, self).__init__()
        LOG.info(_LI("Loading VMware Qos Service Plugin"))

    @db_base_plugin_common.convert_result_to_dict
    def create_policy(self, context, policy):
        tags = utils.build_v3_tags_payload(
            policy['policy'], resource_type='os-neutron-qos-id',
            project_name=context.tenant_name)
        result = nsxlib.create_qos_switching_profile(
                     tags=tags, name=policy['policy'].get("name"),
                     description=policy['policy'].get("description"))
        policy['policy']['id'] = result['id']
        try:
            policy = policy_object.QosPolicy(context, **policy['policy'])
            policy.create()
            return policy
        except Exception:
            with excutils.save_and_reraise_exception():
                # Undo creation on the backend
                LOG.exception(_LE('Failed to create qos-policy'))
                nsxlib.delete_qos_switching_profile(result['id'])

    def delete_policy(self, context, policy_id):
        # Delete policy from neutron first; as neutron checks if there are any
        # active network/ port bindings
        policy = policy_object.QosPolicy(context)
        policy.id = policy_id
        policy.delete()
        nsxlib.delete_qos_switching_profile(policy_id)

    def update_policy(self, context, policy_id, policy):
        raise NotImplementedError()

    def get_policy_bandwidth_limit_rule(self, context, rule_id,
                                        policy_id, fields=None):
        raise NotImplementedError()

    def get_policy_bandwidth_limit_rules(self, context, policy_id,
                                         filters=None, fields=None,
                                         sorts=None, limit=None,
                                         marker=None, page_reverse=False):
        raise NotImplementedError()

    def create_policy_bandwidth_limit_rule(self, context, policy_id,
                                           bandwidth_limit_rule):
        raise NotImplementedError()

    def update_policy_bandwidth_limit_rule(self, context, rule_id, policy_id,
                                           bandwidth_limit_rule):
        raise NotImplementedError()

    def delete_policy_bandwidth_limit_rule(self, context, rule_id, policy_id):
        raise NotImplementedError()

    def get_rule_types(self, context, filters=None, fields=None,
                       sorts=None, limit=None,
                       marker=None, page_reverse=False):
        raise NotImplementedError()
