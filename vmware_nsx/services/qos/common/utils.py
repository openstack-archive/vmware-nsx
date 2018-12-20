# Copyright 2016 VMware, Inc.
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

from neutron_lib.exceptions import qos as qos_exc
from neutron_lib.objects import registry as obj_reg
from neutron_lib.services.qos import constants as qos_consts


def validate_policy_accessable(context, policy_id):
    policy_obj = obj_reg.load_class('QosPolicy').get_object(
        context, id=policy_id)
    if not policy_obj:
        # This means that rbac decided the policy cannot be used with this
        # context
        raise qos_exc.QosPolicyNotFound(policy_id=policy_id)


def update_network_policy_binding(context, net_id, new_policy_id):
    # detach the old policy (if exists) from the network
    old_policy = obj_reg.load_class('QosPolicy').get_network_policy(
        context, net_id)
    if old_policy:
        if old_policy.id == new_policy_id:
            return
        old_policy.detach_network(net_id)

    # attach the new policy (if exists) to the network
    if new_policy_id is not None:
        new_policy = obj_reg.load_class('QosPolicy').get_object(
            context, id=new_policy_id)
        if new_policy:
            new_policy.attach_network(net_id)


def update_port_policy_binding(context, port_id, new_policy_id):
    # detach the old policy (if exists) from the port
    old_policy = obj_reg.load_class('QosPolicy').get_port_policy(
        context, port_id)
    if old_policy:
        if old_policy.id == new_policy_id:
            return
        old_policy.detach_port(port_id)

    # attach the new policy (if exists) to the port
    if new_policy_id is not None:
        new_policy = obj_reg.load_class('QosPolicy').get_object(
            context, id=new_policy_id)
        if new_policy:
            new_policy.attach_port(port_id)


def get_port_policy_id(context, port_id):
    policy = obj_reg.load_class('QosPolicy').get_port_policy(
        context, port_id)
    if policy:
        return policy.id


def get_network_policy_id(context, net_id):
    policy = obj_reg.load_class('QosPolicy').get_network_policy(
        context, net_id)
    if policy:
        return policy.id


def set_qos_policy_on_new_net(context, net_data, created_net):
    """Update the network with the assigned or default QoS policy

    Update the network-qos binding table, and the new network structure
    """
    qos_policy_id = net_data.get(qos_consts.QOS_POLICY_ID)
    if not qos_policy_id:
        # try and get the default one
        qos_obj = obj_reg.load_class('QosPolicyDefault').get_object(
            context, project_id=created_net['project_id'])
        if qos_obj:
            qos_policy_id = qos_obj.qos_policy_id

    if qos_policy_id:
        # attach the policy to the network in the neutron DB
        update_network_policy_binding(
            context,
            created_net['id'],
            qos_policy_id)
    created_net[qos_consts.QOS_POLICY_ID] = qos_policy_id
    return qos_policy_id
