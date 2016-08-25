# Copyright 2016 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron.api.rpc.callbacks import events
from neutron.services.qos.notification_drivers import message_queue
from vmware_nsx.services.qos.nsx_v3 import utils as qos_utils


class DummyNotificationDriver(
    message_queue.RpcQosServiceNotificationDriver):

    def create_policy(self, context, policy):
        qos_utils.handle_qos_notification([policy], events.CREATED)

    def update_policy(self, context, policy):
        qos_utils.handle_qos_notification([policy], events.UPDATED)

    def delete_policy(self, context, policy):
        qos_utils.handle_qos_notification([policy], events.DELETED)
