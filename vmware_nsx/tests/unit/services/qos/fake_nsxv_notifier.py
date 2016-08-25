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

import mock

from neutron.api.rpc.callbacks import events
from neutron.services.qos.notification_drivers import message_queue

from vmware_nsx.services.qos.nsx_v import utils as qos_utils


class DummyNsxVNotificationDriver(
    message_queue.RpcQosServiceNotificationDriver):

    def __init__(self):
        super(DummyNsxVNotificationDriver, self).__init__()
        self._dvs = mock.Mock()

    def create_policy(self, context, policy):
        # there is no notification for newly created policy
        pass

    def update_policy(self, context, policy):
        qos_utils.handle_qos_notification([policy], events.UPDATED, self._dvs)

    def delete_policy(self, context, policy):
        qos_utils.handle_qos_notification([policy], events.DELETED, self._dvs)
