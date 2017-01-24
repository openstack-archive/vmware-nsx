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

from neutron.services.qos.notification_drivers import message_queue


class NsxV3QosNotificationDriver(
    message_queue.RpcQosServiceNotificationDriver):
    """NSXv3 message queue service notification driver for QoS.
    Overriding the create_policy method in order to add a notification
    message in this case too.
    """
    # The message queue is no longer needed in Pike.
    # Keeping this class for a while for existing configurations.
    pass
