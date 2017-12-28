#!/bin/bash
# Copyright 2018 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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
#
# Trigger execution of NSX plugin's housekeeper
#

NEUTRON_ENDPOINT=`openstack endpoint list | awk '/network/{print $14}'`
if [ -z "$NEUTRON_ENDPOINT" ]; then
    echo "Couldn't locate Neutron endpoint"
    exit 1
fi
AUTH_TOKEN=`openstack token issue | awk '/ id /{print $4}'`
if [ -z "$AUTH_TOKEN" ]; then
    echo "Couldn't acquire authentication token"
    exit 1
fi

curl -X PUT -s -H "X-Auth-Token: $AUTH_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{"housekeeper": {}}' ${NEUTRON_ENDPOINT}/v2.0/housekeepers/all
exit 0
