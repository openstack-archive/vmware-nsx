#!/bin/bash

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


dir=${GITDIR['vmware-nsx']}/devstack

if [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    setup_develop ${GITDIR['vmware-nsx']}
fi

if [[ $Q_PLUGIN == 'vmware_nsx_v' ]]; then
    source $dir/lib/vmware_nsx_v
elif [[ $Q_PLUGIN == 'vmware_nsx' ]]; then
    source $dir/lib/vmware_nsx
    if [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        init_vmware_nsx
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        check_vmware_nsx
    fi
fi
