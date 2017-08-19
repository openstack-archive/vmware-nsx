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


GITDIR['vmware-nsxlib']=$DEST/vmware-nsxlib
GITREPO['vmware-nsxlib']=${NSXLIB_REPO:-${GIT_BASE}/openstack/vmware-nsxlib.git}
GITBRANCH['vmware-nsxlib']=${NSXLIB_BRANCH:-stable/pike}

dir=${GITDIR['vmware-nsx']}/devstack

if [[ "$1" == "stack" && "$2" == "install" ]]; then
    if use_library_from_git 'vmware-nsxlib'; then
        git_clone_by_name 'vmware-nsxlib'
        setup_dev_lib 'vmware-nsxlib'
    fi
    setup_develop ${GITDIR['vmware-nsx']}
fi

if [[ $Q_PLUGIN == 'vmware_nsx_v' ]]; then
    source $dir/lib/vmware_nsx_v
    if [[ "$1" == "unstack" ]]; then
        db_connection=$(iniget $NEUTRON_CONF database connection)
        python $dir/tools/nsxv_cleanup.py --vsm-ip ${NSXV_MANAGER_URI/https:\/\/} --user $NSXV_USER --password $NSXV_PASSWORD --db-connection $db_connection
    elif [[ "$1" == "clean" ]]; then
        if is_service_enabled q-svc || is_service_enabled neutron-api; then
            python $dir/tools/nsxv_cleanup.py --vsm-ip ${NSXV_MANAGER_URI/https:\/\/} --user $NSXV_USER --password $NSXV_PASSWORD
        fi
    fi

elif [[ $Q_PLUGIN == 'vmware_nsx' ]]; then
    source $dir/lib/vmware_nsx
    if [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        init_vmware_nsx
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        check_vmware_nsx
    elif [[ "$1" == "unstack" ]]; then
        stop_vmware_nsx
    fi
elif [[ $Q_PLUGIN == 'vmware_nsx_v3' ]]; then
    source $dir/lib/vmware_nsx_v3
    if [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        init_vmware_nsx_v3
    elif [[ "$1" == "unstack" ]]; then
        db_connection=$(iniget $NEUTRON_CONF database connection)
        stop_vmware_nsx_v3
        # only clean up when q-svc (legacy support) or neutron-api is enabled
        if is_service_enabled q-svc || is_service_enabled neutron-api; then
            NSX_MANAGER=${NSX_MANAGERS:-$NSX_MANAGER}
            IFS=','
            NSX_MANAGER=($NSX_MANAGER)
            unset IFS
            python $dir/tools/nsxv3_cleanup.py --mgr-ip $NSX_MANAGER --user $NSX_USER --password $NSX_PASSWORD --db-connection $db_connection
        fi
    elif [[ "$1" == 'clean' ]]; then
        if is_service_enabled q-svc || is_service_enabled neutron-api; then
            python $dir/tools/nsxv3_cleanup.py --mgr-ip $NSX_MANAGER --user $NSX_USER --password $NSX_PASSWORD
        fi
    fi
elif [[ $Q_PLUGIN == 'vmware_dvs' ]]; then
    source $dir/lib/vmware_dvs
fi
