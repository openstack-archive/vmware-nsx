# Copyright 2015 VMware, Inc.
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

import os
import traceback

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log
from tooz import coordination

LOG = log.getLogger(__name__)


class LockManager(object):
    _coordinator = None
    _coordinator_pid = None
    _connect_string = cfg.CONF.locking_coordinator_url

    def __init__(self):
        LOG.debug('LockManager initialized!')

    @staticmethod
    def get_lock(name, **kwargs):
        if cfg.CONF.locking_coordinator_url:
            lck = LockManager._get_lock_distributed(name)
            LOG.debug('Lock %s taken with stack trace %s', name,
                      traceback.extract_stack())
            return lck
        else:
            # Ensure that external=True
            kwargs['external'] = True
            lck = LockManager._get_lock_local(name, **kwargs)
            LOG.debug('Lock %s taken with stack trace %s', name,
                      traceback.extract_stack())
            return lck

    @staticmethod
    def _get_lock_local(name, **kwargs):
        return lockutils.lock(name, **kwargs)

    @staticmethod
    def _get_lock_distributed(name):
        if LockManager._coordinator_pid != os.getpid():
            # We should use a per-process coordinator. If PID is different
            # start a new coordinator.
            # While the API workers are spawned, we have to re-initialize
            # a coordinator, so we validate that the PID is still the same.
            LockManager._coordinator_pid = os.getpid()
            LOG.debug('Initialized coordinator with connect string %s',
                      LockManager._connect_string)
            LockManager._coordinator = coordination.get_coordinator(
                LockManager._connect_string, 'vmware-neutron-plugin')
            LockManager._coordinator.start()

        LOG.debug('Retrieved lock for %s', name)
        return LockManager._coordinator.get_lock(name)
