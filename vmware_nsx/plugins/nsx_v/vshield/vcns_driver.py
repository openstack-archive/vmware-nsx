# Copyright 2013 VMware, Inc
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

from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.plugins.nsx_v.vshield import edge_appliance_driver
from vmware_nsx.plugins.nsx_v.vshield import edge_dynamic_routing_driver
from vmware_nsx.plugins.nsx_v.vshield import edge_firewall_driver
from vmware_nsx.plugins.nsx_v.vshield.tasks import tasks
from vmware_nsx.plugins.nsx_v.vshield import vcns
from vmware_nsx.services.lbaas.nsx_v.v2 import (
    edge_loadbalancer_driver_v2 as lbaas_v2)

LOG = logging.getLogger(__name__)


class VcnsDriver(edge_appliance_driver.EdgeApplianceDriver,
                 lbaas_v2.EdgeLoadbalancerDriverV2,
                 edge_firewall_driver.EdgeFirewallDriver,
                 edge_dynamic_routing_driver.EdgeDynamicRoutingDriver):

    def __init__(self, callbacks):
        super(VcnsDriver, self).__init__()

        self.callbacks = callbacks
        self.vcns_uri = cfg.CONF.nsxv.manager_uri
        self.vcns_user = cfg.CONF.nsxv.user
        self.vcns_passwd = cfg.CONF.nsxv.password
        self.ca_file = cfg.CONF.nsxv.ca_file
        self.insecure = cfg.CONF.nsxv.insecure
        self.deployment_container_id = cfg.CONF.nsxv.deployment_container_id
        self._pid = None
        self._task_manager = None
        self.vcns = vcns.Vcns(self.vcns_uri, self.vcns_user, self.vcns_passwd,
                              self.ca_file, self.insecure)

    @property
    def task_manager(self):
        if (self._task_manager is None or
                self._pid != os.getpid()):
            LOG.debug("Creating task manager")
            self._pid = os.getpid()
            interval = cfg.CONF.nsxv.task_status_check_interval
            self._task_manager = tasks.TaskManager(interval)
            LOG.debug("Starting task manager")
            self._task_manager.start()
        return self._task_manager
