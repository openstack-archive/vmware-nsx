# Copyright 2017 VMware Inc
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

from vmware_nsx_tempest.services import nsxv3_client

LOG = logging.getLogger(__name__)


class NSXClient(object):
    """Base NSX REST client"""
    def __init__(self, backend, host, username, password, *args, **kwargs):
        self.backend = backend.lower()
        self.host = host
        self.username = username
        self.password = password
        if backend.lower() == "nsxv3":
            self.nsx = nsxv3_client.NSXV3Client(host, username, password)

    def get_firewall_section_and_rules(self, *args, **kwargs):
        if self.backend == "nsxv3":
            firewall_section = self.nsx.get_firewall_section(
                *args, **kwargs)
            firewall_section_rules = self.nsx.get_firewall_section_rules(
                firewall_section)
            return firewall_section, firewall_section_rules
        else:
            #TODO(ddoshi) define else for nsxv
            pass

    def get_bridge_cluster_info(self, *args, **kwargs):
        if self.backend == "nsxv3":
            return self.nsx.get_bridge_cluster_info(
                *args, **kwargs)
