# Copyright 2017 VMware, Inc.
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

import abc

from oslo_log import helpers as log_helpers
from oslo_log import log as logging

try:
    from neutron_fwaas.services.firewall.service_drivers.agents.drivers \
        import fwaas_base
except ImportError:
    # FWaaS project no found
    from vmware_nsx.services.fwaas.common import fwaas_mocks \
        as fwaas_base

LOG = logging.getLogger(__name__)


class EdgeFwaasDriverBaseV2(fwaas_base.FwaasDriverBase):
    """NSX Base driver for Firewall As A Service - V2."""

    def __init__(self, driver_name):
        super(EdgeFwaasDriverBaseV2, self).__init__()
        self.driver_name = driver_name

    @log_helpers.log_method_call
    def create_firewall_group(self, agent_mode, apply_list, firewall_group):
        """Create the Firewall with a given policy. """
        self._validate_firewall_group(firewall_group)
        self._update_backend_routers(apply_list, firewall_group['id'])

    @log_helpers.log_method_call
    def update_firewall_group(self, agent_mode, apply_list, firewall_group):
        """Remove previous policy and apply the new policy."""
        self._validate_firewall_group(firewall_group)
        self._update_backend_routers(apply_list, firewall_group['id'])

    @log_helpers.log_method_call
    def delete_firewall_group(self, agent_mode, apply_list, firewall_group):
        """Delete firewall.

        Removes rules created by this instance from the backend firewall
        And add the default allow rule.
        """
        self._update_backend_routers(apply_list, firewall_group['id'])

    @log_helpers.log_method_call
    def apply_default_policy(self, agent_mode, apply_list, firewall_group):
        """Apply the default policy (deny all).

        The backend firewall always has this policy (=deny all) as default,
        so we only need to delete the current rules.
        """
        self._update_backend_routers(apply_list, firewall_group['id'])

    @abc.abstractmethod
    def _update_backend_routers(self, apply_list, fwg_id):
        """Update all the affected router on the backend"""
        pass

    def _validate_firewall_group(self, firewall_group):
        """Validate the rules in the firewall group"""
        for rule in firewall_group['egress_rule_list']:
            if (rule.get('source_ip_address') and
                not rule['source_ip_address'].startswith('0.0.0.0/')):
                # Ignoring interface port as we cannot set it with the ip
                LOG.info("Rule %(id)s with source ips used in an egress "
                         "policy: interface port will be ignored in the NSX "
                         "rule", {'id': rule['id']})
        for rule in firewall_group['ingress_rule_list']:
            if (rule.get('destination_ip_address') and
                not rule['destination_ip_address'].startswith('0.0.0.0/')):
                # Ignoring interface port as we cannot set it with the ip
                LOG.info("Rule %(id)s with destination ips used in an "
                         "ingress policy: interface port will be ignored "
                         "in the NSX rule", {'id': rule['id']})
