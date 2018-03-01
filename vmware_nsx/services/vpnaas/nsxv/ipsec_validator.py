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

from neutron_lib import constants
from neutron_vpnaas.db.vpn import vpn_validator
from oslo_log import log as logging

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsxv_exc
from vmware_nsx.common import nsxv_constants

LOG = logging.getLogger(__name__)


class IPsecValidator(vpn_validator.VpnReferenceValidator):

    """Validator methods for Vmware VPN support"""

    def __init__(self, service_plugin):
        super(IPsecValidator, self).__init__()
        self.vpn_plugin = service_plugin

    def validate_ikepolicy_version(self, policy_info):
        """NSX Edge provides IKEv1"""
        version = policy_info.get('ike_version')
        if version != 'v1':
            msg = _("Unsupported ike policy %s! only v1 "
                    "is supported right now.") % version
            raise nsxv_exc.NsxVpnValidationError(details=msg)

    def validate_ikepolicy_pfs(self, policy_info):
        # Check whether pfs is allowed.
        if not nsxv_constants.PFS_MAP.get(policy_info['pfs']):
            msg = _("Unsupported pfs: %(pfs)s! currently only "
                    "the following pfs are supported on VSE: %s") % {
                        'pfs': policy_info['pfs'],
                        'supported': nsxv_constants.PFS_MAP}
            raise nsxv_exc.NsxVpnValidationError(details=msg)

    def validate_encryption_algorithm(self, policy_info):
        encryption = policy_info['encryption_algorithm']
        if encryption not in nsxv_constants.ENCRYPTION_ALGORITHM_MAP:
            msg = _("Unsupported encryption_algorithm: %(algo)s! please "
                    "select one of the following supported algorithms: "
                    "%(supported_algos)s") % {
                        'algo': encryption,
                        'supported_algos':
                        nsxv_constants.ENCRYPTION_ALGORITHM_MAP}
            raise nsxv_exc.NsxVpnValidationError(details=msg)

    def validate_ipsec_policy(self, context, policy_info):
        """Ensure IPSec policy encap mode is tunnel for current REST API."""
        mode = policy_info['encapsulation_mode']
        if mode not in nsxv_constants.ENCAPSULATION_MODE_ALLOWED:
            msg = _("Unsupported encapsulation mode: %s! currently only"
                    "'tunnel' mode is supported.") % mode
            raise nsxv_exc.NsxVpnValidationError(details=msg)

    def validate_policies_matching_algorithms(self, ikepolicy, ipsecpolicy):
        # In VSE, Phase 1 and Phase 2 share the same encryption_algorithm
        # and authentication algorithms setting. At present, just record the
        # discrepancy error in log and take ipsecpolicy to do configuration.
        keys = ('auth_algorithm', 'encryption_algorithm', 'pfs')
        for key in keys:
            if ikepolicy[key] != ipsecpolicy[key]:
                LOG.warning("IKEPolicy and IPsecPolicy should have consistent "
                            "auth_algorithm, encryption_algorithm and pfs for "
                            "VSE!")
                break

    def _is_shared_router(self, router):
        return router.get('router_type') == constants.SHARED

    def _validate_router(self, context, router_id):
        # Only support distributed and exclusive router type
        router = self.core_plugin.get_router(context, router_id)
        if self._is_shared_router(router):
            msg = _("Router type is not supported for VPN service, only "
                    "support distributed and exclusive router")
            raise nsxv_exc.NsxVpnValidationError(details=msg)

    def validate_vpnservice(self, context, vpnservice):
        """Called upon create/update of a service"""

        # Call general validations
        super(IPsecValidator, self).validate_vpnservice(
            context, vpnservice)

        # Call specific NSX validations
        self._validate_router(context, vpnservice['router_id'])

        if not vpnservice['subnet_id']:
            # we currently do not support multiple subnets so a subnet must
            # be defined
            msg = _("Subnet must be defined in a service")
            raise nsxv_exc.NsxVpnValidationError(details=msg)

    def validate_ipsec_site_connection(self, context, ipsec_site_conn):
        ike_policy_id = ipsec_site_conn.get('ikepolicy_id')
        if ike_policy_id:
            ikepolicy = self.vpn_plugin.get_ikepolicy(context,
                                                      ike_policy_id)

            self.validate_ikepolicy_version(ikepolicy)
            self.validate_ikepolicy_pfs(ikepolicy)
            self.validate_encryption_algorithm(ikepolicy)

        ipsec_policy_id = ipsec_site_conn.get('ipsecpolicy_id')
        if ipsec_policy_id:
            ipsecpolicy = self.vpn_plugin.get_ipsecpolicy(context,
                                                          ipsec_policy_id)
            self.validate_ipsec_policy(context, ipsecpolicy)

        if ike_policy_id and ipsec_policy_id:
            self.validate_policies_matching_algorithms(ikepolicy, ipsecpolicy)
