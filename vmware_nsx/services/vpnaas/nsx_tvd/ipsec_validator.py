# Copyright 2018 VMware, Inc.
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

from oslo_log import log as logging

from neutron_vpnaas.db.vpn import vpn_validator

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.nsx import utils as tvd_utils
from vmware_nsx.services.vpnaas.nsxv import ipsec_validator as v_validator
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_validator as t_validator

LOG = logging.getLogger(__name__)


class IPsecValidator(vpn_validator.VpnReferenceValidator):
    """Wrapper validator for selecting the V/T validator to use"""
    def __init__(self, service_plugin):
        super(IPsecValidator, self).__init__()
        self.vpn_plugin = service_plugin

        # supported validatorss:
        self.validators = {}
        try:
            self.validators[projectpluginmap.NsxPlugins.NSX_T] = (
                t_validator.IPsecV3Validator(service_plugin))
        except Exception as e:
            LOG.error("IPsecValidator failed to initialize the NSX-T "
                      "validator: %s", e)
            self.validators[projectpluginmap.NsxPlugins.NSX_T] = None
        try:
            self.validators[projectpluginmap.NsxPlugins.NSX_V] = (
                v_validator.IPsecValidator(service_plugin))
        except Exception as e:
            LOG.error("IPsecValidator failed to initialize the NSX-V "
                      "validator: %s", e)
            self.validators[projectpluginmap.NsxPlugins.NSX_V] = None

    def _get_validator_for_project(self, project):
        plugin_type = tvd_utils.get_tvd_plugin_type_for_project(project)
        if not self.validators.get(plugin_type):
            msg = (_("Project %(project)s with plugin %(plugin)s has no "
                     "support for VPNaaS"), {'project': project,
                                             'plugin': plugin_type})
            raise nsx_exc.NsxPluginException(err_msg=msg)
        return self.validators[plugin_type]

    def validate_ipsec_site_connection(self, context, ipsec_site_conn):
        if not ipsec_site_conn.get('tenant_id'):
            # nothing we can do here.
            return

        v = self._get_validator_for_project(ipsec_site_conn['tenant_id'])

        # first make sure the plugin is the same as the one of the vpnservice
        srv_id = ipsec_site_conn.get('vpnservice_id')
        srv = self.vpn_plugin._get_vpnservice(context, srv_id)
        srv_validator = self._get_validator_for_project(srv['tenant_id'])
        if v != srv_validator:
            err_msg = _('VPN service should belong to the same plugin '
                        'as the connection')
            raise nsx_exc.NsxVpnValidationError(details=err_msg)

        return v.validate_ipsec_site_connection(context, ipsec_site_conn)

    def validate_vpnservice(self, context, vpnservice):
        if not vpnservice.get('tenant_id'):
            # This will happen during update.
            # nothing significant like router or subnet can be changes
            # so we can skip it.
            return

        v = self._get_validator_for_project(vpnservice['tenant_id'])

        # first make sure the router&subnet plugin matches the vpnservice
        router_id = vpnservice['router_id']
        p = self.core_plugin._get_plugin_from_router_id(context, router_id)
        if self.validators.get(p.plugin_type()) != v:
            err_msg = _('Router & subnet should belong to the same plugin '
                        'as the VPN service')
            raise nsx_exc.NsxVpnValidationError(details=err_msg)
        return v.validate_vpnservice(context, vpnservice)

    def validate_ipsec_policy(self, context, ipsec_policy):
        if not ipsec_policy.get('tenant_id'):
            # nothing we can do here
            return

        v = self._get_validator_for_project(ipsec_policy['tenant_id'])
        return v.validate_ipsec_policy(context, ipsec_policy)

    def validate_ike_policy(self, context, ike_policy):
        if not ike_policy.get('tenant_id'):
            # nothing we can do here
            return

        v = self._get_validator_for_project(ike_policy['tenant_id'])
        return v.validate_ike_policy(context, ike_policy)
