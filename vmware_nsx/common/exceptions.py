# Copyright 2012 VMware, Inc
#
# All Rights Reserved.
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

from neutron_lib import exceptions as n_exc

from vmware_nsx._i18n import _


class NsxPluginException(n_exc.NeutronException):
    message = _("An unexpected error occurred in the NSX Plugin: %(err_msg)s")


class NsxPluginTemporaryError(n_exc.ServiceUnavailable):
    message = _("Temporary error occurred in the NSX Plugin: %(err_msg)s."
                " Please try again later")


class ClientCertificateException(NsxPluginException):
    message = _("Client certificate error: %(err_msg)s")


class InvalidVersion(NsxPluginException):
    message = _("Unable to fulfill request with version %(version)s.")


class InvalidConnection(NsxPluginException):
    message = _("Invalid NSX connection parameters: %(conn_params)s")


class InvalidClusterConfiguration(NsxPluginException):
    message = _("Invalid cluster values: %(invalid_attrs)s. Please ensure "
                "that these values are specified in the [DEFAULT] "
                "section of the NSX plugin ini file.")


class InvalidNovaZone(NsxPluginException):
    message = _("Unable to find cluster config entry "
                "for nova zone: %(nova_zone)s")


class NoMorePortsException(NsxPluginException):
    message = _("Unable to create port on network %(network)s. "
                "Maximum number of ports reached")


class NatRuleMismatch(NsxPluginException):
    message = _("While retrieving NAT rules, %(actual_rules)s were found "
                "whereas rules in the (%(min_rules)s,%(max_rules)s) interval "
                "were expected")


class InvalidAttachmentType(NsxPluginException):
    message = _("Invalid NSX attachment type '%(attachment_type)s'")


class MaintenanceInProgress(NsxPluginException):
    message = _("The networking backend is currently in maintenance mode and "
                "therefore unable to accept requests which modify its state. "
                "Please try later.")


class L2GatewayAlreadyInUse(n_exc.Conflict):
    message = _("Gateway Service %(gateway)s is already in use")


class BridgeEndpointAttachmentInUse(n_exc.Conflict):
    message = _("The NSX backend only allow a single L2 gateway connection "
                "for network %(network_id)s")


class InvalidTransportType(NsxPluginException):
    message = _("The transport type %(transport_type)s is not recognized "
                "by the backend")


class InvalidSecurityCertificate(NsxPluginException):
    message = _("An invalid security certificate was specified for the "
                "gateway device. Certificates must be enclosed between "
                "'-----BEGIN CERTIFICATE-----' and "
                "'-----END CERTIFICATE-----'")


class ServiceOverQuota(n_exc.Conflict):
    message = _("Quota exceeded for NSX resource %(overs)s: %(err_msg)s")


class PortConfigurationError(NsxPluginException):
    message = _("An error occurred while connecting LSN %(lsn_id)s "
                "and network %(net_id)s via port %(port_id)s")

    def __init__(self, **kwargs):
        super(PortConfigurationError, self).__init__(**kwargs)
        self.port_id = kwargs.get('port_id')


class LogicalRouterNotFound(n_exc.NotFound):
    message = _('Unable to find logical router for %(entity_id)s')


class LsnNotFound(n_exc.NotFound):
    message = _('Unable to find LSN for %(entity)s %(entity_id)s')


class LsnPortNotFound(n_exc.NotFound):
    message = (_('Unable to find port for LSN %(lsn_id)s '
                 'and %(entity)s %(entity_id)s'))


class LsnMigrationConflict(n_exc.Conflict):
    message = _("Unable to migrate network '%(net_id)s' to LSN: %(reason)s")


class LsnConfigurationConflict(NsxPluginException):
    message = _("Configuration conflict on Logical Service Node %(lsn_id)s")


class DvsNotFound(n_exc.NotFound):
    message = _('Unable to find DVS %(dvs)s')


class NoRouterAvailable(n_exc.ResourceExhausted):
    message = _("Unable to create the router. "
                "No tenant router is available for allocation.")


class NsxL2GWDeviceNotFound(n_exc.NotFound):
    message = _('Unable to find logical L2 gateway device.')


class NsxL2GWInUse(n_exc.InUse):
    message = _("L2 Gateway '%(gateway_id)s' has been used")


class InvalidIPAddress(n_exc.InvalidInput):
    message = _("'%(ip_address)s' must be a /32 CIDR based IPv4 address")


class QoSOnExternalNet(n_exc.InvalidInput):
    message = _("Cannot configure QOS on external networks")


class SecurityGroupMaximumCapacityReached(NsxPluginException):
    pass


class NsxResourceNotFound(n_exc.NotFound):
    message = _("%(res_name)s %(res_id)s not found on the backend.")


class NsxAZResourceNotFound(NsxResourceNotFound):
    message = _("Availability zone %(res_name)s %(res_id)s not found on the "
                "backend.")


class NsxQosPolicyMappingNotFound(n_exc.NotFound):
    message = _('Unable to find mapping for QoS policy: %(policy)s')


class NumberOfNsgroupCriteriaTagsReached(NsxPluginException):
    message = _("Port can be associated with at most %(max_num)s "
                "security-groups.")


class NsxTaaSDriverException(NsxPluginException):
    message = _("Tap-as-a-Service NSX driver exception: %(msg)s.")


class NsxPortMirrorSessionMappingNotFound(n_exc.NotFound):
    message = _("Unable to find mapping for Tap Flow: %(tf)s")


class NsxInvalidConfiguration(n_exc.InvalidConfigurationOption):
    message = _("An invalid value was provided for %(opt_name)s: "
                "%(opt_value)s: %(reason)s")


class NsxBgpSpeakerUnableToAddGatewayNetwork(n_exc.BadRequest):
    message = _("Unable to add gateway network %(network_id)s to BGP speaker "
                "%(bgp_speaker_id)s, network must have association with an "
                "address-scope and can be associated with one BGP speaker at "
                "most.")


class NsxBgpNetworkNotExternal(n_exc.BadRequest):
    message = _("Network %(net_id)s is not external, only external network "
                "can be associated with a BGP speaker.")


class NsxBgpGatewayNetworkHasNoSubnets(n_exc.BadRequest):
    message = _("Can't associate external network %(net_id)s with BGP "
                "speaker, network doesn't contain any subnets.")


class NsxRouterInterfaceDoesNotMatchAddressScope(n_exc.BadRequest):
    message = _("Unable to update no-NAT router %(router_id)s, "
                "only subnets allocated from address-scope "
                "%(address_scope_id)s can be connected.")


class NsxVpnValidationError(NsxPluginException):
    message = _("Invalid VPN configuration: %(details)s")


class NsxIPsecVpnMappingNotFound(n_exc.NotFound):
    message = _("Unable to find mapping for ipsec site connection: %(conn)s")


class NsxENSPortSecurity(n_exc.BadRequest):
    message = _("Port security is not supported on ENS Transport zones")
