# Copyright 2017 VMware, Inc.
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

import netaddr
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context as n_context
from neutron_lib import exceptions as nexception
from neutron_lib.plugins import directory
from neutron_vpnaas.services.vpn import service_drivers

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_utils
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_validator
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as consts
from vmware_nsxlib.v3 import vpn_ipsec

LOG = logging.getLogger(__name__)
IPSEC = 'ipsec'
VPN_PORT_OWNER = constants.DEVICE_OWNER_NEUTRON_PREFIX + 'vpnservice'


class RouterWithSNAT(nexception.BadRequest):
    message = _("Router %(router_id)s has a VPN service and cannot enable "
                "SNAT")


class NSXv3IPsecVpnDriver(service_drivers.VpnDriver):

    def __init__(self, service_plugin):
        self.vpn_plugin = service_plugin
        self._core_plugin = directory.get_plugin()
        if self._core_plugin.is_tvd_plugin():
            self._core_plugin = self._core_plugin.get_plugin_by_type(
                projectpluginmap.NsxPlugins.NSX_T)
        self._nsxlib = self._core_plugin.nsxlib
        self._nsx_vpn = self._nsxlib.vpn_ipsec
        validator = ipsec_validator.IPsecV3Validator(service_plugin)
        super(NSXv3IPsecVpnDriver, self).__init__(service_plugin, validator)

        registry.subscribe(
            self._delete_local_endpoint, resources.ROUTER_GATEWAY,
            events.AFTER_DELETE)

    @property
    def l3_plugin(self):
        return self._core_plugin

    @property
    def service_type(self):
        return IPSEC

    def _translate_cidr(self, cidr):
        return self._nsxlib.firewall_section.get_ip_cidr_reference(
            cidr,
            consts.IPV6 if netaddr.valid_ipv6(cidr) else consts.IPV4)

    def _translate_addresses_to_target(self, cidrs):
        return [self._translate_cidr(ip) for ip in cidrs]

    def _generate_ipsecvpn_firewall_rules(self, plugin_type, context,
                                          router_id=None):
        """Return the firewall rules needed to allow vpn traffic"""
        fw_rules = []
        # get all the active services of this router
        filters = {'router_id': [router_id],
                   'status': [constants.ACTIVE]}
        services = self.vpn_plugin.get_vpnservices(
            context.elevated(), filters=filters)
        if not services:
            return fw_rules
        for srv in services:
            subnet = self.l3_plugin.get_subnet(
                context.elevated(), srv['subnet_id'])
            local_cidrs = [subnet['cidr']]
            # get all the active connections of this service
            filters = {'vpnservice_id': [srv['id']],
                       'status': [constants.ACTIVE]}
            connections = self.vpn_plugin.get_ipsec_site_connections(
                context.elevated(), filters=filters)
            for conn in connections:
                peer_cidrs = conn['peer_cidrs']
                fw_rules.append({
                    'display_name': 'VPN connection ' + conn['id'],
                    'action': consts.FW_ACTION_ALLOW,
                    'sources': self._translate_addresses_to_target(
                        peer_cidrs),
                    'destinations': self._translate_addresses_to_target(
                        local_cidrs)})

        return fw_rules

    def _update_firewall_rules(self, context, vpnservice):
        LOG.debug("Updating vpn firewall rules for router %s",
                  vpnservice['router_id'])
        self._core_plugin.update_router_firewall(
            context, vpnservice['router_id'])

    def _update_router_advertisement(self, context, vpnservice):
        LOG.debug("Updating router advertisement rules for router %s",
                  vpnservice['router_id'])

        router_id = vpnservice['router_id']
        # skip no-snat router as it is already advertised,
        # and router with no gw
        rtr = self.l3_plugin.get_router(context, router_id)
        if (not rtr.get('external_gateway_info') or
            not rtr['external_gateway_info'].get('enable_snat', True)):
            return

        rules = []

        # get all the active services of this router
        filters = {'router_id': [router_id], 'status': [constants.ACTIVE]}
        services = self.vpn_plugin.get_vpnservices(
            context.elevated(), filters=filters)
        for srv in services:
            # use only services with active connections
            filters = {'vpnservice_id': [srv['id']],
                       'status': [constants.ACTIVE]}
            connections = self.vpn_plugin.get_ipsec_site_connections(
                context.elevated(), filters=filters)
            if not connections:
                continue
            subnet = self.l3_plugin.get_subnet(
                context.elevated(), srv['subnet_id'])
            rules.append({
                'display_name': 'VPN advertisement service ' + srv['id'],
                'action': consts.FW_ACTION_ALLOW,
                'networks': [subnet['cidr']]})

        logical_router_id = db.get_nsx_router_id(context.session, router_id)
        self._nsxlib.logical_router.update_advertisement_rules(
            logical_router_id, rules)

    def _update_status(self, context, vpn_service_id, ipsec_site_conn_id,
                       status, updated_pending_status=True):
        ipsec_site_conn = {'status': status,
                           'updated_pending_status': updated_pending_status}
        vpn_status = {'id': vpn_service_id,
                      'updated_pending_status': updated_pending_status,
                      'status': status,
                      'ipsec_site_connections': {ipsec_site_conn_id:
                                                 ipsec_site_conn}}
        status_list = [vpn_status]
        self.service_plugin.update_status_by_agent(context, status_list)

    def _nsx_tags(self, context, connection):
        return self._nsxlib.build_v3_tags_payload(
            connection, resource_type='os-vpn-connection-id',
            project_name=context.tenant_name)

    def _nsx_tags_for_reused(self):
        # Service & Local endpoint can be reused cross tenants,
        # so we do not add the tenant/object id.
        return self._nsxlib.build_v3_api_version_tag()

    def _create_ike_profile(self, context, connection):
        """Create an ike profile for a connection"""
        # Note(asarfaty) the NSX profile can be reused, so we can consider
        # creating it only once in the future, and keeping a use-count for it.
        # There is no driver callback for profiles creation so it has to be
        # done on connection creation.
        ike_policy_id = connection['ikepolicy_id']
        ikepolicy = self.vpn_plugin.get_ikepolicy(context, ike_policy_id)
        try:
            profile = self._nsx_vpn.ike_profile.create(
                ikepolicy['name'],
                description=ikepolicy['description'],
                encryption_algorithm=ipsec_utils.ENCRYPTION_ALGORITHM_MAP[
                    ikepolicy['encryption_algorithm']],
                digest_algorithm=ipsec_utils.AUTH_ALGORITHM_MAP[
                    ikepolicy['auth_algorithm']],
                ike_version=ipsec_utils.IKE_VERSION_MAP[
                    ikepolicy['ike_version']],
                dh_group=ipsec_utils.PFS_MAP[ikepolicy['pfs']],
                sa_life_time=ikepolicy['lifetime']['value'],
                tags=self._nsx_tags(context, connection))
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create an ike profile: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)
        return profile['id']

    def _delete_ike_profile(self, ikeprofile_id):
        self._nsx_vpn.ike_profile.delete(ikeprofile_id)

    def _create_ipsec_profile(self, context, connection):
        """Create an ipsec profile for a connection"""
        # Note(asarfaty) the NSX profile can be reused, so we can consider
        # creating it only once in the future, and keeping a use-count for it.
        # There is no driver callback for profiles creation so it has to be
        # done on connection creation.
        ipsec_policy_id = connection['ipsecpolicy_id']
        ipsecpolicy = self.vpn_plugin.get_ipsecpolicy(
            context, ipsec_policy_id)

        try:
            profile = self._nsx_vpn.tunnel_profile.create(
                ipsecpolicy['name'],
                description=ipsecpolicy['description'],
                encryption_algorithm=ipsec_utils.ENCRYPTION_ALGORITHM_MAP[
                    ipsecpolicy['encryption_algorithm']],
                digest_algorithm=ipsec_utils.AUTH_ALGORITHM_MAP[
                    ipsecpolicy['auth_algorithm']],
                dh_group=ipsec_utils.PFS_MAP[ipsecpolicy['pfs']],
                pfs=True,
                sa_life_time=ipsecpolicy['lifetime']['value'],
                tags=self._nsx_tags(context, connection))
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a tunnel profile: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)
        return profile['id']

    def _delete_ipsec_profile(self, ipsecprofile_id):
        self._nsx_vpn.tunnel_profile.delete(ipsecprofile_id)

    def _create_dpd_profile(self, context, connection):
        dpd_info = connection['dpd']
        try:
            profile = self._nsx_vpn.dpd_profile.create(
                connection['name'][:240] + '-dpd-profile',
                description='neutron dpd profile',
                timeout=dpd_info.get('timeout'),
                enabled=True if dpd_info.get('action') == 'hold' else False,
                tags=self._nsx_tags(context, connection))
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a DPD profile: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return profile['id']

    def _delete_dpd_profile(self, dpdprofile_id):
        self._nsx_vpn.dpd_profile.delete(dpdprofile_id)

    def _update_dpd_profile(self, connection, dpdprofile_id):
        dpd_info = connection['dpd']
        self._nsx_vpn.dpd_profile.update(dpdprofile_id,
                timeout=dpd_info.get('timeout'),
                enabled=True if dpd_info.get('action') == 'hold' else False)

    def _create_peer_endpoint(self, context, connection, ikeprofile_id,
                              ipsecprofile_id, dpdprofile_id):
        default_auth = vpn_ipsec.AuthenticationModeTypes.AUTH_MODE_PSK
        try:
            peer_endpoint = self._nsx_vpn.peer_endpoint.create(
                connection['name'],
                connection['peer_address'],
                connection['peer_id'],
                description=connection['description'],
                authentication_mode=default_auth,
                dpd_profile_id=dpdprofile_id,
                ike_profile_id=ikeprofile_id,
                ipsec_tunnel_profile_id=ipsecprofile_id,
                connection_initiation_mode=ipsec_utils.INITIATION_MODE_MAP[
                    connection['initiator']],
                psk=connection['psk'],
                tags=self._nsx_tags(context, connection))
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a peer endpoint: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return peer_endpoint['id']

    def _update_peer_endpoint(self, peer_ep_id, connection):
        self._nsx_vpn.peer_endpoint.update(
            peer_ep_id,
            name=connection['name'],
            peer_address=connection['peer_address'],
            peer_id=connection['peer_id'],
            description=connection['description'],
            connection_initiation_mode=ipsec_utils.INITIATION_MODE_MAP[
                connection['initiator']],
            psk=connection['psk'])

    def _delete_peer_endpoint(self, peer_ep_id):
        self._nsx_vpn.peer_endpoint.delete(peer_ep_id)

    def _get_profiles_from_peer_endpoint(self, peer_ep_id):
        peer_ep = self._nsx_vpn.peer_endpoint.get(peer_ep_id)
        return (
            peer_ep['ike_profile_id'],
            peer_ep['ipsec_tunnel_profile_id'],
            peer_ep['dpd_profile_id'])

    def _create_local_endpoint(self, context, local_addr, nsx_service_id,
                               router_id):
        """Creating an NSX local endpoint for a logical router

        This endpoint can be reused by other connections, and will be deleted
        when the router is deleted or gateway is removed
        """
        # Add the neutron router-id to the tags to help search later
        tags = self._nsxlib.build_v3_tags_payload(
            {'id': router_id}, resource_type='os-neutron-router-id',
            project_name=context.tenant_name)

        try:
            local_endpoint = self._nsx_vpn.local_endpoint.create(
                'Local endpoint for OS VPNaaS',
                local_addr,
                nsx_service_id,
                tags=tags)
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a local endpoint: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return local_endpoint['id']

    def _search_local_endpint(self, router_id):
        tags = [{'scope': 'os-neutron-router-id', 'tag': router_id}]
        ep_list = self._nsxlib.search_by_tags(
            tags=tags,
            resource_type=self._nsx_vpn.local_endpoint.resource_type)
        if ep_list['results']:
            return ep_list['results'][0]['id']

    def _get_local_endpoint(self, context, connection, vpnservice):
        """Get the id of the local endpoint for a service

        The NSX allows only one local endpoint per local address
        This method will create it if there is not matching endpoint
        """
        # use the router GW as the local ip
        router_id = vpnservice['router']['id']

        # check if we already have this endpoint on the NSX
        local_ep_id = self._search_local_endpint(router_id)
        if local_ep_id:
            return local_ep_id

        # create a new one
        local_addr = vpnservice['external_v4_ip']
        nsx_service_id = self._get_nsx_vpn_service(context, vpnservice)
        local_ep_id = self._create_local_endpoint(
            context, local_addr, nsx_service_id, router_id)
        return local_ep_id

    def _find_vpn_service_port(self, context, router_id):
        """Look for the neutron port created for the vpnservice of a router"""
        filters = {'device_id': [router_id],
                   'device_owner': [VPN_PORT_OWNER]}
        ports = self.l3_plugin.get_ports(context, filters=filters)
        if ports:
            return ports[0]

    def _delete_local_endpoint(self, resource, event, trigger, **kwargs):
        """Upon router deletion / gw removal delete the matching endpoint"""
        router_id = kwargs.get('router_id')
        # delete the local endpoint from the NSX
        local_ep_id = self._search_local_endpint(router_id)
        if local_ep_id:
            self._nsx_vpn.local_endpoint.delete(local_ep_id)
        # delete the neutron port with this IP
        ctx = n_context.get_admin_context()
        port = self._find_vpn_service_port(ctx, router_id)
        if port:
            self.l3_plugin.delete_port(ctx, port['id'])

    def validate_router_gw_info(self, context, router_id, gw_info):
        """Upon router gw update - verify no-snat"""
        # ckeck if this router has a vpn service
        filters = {'router_id': [router_id],
                   'status': [constants.ACTIVE]}
        services = self.vpn_plugin.get_vpnservices(
            context.elevated(), filters=filters)
        if services:
            # do not allow enable-snat
            if (gw_info and
                gw_info.get('enable_snat', cfg.CONF.enable_snat_by_default)):
                raise RouterWithSNAT(router_id=router_id)

    def _get_session_rules(self, context, connection, vpnservice):
        # TODO(asarfaty): support vpn-endpoint-groups too
        peer_cidrs = connection['peer_cidrs']
        local_cidrs = [vpnservice['subnet']['cidr']]
        rule = self._nsx_vpn.session.get_rule_obj(local_cidrs, peer_cidrs)
        return [rule]

    def _create_session(self, context, connection, local_ep_id,
                        peer_ep_id, rules):
        try:
            session = self._nsx_vpn.session.create(
                connection['name'], local_ep_id, peer_ep_id, rules,
                description=connection['description'],
                tags=self._nsx_tags(context, connection))
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a session: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return session['id']

    def _update_session(self, session_id, connection, rules):
        self._nsx_vpn.session.update(
            session_id,
            name=connection['name'],
            description=connection['description'],
            policy_rules=rules)

    def _delete_session(self, session_id):
        self._nsx_vpn.session.delete(session_id)

    def create_ipsec_site_connection(self, context, ipsec_site_conn):
        LOG.debug('Creating ipsec site connection %(conn_info)s.',
                  {"conn_info": ipsec_site_conn})
        # Note(asarfaty) the plugin already calls the validator
        # which also validated the policies and service

        ikeprofile_id = None
        ipsecprofile_id = None
        dpdprofile_id = None
        peer_ep_id = None
        session_id = None
        vpnservice_id = ipsec_site_conn['vpnservice_id']
        vpnservice = self.service_plugin._get_vpnservice(
            context, vpnservice_id)
        ipsec_id = ipsec_site_conn["id"]

        try:
            # create the ike profile
            ikeprofile_id = self._create_ike_profile(
                context, ipsec_site_conn)
            LOG.debug("Created NSX ike profile %s", ikeprofile_id)

            # create the ipsec profile
            ipsecprofile_id = self._create_ipsec_profile(
                context, ipsec_site_conn)
            LOG.debug("Created NSX ipsec profile %s", ipsecprofile_id)

            # create the dpd profile
            dpdprofile_id = self._create_dpd_profile(
                context, ipsec_site_conn)
            LOG.debug("Created NSX dpd profile %s", dpdprofile_id)

            # create the peer endpoint and add to the DB
            peer_ep_id = self._create_peer_endpoint(
                context, ipsec_site_conn,
                ikeprofile_id, ipsecprofile_id, dpdprofile_id)
            LOG.debug("Created NSX peer endpoint %s", peer_ep_id)

            # create or reuse a local endpoint using the vpn service
            local_ep_id = self._get_local_endpoint(
                context, ipsec_site_conn, vpnservice)

            # Finally: create the session with policy rules
            rules = self._get_session_rules(
                context, ipsec_site_conn, vpnservice)
            session_id = self._create_session(
                context, ipsec_site_conn, local_ep_id, peer_ep_id, rules)

            # update the DB with the session id
            db.add_nsx_vpn_connection_mapping(
                context.session, ipsec_site_conn['id'], session_id,
                dpdprofile_id, ikeprofile_id, ipsecprofile_id, peer_ep_id)

            self._update_status(context, vpnservice_id, ipsec_id,
                                constants.ACTIVE)

        except nsx_exc.NsxPluginException:
            with excutils.save_and_reraise_exception():
                self._update_status(context, vpnservice_id, ipsec_id,
                                    constants.ERROR)

                # delete the NSX objects that were already created
                # Do not delete reused objects: service, local endpoint
                if session_id:
                    self._delete_session(session_id)
                if peer_ep_id:
                    self._delete_peer_endpoint(peer_ep_id)
                if dpdprofile_id:
                    self._delete_dpd_profile(dpdprofile_id)
                if ipsecprofile_id:
                    self._delete_ipsec_profile(ipsecprofile_id)
                if ikeprofile_id:
                    self._delete_ike_profile(ikeprofile_id)

        # update router firewall rules
        self._update_firewall_rules(context, vpnservice)

        # update router advertisement rules
        self._update_router_advertisement(context, vpnservice)

    def delete_ipsec_site_connection(self, context, ipsec_site_conn):
        LOG.debug('Deleting ipsec site connection %(site)s.',
                  {"site": ipsec_site_conn})

        vpnservice_id = ipsec_site_conn['vpnservice_id']
        vpnservice = self.service_plugin._get_vpnservice(
            context, vpnservice_id)

        # get all data from the nsx based on the connection id in the DB
        mapping = db.get_nsx_vpn_connection_mapping(
            context.session, ipsec_site_conn['id'])
        if not mapping:
            LOG.warning("Couldn't find nsx ids for VPN connection %s",
                      ipsec_site_conn['id'])
            # Do not fail the deletion
            return

        if mapping['session_id']:
            self._delete_session(mapping['session_id'])
        if mapping['peer_ep_id']:
            self._delete_peer_endpoint(mapping['peer_ep_id'])
        if mapping['dpd_profile_id']:
            self._delete_dpd_profile(mapping['dpd_profile_id'])
        if mapping['ipsec_profile_id']:
            self._delete_ipsec_profile(mapping['ipsec_profile_id'])
        if mapping['ike_profile_id']:
            self._delete_ike_profile(mapping['ike_profile_id'])

        # Do not delete the local endpoint and service as they are reused
        db.delete_nsx_vpn_connection_mapping(context.session,
                                             ipsec_site_conn['id'])
        # update router firewall rules
        self._update_firewall_rules(context, vpnservice)

        # update router advertisement rules
        self._update_router_advertisement(context, vpnservice)

    def update_ipsec_site_connection(self, context, old_ipsec_conn,
                                     ipsec_site_conn):
        LOG.debug('Updating ipsec site connection new %(site)s.',
                  {"site": ipsec_site_conn})
        LOG.debug('Updating ipsec site connection old %(site)s.',
                  {"site": old_ipsec_conn})

        # Note(asarfaty) the plugin already calls the validator
        # which also validated the policies and service

        ipsec_id = old_ipsec_conn['id']
        vpnservice_id = old_ipsec_conn['vpnservice_id']
        vpnservice = self.service_plugin._get_vpnservice(
            context, vpnservice_id)
        mapping = db.get_nsx_vpn_connection_mapping(
            context.session, ipsec_site_conn['id'])
        if not mapping:
            LOG.error("Couldn't find nsx ids for VPN connection %s",
                      ipsec_site_conn['id'])
            self._update_status(context, vpnservice_id, ipsec_id, "ERROR")
            raise nsx_exc.NsxIPsecVpnMappingNotFound(conn=ipsec_id)

        update_all = (old_ipsec_conn['name'] != ipsec_site_conn['name'] or
                      old_ipsec_conn['description'] !=
                      ipsec_site_conn['description'])
        # check if the dpd configuration changed
        old_dpd = old_ipsec_conn['dpd']
        new_dpd = ipsec_site_conn['dpd']
        if (old_dpd['action'] != new_dpd['action'] or
            old_dpd['timeout'] != new_dpd['timeout'] or
            update_all):
            self._update_dpd_profile(ipsec_site_conn,
                                     mapping['dpd_profile_id'])

        # update peer endpoint with all the parameters that could be modified
        # Note(asarfaty): local endpoints are reusable and will not be updated
        self._update_peer_endpoint(mapping['peer_ep_id'], ipsec_site_conn)
        rules = self._get_session_rules(
            context, ipsec_site_conn, vpnservice)
        self._update_session(mapping['session_id'], ipsec_site_conn, rules)

        if 'peer_cidrs' in ipsec_site_conn:
            # Update firewall
            self._update_firewall_rules(context, vpnservice)

        # No service updates. No need to update router advertisement rules

    def _create_vpn_service(self, tier0_uuid):
        try:
            service = self._nsx_vpn.service.create(
                'Neutron VPN service for router ' + tier0_uuid,
                tier0_uuid,
                enabled=True,
                ike_log_level=ipsec_utils.DEFAULT_LOG_LEVEL,
                tags=self._nsx_tags_for_reused())
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create vpn service: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return service['id']

    def _get_tier0_uuid(self, context, router_id):
        router_db = self._core_plugin._get_router(context, router_id)
        return self._core_plugin._get_tier0_uuid_by_router(context, router_db)

    def _get_router_ext_gw(self, context, router_id):
        router_db = self._core_plugin.get_router(context, router_id)
        gw = router_db['external_gateway_info']
        return gw['external_fixed_ips'][0]["ip_address"]

    def _find_vpn_service(self, tier0_uuid):
        # find the service for the tier0 router in the NSX.
        # Note(asarfaty) we expect only a small number of services
        services = self._nsx_vpn.service.list()['results']
        for srv in services:
            if srv['logical_router_id'] == tier0_uuid:
                # if it exists but disabled: issue an error
                if not srv.get('enabled', True):
                    msg = _("NSX vpn service %s must be enabled") % srv['id']
                    raise nsx_exc.NsxPluginException(err_msg=msg)
                return srv['id']

    def _create_vpn_service_if_needed(self, context, vpnservice):
        # The service is created on the TIER0 router attached to the router GW
        # The NSX can keep only one service per tier0 router so we reuse it
        router_id = vpnservice['router_id']
        tier0_uuid = self._get_tier0_uuid(context, router_id)
        if self._find_vpn_service(tier0_uuid):
            return

        # create a new one
        self._create_vpn_service(tier0_uuid)

    def _get_nsx_vpn_service(self, context, vpnservice):
        router_id = vpnservice['router_id']
        tier0_uuid = self._get_tier0_uuid(context, router_id)
        return self._find_vpn_service(tier0_uuid)

    def _get_service_local_address(self, context, vpnservice):
        """Find/Allocate a port on the external network

        to save the ip to be used as the local ip of this service
        """
        router_id = vpnservice.router['id']
        # check if this router already have an IP
        port = self._find_vpn_service_port(context, router_id)
        if not port:
            # create a new port, on the external network of the router
            ext_net = vpnservice.router.gw_port['network_id']
            port_data = {
                'port': {
                    'network_id': ext_net,
                    'name': None,
                    'admin_state_up': True,
                    'device_id': vpnservice.router['id'],
                    'device_owner': VPN_PORT_OWNER,
                    'fixed_ips': constants.ATTR_NOT_SPECIFIED,
                    'mac_address': constants.ATTR_NOT_SPECIFIED,
                    'port_security_enabled': False,
                    'tenant_id': vpnservice['tenant_id']}}
            port = self.l3_plugin.base_create_port(context, port_data)
        # return the port ip as the local address
        return port['fixed_ips'][0]['ip_address']

    def create_vpnservice(self, context, vpnservice):
        #TODO(asarfaty) support vpn-endpoint-group-create for local & peer
        # cidrs too
        LOG.debug('Creating VPN service %(vpn)s', {'vpn': vpnservice})
        vpnservice_id = vpnservice['id']
        vpnservice = self.service_plugin._get_vpnservice(context,
                                                         vpnservice_id)
        try:
            self.validator.validate_vpnservice(context, vpnservice)
            local_address = self._get_service_local_address(
                context, vpnservice)
        except Exception:
            with excutils.save_and_reraise_exception():
                # Rolling back change on the neutron
                self.service_plugin.delete_vpnservice(context, vpnservice_id)

        vpnservice['external_v4_ip'] = local_address
        self.service_plugin.set_external_tunnel_ips(context,
                                                    vpnservice_id,
                                                    v4_ip=local_address)
        self._create_vpn_service_if_needed(context, vpnservice)

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        # No meaningful field can change here
        pass

    def delete_vpnservice(self, context, vpnservice):
        # Do not delete the NSX service or DB entry as those will be reused.
        pass
