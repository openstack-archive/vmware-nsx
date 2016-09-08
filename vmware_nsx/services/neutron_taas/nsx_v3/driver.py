# Copyright 2016 VMware, Inc.
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

import netaddr

from neutron import manager

from neutron_taas.db import taas_db
from neutron_taas.services.taas import service_drivers as base_driver

from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _, _LE, _LW
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.nsxlib import v3 as nsxlib
from vmware_nsx.nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsx.nsxlib.v3 import resources as nsx_resources

LOG = logging.getLogger(__name__)


class NsxV3Driver(base_driver.TaasBaseDriver,
                  taas_db.Taas_db_Mixin):

    """Class to handle API calls for Port Mirroring and NSXv3 backend."""

    def __init__(self, service_plugin):
        LOG.debug("Loading TaaS NsxV3Driver.")
        super(NsxV3Driver, self).__init__(service_plugin)

    @property
    def _nsx_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _validate_tap_flow(self, source_port, dest_port):
        # Verify whether the source port is not same as the destination port
        if source_port['id'] == dest_port['id']:
            msg = (_("Destination port %(dest)s is same as source port "
                     "%(src)s") % {'dest': dest_port['id'],
                                   'src': source_port['id']})
            raise nsx_exc.NsxTaaSDriverException(msg=msg)

    def create_tap_service_precommit(self, context):
        pass

    def create_tap_service_postcommit(self, context):
        pass

    def delete_tap_service_precommit(self, context):
        pass

    def delete_tap_service_postcommit(self, context):
        pass

    def create_tap_flow_precommit(self, context):
        """Validate and create database entries for creation of tap flow."""
        tf = context.tap_flow
        # Retrieve source port details.
        source_port = self._get_port_details(
            context._plugin_context, tf.get('source_port'))
        # Retrieve tap service and destination port details.
        ts = self._get_tap_service(
            context._plugin_context, tf.get('tap_service_id'))
        dest_port = self._get_port_details(
            context._plugin_context, ts.get('port_id'))
        self._validate_tap_flow(source_port, dest_port)

    def _convert_to_backend_direction(self, direction):
        nsx_direction = None
        if direction == 'BOTH':
            nsx_direction = 'BIDIRECTIONAL'
        elif direction == 'IN':
            nsx_direction = 'INGRESS'
        elif direction == 'OUT':
            nsx_direction = 'EGRESS'
        return nsx_direction

    def _convert_to_backend_source_port(self, session, port_id):
        nsx_port_id = nsx_db.get_nsx_switch_and_port_id(session, port_id)[1]
        return [{"resource_type": "LogicalPortMirrorSource",
                 "port_ids": [nsx_port_id]}]

    def _convert_to_backend_dest_port(self, session, port_id):
        nsx_port_id = nsx_db.get_nsx_switch_and_port_id(session, port_id)[1]
        return {"resource_type": "LogicalPortMirrorDestination",
                "port_ids": [nsx_port_id]}

    def _is_local_span(self, context, src_port_id, dest_port_id):
        """Verify whether the mirror session is Local or L3SPAN."""
        # TODO(abhiraut): Create only L3SPAN until we find a way to
        #                 detect local SPAN support from backend.
        return False

    def _update_port_at_backend(self, context, port_id, switching_profile,
                                delete_profile):
        """Update a logical port on the backend."""
        port = self._get_port_details(context._plugin_context,
                                      port_id)
        # Retrieve logical port ID based on neutron port ID.
        nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
            session=context._plugin_context.session,
            neutron_id=port_id)[1]
        # Retrieve source logical port from the backend.
        nsx_port = self._nsx_plugin._port_client.get(nsx_port_id)
        if delete_profile:
            # Prepare switching profile resources retrieved from backend
            # and pop the port mirror switching profile.
            switching_profile_ids = self._prepare_switch_profiles(
                nsx_port.get('switching_profile_ids', []),
                switching_profile)
        else:
            # Prepare switching profile resources retrieved from backend.
            switching_profile_ids = self._prepare_switch_profiles(
                nsx_port.get('switching_profile_ids', []))
            # Update body with PortMirroring switching profile.
            switching_profile_ids.append(
                self._get_switching_profile_resource(
                    switching_profile['id'],
                    nsx_resources.SwitchingProfileTypes.PORT_MIRRORING))
        address_bindings = self._nsx_plugin._build_address_bindings(port)
        #NOTE(abhiraut): Consider passing attachment_type
        self._nsx_plugin._port_client.update(
            lport_id=nsx_port.get('id'),
            vif_uuid=port_id,
            name=nsx_port.get('display_name'),
            admin_state=nsx_port.get('admin_state'),
            address_bindings=address_bindings,
            switch_profile_ids=switching_profile_ids,)

    def _prepare_switch_profiles(self, profiles, deleted_profile=None):
        switch_profile_ids = []
        if not deleted_profile:
            for profile in profiles:
                # profile is a dict of type {'key': profile_type,
                #                            'value': profile_id}
                profile_resource = self._get_switching_profile_resource(
                    profile_id=profile['value'],
                    profile_type=profile['key'])
                switch_profile_ids.append(profile_resource)
        else:
            for profile in profiles:
                if profile['value'] == deleted_profile['id']:
                    continue
                profile_resource = self._get_switching_profile_resource(
                    profile_id=profile['value'],
                    profile_type=profile['key'])
                switch_profile_ids.append(profile_resource)
        return switch_profile_ids

    def _get_switching_profile_resource(self, profile_id, profile_type):
        return nsx_resources.SwitchingProfileTypeId(
            profile_type=profile_type,
            profile_id=profile_id)

    def create_tap_flow_postcommit(self, context):
        """Create tap flow and port mirror session on NSX backend."""
        tf = context.tap_flow
        # Retrieve tap service.
        ts = self._get_tap_service(context._plugin_context,
                                   tf.get('tap_service_id'))
        src_port_id = tf.get('source_port')
        dest_port_id = ts.get('port_id')
        tags = nsx_utils.build_v3_tags_payload(
                tf, resource_type='os-neutron-mirror-id',
                project_name=context._plugin_context.tenant_name)
        nsx_direction = self._convert_to_backend_direction(
            tf.get('direction'))
        # Create a port mirroring session object if local SPAN. Otherwise
        # create a port mirroring switching profile for L3SPAN.
        if self._is_local_span(context, src_port_id, dest_port_id):
            self._create_local_span(context, src_port_id, dest_port_id,
                                    nsx_direction, tags)
        else:
            self._create_l3span(context, src_port_id, dest_port_id,
                                nsx_direction, tags)

    def _create_l3span(self, context, src_port_id, dest_port_id, direction,
                       tags):
        """Create a PortMirroring SwitchingProfile for L3SPAN."""
        tf = context.tap_flow
        # Verify whether destination port is L3 reachable. i.e. destination
        # port has a floating IP address.
        fips = self._nsx_plugin.get_floatingips(
            context._plugin_context, filters={'port_id': [dest_port_id]})
        if not fips:
            msg = (_("Destination port %s must have a floating IP for "
                     "L3 SPAN") % dest_port_id)
            raise nsx_exc.NsxTaaSDriverException(msg=msg)
        destinations = []
        # Retrieve destination port's IP addresses and add it to the list
        # since the backend expects a list of IP addresses.
        for fip in fips:
            # NOTE(abhiraut): nsx-v3 doesn't seem to handle ipv6 addresses
            # currently so for now we remove them here and do not pass
            # them to the backend which would raise an error.
            if netaddr.IPNetwork(fip['floating_ip_address']).version == 6:
                LOG.warning(_LW("Skipping IPv6 address %(ip)s for L3SPAN "
                                "tap flow: %(tap_flow)s"),
                            {'tap_flow': tf['id'],
                             'ip': fip['floating_ip_address']})
                continue
            destinations.append(fip['floating_ip_address'])
        # Create a switch profile in the backend.
        try:
            port_mirror_profile = (self._nsx_plugin._switching_profiles.
                                   create_port_mirror_profile(
                                       display_name=tf.get('name'),
                                       description=tf.get('description'),
                                       direction=direction,
                                       destinations=destinations,
                                       tags=tags))
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to create port mirror switch profile "
                              "for tap flow %s on NSX backend, rolling back "
                              "changes on neutron."), tf['id'])
        # Create internal mappings between tap flow and port mirror switch
        # profile. Ideally DB transactions must take place in precommit, but
        # we rely on the NSX backend to retrieve the port mirror profile UUID,
        # we perform the create action in postcommit.
        try:
            nsx_db.add_port_mirror_session_mapping(
                session=context._plugin_context.session,
                tf_id=tf['id'],
                pm_session_id=port_mirror_profile['id'])
        except db_exc.DBError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to create port mirror session db "
                              "mappings for tap flow %s. Rolling back "
                              "changes in Neutron."), tf['id'])
                self._nsx_plugin._switching_profiles.delete(
                    port_mirror_profile['id'])
        # Update the source port to include the port mirror switch profile.
        try:
            self._update_port_at_backend(context=context, port_id=src_port_id,
                                         switching_profile=port_mirror_profile,
                                         delete_profile=False)
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to update source port %(port)s with "
                              "switching profile %(profile) for tap flow "
                              "%(tap_flow)s on NSX backend, rolling back "
                              "changes on neutron."),
                          {'tap_flow': tf['id'],
                           'port': src_port_id,
                           'profile': port_mirror_profile['id']})
                self._nsx_plugin._switching_profiles.delete(
                    port_mirror_profile['id'])

    def _create_local_span(self, context, src_port_id, dest_port_id,
                           direction, tags):
        """Create a PortMirroring session on the backend for local SPAN."""
        tf = context.tap_flow
        # Backend expects a list of source ports and destination ports.
        # Due to TaaS API requirements, we are only able to add one port
        # as a source port and one port as a destination port in a single
        # request. Hence we send a list of one port for source_ports
        # and dest_ports.
        nsx_src_ports = self._convert_to_backend_source_port(
            context._plugin_context.session, src_port_id)
        nsx_dest_ports = self._convert_to_backend_dest_port(
            context._plugin_context.session, dest_port_id)
        # Create port mirror session on the backend
        try:
            pm_session = nsxlib.NsxLib().create_port_mirror_session(
                source_ports=nsx_src_ports,
                dest_ports=nsx_dest_ports,
                direction=direction,
                description=tf.get('description'),
                name=tf.get('name'),
                tags=tags)
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to create port mirror session %s "
                              "on NSX backend, rolling back "
                              "changes on neutron."), tf['id'])
        # Create internal mappings between tap flow and port mirror session.
        # Ideally DB transactions must take place in precommit, but since we
        # rely on the NSX backend to retrieve the port session UUID, we perform
        # the create action in postcommit.
        try:
            nsx_db.add_port_mirror_session_mapping(
                session=context._plugin_context.session,
                tf_id=tf['id'],
                pm_session_id=pm_session['id'])
        except db_exc.DBError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to create port mirror session db "
                              "mappings for tap flow %s. Rolling back "
                              "changes in Neutron."), tf['id'])
                nsxlib.NsxLib().delete_port_mirror_session(pm_session['id'])

    def delete_tap_flow_precommit(self, context):
        pass

    def delete_tap_flow_postcommit(self, context):
        """Delete tap flow and port mirror session on NSX backend."""
        tf = context.tap_flow
        ts = self._get_tap_service(context._plugin_context,
                                   tf.get('tap_service_id'))
        # Retrieve port mirroring session mappings.
        pm_session_mapping = nsx_db.get_port_mirror_session_mapping(
            session=context._plugin_context.session,
            tf_id=tf['id'])
        src_port_id = tf.get('source_port')
        dest_port_id = ts.get('port_id')
        if self._is_local_span(context, src_port_id, dest_port_id):
            self._delete_local_span(
                context, pm_session_mapping['port_mirror_session_id'])
        else:
            self._delete_l3span(
                context, pm_session_mapping['port_mirror_session_id'])
        # Delete internal mappings between tap flow and port mirror session.
        # Ideally DB transactions must take place in precommit, but since we
        # rely on the DB mapping to retrieve NSX backend UUID for the port
        # session mapping, we perform the delete action in postcommit.
        try:
            nsx_db.delete_port_mirror_session_mapping(
                session=context._plugin_context.session,
                tf_id=tf['id'])
        except db_exc.DBError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to delete port mirror session db "
                              "mappings %(pm)s for tap flow %(tf)s"), tf['id'])

    def _delete_l3span(self, context, pm_profile_id):
        tf = context.tap_flow
        src_port_id = tf.get('source_port')
        port_mirror_profile = self._nsx_plugin._switching_profiles.get(
            uuid=pm_profile_id)
        try:
            # Update source port and remove L3 switching profile.
            self._update_port_at_backend(context=context, port_id=src_port_id,
                                         switching_profile=port_mirror_profile,
                                         delete_profile=True)
        except nsxlib_exc.ManagerError:
            LOG.error(_LE("Unable to update source port %(port)s "
                          "to delete port mirror profile %(pm)s on NSX "
                          "backend."),
                      {'pm': pm_profile_id,
                      'port': src_port_id})
        try:
            # Delete port mirroring switching profile
            self._nsx_plugin._switching_profiles.delete(uuid=pm_profile_id)
        except nsxlib_exc.ManagerError:
            LOG.error(_LE("Unable to delete port mirror switching profile "
                          "%s on NSX backend."), pm_profile_id)

    def _delete_local_span(self, context, pm_session_id):
        # Delete port mirroring session on the backend
        try:
            nsxlib.delete_port_mirror_session(pm_session_id)
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to delete port mirror session %s "
                              "on NSX backend."), pm_session_id)
