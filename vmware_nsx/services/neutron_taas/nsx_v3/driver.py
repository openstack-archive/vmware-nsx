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

from neutron_taas.db import taas_db
from neutron_taas.services.taas import service_drivers as base_driver

from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _, _LE
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.nsxlib import v3 as nsxlib

LOG = logging.getLogger(__name__)


class NsxV3Driver(base_driver.TaasBaseDriver,
                  taas_db.Taas_db_Mixin):

    """Class to handle API calls for Port Mirroring and NSXv3 backend."""

    def __init__(self, service_plugin):
        LOG.debug("Loading TaaS NsxV3Driver.")
        super(NsxV3Driver, self).__init__(service_plugin)

    def _validate_tap_flow(self, source_port, dest_port):
        # Verify whether the source port and monitored port belong to the
        # same network.
        if source_port['network_id'] != dest_port['network_id']:
            msg = (_("Destination port %(dest)s and source port %(src)s "
                     "should be on the same network") %
                   {'dest': dest_port['id'], 'src': source_port['id']})
            raise nsx_exc.NsxTaaSDriverException(msg=msg)
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

    def create_tap_flow_postcommit(self, context):
        """Create tap flow and port mirror session on NSX backend."""
        tf = context.tap_flow
        # Retrieve tap service.
        ts = self._get_tap_service(context._plugin_context,
                                   tf.get('tap_service_id'))
        tags = nsx_utils.build_v3_tags_payload(
                tf, resource_type='os-neutron-mirror-id',
                project_name=context._plugin_context.tenant_name)
        nsx_direction = self._convert_to_backend_direction(
            tf.get('direction'))
        # Backend expects a list of source ports and destination ports.
        # Due to TaaS API requirements, we are only able to add one port
        # as a source port and one port as a destination port in a single
        # request. Hence we send a list of one port for source_ports
        # and dest_ports.
        nsx_src_ports = self._convert_to_backend_source_port(
            context._plugin_context.session, tf.get('source_port'))
        nsx_dest_ports = self._convert_to_backend_dest_port(
            context._plugin_context.session, ts.get('port_id'))
        # Create port mirror session on the backend
        try:
            pm_session = nsxlib.create_port_mirror_session(
                source_ports=nsx_src_ports,
                dest_ports=nsx_dest_ports,
                direction=nsx_direction,
                description=tf.get('description'),
                name=tf.get('name'),
                tags=tags)
        except nsx_exc.ManagerError:
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
                nsxlib.delete_port_mirror_session(pm_session['id'])

    def delete_tap_flow_precommit(self, context):
        pass

    def delete_tap_flow_postcommit(self, context):
        """Delete tap flow and port mirror session on NSX backend."""
        tf = context.tap_flow
        # Retrieve port mirroring session mappings.
        pm_session_mapping = nsx_db.get_port_mirror_session_mapping(
            session=context._plugin_context.session,
            tf_id=tf['id'])
        # Delete port mirroring session on the backend
        try:
            nsxlib.delete_port_mirror_session(
                pm_session_mapping['port_mirror_session_id'])
        except nsx_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to delete port mirror session %s "
                              "on NSX backend."),
                          pm_session_mapping['port_mirror_session_id'])
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
                              "mappings for tap flow %s"), tf['id'])
