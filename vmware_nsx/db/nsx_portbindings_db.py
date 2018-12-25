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

from oslo_log import log as logging
from oslo_serialization import jsonutils

from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import portbindings as pbin
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as p_utils

from neutron.db import portbindings_db as pbin_db
from neutron.plugins.ml2 import models as pbin_model
from vmware_nsx._i18n import _
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils as c_utils
from vmware_nsx.db import nsxv_db
from vmware_nsx.extensions import projectpluginmap


LOG = logging.getLogger(__name__)

FLAT_VLAN = 0
SUPPORTED_VNIC_TYPES = (pbin.VNIC_NORMAL,
                        pbin.VNIC_DIRECT,
                        pbin.VNIC_DIRECT_PHYSICAL)

VNIC_TYPES_DIRECT_PASSTHROUGH = (pbin.VNIC_DIRECT, pbin.VNIC_DIRECT_PHYSICAL)
SUPPORTED_V_NETWORK_TYPES = (c_utils.NsxVNetworkTypes.VLAN,
                             c_utils.NsxVNetworkTypes.FLAT,
                             c_utils.NsxVNetworkTypes.PORTGROUP)
SUPPORTED_T_NETWORK_TYPES = (c_utils.NsxV3NetworkTypes.VLAN,
                             c_utils.NsxV3NetworkTypes.FLAT)


#Note(asarfaty): This class is currently used also by the NSX-V3 plugin,
# although it uses the NsxvPortExtAttributes DB table (which can be renamed
# in the future)
@resource_extend.has_resource_extenders
class NsxPortBindingMixin(pbin_db.PortBindingMixin):

    def _validate_port_vnic_type(
        self, context, port_data, network_id,
        plugin_type=projectpluginmap.NsxPlugins.NSX_V):
        vnic_type = port_data.get(pbin.VNIC_TYPE)

        if vnic_type and vnic_type not in SUPPORTED_VNIC_TYPES:
            err_msg = _("Invalid port vnic-type '%(vnic_type)s'."
                        "Supported vnic-types are %(valid_types)s"
                        ) % {'vnic_type': vnic_type,
                             'valid_types': SUPPORTED_VNIC_TYPES}
            raise exceptions.InvalidInput(error_message=err_msg)
        direct_vnic_type = vnic_type in VNIC_TYPES_DIRECT_PASSTHROUGH
        if direct_vnic_type:
            self._validate_vnic_type_direct_passthrough_for_network(
                context, network_id, plugin_type)
        return direct_vnic_type

    def _validate_vnic_type_direct_passthrough_for_network(self,
                                                           context,
                                                           network_id,
                                                           plugin_type):
        supported_network_types = SUPPORTED_V_NETWORK_TYPES
        if plugin_type == projectpluginmap.NsxPlugins.NSX_T:
            supported_network_types = SUPPORTED_T_NETWORK_TYPES

        if not self._validate_network_type(context, network_id,
                                           supported_network_types):
            msg_info = {
                'vnic_types': VNIC_TYPES_DIRECT_PASSTHROUGH,
                'networks': supported_network_types}
            err_msg = _("%(vnic_types)s port vnic-types are only supported "
                        "for ports on networks of types "
                        "%(networks)s") % msg_info
            raise exceptions.InvalidInput(error_message=err_msg)

    def _process_portbindings_create_and_update(
        self, context, port, port_res,
        vif_type=nsx_constants.VIF_TYPE_DVS):
        super(NsxPortBindingMixin,
              self)._process_portbindings_create_and_update(
                  context, port, port_res)

        port_id = port_res['id']
        org_vnic_type = nsxv_db.get_nsxv_ext_attr_port_vnic_type(
            context.session, port_id)
        vnic_type = port.get(pbin.VNIC_TYPE, org_vnic_type)
        cap_port_filter = (port.get(pbin.VNIC_TYPE, org_vnic_type) ==
                           pbin.VNIC_NORMAL)
        vif_details = {pbin.CAP_PORT_FILTER: cap_port_filter}
        network = self.get_network(context, port_res['network_id'])
        if network.get(pnet.NETWORK_TYPE) == c_utils.NsxVNetworkTypes.FLAT:
            vif_details[pbin.VIF_DETAILS_VLAN] = FLAT_VLAN
        elif network.get(pnet.NETWORK_TYPE) == c_utils.NsxVNetworkTypes.VLAN:
            vif_details[pbin.VIF_DETAILS_VLAN] = network[pnet.SEGMENTATION_ID]

        with db_api.CONTEXT_WRITER.using(context):
            port_binding = context.session.query(
                pbin_model.PortBinding).filter_by(port_id=port_id).first()

            if not port_binding:
                port_binding = pbin_model.PortBinding(
                    port_id=port_id,
                    vif_type=vif_type)
                context.session.add(port_binding)

            port_binding.host = port_res[pbin.HOST_ID] or ''
            port_binding.vnic_type = vnic_type
            port_binding.vif_details = jsonutils.dumps(vif_details)
            nsxv_db.update_nsxv_port_ext_attributes(
                context.session, port_id, vnic_type)

            profile = port.get(pbin.PROFILE, constants.ATTR_NOT_SPECIFIED)
            if validators.is_attr_set(profile) or profile is None:
                port_binding.profile = (jsonutils.dumps(profile)
                                        if profile else "")

            port_res[pbin.VNIC_TYPE] = vnic_type
        self.extend_port_portbinding(port_res, port_binding)

    def extend_port_portbinding(self, port_res, binding):
        port_res[pbin.PROFILE] = self._get_profile(binding)
        port_res[pbin.VIF_TYPE] = binding.vif_type
        port_res[pbin.VIF_DETAILS] = self._get_vif_details(binding)

    def _get_vif_details(self, binding):
        if binding.vif_details:
            try:
                return jsonutils.loads(binding.vif_details)
            except Exception:
                LOG.error("Serialized vif_details DB value '%(value)s' "
                          "for port %(port)s is invalid",
                          {'value': binding.vif_details,
                           'port': binding.port_id})
        return {}

    def _get_profile(self, binding):
        if binding.profile:
            try:
                return jsonutils.loads(binding.profile)
            except Exception:
                LOG.error("Serialized profile DB value '%(value)s' for "
                          "port %(port)s is invalid",
                          {'value': binding.profile,
                           'port': binding.port_id})
        return {}

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _extend_port_portbinding(port_res, port_db):
        plugin = directory.get_plugin()
        plugin.extend_port_dict_binding(port_res, port_db)

        if port_db.nsx_port_attributes:
            port_res[pbin.VNIC_TYPE] = port_db.nsx_port_attributes.vnic_type

        if hasattr(port_db, 'port_bindings'):
            binding = p_utils.get_port_binding_by_status_and_host(
                port_db.port_bindings, constants.ACTIVE)

            if binding:
                plugin.extend_port_portbinding(port_res, binding)
