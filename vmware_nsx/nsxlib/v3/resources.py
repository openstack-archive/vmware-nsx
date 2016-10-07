# Copyright 2015 VMware, Inc.
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
#
import abc
import collections
import six

from oslo_config import cfg

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils
from vmware_nsx.nsxlib.v3 import client


SwitchingProfileTypeId = collections.namedtuple(
    'SwitchingProfileTypeId', 'profile_type, profile_id')


PacketAddressClassifier = collections.namedtuple(
    'PacketAddressClassifier', 'ip_address, mac_address, vlan')


@six.add_metaclass(abc.ABCMeta)
class AbstractRESTResource(object):

    def __init__(self, rest_client, *args, **kwargs):
        self._client = rest_client.new_client_for(self.uri_segment)

    @abc.abstractproperty
    def uri_segment(self):
        pass

    def list(self):
        return self._client.list()

    def get(self, uuid):
        return self._client.get(uuid)

    def delete(self, uuid):
        return self._client.delete(uuid)

    @abc.abstractmethod
    def create(self, *args, **kwargs):
        pass

    @abc.abstractmethod
    def update(self, uuid, *args, **kwargs):
        pass

    def find_by_display_name(self, display_name):
        found = []
        for resource in self.list()['results']:
            if resource['display_name'] == display_name:
                found.append(resource)
        return found


class SwitchingProfileTypes(object):
    IP_DISCOVERY = 'IpDiscoverySwitchingProfile'
    MAC_LEARNING = 'MacManagementSwitchingProfile'
    PORT_MIRRORING = 'PortMirroringSwitchingProfile'
    QOS = 'QosSwitchingProfile'
    SPOOF_GUARD = 'SpoofGuardSwitchingProfile'
    SWITCH_SECURITY = 'SwitchSecuritySwitchingProfile'


class WhiteListAddressTypes(object):
    PORT = 'LPORT_BINDINGS'
    SWITCH = 'LSWITCH_BINDINGS'


class SwitchingProfile(AbstractRESTResource):

    @property
    def uri_segment(self):
        return 'switching-profiles'

    def list(self):
        return self._client.url_get('?include_system_owned=True')

    def create(self, profile_type, display_name=None,
               description=None, **api_args):
        body = {
            'resource_type': profile_type,
            'display_name': display_name or '',
            'description': description or ''
        }
        body.update(api_args)

        return self._client.create(body=body)

    def update(self, uuid, profile_type, **api_args):
        body = {
            'resource_type': profile_type
        }
        body.update(api_args)

        return self._client.update(uuid, body=body)

    def create_spoofguard_profile(self, display_name,
                                  description,
                                  whitelist_ports=False,
                                  whitelist_switches=False,
                                  tags=None):
        whitelist_providers = []
        if whitelist_ports:
            whitelist_providers.append(WhiteListAddressTypes.PORT)
        if whitelist_switches:
            whitelist_providers.append(WhiteListAddressTypes.SWITCH)

        return self.create(SwitchingProfileTypes.SPOOF_GUARD,
                           display_name=display_name,
                           description=description,
                           white_list_providers=whitelist_providers,
                           tags=tags or [])

    def create_dhcp_profile(self, display_name,
                            description, tags=None):
        dhcp_filter = {
            'client_block_enabled': True,
            'server_block_enabled': False
        }
        rate_limits = {
            'enabled': False,
            'rx_broadcast': 0,
            'tx_broadcast': 0,
            'rx_multicast': 0,
            'tx_multicast': 0
        }
        bpdu_filter = {
            'enabled': True,
            'white_list': []
        }
        return self.create(SwitchingProfileTypes.SWITCH_SECURITY,
                           display_name=display_name,
                           description=description,
                           tags=tags or [],
                           dhcp_filter=dhcp_filter,
                           rate_limits=rate_limits,
                           bpdu_filter=bpdu_filter,
                           block_non_ip_traffic=True)

    def create_mac_learning_profile(self, display_name,
                                    description, tags=None):
        mac_learning = {
            'enabled': True,
        }
        return self.create(SwitchingProfileTypes.MAC_LEARNING,
                           display_name=display_name,
                           description=description,
                           tags=tags or [],
                           mac_learning=mac_learning,
                           mac_change_allowed=True)

    @classmethod
    def build_switch_profile_ids(cls, client, *profiles):
        ids = []
        for profile in profiles:
            if type(profile) is str:
                profile = client.get(profile)
            if not isinstance(profile, SwitchingProfileTypeId):
                profile = SwitchingProfileTypeId(
                    profile.get('key', profile.get('resource_type')),
                    profile.get('value', profile.get('id')))
            ids.append(profile)
        return ids


class LogicalPort(AbstractRESTResource):

    @property
    def uri_segment(self):
        return 'logical-ports'

    def _build_body_attrs(
            self, display_name=None,
            admin_state=True, tags=None,
            address_bindings=None,
            switch_profile_ids=None,
            attachment=None):
        tags = tags or []
        address_bindings = address_bindings or []
        switch_profile_ids = switch_profile_ids or []
        body = {}
        if tags:
            body['tags'] = tags
        if display_name is not None:
            body['display_name'] = display_name

        if admin_state is not None:
            if admin_state:
                body['admin_state'] = nsx_constants.ADMIN_STATE_UP
            else:
                body['admin_state'] = nsx_constants.ADMIN_STATE_DOWN

        if address_bindings:
            bindings = []
            for binding in address_bindings:
                address_classifier = {
                    'ip_address': binding.ip_address,
                    'mac_address': binding.mac_address
                }
                if binding.vlan is not None:
                    address_classifier['vlan'] = int(binding.vlan)
                bindings.append(address_classifier)
            body['address_bindings'] = bindings
        elif address_bindings == []:
            # explicitly clear out address bindings
            body['address_bindings'] = []

        if switch_profile_ids:
            profiles = []
            for profile in switch_profile_ids:
                profiles.append({
                    'value': profile.profile_id,
                    'key': profile.profile_type
                })
            body['switching_profile_ids'] = profiles

        # Note that attachment could be None, meaning reset it.
        if attachment is not False:
            body['attachment'] = attachment

        return body

    def _prepare_attachment(self, vif_uuid, parent_name, parent_tag,
                            address_bindings, attachment_type):
        # NOTE(arosen): if a parent_name is specified we need to use the
        # CIF's attachment.
        key_values = None
        if parent_name:
            attachment_type = nsx_constants.ATTACHMENT_CIF
            key_values = [
                {'key': 'VLAN_ID', 'value': parent_tag},
                {'key': 'Host_VIF_ID', 'value': parent_name},
                {'key': 'IP', 'value': address_bindings[0].ip_address},
                {'key': 'MAC', 'value': address_bindings[0].mac_address}]
            # NOTE(arosen): The above api body structure might change
            # in the future

        if attachment_type and vif_uuid:
            attachment = {'attachment_type': attachment_type,
                          'id': vif_uuid}

            if key_values:
                attachment['context'] = {'key_values': key_values}
                attachment['context']['resource_type'] = \
                    nsx_constants.CIF_RESOURCE_TYPE
            return attachment
        elif attachment_type is None or vif_uuid is None:
            return None   # reset attachment
        else:
            return False  # no attachment change

    def create(self, lswitch_id, vif_uuid, tags=None,
               attachment_type=nsx_constants.ATTACHMENT_VIF,
               admin_state=True, name=None, address_bindings=None,
               parent_name=None, parent_tag=None,
               switch_profile_ids=None):
        tags = tags or []

        body = {'logical_switch_id': lswitch_id}
        attachment = self._prepare_attachment(vif_uuid, parent_name,
                                              parent_tag, address_bindings,
                                              attachment_type)
        body.update(self._build_body_attrs(
            display_name=name,
            admin_state=admin_state, tags=tags,
            address_bindings=address_bindings,
            switch_profile_ids=switch_profile_ids,
            attachment=attachment))
        return self._client.create(body=body)

    @utils.retry_upon_exception_nsxv3(
        nsx_exc.StaleRevision,
        max_attempts=cfg.CONF.nsx_v3.retries)
    def delete(self, lport_id):
        return self._client.url_delete('%s?detach=true' % lport_id)

    @utils.retry_upon_exception_nsxv3(
        nsx_exc.StaleRevision,
        max_attempts=cfg.CONF.nsx_v3.retries)
    def update(self, lport_id, vif_uuid,
               name=None, admin_state=None,
               address_bindings=None, switch_profile_ids=None,
               tags_update=None,
               attachment_type=nsx_constants.ATTACHMENT_VIF,
               parent_name=None, parent_tag=None):
        lport = self.get(lport_id)
        tags = lport.get('tags', [])
        if tags_update:
            tags = utils.update_v3_tags(tags, tags_update)
        attachment = self._prepare_attachment(vif_uuid, parent_name,
                                              parent_tag, address_bindings,
                                              attachment_type)
        lport.update(self._build_body_attrs(
            display_name=name,
            admin_state=admin_state, tags=tags,
            address_bindings=address_bindings,
            switch_profile_ids=switch_profile_ids,
            attachment=attachment))

        # If revision_id of the payload that we send is older than what NSX has
        # then we will get a 412: Precondition Failed. In that case we need to
        # re-fetch, patch the response and send it again with the
        # new revision_id
        return self._client.update(lport_id, body=lport)


class LogicalRouter(AbstractRESTResource):

    @property
    def uri_segment(self):
        return 'logical-routers'

    def create(self, display_name, tags, edge_cluster_uuid=None, tier_0=False):
        # TODO(salv-orlando): If possible do not manage edge clusters
        # in the main plugin logic.
        router_type = (nsx_constants.ROUTER_TYPE_TIER0 if tier_0 else
                       nsx_constants.ROUTER_TYPE_TIER1)
        body = {'display_name': display_name,
                'router_type': router_type,
                'tags': tags}
        if edge_cluster_uuid:
            body['edge_cluster_id'] = edge_cluster_uuid
        return self._client.create(body=body)

    def delete(self, lrouter_id):
        return self._client.url_delete(lrouter_id)

    @utils.retry_upon_exception_nsxv3(
        nsx_exc.StaleRevision,
        max_attempts=cfg.CONF.nsx_v3.retries)
    def update(self, lrouter_id, *args, **kwargs):
        lrouter = self.get(lrouter_id)
        for k in kwargs:
            lrouter[k] = kwargs[k]
        # If revision_id of the payload that we send is older than what NSX has
        # then we will get a 412: Precondition Failed. In that case we need to
        # re-fetch, patch the response and send it again with the
        # new revision_id
        return self._client.update(lrouter_id, body=lrouter)


class LogicalRouterPort(AbstractRESTResource):

    @property
    def uri_segment(self):
        return 'logical-router-ports'

    def create(self, logical_router_id,
               display_name,
               tags,
               resource_type,
               logical_port_id,
               address_groups,
               edge_cluster_member_index=None):
        body = {'display_name': display_name,
                'resource_type': resource_type,
                'logical_router_id': logical_router_id,
                'tags': tags or []}
        if address_groups:
            body['subnets'] = address_groups
        if resource_type in [nsx_constants.LROUTERPORT_UPLINK,
                             nsx_constants.LROUTERPORT_DOWNLINK]:
            body['linked_logical_switch_port_id'] = {
                'target_id': logical_port_id}
        elif resource_type == nsx_constants.LROUTERPORT_LINKONTIER1:
            body['linked_logical_router_port_id'] = {
                'target_id': logical_port_id}
        elif logical_port_id:
            body['linked_logical_router_port_id'] = logical_port_id
        if edge_cluster_member_index:
            body['edge_cluster_member_index'] = edge_cluster_member_index

        return self._client.create(body)

    @utils.retry_upon_exception_nsxv3(
        nsx_exc.StaleRevision,
        max_attempts=cfg.CONF.nsx_v3.retries)
    def update(self, logical_port_id, **kwargs):
        logical_router_port = self.get(logical_port_id)
        for k in kwargs:
            logical_router_port[k] = kwargs[k]
        # If revision_id of the payload that we send is older than what NSX has
        # then we will get a 412: Precondition Failed. In that case we need to
        # re-fetch, patch the response and send it again with the
        # new revision_id
        return self._client.update(logical_port_id, body=logical_router_port)

    @utils.retry_upon_exception_nsxv3(
        nsx_exc.StaleRevision,
        max_attempts=cfg.CONF.nsx_v3.retries)
    def delete(self, logical_port_id):
        return self._client.url_delete(logical_port_id)

    def get_by_lswitch_id(self, logical_switch_id):
        resource = '?logical_switch_id=%s' % logical_switch_id
        router_ports = self._client.url_get(resource)
        result_count = int(router_ports.get('result_count', "0"))
        if result_count >= 2:
            raise nsx_exc.NsxPluginException(
                err_msg=_("Can't support more than one logical router ports "
                          "on same logical switch %s ") % logical_switch_id)
        elif result_count == 1:
            return router_ports['results'][0]
        else:
            err_msg = (_("Logical router link port not found on logical "
                         "switch %s") % logical_switch_id)
            raise nsx_exc.ResourceNotFound(
                manager=client._get_nsx_managers_from_conf(),
                operation=err_msg)

    def update_by_lswitch_id(self, logical_router_id, ls_id, **payload):
        port = self.get_by_lswitch_id(ls_id)
        return self.update(port['id'], **payload)

    def delete_by_lswitch_id(self, ls_id):
        port = self.get_by_lswitch_id(ls_id)
        self.delete(port['id'])

    def get_by_router_id(self, logical_router_id):
        resource = '?logical_router_id=%s' % logical_router_id
        logical_router_ports = self._client.url_get(resource)
        return logical_router_ports['results']

    def get_tier1_link_port(self, logical_router_id):
        logical_router_ports = self.get_by_router_id(logical_router_id)
        for port in logical_router_ports:
            if port['resource_type'] == nsx_constants.LROUTERPORT_LINKONTIER1:
                return port
        raise nsx_exc.ResourceNotFound(
            manager=client._get_nsx_managers_from_conf(),
            operation="get router link port")
