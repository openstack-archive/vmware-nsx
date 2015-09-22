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
import six

from oslo_config import cfg
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils


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
    PORT_MIRRORING = 'PortMirroringSwitchingProfile'
    QOS = 'QosSwitchingProfile'
    SPOOF_GUARD = 'SpoofGuardSwitchingProfile'


class WhiteListAddressTypes(object):
    PORT = 'LPORT_BINDINGS'
    SWITCH = 'LSWITCH_BINDINGS'


class SwitchingProfile(AbstractRESTResource):

    @property
    def uri_segment(self):
        return 'switching-profiles'

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

    def build_switch_profile_ids(self, *profiles):
        ids = []
        for profile in profiles:
            if type(profile) is str:
                profile = self.get(profile)
            ids.append({
                'value': profile['id'],
                'key': profile['resource_type']
            })
        return ids


class LogicalPort(AbstractRESTResource):

    @property
    def uri_segment(self):
        return 'logical-ports'

    def create(self, lswitch_id, vif_uuid, tags=[],
               attachment_type=nsx_constants.ATTACHMENT_VIF,
               admin_state=True, name=None, address_bindings=None,
               parent_name=None, parent_tag=None,
               switch_profile_ids=None):

        # NOTE(arosen): if a parent_name is specified we need to use the
        # CIF's attachment.
        key_values = None
        if parent_name:
            attachment_type = nsx_constants.ATTACHMENT_CIF
            key_values = [
                {'key': 'VLAN_ID', 'value': parent_tag},
                {'key': 'Host_VIF_ID', 'value': parent_name},
                {'key': 'IP', 'value': address_bindings[0]['ip_address']},
                {'key': 'MAC', 'value': address_bindings[0]['mac_address']}]
            # NOTE(arosen): The above api body structure might change
            # in the future

        body = {'logical_switch_id': lswitch_id,
                'attachment': {'attachment_type': attachment_type,
                               'id': vif_uuid}}

        if tags:
            body['tags'] = tags
        if name:
            body['display_name'] = name
        if admin_state:
            body['admin_state'] = nsx_constants.ADMIN_STATE_UP
        else:
            body['admin_state'] = nsx_constants.ADMIN_STATE_DOWN

        if key_values:
            body['attachment']['context'] = {'key_values': key_values}
            body['attachment']['context']['resource_type'] = \
                nsx_constants.CIF_RESOURCE_TYPE
        if address_bindings:
            body['address_bindings'] = address_bindings

        if switch_profile_ids:
            body['switching_profile_ids'] = switch_profile_ids

        return self._client.create(body=body)

    def delete(self, lport_id):
        return self._client.url_delete('%s?detach=true' % lport_id)

    @utils.retry_upon_exception_nsxv3(
        nsx_exc.StaleRevision,
        max_attempts=cfg.CONF.nsx_v3.retries)
    def update(self, lport_id, name=None, admin_state=None):
        lport = self.get(lport_id)
        if name is not None:
            lport['display_name'] = name
        if admin_state is not None:
            if admin_state:
                lport['admin_state'] = nsx_constants.ADMIN_STATE_UP
            else:
                lport['admin_state'] = nsx_constants.ADMIN_STATE_DOWN
        # If revision_id of the payload that we send is older than what NSX has
        # then we will get a 412: Precondition Failed. In that case we need to
        # re-fetch, patch the response and send it again with the
        # new revision_id
        return self._client.update(lport_id, body=lport)
