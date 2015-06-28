# Copyright 2015 OpenStack Foundation
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

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
import requests
from requests import auth

from neutron.i18n import _LI, _LW
from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.common import nsx_constants

LOG = log.getLogger(__name__)


def _get_controller_endpoint():
    # For now only work with one controller
    # NOTE: The same options defined for 'old' NSX controller connection can be
    # reused for connecting to next-gen NSX controllers
    controller = cfg.CONF.nsx_controllers[0]
    username = cfg.CONF.nsx_v3.nsx_user
    password = cfg.CONF.nsx_v3.nsx_password
    return "https://%s" % controller, username, password


def _validate_result(result, expected, operation):
    if result.status_code != expected:
        # Do not reveal internal details in the exception message, as it will
        # be user-visible
        LOG.warning(_LW("The HTTP request returned error code %(result)d, "
                        "whereas a %(expected)d response code was expected"),
                    {'result': result.status_code,
                     'expected': expected})
        raise nsx_exc.NsxPluginException(
            err_msg=_("Unexpected error in backend while "
                      "%s") % operation)


def create_logical_switch(display_name, transport_zone_id, tags,
                          replication_mode=nsx_constants.MTEP,
                          admin_state=nsx_constants.ADMIN_STATE_UP):
    # TODO(salv-orlando): Validate Replication mode and admin_state
    # NOTE: These checks might be moved to the API client library if one that
    # performs such checks in the client is available

    controller, user, password = _get_controller_endpoint()
    url = controller + "/api/v1/logical-switches"
    headers = {'Content-Type': 'application/json'}
    body = {'transport_zone_id': transport_zone_id,
            'replication_mode': replication_mode,
            'admin_state': admin_state,
            'display_name': display_name,
            'tags': tags}

    # TODO(salv-orlando): Move actual HTTP request to separate module which
    # should be accessed through interface, in order to be able to switch API
    # client as needed.
    result = requests.post(url, auth=auth.HTTPBasicAuth(user, password),
                           verify=False, headers=headers,
                           data=jsonutils.dumps(body))
    _validate_result(result, requests.codes.created,
                     _("creating logical switch"))
    return result.json()


def delete_logical_switch(lswitch_id):
    controller, user, password = _get_controller_endpoint()
    url = ("%s/api/v1/logical-switches/%s?detach=true&cascade=true" %
           (controller, lswitch_id))
    headers = {'Content-Type': 'application/json'}
    result = requests.delete(url, auth=auth.HTTPBasicAuth(user, password),
                             verify=False, headers=headers)
    _validate_result(result, requests.codes.ok,
                     _("deleting logical switch"))


def create_logical_port(lswitch_id, vif_uuid, tags,
                        attachment_type=nsx_constants.ATTACHMENT_VIF,
                        admin_state=True, name=None, address_bindings=None):

    controller, user, password = _get_controller_endpoint()
    url = controller + "/api/v1/logical-ports"
    headers = {'Content-Type': 'application/json'}
    body = {'logical_switch_id': lswitch_id,
            'attachment': {'attachment_type': attachment_type,
                           'id': vif_uuid},
            'tags': tags}
    if name:
        body['display_name'] = name
    if admin_state:
        body['admin_state'] = nsx_constants.ADMIN_STATE_UP
    else:
        body['admin_state'] = nsx_constants.ADMIN_STATE_DOWN

    if address_bindings:
        body['address_bindings'] = address_bindings
    result = requests.post(url, auth=auth.HTTPBasicAuth(user, password),
                           verify=False, headers=headers,
                           data=jsonutils.dumps(body))
    _validate_result(result, requests.codes.created,
                     _("creating logical port"))
    return result.json()


def delete_logical_port(logical_port_id):
    controller, user, password = _get_controller_endpoint()
    url = controller + "/api/v1/logical-ports/%s?detach=true" % logical_port_id
    headers = {'Content-Type': 'application/json'}
    result = requests.delete(url, auth=auth.HTTPBasicAuth(user, password),
                             verify=False, headers=headers)
    _validate_result(result, requests.codes.ok,
                     _("deleting logical port"))


def create_logical_router(display_name, edge_cluster_uuid, tags, tier_0=False):
    # TODO(salv-orlando): If possible do not manage edge clusters in the main
    # plugin logic.
    router_type = (nsx_constants.ROUTER_TYPE_TIER0 if tier_0 else
                   nsx_constants.ROUTER_TYPE_TIER1)
    controller, user, password = _get_controller_endpoint()
    url = controller + "/api/v1/logical-routers"
    headers = {'Content-Type': 'application/json'}
    body = {'edge_cluster_id': edge_cluster_uuid,
            'display_name': display_name,
            'router_type': router_type,
            'tags': tags}
    # TODO(salv-orlando): Must handle connection exceptions
    result = requests.post(url, auth=auth.HTTPBasicAuth(user, password),
                           verify=False, headers=headers,
                           data=jsonutils.dumps(body))
    _validate_result(result, requests.codes.created,
                     _("creating logical router"))
    return result.json()


def delete_logical_router(lrouter_id):
    controller, user, password = _get_controller_endpoint()
    url = controller + "/api/v1/logical-routers/%s/" % lrouter_id
    headers = {'Content-Type': 'application/json'}

    # TODO(salv-orlando): Must handle connection exceptions
    result = requests.delete(url, auth=auth.HTTPBasicAuth(user, password),
                             verify=False, headers=headers)
    if result.status_code == requests.codes.not_found:
        LOG.info(_LI("Logical router %s not found on NSX backend"), lrouter_id)
        raise nsx_exc.LogicalRouterNotFound(entity_id=lrouter_id)
    _validate_result(result, requests.codes.ok,
                     _("deleting logical router"))


def create_logical_router_port(logical_router_id,
                               logical_switch_port_id,
                               resource_type,
                               cidr_length,
                               ip_address):
    controller, user, password = _get_controller_endpoint()
    url = controller + "/api/v1/logical-router-ports"
    headers = {'Content-Type': 'application/json'}
    body = {'resource_type': resource_type,
            'logical_router_id': logical_router_id,
            'subnets': [{"prefix_length": cidr_length,
                         "ip_addresses": [ip_address]}],
            'linked_logical_switch_port_id': logical_switch_port_id}

    result = requests.post(url, auth=auth.HTTPBasicAuth(user, password),
                           verify=False, headers=headers,
                           data=jsonutils.dumps(body))
    _validate_result(result, requests.codes.created,
                     _("creating logical router port"))
    return result.json()


def delete_logical_router_port(logical_port_id):
    controller, user, password = _get_controller_endpoint()
    url = ("%s/api/v1/logical-router-ports/%s?detach=true" %
           (controller, logical_port_id))
    headers = {'Content-Type': 'application/json'}
    result = requests.delete(url, auth=auth.HTTPBasicAuth(user, password),
                             verify=False, headers=headers)
    _validate_result(result, requests.codes.ok,
                     _("deleting logical router port"))
