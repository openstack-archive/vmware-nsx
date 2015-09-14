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

from neutron.i18n import _LW

from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.common import nsx_constants
from vmware_nsx.neutron.plugins.vmware.common import utils
from vmware_nsx.neutron.plugins.vmware.nsxlib.v3 import client

LOG = log.getLogger(__name__)

# TODO(berlin): move them to nsx_constants file
# Router logical port types
LROUTERPORT_UPLINK = "LogicalRouterUplinkPort"
LROUTERPORT_DOWNLINK = "LogicalRouterDownLinkPort"
LROUTERPORT_LINK = "LogicalRouterLinkPort"

LROUTER_TYPES = [LROUTERPORT_UPLINK,
                 LROUTERPORT_DOWNLINK,
                 LROUTERPORT_LINK]

ROUTER_INTF_PORT_NAME = "Tier1-RouterDownLinkPort"


def get_edge_cluster(edge_cluster_uuid):
    resource = "edge-clusters/%s" % edge_cluster_uuid
    return client.get_resource(resource)


@utils.retry_upon_exception_nsxv3(nsx_exc.StaleRevision)
def update_resource_with_retry(resource, payload):
    revised_payload = client.get_resource(resource)
    for key_name in payload.keys():
        revised_payload[key_name] = payload[key_name]
    return client.update_resource(resource, revised_payload)


def delete_resource_by_values(resource, res_id='id', skip_not_found=True,
                              **kwargs):
    resources_get = client.get_resource(resource)
    for res in resources_get['results']:
        is_matched = True
        for (key, value) in kwargs.items():
            if res.get(key) != value:
                is_matched = False
                break
        if is_matched:
            LOG.debug("Deleting %s from resource %s", res, resource)
            delete_resource = resource + "/" + str(res[res_id])
            client.delete_resource(delete_resource)
            return
    if skip_not_found:
        LOG.warning(_LW("No resource in %(res)s matched for values: "
                        "%(values)s"), {'res': resource,
                                        'values': kwargs})
    else:
        err_msg = (_("No resource in %(res)s matched for values: %(values)s") %
                   {'res': resource,
                    'values': kwargs})
        raise nsx_exc.ResourceNotFound(manager=client._get_manager_ip(),
                                       operation=err_msg)


def create_logical_switch(display_name, transport_zone_id, tags,
                          replication_mode=nsx_constants.MTEP,
                          admin_state=True, vlan_id=None):
    # TODO(salv-orlando): Validate Replication mode and admin_state
    # NOTE: These checks might be moved to the API client library if one that
    # performs such checks in the client is available

    resource = 'logical-switches'
    body = {'transport_zone_id': transport_zone_id,
            'replication_mode': replication_mode,
            'display_name': display_name,
            'tags': tags}

    if admin_state:
        body['admin_state'] = nsx_constants.ADMIN_STATE_UP
    else:
        body['admin_state'] = nsx_constants.ADMIN_STATE_DOWN

    if vlan_id:
        body['vlan'] = vlan_id

    return client.create_resource(resource, body)


def delete_logical_switch(lswitch_id):
    resource = 'logical-switches/%s?detach=true&cascade=true' % lswitch_id
    client.delete_resource(resource)


def get_logical_switch(logical_switch_id):
    resource = "logical-switches/%s" % logical_switch_id
    return client.get_resource(resource)


@utils.retry_upon_exception_nsxv3(nsx_exc.StaleRevision,
                                  max_attempts=cfg.CONF.nsx_v3.retries)
def update_logical_switch(lswitch_id, name=None, admin_state=None):
    resource = "logical-switches/%s" % lswitch_id
    lswitch = get_logical_switch(lswitch_id)
    if name is not None:
        lswitch['display_name'] = name
    if admin_state is not None:
        if admin_state:
            lswitch['admin_state'] = nsx_constants.ADMIN_STATE_UP
        else:
            lswitch['admin_state'] = nsx_constants.ADMIN_STATE_DOWN
    return client.update_resource(resource, lswitch)


def create_logical_port(lswitch_id, vif_uuid, tags,
                        attachment_type=nsx_constants.ATTACHMENT_VIF,
                        admin_state=True, name=None, address_bindings=None,
                        parent_name=None, parent_tag=None):

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
        # NOTE(arosen): The above api body structure might change in the future

    resource = 'logical-ports'
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

    if key_values:
        body['attachment']['context'] = {'key_values': key_values}
        body['attachment']['context']['resource_type'] = \
            nsx_constants.CIF_RESOURCE_TYPE
    if address_bindings:
        body['address_bindings'] = address_bindings

    return client.create_resource(resource, body)


def delete_logical_port(logical_port_id):
    resource = 'logical-ports/%s?detach=true' % logical_port_id
    client.delete_resource(resource)


def get_logical_port(logical_port_id):
    resource = "logical-ports/%s" % logical_port_id
    return client.get_resource(resource)


@utils.retry_upon_exception_nsxv3(nsx_exc.StaleRevision,
                                  max_attempts=cfg.CONF.nsx_v3.retries)
def update_logical_port(lport_id, name=None, admin_state=None):
    resource = "logical-ports/%s" % lport_id
    lport = get_logical_port(lport_id)
    if name is not None:
        lport['display_name'] = name
    if admin_state is not None:
        if admin_state:
            lport['admin_state'] = nsx_constants.ADMIN_STATE_UP
        else:
            lport['admin_state'] = nsx_constants.ADMIN_STATE_DOWN
    # If revision_id of the payload that we send is older than what NSX has
    # then we will get a 412: Precondition Failed. In that case we need to
    # re-fetch, patch the response and send it again with the new revision_id
    return client.update_resource(resource, lport)


def create_logical_router(display_name, tags,
                          edge_cluster_uuid=None, tier_0=False):
    # TODO(salv-orlando): If possible do not manage edge clusters in the main
    # plugin logic.
    router_type = (nsx_constants.ROUTER_TYPE_TIER0 if tier_0 else
                   nsx_constants.ROUTER_TYPE_TIER1)
    resource = 'logical-routers'
    body = {'display_name': display_name,
            'router_type': router_type,
            'tags': tags}
    if edge_cluster_uuid:
        body['edge_cluster_id'] = edge_cluster_uuid
    return client.create_resource(resource, body)


def get_logical_router(lrouter_id):
    resource = 'logical-routers/%s' % lrouter_id
    return client.get_resource(resource)


def update_logical_router(lrouter_id, **kwargs):
    resource = 'logical-routers/%s' % lrouter_id
    return update_resource_with_retry(resource, kwargs)


def delete_logical_router(lrouter_id):
    # TODO(berlin): need to verify whether cascade prefix is valid to delete
    # router link port and its relative nat rules
    resource = 'logical-routers/%s/' % lrouter_id

    # TODO(salv-orlando): Must handle connection exceptions
    return client.delete_resource(resource)


def get_logical_router_port_by_ls_id(logical_switch_id):
    resource = 'logical-router-ports?logical_switch_id=%s' % logical_switch_id
    router_ports = client.get_resource(resource)
    if int(router_ports['result_count']) >= 2:
        raise nsx_exc.NsxPluginException(
            err_msg=_("Can't support more than one logical router ports "
                      "on same logical switch %s ") % logical_switch_id)
    elif int(router_ports['result_count']) == 1:
        return router_ports['results'][0]
    else:
        err_msg = (_("Logical router link port not found on logical "
                     "switch %s") % logical_switch_id)
        raise nsx_exc.ResourceNotFound(manager=client._get_manager_ip(),
                                       operation=err_msg)


def create_logical_router_port_by_ls_id(logical_router_id,
                                        ls_id,
                                        logical_switch_port_id,
                                        resource_type,
                                        address_groups):
    try:
        port = get_logical_router_port_by_ls_id(ls_id)
    except nsx_exc.ResourceNotFound:
        return create_logical_router_port(logical_router_id,
                                          ROUTER_INTF_PORT_NAME,
                                          resource_type,
                                          logical_switch_port_id,
                                          address_groups)
    else:
        return update_logical_router_port(port['id'], subnets=address_groups)


def create_logical_router_port(logical_router_id,
                               display_name,
                               resource_type,
                               logical_port_id,
                               address_groups,
                               edge_cluster_member_index=None):
    resource = 'logical-router-ports'
    body = {'display_name': display_name,
            'resource_type': resource_type,
            'logical_router_id': logical_router_id}
    if address_groups:
        body['subnets'] = address_groups
    if resource_type in [LROUTERPORT_UPLINK,
                         LROUTERPORT_DOWNLINK]:
        body['linked_logical_switch_port_id'] = logical_port_id
    elif logical_port_id:
        body['linked_logical_router_port_id'] = logical_port_id
    if edge_cluster_member_index:
        body['edge_cluster_member_index'] = edge_cluster_member_index

    return client.create_resource(resource, body)


def update_logical_router_port_by_ls_id(logical_router_id, ls_id,
                                       **payload):
    port = get_logical_router_port_by_ls_id(ls_id)
    return update_logical_router_port(port['id'], **payload)


def update_logical_router_port(logical_port_id, **kwargs):
    resource = 'logical-router-ports/%s?detach=true' % logical_port_id
    return update_resource_with_retry(resource, kwargs)


def delete_logical_router_port_by_ls_id(ls_id):
    port = get_logical_router_port_by_ls_id(ls_id)
    delete_logical_router_port(port['id'])


def delete_logical_router_port(logical_port_id):
    resource = 'logical-router-ports/%s?detach=true' % logical_port_id
    client.delete_resource(resource)


def get_logical_router_ports_by_router_id(logical_router_id):
    resource = 'logical-router-ports'
    logical_router_ports = client.get_resource(
        resource, logical_router_id=logical_router_id)
    return logical_router_ports['results']


def get_tier1_logical_router_link_port(logical_router_id):
    logical_router_ports = get_logical_router_ports_by_router_id(
        logical_router_id)
    for port in logical_router_ports:
        if port['resource_type'] == LROUTERPORT_LINK:
            return port
    raise nsx_exc.ResourceNotFound(
        manager=client._get_manager_ip(),
        operation="get router link port")


def add_nat_rule(logical_router_id, action, translated_network,
                 source_net=None, dest_net=None,
                 enabled=True, rule_priority=None):
    resource = 'logical-routers/%s/nat/rules' % logical_router_id
    body = {'action': action,
            'enabled': enabled,
            'translated_network': translated_network}
    if source_net:
        body['match_source_network'] = source_net
    if dest_net:
        body['match_destination_network'] = dest_net
    if rule_priority:
        body['rule_priority'] = rule_priority
    return client.create_resource(resource, body)


def delete_nat_rule(logical_router_id, nat_rule_id):
    resource = 'logical-routers/%s/nat/rules/%s' % (logical_router_id,
                                                    nat_rule_id)
    client.delete_resource(resource)


def delete_nat_rule_by_values(logical_router_id, **kwargs):
    resource = 'logical-routers/%s/nat/rules' % logical_router_id
    return delete_resource_by_values(resource, res_id='rule_id', **kwargs)


def update_logical_router_advertisement(logical_router_id, **kwargs):
    resource = 'logical-routers/%s/routing/advertisement' % logical_router_id
    return update_resource_with_retry(resource, kwargs)


def create_qos_switching_profile(tags, qos_marking=None, dscp=None, name=None,
                                 description=None):
    resource = 'switching-profiles'
    body = {"resource_type": "QosSwitchingProfile",
            "tags": tags}
    # TODO(abhide): Add TrafficShaper configuration.
    if qos_marking:
        body["dscp"] = {}
        body["dscp"]["mode"] = qos_marking.upper()
        if dscp:
            body["dscp"]["priority"] = dscp
    if name:
        body["display_name"] = name
    if description:
        body["description"] = description
    return client.create_resource(resource, body)


def get_qos_switching_profile(profile_id):
    resource = 'switching-profiles/%s' % profile_id
    return client.get_resource(resource)


def delete_qos_switching_profile(profile_id):
    resource = 'switching-profiles/%s' % profile_id
    client.delete_resource(resource)


def create_bridge_endpoint(device_name, seg_id, tags):
    """Create a bridge endpoint on the backend.

    Create a bridge endpoint resource on a bridge cluster for the L2 gateway
    network connection.
    :param device_name: device_name actually refers to the bridge cluster's
                        UUID.
    :param seg_id: integer representing the VLAN segmentation ID.
    :param tags: nsx backend specific tags.
    """
    resource = 'bridge-endpoints'
    body = {'bridge_cluster_id': device_name,
            'tags': tags,
            'vlan': seg_id}
    return client.create_resource(resource, body)


def delete_bridge_endpoint(bridge_endpoint_id):
    """Delete a bridge endpoint on the backend.

    :param bridge_endpoint_id: string representing the UUID of the bridge
                               endpoint to be deleted.
    """
    resource = 'bridge-endpoints/%s' % bridge_endpoint_id
    client.delete_resource(resource)
