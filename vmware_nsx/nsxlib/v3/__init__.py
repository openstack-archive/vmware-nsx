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

from vmware_nsx._i18n import _, _LW
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils
from vmware_nsx.nsxlib.v3 import client

LOG = log.getLogger(__name__)


def get_version():
    node = client.get_resource("node")
    version = node.get('node_version')
    return version


def get_edge_cluster(edge_cluster_uuid):
    resource = "edge-clusters/%s" % edge_cluster_uuid
    return client.get_resource(resource)


@utils.retry_upon_exception_nsxv3(nsx_exc.StaleRevision)
def update_resource_with_retry(resource, payload):
    revised_payload = client.get_resource(resource)
    for key_name in payload.keys():
        revised_payload[key_name] = payload[key_name]
    return client.update_resource(resource, revised_payload)


def delete_resource_by_values(resource, skip_not_found=True, **kwargs):
    resources_get = client.get_resource(resource)
    matched_num = 0
    for res in resources_get['results']:
        if utils.dict_match(kwargs, res):
            LOG.debug("Deleting %s from resource %s", res, resource)
            delete_resource = resource + "/" + str(res['id'])
            client.delete_resource(delete_resource)
            matched_num = matched_num + 1
    if matched_num == 0:
        if skip_not_found:
            LOG.warning(_LW("No resource in %(res)s matched for values: "
                            "%(values)s"), {'res': resource,
                                            'values': kwargs})
        else:
            err_msg = (_("No resource in %(res)s matched for values: "
                         "%(values)s") % {'res': resource,
                                          'values': kwargs})
            raise nsx_exc.ResourceNotFound(
                manager=client._get_nsx_managers_from_conf(),
                operation=err_msg)
    elif matched_num > 1:
        LOG.warning(_LW("%(num)s resources in %(res)s matched for values: "
                        "%(values)s"), {'num': matched_num,
                                        'res': resource,
                                        'values': kwargs})


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


@utils.retry_upon_exception_nsxv3(nsx_exc.StaleRevision,
                                  max_attempts=cfg.CONF.nsx_v3.retries)
def delete_logical_switch(lswitch_id):
    resource = 'logical-switches/%s?detach=true&cascade=true' % lswitch_id
    client.delete_resource(resource)


def get_logical_switch(logical_switch_id):
    resource = "logical-switches/%s" % logical_switch_id
    return client.get_resource(resource)


@utils.retry_upon_exception_nsxv3(nsx_exc.StaleRevision,
                                  max_attempts=cfg.CONF.nsx_v3.retries)
def update_logical_switch(lswitch_id, name=None, admin_state=None, tags=None):
    resource = "logical-switches/%s" % lswitch_id
    lswitch = get_logical_switch(lswitch_id)
    if name is not None:
        lswitch['display_name'] = name
    if admin_state is not None:
        if admin_state:
            lswitch['admin_state'] = nsx_constants.ADMIN_STATE_UP
        else:
            lswitch['admin_state'] = nsx_constants.ADMIN_STATE_DOWN
    if tags is not None:
        lswitch['tags'] = tags
    return client.update_resource(resource, lswitch)


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


def add_static_route(logical_router_id, dest_cidr, nexthop):
    resource = 'logical-routers/%s/routing/static-routes' % logical_router_id
    body = {}
    if dest_cidr:
        body['network'] = dest_cidr
    if nexthop:
        body['next_hops'] = [{"ip_address": nexthop}]
    return client.create_resource(resource, body)


def delete_static_route(logical_router_id, static_route_id):
    resource = 'logical-routers/%s/routing/static-routes/%s' % (
        logical_router_id, static_route_id)
    client.delete_resource(resource)


def delete_static_route_by_values(logical_router_id,
                                  dest_cidr=None, nexthop=None):
    resource = 'logical-routers/%s/routing/static-routes' % logical_router_id
    kwargs = {}
    if dest_cidr:
        kwargs['network'] = dest_cidr
    if nexthop:
        kwargs['next_hops'] = [{"ip_address": nexthop}]
    return delete_resource_by_values(resource, **kwargs)


def delete_nat_rule(logical_router_id, nat_rule_id):
    resource = 'logical-routers/%s/nat/rules/%s' % (logical_router_id,
                                                    nat_rule_id)
    client.delete_resource(resource)


def delete_nat_rule_by_values(logical_router_id, **kwargs):
    resource = 'logical-routers/%s/nat/rules' % logical_router_id
    return delete_resource_by_values(resource, **kwargs)


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
