# Copyright (c) 2015 VMware, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import nsx_constants


FAKE_NAME = "fake_name"
DEFAULT_TIER0_ROUTER_UUID = "fake_default_tier0_router_uuid"
FAKE_MANAGER = "fake_manager_ip"


def make_fake_switch(switch_uuid=None, tz_uuid=None, name=FAKE_NAME):
    if not switch_uuid:
        switch_uuid = uuidutils.generate_uuid()
    if not tz_uuid:
        tz_uuid = uuidutils.generate_uuid()

    fake_switch = {
        "id": switch_uuid,
        "display_name": name,
        "resource_type": "LogicalSwitch",
        "address_bindings": [],
        "transport_zone_id": tz_uuid,
        "replication_mode": nsx_constants.MTEP,
        "admin_state": nsx_constants.ADMIN_STATE_UP,
        "vni": 50056,
        "switching_profile_ids": [
            {
                "value": "64814784-7896-3901-9741-badeff705639",
                "key": "IpDiscoverySwitchingProfile"
            },
            {
                "value": "fad98876-d7ff-11e4-b9d6-1681e6b88ec1",
                "key": "SpoofGuardSwitchingProfile"
            },
            {
                "value": "93b4b7e8-f116-415d-a50c-3364611b5d09",
                "key": "PortMirroringSwitchingProfile"
            },
            {
                "value": "fbc4fb17-83d9-4b53-a286-ccdf04301888",
                "key": "SwitchSecuritySwitchingProfile"
            },
            {
                "value": "f313290b-eba8-4262-bd93-fab5026e9495",
                "key": "QosSwitchingProfile"
            }
        ],
    }
    return fake_switch


def create_logical_switch(display_name, transport_zone_id, tags,
                          replication_mode=nsx_constants.MTEP,
                          admin_state=True, vlan_id=None):
    return make_fake_switch()


def get_logical_switch(lswitch_id):
    return make_fake_switch(switch_uuid=lswitch_id)


def update_logical_switch(lswitch_id, name=None, admin_state=None):
    lswitch = get_logical_switch(lswitch_id)
    if name is not None:
        lswitch['display_name'] = name
    if admin_state is not None:
        if admin_state:
            lswitch['admin_state'] = nsx_constants.ADMIN_STATE_UP
        else:
            lswitch['admin_state'] = nsx_constants.ADMIN_STATE_DOWN
    return lswitch


def create_logical_port(lswitch_id, vif_uuid, tags,
                        attachment_type=nsx_constants.ATTACHMENT_VIF,
                        admin_state=True, name=None, address_bindings=None,
                        parent_name=None, parent_tag=None):
    FAKE_SWITCH_UUID = uuidutils.generate_uuid()
    FAKE_PORT_UUID = uuidutils.generate_uuid()
    FAKE_PORT = {
        "id": FAKE_PORT_UUID,
        "display_name": FAKE_NAME,
        "resource_type": "LogicalPort",
        "address_bindings": [],
        "logical_switch_id": FAKE_SWITCH_UUID,
        "admin_state": nsx_constants.ADMIN_STATE_UP,
        "attachment": {
            "id": "9ca8d413-f7bf-4276-b4c9-62f42516bdb2",
            "attachment_type": "VIF"
        },
        "switching_profile_ids": [
            {
                "value": "64814784-7896-3901-9741-badeff705639",
                "key": "IpDiscoverySwitchingProfile"
            },
            {
                "value": "fad98876-d7ff-11e4-b9d6-1681e6b88ec1",
                "key": "SpoofGuardSwitchingProfile"
            },
            {
                "value": "93b4b7e8-f116-415d-a50c-3364611b5d09",
                "key": "PortMirroringSwitchingProfile"
            },
            {
                "value": "fbc4fb17-83d9-4b53-a286-ccdf04301888",
                "key": "SwitchSecuritySwitchingProfile"
            },
            {
                "value": "f313290b-eba8-4262-bd93-fab5026e9495",
                "key": "QosSwitchingProfile"
            }
        ]
    }
    return FAKE_PORT


def get_logical_port(lport_id):
    FAKE_SWITCH_UUID = uuidutils.generate_uuid()
    FAKE_PORT = {
        "id": lport_id,
        "display_name": FAKE_NAME,
        "resource_type": "LogicalPort",
        "address_bindings": [],
        "logical_switch_id": FAKE_SWITCH_UUID,
        "admin_state": nsx_constants.ADMIN_STATE_UP,
        "attachment": {
            "id": "9ca8d413-f7bf-4276-b4c9-62f42516bdb2",
            "attachment_type": "VIF"
        },
        "switching_profile_ids": [
            {
                "value": "64814784-7896-3901-9741-badeff705639",
                "key": "IpDiscoverySwitchingProfile"
            },
            {
                "value": "fad98876-d7ff-11e4-b9d6-1681e6b88ec1",
                "key": "SpoofGuardSwitchingProfile"
            },
            {
                "value": "93b4b7e8-f116-415d-a50c-3364611b5d09",
                "key": "PortMirroringSwitchingProfile"
            },
            {
                "value": "fbc4fb17-83d9-4b53-a286-ccdf04301888",
                "key": "SwitchSecuritySwitchingProfile"
            },
            {
                "value": "f313290b-eba8-4262-bd93-fab5026e9495",
                "key": "QosSwitchingProfile"
            }
        ]
    }
    return FAKE_PORT


def update_logical_port(lport_id, name=None, admin_state=None):
    lport = get_logical_port(lport_id)
    if name:
        lport['display_name'] = name
    if admin_state is not None:
        if admin_state:
            lport['admin_state'] = nsx_constants.ADMIN_STATE_UP
        else:
            lport['admin_state'] = nsx_constants.ADMIN_STATE_DOWN
    return lport


def add_rules_in_section(rules, section_id):
    for rule in rules:
        rule['id'] = uuidutils.generate_uuid()
    return {'rules': rules}


def get_resource(resource):
    return {'id': resource.split('/')[-1]}


def create_resource(resource, data):
    data['id'] = uuidutils.generate_uuid()
    return data


def update_resource(resource, data):
    return resource


def delete_resource(resource):
    pass


def create_bridge_endpoint(device_name, seg_id, tags):
    FAKE_BE = {
        "id": uuidutils.generate_uuid(),
        "display_name": FAKE_NAME,
        "resource_type": "BridgeEndpoint",
        "bridge_endpoint_id": device_name,
        "vlan": seg_id,
    }
    return FAKE_BE


class NsxV3Mock(object):
    def __init__(self, default_tier0_router_uuid=DEFAULT_TIER0_ROUTER_UUID):
        self.logical_routers = {}
        self.logical_router_ports = {}
        self.logical_ports = {}
        self.logical_router_nat_rules = {}
        if default_tier0_router_uuid:
            self.create_logical_router(
                DEFAULT_TIER0_ROUTER_UUID, None,
                edge_cluster_uuid="fake_edge_cluster_uuid",
                tier_0=True)

    def get_edge_cluster(self, edge_cluster_uuid):
        FAKE_CLUSTER = {
            "id": edge_cluster_uuid,
            "members": [
                {"member_index": 0},
                {"member_index": 1}]}
        return FAKE_CLUSTER

    def create_logical_router(self, display_name, tags,
                              edge_cluster_uuid=None,
                              tier_0=False):
        router_type = (nsx_constants.ROUTER_TYPE_TIER0 if tier_0 else
                       nsx_constants.ROUTER_TYPE_TIER1)
        if display_name == DEFAULT_TIER0_ROUTER_UUID:
            fake_router_uuid = DEFAULT_TIER0_ROUTER_UUID
        else:
            fake_router_uuid = uuidutils.generate_uuid()
        result = {'display_name': display_name,
                  'router_type': router_type,
                  'tags': tags,
                  'id': fake_router_uuid}
        if edge_cluster_uuid:
            result['edge_cluster_id'] = edge_cluster_uuid
        self.logical_routers[fake_router_uuid] = result
        return result

    def get_logical_router(self, lrouter_id):
        if lrouter_id in self.logical_routers:
            return self.logical_routers[lrouter_id]
        else:
            raise nsx_exc.ResourceNotFound(manager=FAKE_MANAGER,
                                           operation="get_logical_router")

    def update_logical_router(self, lrouter_id, **kwargs):
        if lrouter_id in self.logical_routers:
            payload = self.logical_routers[lrouter_id]
            payload.update(kwargs)
            return payload
        else:
            raise nsx_exc.ResourceNotFound(manager=FAKE_MANAGER,
                                           operation="update_logical_router")

    def delete_logical_router(self, lrouter_id):
        if lrouter_id in self.logical_routers:
            del self.logical_routers[lrouter_id]
        else:
            raise nsx_exc.ResourceNotFound(manager=FAKE_MANAGER,
                                           operation="delete_logical_router")

    def get_logical_router_port_by_ls_id(self, logical_switch_id):
        router_ports = []
        for router_port in self.logical_router_ports.values():
            ls_port_id = router_port.get('linked_logical_switch_port_id')
            if ls_port_id:
                port = self.get_logical_port(ls_port_id)
                if port['logical_switch_id'] == logical_switch_id:
                    router_ports.append(router_port)
        if len(router_ports) >= 2:
            raise nsx_exc.NsxPluginException(
                err_msg=_("Can't support more than one logical router ports "
                          "on same logical switch %s ") % logical_switch_id)
        elif len(router_ports) == 1:
            return router_ports[0]
        else:
            err_msg = (_("Logical router link port not found on logical "
                         "switch %s") % logical_switch_id)
            raise nsx_exc.ResourceNotFound(manager=FAKE_MANAGER,
                                           operation=err_msg)

    def create_logical_port(self, lswitch_id, vif_uuid, tags,
                            attachment_type=nsx_constants.ATTACHMENT_VIF,
                            admin_state=True, name=None, address_bindings=None,
                            parent_name=None, parent_tag=None):
        fake_port = create_logical_port(
            lswitch_id, vif_uuid, tags,
            attachment_type=attachment_type,
            admin_state=admin_state, name=name,
            address_bindings=address_bindings,
            parent_name=parent_name, parent_tag=parent_tag)
        fake_port_uuid = fake_port['id']
        self.logical_ports[fake_port_uuid] = fake_port
        return fake_port

    def get_logical_port(self, logical_port_id):
        if logical_port_id in self.logical_ports:
            return self.logical_ports[logical_port_id]
        else:
            raise nsx_exc.ResourceNotFound(
                manager=FAKE_MANAGER, operation="get_logical_port")

    def get_logical_router_ports_by_router_id(self, logical_router_id):
        logical_router_ports = []
        for port_id in self.logical_router_ports.keys():
            if (self.logical_router_ports[port_id]['logical_router_id'] ==
                logical_router_id):
                logical_router_ports.append(self.logical_router_ports[port_id])
        return logical_router_ports

    def create_logical_router_port(self, logical_router_id,
                                   display_name,
                                   resource_type,
                                   logical_port_id,
                                   address_groups,
                                   edge_cluster_member_index=None):
        fake_router_port_uuid = uuidutils.generate_uuid()
        body = {'display_name': display_name,
                'resource_type': resource_type,
                'logical_router_id': logical_router_id}
        if address_groups:
            body['subnets'] = address_groups
        if resource_type in ["LogicalRouterUplinkPort",
                             "LogicalRouterDownLinkPort"]:
            body['linked_logical_switch_port_id'] = logical_port_id
        elif logical_port_id:
            body['linked_logical_router_port_id'] = logical_port_id
        if edge_cluster_member_index:
            body['edge_cluster_member_index'] = edge_cluster_member_index
        body['id'] = fake_router_port_uuid
        self.logical_router_ports[fake_router_port_uuid] = body
        return body

    def update_logical_router_port(self, logical_port_id, **kwargs):
        if logical_port_id in self.logical_router_ports:
            payload = self.logical_router_ports[logical_port_id]
            payload.update(kwargs)
            return payload
        else:
            raise nsx_exc.ResourceNotFound(
                manager=FAKE_MANAGER, operation="update_logical_router_port")

    def delete_logical_router_port(self, logical_port_id):
        if logical_port_id in self.logical_router_ports:
            del self.logical_router_ports[logical_port_id]
        else:
            raise nsx_exc.ResourceNotFound(
                manager=FAKE_MANAGER, operation="update_logical_router_port")

    def add_nat_rule(self, logical_router_id, action, translated_network,
                     source_net=None, dest_net=None, enabled=True,
                     rule_priority=None):
        fake_rule_id = uuidutils.generate_uuid()
        if logical_router_id not in self.logical_routers.keys():
            raise nsx_exc.ResourceNotFound(
                manager=FAKE_MANAGER, operation="get_logical_router")
        body = {'action': action,
                'enabled': enabled,
                'translated_network': translated_network}
        if source_net:
            body['match_source_network'] = source_net
        if dest_net:
            body['match_destination_network'] = dest_net
        if rule_priority:
            body['rule_priority'] = rule_priority
        body['rule_id'] = fake_rule_id
        if self.logical_router_nat_rules.get(logical_router_id):
            self.logical_router_nat_rules[logical_router_id][fake_rule_id] = (
                body)
        else:
            self.logical_router_nat_rules[logical_router_id] = {
                fake_rule_id: body}
        return body

    def delete_nat_rule(self, logical_router_id, nat_rule_id):
        if (self.logical_router_nat_rules.get(logical_router_id) and
            self.logical_router_nat_rules[logical_router_id].get(nat_rule_id)):
            del self.logical_router_nat_rules[logical_router_id][nat_rule_id]
        else:
            raise nsx_exc.ResourceNotFound(
                manager=FAKE_MANAGER, operation="delete_nat_rule")

    def delete_nat_rule_by_values(self, logical_router_id, **kwargs):
        if self.logical_router_nat_rules.get(logical_router_id):
            nat_rules = self.logical_router_nat_rules[logical_router_id]
            remove_nat_rule_ids = []
            for nat_id, nat_body in nat_rules.items():
                remove_flag = True
                for k, v in kwargs.items():
                    if nat_body[k] != v:
                        remove_flag = False
                        break
                if remove_flag:
                    remove_nat_rule_ids.append(nat_id)
            for nat_id in remove_nat_rule_ids:
                del nat_rules[nat_id]
        else:
            raise nsx_exc.ResourceNotFound(
                manager=FAKE_MANAGER, operation="delete_nat_rule_by_values")

    def update_logical_router_advertisement(self, logical_router_id, **kwargs):
        # TODO(berlin): implement this latter.
        pass


class MockRequestsResponse(object):
    def __init__(self, status_code, content=None):
        self.status_code = status_code
        self.content = content

    def json(self):
        return jsonutils.loads(self.content)
