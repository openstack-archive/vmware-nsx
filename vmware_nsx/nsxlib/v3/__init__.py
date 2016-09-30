# Copyright 2016 OpenStack Foundation
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

from oslo_log import log

from vmware_nsx._i18n import _, _LW
from vmware_nsx.nsxlib.v3 import client
from vmware_nsx.nsxlib.v3 import cluster
from vmware_nsx.nsxlib.v3 import exceptions
from vmware_nsx.nsxlib.v3 import native_dhcp
from vmware_nsx.nsxlib.v3 import nsx_constants
from vmware_nsx.nsxlib.v3 import security
from vmware_nsx.nsxlib.v3 import utils

LOG = log.getLogger(__name__)


class NsxLib(object):

    def __init__(self, nsxlib_config):

        self.nsxlib_config = nsxlib_config

        # create the Cluster
        self.cluster = cluster.NSXClusteredAPI(nsxlib_config)

        # create the Client
        self.client = client.NSX3Client(
            self.cluster,
            max_attempts=nsxlib_config.max_attempts)

        # init the api object
        self.general_apis = utils.NsxLibApiBase(
            self.client, nsxlib_config)
        self.port_mirror = NsxLibPortMirror(
            self.client, nsxlib_config)
        self.bridge_endpoint = NsxLibBridgeEndpoint(
            self.client, nsxlib_config)
        self.logical_switch = NsxLibLogicalSwitch(
            self.client, nsxlib_config)
        self.logical_router = NsxLibLogicalRouter(
            self.client, nsxlib_config)
        self.qos_switching_profile = NsxLibQosSwitchingProfile(
            self.client, nsxlib_config)
        self.edge_cluster = NsxLibEdgeCluster(
            self.client, nsxlib_config)
        self.bridge_cluster = NsxLibBridgeCluster(
            self.client, nsxlib_config)
        self.transport_zone = NsxLibTransportZone(
            self.client, nsxlib_config)
        self.firewall_section = security.NsxLibFirewallSection(
            self.client, nsxlib_config)
        self.ns_group = security.NsxLibNsGroup(
            self.client, nsxlib_config, self.firewall_section)
        self.native_dhcp = native_dhcp.NsxLibNativeDhcp(
            self.client, nsxlib_config)

        super(NsxLib, self).__init__()

    def get_version(self):
        node = self.client.get("node")
        version = node.get('node_version')
        return version

    def build_v3_api_version_tag(self):
        return self.general_apis.build_v3_api_version_tag()

    def is_internal_resource(self, nsx_resource):
        return self.general_apis.is_internal_resource(nsx_resource)

    def build_v3_tags_payload(self, resource, resource_type, project_name):
        return self.general_apis.build_v3_tags_payload(
            resource, resource_type, project_name)

    def reinitialize_cluster(self, resource, event, trigger, **kwargs):
        self.cluster.reinit_cluster()


class NsxLibPortMirror(utils.NsxLibApiBase):

    def create_session(self, source_ports, dest_ports, direction,
                       description, name, tags):
        """Create a PortMirror Session on the backend.

        :param source_ports: List of UUIDs of the ports whose traffic is to be
                            mirrored.
        :param dest_ports: List of UUIDs of the ports where the mirrored
                          traffic is to be sent.
        :param direction: String representing the direction of traffic to be
                          mirrored. [INGRESS, EGRESS, BIDIRECTIONAL]
        :param description: String representing the description of the session.
        :param name: String representing the name of the session.
        :param tags: nsx backend specific tags.
        """

        resource = 'mirror-sessions'
        body = {'direction': direction,
                'tags': tags,
                'display_name': name,
                'description': description,
                'mirror_sources': source_ports,
                'mirror_destination': dest_ports}
        return self.client.create(resource, body)

    def delete_session(self, mirror_session_id):
        """Delete a PortMirror session on the backend.

        :param mirror_session_id: string representing the UUID of the port
                                  mirror session to be deleted.
        """
        resource = 'mirror-sessions/%s' % mirror_session_id
        self.client.delete(resource)


class NsxLibBridgeEndpoint(utils.NsxLibApiBase):

    def create(self, device_name, seg_id, tags):
        """Create a bridge endpoint on the backend.

        Create a bridge endpoint resource on a bridge cluster for the L2
        gateway network connection.
        :param device_name: device_name actually refers to the bridge cluster's
                            UUID.
        :param seg_id: integer representing the VLAN segmentation ID.
        :param tags: nsx backend specific tags.
        """
        resource = 'bridge-endpoints'
        body = {'bridge_cluster_id': device_name,
                'tags': tags,
                'vlan': seg_id}
        return self.client.create(resource, body)

    def delete(self, bridge_endpoint_id):
        """Delete a bridge endpoint on the backend.

        :param bridge_endpoint_id: string representing the UUID of the bridge
                                   endpoint to be deleted.
        """
        resource = 'bridge-endpoints/%s' % bridge_endpoint_id
        self.client.delete(resource)


class NsxLibLogicalSwitch(utils.NsxLibApiBase):

    def create(self, display_name, transport_zone_id, tags,
               replication_mode=nsx_constants.MTEP,
               admin_state=True, vlan_id=None):
        # TODO(salv-orlando): Validate Replication mode and admin_state
        # NOTE: These checks might be moved to the API client library if one
        # that performs such checks in the client is available

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

        return self.client.create(resource, body)

    def delete(self, lswitch_id):
        #Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self.nsxlib_config.max_attempts)
        def _do_delete():
            resource = ('logical-switches/%s?detach=true&cascade=true' %
                        lswitch_id)
            self.client.delete(resource)

        _do_delete()

    def get(self, logical_switch_id):
        resource = "logical-switches/%s" % logical_switch_id
        return self.client.get(resource)

    def update(self, lswitch_id, name=None, admin_state=None, tags=None):
        #Using internal method so we can access max_attempts in the decorator
        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self.nsxlib_config.max_attempts)
        def _do_update():
            resource = "logical-switches/%s" % lswitch_id
            lswitch = self.get(lswitch_id)
            if name is not None:
                lswitch['display_name'] = name
            if admin_state is not None:
                if admin_state:
                    lswitch['admin_state'] = nsx_constants.ADMIN_STATE_UP
                else:
                    lswitch['admin_state'] = nsx_constants.ADMIN_STATE_DOWN
            if tags is not None:
                lswitch['tags'] = tags
            return self.client.update(resource, lswitch)

        return _do_update()


class NsxLibQosSwitchingProfile(utils.NsxLibApiBase):

    def _build_args(self, tags, name=None, description=None):
        body = {"resource_type": "QosSwitchingProfile",
                "tags": tags}
        return self._update_args(
            body, name=name, description=description)

    def _update_args(self, body, name=None, description=None):
        if name:
            body["display_name"] = name
        if description:
            body["description"] = description
        return body

    def _enable_shaping_in_args(self, body, burst_size=None,
                                peak_bandwidth=None, average_bandwidth=None):
        for shaper in body["shaper_configuration"]:
            # We currently supports only shaping of Egress traffic
            if shaper["resource_type"] == "EgressRateShaper":
                shaper["enabled"] = True
                if burst_size:
                    shaper["burst_size_bytes"] = burst_size
                if peak_bandwidth:
                    shaper["peak_bandwidth_mbps"] = peak_bandwidth
                if average_bandwidth:
                    shaper["average_bandwidth_mbps"] = average_bandwidth
                break

        return body

    def _disable_shaping_in_args(self, body):
        for shaper in body["shaper_configuration"]:
            # We currently supports only shaping of Egress traffic
            if shaper["resource_type"] == "EgressRateShaper":
                shaper["enabled"] = False
                shaper["burst_size_bytes"] = 0
                shaper["peak_bandwidth_mbps"] = 0
                shaper["average_bandwidth_mbps"] = 0
                break

        return body

    def _update_dscp_in_args(self, body, qos_marking, dscp):
        body["dscp"] = {}
        body["dscp"]["mode"] = qos_marking.upper()
        if dscp:
            body["dscp"]["priority"] = dscp

        return body

    def create(self, tags, name=None, description=None):
        resource = 'switching-profiles'
        body = self._build_args(tags, name, description)
        return self.client.create(resource, body)

    def update(self, profile_id, tags, name=None, description=None):
        resource = 'switching-profiles/%s' % profile_id
        # get the current configuration
        body = self.get(profile_id)
        # update the relevant fields
        body = self._update_args(body, name, description)
        return self._update_resource_with_retry(resource, body)

    def update_shaping(self, profile_id,
                       shaping_enabled=False,
                       burst_size=None,
                       peak_bandwidth=None,
                       average_bandwidth=None,
                       qos_marking=None, dscp=None):
        resource = 'switching-profiles/%s' % profile_id
        # get the current configuration
        body = self.get(profile_id)
        # update the relevant fields
        if shaping_enabled:
            body = self._enable_shaping_in_args(
                body, burst_size=burst_size,
                peak_bandwidth=peak_bandwidth,
                average_bandwidth=average_bandwidth)
        else:
            body = self._disable_shaping_in_args(body)
        body = self._update_dscp_in_args(body, qos_marking, dscp)
        return self._update_resource_with_retry(resource, body)

    def get(self, profile_id):
        resource = 'switching-profiles/%s' % profile_id
        return self.client.get(resource)

    def delete(self, profile_id):
        resource = 'switching-profiles/%s' % profile_id
        self.client.delete(resource)


class NsxLibLogicalRouter(utils.NsxLibApiBase):

    def _delete_resource_by_values(self, resource,
                                   skip_not_found=True, **kwargs):
        resources_get = self.client.get(resource)
        matched_num = 0
        for res in resources_get['results']:
            if utils.dict_match(kwargs, res):
                LOG.debug("Deleting %s from resource %s", res, resource)
                delete_resource = resource + "/" + str(res['id'])
                self.client.delete(delete_resource)
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
                raise exceptions.ResourceNotFound(
                    manager=self.cluster.nsx_api_managers,
                    operation=err_msg)
        elif matched_num > 1:
            LOG.warning(_LW("%(num)s resources in %(res)s matched for values: "
                            "%(values)s"), {'num': matched_num,
                                            'res': resource,
                                            'values': kwargs})

    def add_nat_rule(self, logical_router_id, action, translated_network,
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
        return self.client.create(resource, body)

    def add_static_route(self, logical_router_id, dest_cidr, nexthop):
        resource = ('logical-routers/%s/routing/static-routes' %
                    logical_router_id)
        body = {}
        if dest_cidr:
            body['network'] = dest_cidr
        if nexthop:
            body['next_hops'] = [{"ip_address": nexthop}]
        return self.client.create(resource, body)

    def delete_static_route(self, logical_router_id, static_route_id):
        resource = 'logical-routers/%s/routing/static-routes/%s' % (
            logical_router_id, static_route_id)
        self.client.delete(resource)

    def delete_static_route_by_values(self, logical_router_id,
                                      dest_cidr=None, nexthop=None):
        resource = ('logical-routers/%s/routing/static-routes' %
                    logical_router_id)
        kwargs = {}
        if dest_cidr:
            kwargs['network'] = dest_cidr
        if nexthop:
            kwargs['next_hops'] = [{"ip_address": nexthop}]
        return self._delete_resource_by_values(resource, **kwargs)

    def delete_nat_rule(self, logical_router_id, nat_rule_id):
        resource = 'logical-routers/%s/nat/rules/%s' % (logical_router_id,
                                                        nat_rule_id)
        self.client.delete(resource)

    def delete_nat_rule_by_values(self, logical_router_id, **kwargs):
        resource = 'logical-routers/%s/nat/rules' % logical_router_id
        return self._delete_resource_by_values(resource, **kwargs)

    def update_advertisement(self, logical_router_id, **kwargs):
        resource = ('logical-routers/%s/routing/advertisement' %
                    logical_router_id)
        return self._update_resource_with_retry(resource, kwargs)

    def get_id_by_name_or_id(self, name_or_id):
        """Get a logical router by it's display name or uuid

        Return the logical router data, or raise an exception if not found or
        not unique
        """

        return self._get_resource_by_name_or_id(name_or_id,
                                                'logical-routers')


class NsxLibEdgeCluster(utils.NsxLibApiBase):

    def get(self, edge_cluster_uuid):
        resource = "edge-clusters/%s" % edge_cluster_uuid
        return self.client.get(resource)


class NsxLibTransportZone(utils.NsxLibApiBase):

    def get_id_by_name_or_id(self, name_or_id):
        """Get a transport zone by it's display name or uuid

        Return the transport zone data, or raise an exception if not found or
        not unique
        """

        return self._get_resource_by_name_or_id(name_or_id,
                                                'transport-zones')


class NsxLibBridgeCluster(utils.NsxLibApiBase):

    def get_id_by_name_or_id(self, name_or_id):
        """Get a bridge cluster by it's display name or uuid

        Return the bridge cluster data, or raise an exception if not found or
        not unique
        """

        return self._get_resource_by_name_or_id(name_or_id,
                                                'bridge-clusters')
