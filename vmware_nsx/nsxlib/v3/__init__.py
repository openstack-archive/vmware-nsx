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
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils
from vmware_nsx.nsxlib.v3 import client
from vmware_nsx.nsxlib.v3 import cluster
from vmware_nsx.nsxlib.v3 import dfw_api
from vmware_nsx.nsxlib.v3 import exceptions
from vmware_nsx.nsxlib.v3 import security

LOG = log.getLogger(__name__)

# Max amount of time to try a request
DEFAULT_MAX_ATTEMPTS = 3


class NsxLib(dfw_api.DfwApi, security.Security):

    MAX_ATTEMPTS = DEFAULT_MAX_ATTEMPTS

    def __init__(self,
                 username=None,
                 password=None,
                 retries=None,
                 insecure=None,
                 ca_file=None,
                 concurrent_connections=None,
                 http_timeout=None,
                 http_read_timeout=None,
                 conn_idle_timeout=None,
                 http_provider=None,
                 max_attempts=DEFAULT_MAX_ATTEMPTS):

        self.max_attempts = max_attempts
        self.cluster = cluster.NSXClusteredAPI(
            username=username, password=password,
            retries=retries, insecure=insecure,
            ca_file=ca_file,
            concurrent_connections=concurrent_connections,
            http_timeout=http_timeout,
            http_read_timeout=http_read_timeout,
            conn_idle_timeout=conn_idle_timeout,
            http_provider=http_provider)

        self.client = client.NSX3Client(self.cluster)
        super(NsxLib, self).__init__()

    def get_version(self):
        node = self.client.get("node")
        version = node.get('node_version')
        return version

    def get_edge_cluster(self, edge_cluster_uuid):
        resource = "edge-clusters/%s" % edge_cluster_uuid
        return self.client.get(resource)

    @utils.retry_upon_exception_nsxv3(exceptions.StaleRevision)
    def update_resource_with_retry(self, resource, payload):
        revised_payload = self.client.get(resource)
        for key_name in payload.keys():
            revised_payload[key_name] = payload[key_name]
        return self.client.update(resource, revised_payload)

    def delete_resource_by_values(self, resource,
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
                    manager=client._get_nsx_managers_from_conf(),
                    operation=err_msg)
        elif matched_num > 1:
            LOG.warning(_LW("%(num)s resources in %(res)s matched for values: "
                            "%(values)s"), {'num': matched_num,
                                            'res': resource,
                                            'values': kwargs})

    def create_logical_switch(self, display_name, transport_zone_id, tags,
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

    @utils.retry_upon_exception_nsxv3(exceptions.StaleRevision,
                                      max_attempts=MAX_ATTEMPTS)
    def delete_logical_switch(self, lswitch_id):
        resource = 'logical-switches/%s?detach=true&cascade=true' % lswitch_id
        self.client.delete(resource)

    def get_logical_switch(self, logical_switch_id):
        resource = "logical-switches/%s" % logical_switch_id
        return self.client.get(resource)

    @utils.retry_upon_exception_nsxv3(exceptions.StaleRevision,
                                      max_attempts=MAX_ATTEMPTS)
    def update_logical_switch(self, lswitch_id, name=None, admin_state=None,
                              tags=None):
        resource = "logical-switches/%s" % lswitch_id
        lswitch = self.get_logical_switch(lswitch_id)
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
        return self.delete_resource_by_values(resource, **kwargs)

    def delete_nat_rule(self, logical_router_id, nat_rule_id):
        resource = 'logical-routers/%s/nat/rules/%s' % (logical_router_id,
                                                        nat_rule_id)
        self.client.delete(resource)

    def delete_nat_rule_by_values(self, logical_router_id, **kwargs):
        resource = 'logical-routers/%s/nat/rules' % logical_router_id
        return self.delete_resource_by_values(resource, **kwargs)

    def update_logical_router_advertisement(self, logical_router_id, **kwargs):
        resource = ('logical-routers/%s/routing/advertisement' %
                    logical_router_id)
        return self.update_resource_with_retry(resource, kwargs)

    def _build_qos_switching_profile_args(self, tags, name=None,
                                          description=None):
        body = {"resource_type": "QosSwitchingProfile",
                "tags": tags}
        return self._update_qos_switching_profile_args(
            body, name=name, description=description)

    def _update_qos_switching_profile_args(self, body, name=None,
                                           description=None):
        if name:
            body["display_name"] = name
        if description:
            body["description"] = description
        return body

    def _enable_shaping_in_args(self, body, burst_size=None,
                                peak_bandwidth=None, average_bandwidth=None):
        for shaper in body["shaper_configuration"]:
            # Neutron currently supports only shaping of Egress traffic
            # And the direction on NSX is opposite (vswitch point of view)
            if shaper["resource_type"] == "IngressRateShaper":
                shaper["enabled"] = True
                if burst_size is not None:
                    shaper["burst_size_bytes"] = burst_size
                if peak_bandwidth is not None:
                    shaper["peak_bandwidth_mbps"] = peak_bandwidth
                if average_bandwidth is not None:
                    shaper["average_bandwidth_mbps"] = average_bandwidth
                break

        return body

    def _disable_shaping_in_args(self, body):
        for shaper in body["shaper_configuration"]:
            # Neutron currently supports only shaping of Egress traffic
            # And the direction on NSX is opposite (vswitch point of view)
            if shaper["resource_type"] == "IngressRateShaper":
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

    def create_qos_switching_profile(self, tags, name=None,
                                     description=None):
        resource = 'switching-profiles'
        body = self._build_qos_switching_profile_args(tags, name,
                                                      description)
        return self.client.create(resource, body)

    def update_qos_switching_profile(self, profile_id, tags, name=None,
                                     description=None):
        resource = 'switching-profiles/%s' % profile_id
        # get the current configuration
        body = self.get_qos_switching_profile(profile_id)
        # update the relevant fields
        body = self._update_qos_switching_profile_args(body, name,
                                                       description)
        return self.update_resource_with_retry(resource, body)

    def update_qos_switching_profile_shaping(self, profile_id,
                                             shaping_enabled=False,
                                             burst_size=None,
                                             peak_bandwidth=None,
                                             average_bandwidth=None,
                                             qos_marking=None, dscp=None):
        resource = 'switching-profiles/%s' % profile_id
        # get the current configuration
        body = self.get_qos_switching_profile(profile_id)
        # update the relevant fields
        if shaping_enabled:
            body = self._enable_shaping_in_args(
                body, burst_size=burst_size,
                peak_bandwidth=peak_bandwidth,
                average_bandwidth=average_bandwidth)
        else:
            body = self._disable_shaping_in_args(body)
        body = self._update_dscp_in_args(body, qos_marking, dscp)
        return self.update_resource_with_retry(resource, body)

    def get_qos_switching_profile(self, profile_id):
        resource = 'switching-profiles/%s' % profile_id
        return self.client.get(resource)

    def delete_qos_switching_profile(self, profile_id):
        resource = 'switching-profiles/%s' % profile_id
        self.client.delete(resource)

    def create_bridge_endpoint(self, device_name, seg_id, tags):
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

    def delete_bridge_endpoint(self, bridge_endpoint_id):
        """Delete a bridge endpoint on the backend.

        :param bridge_endpoint_id: string representing the UUID of the bridge
                                   endpoint to be deleted.
        """
        resource = 'bridge-endpoints/%s' % bridge_endpoint_id
        self.client.delete(resource)

    def _get_resource_by_name_or_id(self, name_or_id, resource):
        all_results = self.client.get(resource)['results']
        matched_results = []
        for rs in all_results:
            if rs.get('id') == name_or_id:
                # Matched by id - must be unique
                return name_or_id

            if rs.get('display_name') == name_or_id:
                # Matched by name - add to the list to verify it is unique
                matched_results.append(rs)

        if len(matched_results) == 0:
            err_msg = (_("Could not find %(resource)s %(name)s") %
                       {'name': name_or_id, 'resource': resource})
            # XXX improve exception handling...
            raise exceptions.ManagerError(details=err_msg)
        elif len(matched_results) > 1:
            err_msg = (_("Found multiple %(resource)s named %(name)s") %
                       {'name': name_or_id, 'resource': resource})
            # XXX improve exception handling...
            raise exceptions.ManagerError(details=err_msg)

        return matched_results[0].get('id')

    def get_transport_zone_id_by_name_or_id(self, name_or_id):
        """Get a transport zone by it's display name or uuid

        Return the transport zone data, or raise an exception if not found or
        not unique
        """

        return self._get_resource_by_name_or_id(name_or_id,
                                                'transport-zones')

    def get_logical_router_id_by_name_or_id(self, name_or_id):
        """Get a logical router by it's display name or uuid

        Return the logical router data, or raise an exception if not found or
        not unique
        """

        return self._get_resource_by_name_or_id(name_or_id,
                                                'logical-routers')

    def get_bridge_cluster_id_by_name_or_id(self, name_or_id):
        """Get a bridge cluster by it's display name or uuid

        Return the bridge cluster data, or raise an exception if not found or
        not unique
        """

        return self._get_resource_by_name_or_id(name_or_id,
                                                'bridge-clusters')

    def create_port_mirror_session(self, source_ports, dest_ports, direction,
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

    def delete_port_mirror_session(self, mirror_session_id):
        """Delete a PortMirror session on the backend.

        :param mirror_session_id: string representing the UUID of the port
                                  mirror session to be deleted.
        """
        resource = 'mirror-sessions/%s' % mirror_session_id
        self.client.delete(resource)
