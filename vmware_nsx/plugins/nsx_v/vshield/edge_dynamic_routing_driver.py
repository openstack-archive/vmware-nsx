# Copyright 2017 VMware, Inc
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
import time

from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.common import locking

LOG = logging.getLogger(__name__)


class EdgeDynamicRoutingDriver(object):

    """Edge driver API to implement the dynamic routing"""

    def __init__(self):
        # it will be initialized at subclass
        self.vcns = None
        self.ecmp_wait_time = cfg.CONF.nsxv.ecmp_wait_time

    def _prepare_bgp_config(self, bgp_config):
        bgp_config.setdefault('enabled', False)
        bgp_config.setdefault('bgpNeighbours', {'bgpNeighbours': []})
        bgp_config.setdefault('redistribution', {'rules': {'rules': []}})

        curr_neighbours = [{'bgpNeighbour': nbr} for nbr in
                           bgp_config['bgpNeighbours']['bgpNeighbours']]
        bgp_config['bgpNeighbours'] = curr_neighbours
        for nbr in curr_neighbours:
            bgp_filters = [{'bgpFilter': bf} for bf
                           in nbr['bgpNeighbour']['bgpFilters']['bgpFilters']]
            nbr['bgpNeighbour']['bgpFilters'] = bgp_filters
        redistribution_rules = [{'rule': rule} for rule in
                                bgp_config['redistribution']['rules']['rules']]
        bgp_config['redistribution']['rules'] = redistribution_rules

    def _get_routing_config(self, edge_id):
        h, config = self.vcns.get_edge_routing_config(edge_id)
        # Backend complains when adding this in the request.
        config.pop('featureType')
        config.pop('ospf')
        global_config = config['routingGlobalConfig']
        bgp_config = config.get('bgp', {})

        self._prepare_bgp_config(bgp_config)

        global_config.setdefault('ipPrefixes', {'ipPrefixes': []})
        curr_prefixes = [{'ipPrefix': prx}
                         for prx in global_config['ipPrefixes']['ipPrefixes']]
        global_config['ipPrefixes'] = curr_prefixes

        # Don't change any static routes.
        static_routing = config.get('staticRouting', {})
        static_routes = static_routing.get('staticRoutes', {})
        current_routes = [{'route': route}
                          for route in static_routes.get('staticRoutes', [])]
        static_routing['staticRoutes'] = current_routes
        return {'routing': config}

    def _update_routing_config(self, edge_id, **kwargs):
        routing_config = self._get_routing_config(edge_id)
        global_config = routing_config['routing']['routingGlobalConfig']
        current_prefixes = global_config['ipPrefixes']

        global_config['ecmp'] = True

        if 'router_id' in kwargs:
            global_config['routerId'] = kwargs['router_id']

        current_prefixes[:] = [p for p in current_prefixes
                               if p['ipPrefix']['name'] not in
                               kwargs.get('prefixes_to_remove', [])]
        # Avoid adding duplicate rules when shared router relocation
        current_prefixes.extend([p for p in kwargs.get('prefixes_to_add', [])
                                 if p not in current_prefixes])

        self.vcns.update_edge_routing_config(edge_id, routing_config)

    def _reset_routing_global_config(self, edge_id):
        routing_config = self._get_routing_config(edge_id)
        global_config = routing_config['routing']['routingGlobalConfig']
        global_config['ecmp'] = False
        global_config.pop('routerId')
        global_config.pop('ipPrefixes')
        self.vcns.update_edge_routing_config(edge_id, routing_config)

    def get_routing_bgp_config(self, edge_id):
        h, config = self.vcns.get_bgp_routing_config(edge_id)
        bgp_config = config if config else {}
        self._prepare_bgp_config(bgp_config)
        return {'bgp': bgp_config}

    def _update_bgp_routing_config(self, edge_id, **kwargs):
        bgp_config = self.get_routing_bgp_config(edge_id)
        curr_neighbours = bgp_config['bgp']['bgpNeighbours']
        curr_rules = bgp_config['bgp']['redistribution']['rules']

        bgp_config['bgp']['enabled'] = True

        if 'default_originate' in kwargs:
            bgp_config['bgp']['defaultOriginate'] = kwargs['default_originate']

        if 'local_as' in kwargs:
            bgp_config['bgp']['localAS'] = kwargs['local_as']

        if 'enabled' in kwargs:
            bgp_config['bgp']['redistribution']['enabled'] = kwargs['enabled']

        curr_rules[:] = [rule for rule in curr_rules
                         if rule['rule'].get('prefixName') not in
                         kwargs.get('rules_to_remove', [])]
        # Avoid adding duplicate rules when shared router relocation
        curr_rules_prefixes = [r['rule'].get('prefixName') for r in curr_rules]
        curr_rules.extend([r for r in kwargs.get('rules_to_add', [])
                           if r['rule'].get('prefixName') not in
                           curr_rules_prefixes])

        neighbours_to_remove = [nbr['bgpNeighbour']['ipAddress'] for nbr in
                                kwargs.get('neighbours_to_remove', [])]
        curr_neighbours[:] = [nbr for nbr in curr_neighbours
                              if nbr['bgpNeighbour']['ipAddress']
                              not in neighbours_to_remove]
        curr_neighbours.extend(kwargs.get('neighbours_to_add', []))

        self.vcns.update_bgp_dynamic_routing(edge_id, bgp_config)

    def add_bgp_speaker_config(self, edge_id, prot_router_id, local_as,
                               enabled, bgp_neighbours,
                               prefixes, redistribution_rules,
                               default_originate=False):
        with locking.LockManager.get_lock(str(edge_id)):
            self._update_routing_config(edge_id,
                                        router_id=prot_router_id,
                                        prefixes_to_add=prefixes)
            if self.ecmp_wait_time > 0:
                time.sleep(self.ecmp_wait_time)
            self._update_bgp_routing_config(
                edge_id, enabled=enabled, local_as=local_as,
                neighbours_to_add=bgp_neighbours, prefixes_to_add=prefixes,
                rules_to_add=redistribution_rules,
                default_originate=default_originate)

    def delete_bgp_speaker_config(self, edge_id):
        with locking.LockManager.get_lock(str(edge_id)):
            self.vcns.delete_bgp_routing_config(edge_id)
            self._reset_routing_global_config(edge_id)

    def add_bgp_neighbours(self, edge_id, bgp_neighbours):
        # Query the bgp config first and update the bgpNeighbour
        with locking.LockManager.get_lock(str(edge_id)):
            self._update_bgp_routing_config(edge_id,
                                            neighbours_to_add=bgp_neighbours)

    def remove_bgp_neighbours(self, edge_id, bgp_neighbours):
        with locking.LockManager.get_lock(str(edge_id)):
            self._update_bgp_routing_config(
                edge_id, neighbours_to_remove=bgp_neighbours)

    def update_bgp_neighbours(self, edge_id, neighbours_to_add=None,
                              neighbours_to_remove=None):
        with locking.LockManager.get_lock(str(edge_id)):
            self._update_bgp_routing_config(
                edge_id,
                neighbours_to_add=neighbours_to_add,
                neighbours_to_remove=neighbours_to_remove)

    def update_routing_redistribution(self, edge_id, enabled):
        with locking.LockManager.get_lock(str(edge_id)):
            self._update_bgp_routing_config(edge_id, enabled=enabled)

    def add_bgp_redistribution_rules(self, edge_id, prefixes, rules):
        with locking.LockManager.get_lock(str(edge_id)):
            self._update_routing_config(edge_id, prefixes_to_add=prefixes)
            self._update_bgp_routing_config(edge_id, rules_to_add=rules)
        LOG.debug("Added redistribution rules %s on edge %s", rules, edge_id)

    def remove_bgp_redistribution_rules(self, edge_id, prefixes):
        with locking.LockManager.get_lock(str(edge_id)):
            self._update_bgp_routing_config(edge_id, rules_to_remove=prefixes)
            self._update_routing_config(edge_id, prefixes_to_remove=prefixes)
        LOG.debug("Removed redistribution rules for prefixes %s on edge %s",
                  prefixes, edge_id)

    def update_router_id(self, edge_id, router_id):
        with locking.LockManager.get_lock(str(edge_id)):
            self._update_routing_config(edge_id, router_id=router_id)
