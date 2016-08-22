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

import six

from neutronclient.common import exceptions as n_exc
from neutronclient.v2_0 import client


class ApiReplayClient(object):

    def __init__(self, source_os_username, source_os_tenant_name,
                 source_os_password, source_os_auth_url,
                 dest_os_username, dest_os_tenant_name,
                 dest_os_password, dest_os_auth_url):

        self._source_os_username = source_os_username
        self._source_os_tenant_name = source_os_tenant_name
        self._source_os_password = source_os_password
        self._source_os_auth_url = source_os_auth_url

        self._dest_os_username = dest_os_username
        self._dest_os_tenant_name = dest_os_tenant_name
        self._dest_os_password = dest_os_password
        self._dest_os_auth_url = dest_os_auth_url

        self.source_neutron = client.Client(
            username=self._source_os_username,
            tenant_name=self._source_os_tenant_name,
            password=self._source_os_password,
            auth_url=self._source_os_auth_url)

        self.dest_neutron = client.Client(
            username=self._dest_os_username,
            tenant_name=self._dest_os_tenant_name,
            password=self._dest_os_password,
            auth_url=self._dest_os_auth_url)

        self.migrate_security_groups()
        self.migrate_qos_policies()
        routers_routes = self.migrate_routers()
        self.migrate_networks_subnets_ports()
        self.migrate_floatingips()
        self.migrate_routers_routes(routers_routes)

    def find_subnet_by_id(self, subnet_id, subnets):
        for subnet in subnets:
            if subnet['id'] == subnet_id:
                return subnet

    def subnet_drop_ipv6_fields_if_v4(self, body):
        """
        Drops v6 fields on subnets that are v4 as server doesn't allow them.
        """
        v6_fields_to_remove = ['ipv6_address_mode', 'ipv6_ra_mode']
        if body['ip_version'] != 4:
            return

        for field in v6_fields_to_remove:
            if field in body:
                body.pop(field)

    def get_ports_on_network(self, network_id, ports):
        """Returns all the ports on a given network_id."""
        ports_on_network = []
        for port in ports:
            if port['network_id'] == network_id:
                ports_on_network.append(port)
        return ports_on_network

    def have_id(self, id, groups):
        """If the sg_id is in groups return true else false."""
        for group in groups:
            if id == group['id']:
                return group

        return False

    def drop_fields(self, item, drop_fields):
        body = {}
        for k, v in item.items():
            if k in drop_fields:
                continue
            body[k] = v
        return body

    def migrate_qos_rule(self, dest_policy, source_rule):
        """Add the QoS rule from the source to the QoS policy

        If there is already a rule of that type, skip it since
        the QoS policy can have only one rule of each type
        """
        #TODO(asarfaty) also take rule direction into account once
        #ingress support is upstream
        rule_type = source_rule.get('type')
        dest_rules = dest_policy.get('rules')
        if dest_rules:
            for dest_rule in dest_rules:
                if dest_rule['type'] == rule_type:
                    return
        pol_id = dest_policy['id']
        drop_qos_rule_fields = ['revision', 'type', 'qos_policy_id', 'id']
        body = self.drop_fields(source_rule, drop_qos_rule_fields)
        try:
            if rule_type == 'bandwidth_limit':
                rule = self.dest_neutron.create_bandwidth_limit_rule(
                    pol_id, body={'bandwidth_limit_rule': body})
            elif rule_type == 'dscp_marking':
                rule = self.dest_neutron.create_dscp_marking_rule(
                    pol_id, body={'dscp_marking_rule': body})
            else:
                print("QoS rule type %s is not supported for policy %s" % (
                    rule_type, pol_id))
            print("created QoS policy %s rule %s " % (pol_id, rule))
        except Exception as e:
            print("Failed to create QoS rule for policy %s: %s" % (pol_id, e))

    def migrate_qos_policies(self):
        """Migrates QoS policies from source to dest neutron."""

        # first fetch the QoS policies from both the
        # source and destination neutron server
        try:
            source_qos_pols = self.source_neutron.list_qos_policies()[
                'policies']
        except n_exc.NotFound:
            # QoS disabled on source
            return
        try:
            dest_qos_pols = self.dest_neutron.list_qos_policies()['policies']
        except n_exc.NotFound:
            # QoS disabled on dest
            print("QoS is disabled on destination: ignoring QoS policies")
            return

        drop_qos_policy_fields = ['revision']

        for pol in source_qos_pols:
            dest_pol = self.have_id(pol['id'], dest_qos_pols)
            # If the policy already exists on the the dest_neutron
            if dest_pol:
                # make sure all the QoS policy rules are there and
                # create them if not
                for qos_rule in pol['rules']:
                    self.migrate_qos_rule(dest_pol, qos_rule)

            # dest server doesn't have the group so we create it here.
            else:
                qos_rules = pol.pop('rules')
                try:
                    body = self.drop_fields(pol, drop_qos_policy_fields)
                    new_pol = self.dest_neutron.create_qos_policy(
                        body={'policy': body})
                except Exception as e:
                    print("Failed to create QoS policy %s: %s" % (
                        pol['id'], e))
                    continue
                print("Created QoS policy %s" % new_pol)
                for qos_rule in qos_rules:
                    self.migrate_qos_rule(new_pol['policy'], qos_rule)

    def migrate_security_groups(self):
        """Migrates security groups from source to dest neutron."""

        # first fetch the security groups from both the
        # source and dest neutron server
        source_sec_groups = self.source_neutron.list_security_groups()
        dest_sec_groups = self.dest_neutron.list_security_groups()

        source_sec_groups = source_sec_groups['security_groups']
        dest_sec_groups = dest_sec_groups['security_groups']

        drop_sg_fields = ['revision']

        for sg in source_sec_groups:
            dest_sec_group = self.have_id(sg['id'], dest_sec_groups)
            # If the security group already exists on the the dest_neutron
            if dest_sec_group:
                # make sure all the security group rules are there and
                # create them if not
                for sg_rule in sg['security_group_rules']:
                    if(self.have_id(sg_rule['id'],
                                    dest_sec_group['security_group_rules'])
                       is False):
                        try:
                            body = self.drop_fields(sg_rule, drop_sg_fields)
                            print(
                                self.dest_neutron.create_security_group_rule(
                                    {'security_group_rule': body}))
                        except n_exc.Conflict:
                            # NOTE(arosen): when you create a default
                            # security group it is automatically populated
                            # with some rules. When we go to create the rules
                            # that already exist because of a match an error
                            # is raised here but thats okay.
                            pass

            # dest server doesn't have the group so we create it here.
            else:
                sg_rules = sg.pop('security_group_rules')
                try:
                    body = self.drop_fields(sg, drop_sg_fields)
                    new_sg = self.dest_neutron.create_security_group(
                        {'security_group': body})
                    print("Created security-group %s" % new_sg)
                except Exception as e:
                    # TODO(arosen): improve exception handing here.
                    print(e)

                for sg_rule in sg_rules:
                    try:
                        body = self.drop_fields(sg_rule, drop_sg_fields)
                        rule = self.dest_neutron.create_security_group_rule(
                            {'security_group_rule': body})
                        print("created security group rule %s " % rule['id'])
                    except Exception:
                        # NOTE(arosen): when you create a default
                        # security group it is automatically populated
                        # with some rules. When we go to create the rules
                        # that already exist because of a match an error
                        # is raised here but thats okay.
                        pass

    def migrate_routers(self):
        """Migrates routers from source to dest neutron.

        Also return a dictionary of the routes that should be added to
        each router. Static routes must be added later, after the router
        ports are set.
        """
        source_routers = self.source_neutron.list_routers()['routers']
        dest_routers = self.dest_neutron.list_routers()['routers']
        update_routes = {}

        for router in source_routers:
            dest_router = self.have_id(router['id'], dest_routers)
            if dest_router is False:
                if router.get('routes'):
                    update_routes[router['id']] = router['routes']

                drop_router_fields = ['status',
                                      'routes',
                                      'ha',
                                      'external_gateway_info',
                                      'router_type',
                                      'availability_zone_hints',
                                      'availability_zones',
                                      'distributed',
                                      'revision']
                body = self.drop_fields(router, drop_router_fields)
                new_router = (self.dest_neutron.create_router(
                    {'router': body}))
                print("created router %s" % new_router)
        return update_routes

    def migrate_routers_routes(self, routers_routes):
        """Add static routes to the created routers."""
        for router_id, routes in six.iteritems(routers_routes):
            self.dest_neutron.update_router(router_id,
                {'router': {'routes': routes}})
            print("Added routes to router %s" % router_id)

    def migrate_networks_subnets_ports(self):
        """Migrates networks/ports/router-uplinks from src to dest neutron."""
        source_ports = self.source_neutron.list_ports()['ports']
        source_subnets = self.source_neutron.list_subnets()['subnets']
        source_networks = self.source_neutron.list_networks()['networks']
        dest_networks = self.dest_neutron.list_networks()['networks']
        dest_ports = self.dest_neutron.list_ports()['ports']

        # NOTE: These are fields we drop of when creating a subnet as the
        # network api doesn't allow us to specify them.
        # TODO(arosen): revisit this to make these fields passable.
        drop_subnet_fields = ['updated_at',
                              'created_at',
                              'network_id',
                              'advanced_service_providers',
                              'id', 'revision']

        drop_port_fields = ['updated_at',
                            'created_at',
                            'status',
                            'port_security_enabled',
                            'binding:vif_details',
                            'binding:vif_type',
                            'binding:host_id',
                            'revision',
                            'vnic_index']

        drop_network_fields = ['status', 'subnets', 'availability_zones',
                               'created_at', 'updated_at', 'tags',
                               'ipv4_address_scope', 'ipv6_address_scope',
                               'mtu', 'revision']

        for network in source_networks:
            body = self.drop_fields(network, drop_network_fields)

            # neutron doesn't like description being None even though its
            # what it returns to us.
            if 'description' in body and body['description'] is None:
                body['description'] = ''

            # only create network if the dest server doesn't have it
            if self.have_id(network['id'], dest_networks) is False:
                created_net = self.dest_neutron.create_network(
                    {'network': body})['network']
                print("Created network:  %s " % created_net)

            created_subnet = None
            for subnet_id in network['subnets']:
                subnet = self.find_subnet_by_id(subnet_id, source_subnets)
                body = self.drop_fields(subnet, drop_subnet_fields)

                # specify the network_id that we just created above
                body['network_id'] = network['id']
                self.subnet_drop_ipv6_fields_if_v4(body)
                if 'description' in body and body['description'] is None:
                    body['description'] = ''
                try:
                    created_subnet = self.dest_neutron.create_subnet(
                        {'subnet': body})['subnet']
                    print("Created subnet: " + created_subnet['id'])
                except n_exc.BadRequest as e:
                    print(e)
                    # NOTE(arosen): this occurs here if you run the script
                    # multiple times as we don't currently
                    # perserve the subnet_id. Also, 409 would be a better
                    # response code for this in neutron :(

            # create the ports on the network
            ports = self.get_ports_on_network(network['id'], source_ports)
            for port in ports:

                body = self.drop_fields(port, drop_port_fields)

                # specify the network_id that we just created above
                port['network_id'] = network['id']

                # remove the subnet id field from fixed_ips dict
                for fixed_ips in body['fixed_ips']:
                    del fixed_ips['subnet_id']

                # only create port if the dest server doesn't have it
                if self.have_id(port['id'], dest_ports) is False:
                    if port['device_owner'] == 'network:router_gateway':
                        body = {
                            "external_gateway_info":
                                {"network_id": port['network_id']}}
                        router_uplink = self.dest_neutron.update_router(
                            port['device_id'],  # router_id
                            {'router': body})
                        print("Uplinked router %s" % router_uplink)
                        continue

                    # Let the neutron dhcp-agent recreate this on it's own
                    if port['device_owner'] == 'network:dhcp':
                        continue

                    # ignore these as we create them ourselves later
                    if port['device_owner'] == 'network:floatingip':
                        continue

                    if (port['device_owner'] == 'network:router_interface' and
                        created_subnet is not None):
                        try:
                            # uplink router_interface ports
                            self.dest_neutron.add_interface_router(
                                port['device_id'],
                                {'subnet_id': created_subnet['id']})
                            print("Uplinked router %s to subnet %s" %
                                  (port['device_id'], created_subnet['id']))
                            continue
                        except n_exc.BadRequest as e:
                            # NOTE(arosen): this occurs here if you run the
                            # script multiple times as we don't track this.
                            print(e)
                            raise

                    created_port = self.dest_neutron.create_port(
                        {'port': body})['port']
                    print("Created port: " + created_port['id'])

    def migrate_floatingips(self):
        """Migrates floatingips from source to dest neutron."""
        source_fips = self.source_neutron.list_floatingips()['floatingips']
        drop_fip_fields = ['status', 'router_id', 'id', 'revision']

        for source_fip in source_fips:
            body = self.drop_fields(source_fip, drop_fip_fields)
            fip = self.dest_neutron.create_floatingip({'floatingip': body})
            print("Created floatingip %s" % fip)
