# Copyright 2018 VMware Inc
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

import optparse

import sqlalchemy as sa

from neutron.db.models import l3
from neutron.db.models import securitygroup
from neutron.db.models import segment  # noqa
from neutron.db import models_v2

from vmware_nsx.db import nsx_models
from vmware_nsxlib import v3
from vmware_nsxlib.v3 import config
from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import policy


class NeutronNsxDB(object):
    def __init__(self, db_connection):
        super(NeutronNsxDB, self).__init__()
        engine = sa.create_engine(db_connection)
        self.session = sa.orm.session.sessionmaker()(bind=engine)

    def query_all(self, column, model):
        return list(set([r[column] for r in self.session.query(model).all()]))

    def get_security_groups(self):
        return self.query_all('id', securitygroup.SecurityGroup)

    def get_security_groups_rules(self):
        return self.query_all('id', securitygroup.SecurityGroupRule)

    def get_routers(self):
        return self.query_all('id', l3.Router)

    def get_networks(self):
        return self.query_all('id', models_v2.Network)

    def get_ports(self):
        return self.query_all('id', models_v2.Port)

    def get_logical_dhcp_servers(self):
        """The policy plugin still has mapping for the dhcp servers
        because it uses the passthrough api
        """
        return self.query_all('nsx_service_id',
                              nsx_models.NeutronNsxServiceBinding)

    def get_logical_ports(self):
        return self.query_all('nsx_port_id',
                              nsx_models.NeutronNsxPortMapping)


class NSXClient(object):
    """Base NSX REST client"""
    API_VERSION = "v1"
    NULL_CURSOR_PREFIX = '0000'

    def __init__(self, host, username, password, db_connection,
                 allow_passthrough=True):
        self.host = host
        self.username = username
        self.password = password
        self.neutron_db = (NeutronNsxDB(db_connection)
                           if db_connection else None)

        nsxlib_config = config.NsxLibConfig(
            username=self.username,
            password=self.password,
            nsx_api_managers=[self.host],
            # allow admin user to delete entities created
            # under openstack principal identity
            allow_overwrite_header=True)
        self.nsxpolicy = policy.NsxPolicyLib(nsxlib_config)
        if allow_passthrough:
            self.nsxlib = v3.NsxLib(nsxlib_config)
        else:
            self.NsxLib = None

    def get_nsx_os_domains(self):
        domains = self.get_os_resources(self.nsxpolicy.domain.list())
        return [d['id'] for d in domains]

    def cleanup_domains(self, domains):
        """Delete all OS created NSX Policy segments ports per segment"""
        for domain_id in domains:
            try:
                self.nsxpolicy.domain.delete(domain_id)
            except exceptions.ManagerError as e:
                print("Failed to delete domain %s: %s" % (domain_id, e))

    def get_os_resources(self, resources):
        """
        Get all logical resources created by OpenStack
        """
        os_resources = [r for r in resources if 'tags' in r
                        for tag in r['tags']
                        if 'os-api-version' in tag.values()]
        return os_resources

    def get_os_nsx_groups_and_maps(self, domain_id):
        """
        Retrieve all NSX policy groups & maps created from OpenStack (by tags)
        If the DB is available - use only objects in the neutron DB
        """
        groups = self.get_os_resources(self.nsxpolicy.group.list(domain_id))
        maps = self.get_os_resources(self.nsxpolicy.comm_map.list(domain_id))

        if self.neutron_db:
            db_sgs = self.neutron_db.get_security_groups()
            filtered_groups = [g for g in groups if g['id'] in db_sgs]
            maps = [m for m in maps if m['id'] in db_sgs]
            # Add groups based on SG rules local/remote ips
            db_rules = self.neutron_db.get_security_groups_rules()
            filtered_groups.extend([g for g in groups
                                   if g['id'][:36] in db_rules])
            groups = filtered_groups
        return groups, maps

    def cleanup_security_groups(self, domain_id):
        """Delete all OS created NSX Policy security group resources"""
        groups, maps = self.get_os_nsx_groups_and_maps(domain_id)
        print("Number of OS Communication maps of domain %s to be deleted: "
              "%s" % (domain_id, len(maps)))
        for m in maps:
            self.nsxpolicy.comm_map.delete(domain_id, m['id'])
        print("Number of OS Groups of domain %s to be deleted: "
              "%s" % (domain_id, len(groups)))
        for grp in groups:
            try:
                self.nsxpolicy.group.delete(domain_id, grp['id'])
            except exceptions.ManagerError as e:
                print("Failed to delete group %s: %s" % (grp['id'], e))

    def get_os_nsx_tier1_routers(self):
        """
        Retrieve all NSX policy routers created from OpenStack (by tags)
        If the DB is available - use only objects in the neutron DB
        """
        routers = self.get_os_resources(self.nsxpolicy.tier1.list())
        if routers and self.neutron_db:
            db_routers = self.neutron_db.get_routers()
            routers = [r for r in routers if r['id'] in db_routers]
        return routers

    def cleanup_tier1_nat_rules(self, tier1_uuid):
        rules = self.nsxpolicy.tier1_nat_rule.list(tier1_uuid)
        for rule in rules:
            try:
                self.nsxpolicy.tier1_nat_rule.delete(tier1_uuid, rule['id'])
            except exceptions.ManagerError as e:
                print("Failed to delete nat rule %s: %s" % (rule['id'], e))

    def cleanup_tier1_routers(self):
        """Delete all OS created NSX Policy routers"""
        routers = self.get_os_nsx_tier1_routers()
        print("Number of OS Tier1 routers to be deleted: %s" % len(routers))
        for rtr in routers:
            # remove all nat rules from this router before deletion
            self.cleanup_tier1_nat_rules(rtr['id'])
            try:
                self.nsxpolicy.tier1.remove_edge_cluster(rtr['id'])
            except exceptions.ManagerError as e:
                # Not always exists
                pass
            try:
                self.nsxpolicy.tier1.delete(rtr['id'])
            except exceptions.ManagerError as e:
                print("Failed to delete tier1 %s: %s" % (rtr['id'], e))

    def get_os_nsx_segments(self):
        """
        Retrieve all NSX policy segments created from OpenStack (by tags)
        If the DB is available - use only objects in the neutron DB
        """
        segments = self.get_os_resources(self.nsxpolicy.segment.list())
        if segments and self.neutron_db:
            db_networks = self.neutron_db.get_networks()
            segments = [s for s in segments if s['id'] in db_networks]
        return segments

    def delete_network_nsx_dhcp_port(self, network_id):
        if not self.nsxlib:
            # no passthrough api
            return
        port_id = self.nsxlib.get_id_by_resource_and_tag(
            self.nsxlib.logical_port.resource_type,
            'os-neutron-net-id', network_id)
        if port_id:
            self.nsxlib.logical_port.delete(port_id)

    def cleanup_segments(self):
        """Delete all OS created NSX Policy segments & ports"""
        segments = self.get_os_nsx_segments()
        print("Number of OS segments to be deleted: %s" % len(segments))
        for s in segments:
            # Delete all the ports
            self.cleanup_segment_ports(s['id'])
            # Delete the nsx mdproxy port
            self.delete_network_nsx_dhcp_port(s['id'])
            try:
                # Disassociate from a tier1 router
                self.nsxpolicy.segment.remove_connectivity_and_subnets(s['id'])
                # Delete the segment
                self.nsxpolicy.segment.delete(s['id'])
            except exceptions.ManagerError as e:
                print("Failed to delete segment %s: %s" % (s['id'], e))

    def get_os_nsx_segment_ports(self, segment_id):
        """
        Retrieve all NSX policy segment ports created from OpenStack (by tags)
        If the DB is available - use only objects in the neutron DB
        """
        segment_ports = self.get_os_resources(
            self.nsxpolicy.segment_port.list(segment_id))
        if segment_ports and self.neutron_db:
            db_ports = self.neutron_db.get_ports()
            segment_ports = [s for s in segment_ports if s['id'] in db_ports]
        return segment_ports

    def cleanup_segment_ports(self, segment_id):
        """Delete all OS created NSX Policy segments ports per segment"""
        segment_ports = self.get_os_nsx_segment_ports(segment_id)
        for p in segment_ports:
            try:
                self.nsxpolicy.segment_port_security_profiles.delete(
                    segment_id, p['id'])
            except Exception:
                pass
            try:
                self.nsxpolicy.segment_port_discovery_profiles.delete(
                    segment_id, p['id'])
            except Exception:
                pass
            try:
                self.nsxpolicy.segment_port_qos_profiles.delete(
                    segment_id, p['id'])
            except Exception:
                pass
            try:
                self.nsxpolicy.segment_port.delete(segment_id, p['id'])
            except exceptions.ManagerError as e:
                print("Failed to delete segment port %s: %s" % (p['id'], e))

    def get_logical_dhcp_servers(self):
        """
        Retrieve all logical DHCP servers on NSX backend
        The policy plugin still uses nsxlib for this because it uses the
        passthrough api.
        """
        return self.nsxlib.dhcp_server.list()['results']

    def get_logical_ports(self):
        """
        Retrieve all logical ports on NSX backend
        """
        return self.nsxlib.logical_port.list()['results']

    def get_os_dhcp_logical_ports(self):
        """
        Retrieve all DHCP logical ports created from OpenStack
        """
        # Get all NSX openstack ports, and filter the DHCP ones
        lports = self.get_os_resources(
            self.get_logical_ports())
        lports = [lp for lp in lports if lp.get('attachment') and
                  lp['attachment'].get(
                        'attachment_type') == nsx_constants.ATTACHMENT_DHCP]
        if self.neutron_db:
            db_lports = self.neutron_db.get_logical_ports()
            lports = [lp for lp in lports if lp['id'] in db_lports]
        return lports

    def cleanup_os_dhcp_logical_ports(self):
        """Delete all DHCP logical ports created by OpenStack

        DHCP ports are the only ones the policy plugin creates directly on
        the NSX
        """
        os_lports = self.get_os_dhcp_logical_ports()
        print("Number of OS Logical Ports to be deleted: %s" % len(os_lports))
        for p in os_lports:
            try:
                self.nsxlib.logical_port.update(
                    p['id'], None, attachment_type=None)
                self.nsxlib.logical_port.delete(p['id'])
            except Exception as e:
                print("ERROR: Failed to delete logical port %s, error %s" %
                      (p['id'], e))
            else:
                print("Successfully deleted logical port %s" % p['id'])

    def get_os_logical_dhcp_servers(self):
        """
        Retrieve all logical DHCP servers created from OpenStack
        """
        dhcp_servers = self.get_os_resources(
            self.get_logical_dhcp_servers())

        if self.neutron_db:
            db_dhcp_servers = self.neutron_db.get_logical_dhcp_servers()
            dhcp_servers = [srv for srv in dhcp_servers
                            if srv['id'] in db_dhcp_servers]
        return dhcp_servers

    def cleanup_nsx_logical_dhcp_servers(self):
        """
        Cleanup all logical DHCP servers created from OpenStack plugin
        The policy plugin still uses nsxlib for this because it uses the
        passthrough api.
        """
        if not self.nsxlib:
            # No passthrough api
            return
        # First delete the DHCP ports (from the NSX)
        self.cleanup_os_dhcp_logical_ports()

        dhcp_servers = self.get_os_logical_dhcp_servers()
        print("Number of OS Logical DHCP Servers to be deleted: %s" %
              len(dhcp_servers))
        for server in dhcp_servers:
            try:
                self.nsxlib.dhcp_server.delete(server['id'])
            except Exception as e:
                print("ERROR: Failed to delete logical DHCP server %s, "
                      "error %s" % (server['display_name'], e))
            else:
                print("Successfully deleted logical DHCP server %s" %
                      server['display_name'])

    def get_os_nsx_services(self):
        """
        Retrieve all NSX policy services created from OpenStack SG rules
        (by tags)
        If the DB is available - use only objects in the neutron DB
        """
        services = self.get_os_resources(self.nsxpolicy.service.list())
        if services and self.neutron_db:
            db_rules = self.neutron_db.get_security_groups_rules()
            services = [s for s in services if s['id'] in db_rules]
        return services

    def cleanup_rules_services(self):
        """Delete all OS created NSX services"""
        services = self.get_os_nsx_services()
        print("Number of OS rule services to be deleted: %s" % len(services))
        for srv in services:
            try:
                self.nsxpolicy.service.delete(srv['id'])
            except exceptions.ManagerError as e:
                print("Failed to delete service %s: %s" % (srv['id'], e))

    def _cleanup_lb_resource(self, service, service_name):
        r_list = self.get_os_resources(service.list())

        print("Number of %s to be deleted: %d" % (service_name, len(r_list)))
        for r in r_list:
            try:
                service.delete(
                    r['id'])
            except Exception as e:
                print("ERROR: Failed to delete %s %s, error %s" %
                      (r['resource_type'], r['id'], e))

    def cleanup_lb_virtual_servers(self):
        self._cleanup_lb_resource(self.nsxpolicy.load_balancer.virtual_server,
                                  'LB virtual servers')

    def cleanup_lb_server_pools(self):
        self._cleanup_lb_resource(self.nsxpolicy.load_balancer.lb_pool,
                                  'LB pools')

    def cleanup_lb_profiles(self):
        lb_svc = self.nsxpolicy.load_balancer
        self._cleanup_lb_resource(lb_svc.lb_http_profile,
                                  'LB HTTP app profiles')
        self._cleanup_lb_resource(lb_svc.lb_fast_tcp_profile,
                                  'LB HTTPS app profiles')
        self._cleanup_lb_resource(lb_svc.lb_fast_udp_profile,
                                  'LB UDP app profiles')
        self._cleanup_lb_resource(lb_svc.client_ssl_profile,
                                  'LB SSL client profiles')
        self._cleanup_lb_resource(lb_svc.lb_cookie_persistence_profile,
                                  'LB cookie persistence profiles')
        self._cleanup_lb_resource(lb_svc.lb_source_ip_persistence_profile,
                                  'LB source IP persistence profiles')

    def cleanup_lb_monitors(self):
        lb_svc = self.nsxpolicy.load_balancer
        self._cleanup_lb_resource(lb_svc.lb_monitor_profile_http,
                                  'LB HTTP monitor profiles')
        self._cleanup_lb_resource(lb_svc.lb_monitor_profile_https,
                                  'LB HTTPS monitor profiles')
        self._cleanup_lb_resource(lb_svc.lb_monitor_profile_udp,
                                  'LB UDP monitor profiles')
        self._cleanup_lb_resource(lb_svc.lb_monitor_profile_icmp,
                                  'LB ICMP monitor profiles')
        self._cleanup_lb_resource(lb_svc.lb_monitor_profile_tcp,
                                  'LB TCP monitor profiles')

    def cleanup_lb_services(self):
        self._cleanup_lb_resource(self.nsxpolicy.load_balancer.lb_service,
                                  'LB services')

    def cleanup_load_balancers(self):
        self.cleanup_lb_virtual_servers()
        self.cleanup_lb_profiles()
        self.cleanup_lb_services()
        self.cleanup_lb_server_pools()
        self.cleanup_lb_monitors()

    def cleanup_all(self):
        """
        Per domain cleanup steps:
            - Security groups resources

        Global cleanup steps:
            - Tier1 routers
            - Segments and ports
        """
        domains = self.get_nsx_os_domains()
        for domain_id in domains:
            print("Cleaning up openstack resources from domain %s" % domain_id)
            self.cleanup_security_groups(domain_id)

        print("Cleaning up openstack global resources")
        self.cleanup_segments()
        self.cleanup_load_balancers()
        self.cleanup_nsx_logical_dhcp_servers()
        self.cleanup_tier1_routers()
        self.cleanup_rules_services()
        self.cleanup_domains(domains)


if __name__ == "__main__":

    parser = optparse.OptionParser()
    parser.add_option("--policy-ip", dest="policy_ip", help="NSX Policy IP "
                                                            "address")
    parser.add_option("-u", "--username", default="admin", dest="username",
                      help="NSX Policy username")
    parser.add_option("-p", "--password", default="default", dest="password",
                      help="NSX Policy password")
    parser.add_option("--db-connection", default="", dest="db_connection",
                      help=("When set, cleaning only backend resources that "
                            "have db record."))
    parser.add_option("--allow-passthrough", default="true",
                      dest="allow_passthrough",
                      help=("When True, passthrough api will be used to "
                           "cleanup some NSX objects."))
    (options, args) = parser.parse_args()

    # Get NSX REST client
    nsx_client = NSXClient(options.policy_ip, options.username,
                           options.password, options.db_connection,
                           options.allow_passthrough)
    # Clean all objects created by OpenStack
    nsx_client.cleanup_all()
