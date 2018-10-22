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

from vmware_nsxlib import v3
from vmware_nsxlib.v3 import config


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


class NSXClient(object):
    """Base NSX REST client"""
    API_VERSION = "v1"
    NULL_CURSOR_PREFIX = '0000'

    def __init__(self, host, username, password, db_connection):
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
        self.nsxlib = v3.NsxPolicyLib(nsxlib_config)

    def get_nsx_os_domains(self):
        domains = self.get_os_resources(self.nsxlib.domain.list())
        return [d['id'] for d in domains]

    def cleanup_domains(self, domains):
        """Delete all OS created NSX Policy segments ports per segment"""
        for domain_id in domains:
            self.nsxlib.domain.delete(domain_id)

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
        groups = self.get_os_resources(self.nsxlib.group.list(domain_id))
        maps = self.get_os_resources(self.nsxlib.comm_map.list(domain_id))

        if self.neutron_db:
            db_sgs = self.neutron_db.get_security_groups()
            groups = [g for g in groups if g['id'] in db_sgs]
            maps = [m for m in maps if m['id'] in db_sgs]
        return groups, maps

    def cleanup_security_groups(self, domain_id):
        """Delete all OS created NSX Policy security group resources"""
        groups, maps = self.get_os_nsx_groups_and_maps(domain_id)
        print("Number of OS Communication maps of domain %s to be deleted: "
              "%s" % (domain_id, len(maps)))
        for m in maps:
            self.nsxlib.comm_map.delete(domain_id, m['id'])
        print("Number of OS Groups of domain %s to be deleted: "
              "%s" % (domain_id, len(groups)))
        for grp in groups:
            self.nsxlib.group.delete(domain_id, grp['id'])

    def get_os_nsx_tier1_routers(self):
        """
        Retrieve all NSX policy routers created from OpenStack (by tags)
        If the DB is available - use only objects in the neutron DB
        """
        routers = self.get_os_resources(self.nsxlib.tier1.list())
        if routers and self.neutron_db:
            db_routers = self.neutron_db.get_routers()
            routers = [r for r in routers if r['id'] in db_routers]
        return routers

    def cleanup_tier1_routers(self):
        """Delete all OS created NSX Policy routers"""
        routers = self.get_os_nsx_tier1_routers()
        print("Number of OS Tier1 routers to be deleted: %s" % len(routers))
        for rtr in routers:
            self.nsxlib.tier1.delete(rtr['id'])

    def get_os_nsx_segments(self):
        """
        Retrieve all NSX policy segments created from OpenStack (by tags)
        If the DB is available - use only objects in the neutron DB
        """
        segments = self.get_os_resources(self.nsxlib.segment.list())
        if segments and self.neutron_db:
            db_networks = self.neutron_db.get_networks()
            segments = [s for s in segments if s['id'] in db_networks]
        return segments

    def cleanup_segments(self):
        """Delete all OS created NSX Policy segments & ports"""
        segments = self.get_os_nsx_segments()
        print("Number of OS segments to be deleted: %s" % len(segments))
        for s in segments:
            self.cleanup_segment_ports(s['id'])
            self.nsxlib.segment.delete(s['id'])

    def get_os_nsx_segment_ports(self, segment_id):
        """
        Retrieve all NSX policy segment ports created from OpenStack (by tags)
        If the DB is available - use only objects in the neutron DB
        """
        segment_ports = self.get_os_resources(
            self.nsxlib.segment_port.list(segment_id))
        if segment_ports and self.neutron_db:
            db_ports = self.neutron_db.get_ports()
            segment_ports = [s for s in segment_ports if s['id'] in db_ports]
        return segment_ports

    def cleanup_segment_ports(self, segment_id):
        """Delete all OS created NSX Policy segments ports per segment"""
        segment_ports = self.get_os_nsx_segment_ports(segment_id)
        for p in segment_ports:
            self.nsxlib.segment_port.delete(segment_id, p['id'])

    def get_os_nsx_services(self):
        """
        Retrieve all NSX policy services created from OpenStack SG rules
        (by tags)
        If the DB is available - use only objects in the neutron DB
        """
        services = self.get_os_resources(self.nsxlib.service.list())
        if services and self.neutron_db:
            db_rules = self.neutron_db.get_security_groups_rules()
            services = [s for s in services if s['id'] in db_rules]
        return services

    def cleanup_rules_services(self):
        """Delete all OS created NSX services"""
        services = self.get_os_nsx_services()
        print("Number of OS rule services to be deleted: %s" % len(services))
        for srv in services:
            self.nsxlib.service.delete(srv['id'])

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
        self.cleanup_tier1_routers()
        self.cleanup_rules_services()
        self.cleanup_domains(domains)
        return


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
    (options, args) = parser.parse_args()

    # Get NSX REST client
    nsx_client = NSXClient(options.policy_ip, options.username,
                           options.password, options.db_connection)
    # Clean all objects created by OpenStack
    nsx_client.cleanup_all()
