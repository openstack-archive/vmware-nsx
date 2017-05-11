# Copyright 2017 VMware Inc
# All Rights Reserved.
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
from oslo_log import log as logging

from tempest import config
from tempest.lib import decorators
from tempest import test

from vmware_nsx_tempest.lib import feature_manager
from vmware_nsx_tempest.services import nsx_client

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestMicroSegmentationOps(feature_manager.FeatureManager):

    @classmethod
    def skip_checks(cls):
        super(TestMicroSegmentationOps, cls).skip_checks()
        if not (CONF.network.project_networks_reachable or
                CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        for ext in ['router', 'security-group']:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)
        if not CONF.network.public_network_cidr:
            msg = "public_network_cidr must be defined in network section."
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(TestMicroSegmentationOps, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        """
        Create various client connections. Such as NSX.
        """
        super(TestMicroSegmentationOps, cls).setup_clients()
        cls.nsx_client = nsx_client.NSXClient(
            CONF.network.backend,
            CONF.nsxv3.nsx_manager,
            CONF.nsxv3.nsx_user,
            CONF.nsxv3.nsx_password)

    def define_security_groups(self):
        self.web_sg = self.create_topology_empty_security_group(
            namestart="web_sg_")
        self.app_sg = self.create_topology_empty_security_group(
            namestart="app_sg_")
        # Common rules to allow the following traffic
        # 1. Egress ICMP IPv4 any any
        # 2. Egress ICMP IPv6 any any
        # 3. Ingress ICMP IPv4 from public network
        # 4. Ingress TCP 22 (SSH) from public network
        common_ruleset = [dict(direction='egress', protocol='icmp'),
                          dict(direction='egress', protocol='icmp',
                               ethertype='IPv6'),
                          dict(direction='ingress', protocol='tcp',
                               port_range_min=22, port_range_max=22,
                               remote_ip_prefix=CONF.network
                               .public_network_cidr),
                          dict(direction='ingress', protocol='icmp',
                               remote_ip_prefix=CONF.network
                               .public_network_cidr)]
        # Rules that are specific to web tier network
        # 1. Ingress ICMP IPv4 from web_sg
        # 2. Ingress TCP 80 (HTTP) any any
        # 3. Ingress TCP 443 (HTTPS) any any
        web_rules = [dict(direction='ingress', protocol='icmp',
                          remote_group_id=self.web_sg['id']),
                     dict(direction='ingress', protocol='tcp',
                          port_range_min=80, port_range_max=80, ),
                     dict(direction='ingress', protocol='tcp',
                          port_range_min=443, port_range_max=443, )]
        web_rules = common_ruleset + web_rules
        # Rules that are specific to app tier network
        # 1. Ingress ICMP IPv4 from app_sg
        # 2. Ingress TCP 22 (SSH) from web_sg
        app_rules = [dict(direction='ingress', protocol='icmp',
                          remote_group_id=self.app_sg['id']),
                     dict(direction='ingress', protocol='tcp',
                          port_range_min=22, port_range_max=22,
                          remote_group_id=self.web_sg['id'])]
        app_rules = common_ruleset + app_rules
        for rule in web_rules:
            self.add_security_group_rule(self.web_sg, rule)
        for rule in app_rules:
            self.add_security_group_rule(self.app_sg, rule)

    def deploy_micro_segmentation_topology(self):
        router_microseg = self.create_topology_router("router_microseg")
        # Web network
        network_web = self.create_topology_network("network_web")
        self.create_topology_subnet("subnet_web", network_web,
                           router_id=router_microseg["id"])
        self.create_topology_instance(
            "server_web_1", [network_web],
            security_groups=[{'name': self.web_sg['name']}])
        self.create_topology_instance(
            "server_web_2", [network_web],
            security_groups=[{'name': self.web_sg['name']}])
        # App network
        network_app = self.create_topology_network("network_app")
        self.create_topology_subnet("subnet_app", network_app,
                           router_id=router_microseg["id"])
        self.create_topology_instance(
            "server_app_1", [network_app],
            security_groups=[{'name': self.app_sg['name']}])
        self.create_topology_instance(
            "server_app_2", [network_app],
            security_groups=[{'name': self.app_sg['name']}])

    def check_server_project_connectivity(self, server_details):
        self.using_floating_ip_check_server_and_project_network_connectivity(
            server_details)

    @decorators.attr(type=["nsxv3", "nsxv"])
    @decorators.idempotent_id('91e1ee1f-10d9-4b19-8350-804aea7e57b4')
    def test_micro_segmentation_ops(self):
        """Test micro-segmentation use case

        Create two-tier application web and app networks, define security
        group rules based on the requirements, apply them to the VMs created
        on the network, and verify the connectivity based on the rule.

        """
        self.define_security_groups()
        self.deploy_micro_segmentation_topology()
        for server, details in self.servers_details.items():
            self.check_server_project_connectivity(details)
        self.check_cross_network_connectivity(
            self.topology_networks["network_web"],
            self.servers_details["server_app_1"].floating_ip,
            self.servers_details["server_app_1"].server)
        self.check_cross_network_connectivity(
            self.topology_networks["network_app"],
            self.servers_details["server_web_1"].floating_ip,
            self.servers_details["server_web_1"].server)
