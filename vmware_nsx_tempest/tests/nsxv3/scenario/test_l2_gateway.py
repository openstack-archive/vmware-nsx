# Copyright 2015 OpenStack Foundation
# Copyright 2016 VMware Inc
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

import netaddr

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest import test

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.lib import feature_manager

CONF = config.CONF

LOG = constants.log.getLogger(__name__)


class L2GatewayScenarioTest(feature_manager.FeatureManager):
    """
    Test l2 gateway connection operations.
    """

    @classmethod
    def skip_checks(cls):
        """
        Skip running test if we do not meet criteria to run the tests.
        """
        super(L2GatewayScenarioTest, cls).skip_checks()
        if not test.is_extension_enabled("l2-gateway", "network"):
            raise cls.skipException("l2-gateway extension not enabled.")

    @classmethod
    def resource_setup(cls):
        """
        Setting up the resources for the test.
        """
        super(L2GatewayScenarioTest, cls).resource_setup()
        # Create subnet on the network just created.
        cls.SUBNET_1_NETWORK_CIDR = CONF.l2gw.subnet_1_cidr
        # VLAN id used in setups
        cls.VLAN_1 = CONF.l2gw.vlan_1
        cls.VLAN_2 = CONF.l2gw.vlan_2
        # IPs of predeployed vms.
        cls.VM_ON_VDS_TZ1_VLAN16_IP = CONF.l2gw.vm_on_vds_tz1_vlan16_ip
        cls.VM1_ON_SWITCH_VLAN16 = CONF.l2gw.vm_on_switch_vlan16
        cls.VM1_ON_VDS_TZ2_VLAN16_IP = CONF.l2gw.vm_on_vds_tz2_vlan16_ip
        cls.VM1_ON_VDS_TZ2_VLAN17_IP = CONF.l2gw.vm_on_vds_tz2_vlan17_ip
        cls.SUBNET_1_MASK = cls.SUBNET_1_NETWORK_CIDR.split("/")[1]
        cls.CIDR = netaddr.IPNetwork(cls.SUBNET_1_NETWORK_CIDR)

    @classmethod
    def resource_cleanup(cls):
        """
        Clean all the resources used during the test.
        """
        super(L2GatewayScenarioTest, cls).resource_cleanup()

    def deploy_l2gateway_topology(self):
        router_l2gateway = self.create_topology_router("router_l2gateway")
        # L2gateway network with router
        network_l2gateway = self.create_topology_network("network_l2gateway")
        # cidr must be presented & in IPNetwork structure.
        self.CIDR = netaddr.IPNetwork(self.SUBNET_1_NETWORK_CIDR)
        self.create_topology_subnet(
            "subnet1_l2gateway", network_l2gateway, cidr=self.CIDR,
            router_id=router_l2gateway["id"],
            mask_bits=int(self.SUBNET_1_MASK))
        secgroup = self.create_topology_security_group()
        secgroups = [{'name': secgroup['name']}]
        self.create_topology_instance(
            "server1_l2gateway", [network_l2gateway],
            security_groups=secgroups)
        self.create_topology_instance(
            "server2_l2gateway", [network_l2gateway],
            security_groups=secgroups)

    def deploy_topology_and_create_l2gateway(self, vlan_id):
        self.deploy_l2gateway_topology()
        cluster_info = self.nsx_bridge_cluster_info()
        device_name, interface_name = cluster_info[0][0], cluster_info[0][1]
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [vlan_id]}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id":
                           self.topology_networks["network_l2gateway"]["id"]}
        l2gwc_rsp = self.create_l2gw_connection(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        self.assertEqual(l2gwc_param["l2_gateway_id"],
                         l2gwc_rsp[constants.L2GWC]["l2_gateway_id"],
                         "l2gw id is not same as expected in "
                         "create l2gw connection response")
        self.assertEqual(l2gwc_param["network_id"],
                         l2gwc_rsp[constants.L2GWC]["network_id"],
                         "network id is not same as expected in "
                         "create l2gw connection response")

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("b62a7452-f2c1-4f2b-9403-f121f5201516")
    def test_l2_gateway_ping_servers_on_overlays(self):
        """
        Create l2 gateway connection using one vlan. Vlan parameter is
        passed into L2GW create.
        """
        LOG.info("Testing test_l2_gateway_ping_servers_on_overlays")
        self.deploy_topology_and_create_l2gateway(self.VLAN_1)
        server1_floatingip = self.topology_servers["server1_l2gateway"][
            "floating_ip"]
        server1 = self.topology_servers["server1_l2gateway"]
        address_list = [server1_floatingip["fixed_ip_address"]]
        address_list.append(self.topology_servers["server2_l2gateway"][
            "floating_ip"]["fixed_ip_address"])
        self.check_server_internal_ips_using_floating_ip(
            server1_floatingip, server1, address_list)

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("74e67d5f-0319-45e8-9731-d2c245c05beb")
    def test_l2_gateway_ping_servers_overlay_to_vds_with_same_tz(self):
        """
        Create l2 gateway connection using one vlan. Vlan parameter is
        passed into L2GW create. ping from server on OS ls to NSX ls
        """
        LOG.info("Testing test_l2_gateway_ping_servers_overlay_to_nsx_ls")
        self.deploy_topology_and_create_l2gateway(self.VLAN_1)
        server1_floatingip = self.topology_servers["server1_l2gateway"][
            "floating_ip"]
        server1 = self.topology_servers["server1_l2gateway"]
        address_list = [server1_floatingip["fixed_ip_address"]]
        address_list.append(self.VM_ON_VDS_TZ1_VLAN16_IP)
        self.check_server_internal_ips_using_floating_ip(
            server1_floatingip, server1, address_list)

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("4e66584f-f61b-465d-952c-795a285d7c55")
    def test_l2_gateway_ping_servers_overlay_to_vds_with_diff_tz(self):
        """
        Create l2 gateway connection using one vlan. Vlan parameter is
        passed into L2GW create. ping from server on OS ls to NSX ls
        """
        LOG.info("Testing test_l2_gateway_ping_servers_overlay_to_nsx_ls")
        self.deploy_topology_and_create_l2gateway(self.VLAN_1)
        server1_floatingip = self.topology_servers["server1_l2gateway"][
            "floating_ip"]
        server1 = self.topology_servers["server1_l2gateway"]
        address_list = [server1_floatingip["fixed_ip_address"]]
        address_list.append(self.VM1_ON_VDS_TZ2_VLAN16_IP)
        self.check_server_internal_ips_using_floating_ip(
            server1_floatingip, server1, address_list)

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("aef2a142-0b49-48a9-8881-f47897c09745")
    def test_l2_gateway_ping_servers_overlay_to_physical_vlan(self):
        """
        Create l2 gateway connection using one vlan. Vlan parameter is
        passed into L2GW create. ping from server on OS ls to NSX ls
        """
        LOG.info("Testing test_l2_gateway_ping_servers_overlay_to_nsx_ls")
        self.deploy_topology_and_create_l2gateway(self.VLAN_1)
        server1_floatingip = self.topology_servers["server1_l2gateway"][
            "floating_ip"]
        server1 = self.topology_servers["server1_l2gateway"]
        address_list = [server1_floatingip["fixed_ip_address"]]
        address_list.append(self.VM1_ON_SWITCH_VLAN16)
        self.check_server_internal_ips_using_floating_ip(
            server1_floatingip, server1, address_list)

    @decorators.attr(type="nsxv3")
    @decorators.idempotent_id("00036e1d-69e0-4faf-a62f-602600bc5631")
    def test_l2_gateway_reconfig_ping_servers_overlay_to_vds_with_diff_tz(
            self):
        """
        Create l2 gateway connection using one vlan. Vlan parameter is
        passed into L2GW create. ping from server on OS ls to NSX ls
        """
        LOG.info(
            "Testing test_l2_gateway_reconfig_ping_servers_overlay_to_vds_"
            "with_diff_tz")
        self.deploy_topology_and_create_l2gateway(self.VLAN_2)
        server1_floatingip = self.topology_servers["server1_l2gateway"][
            "floating_ip"]
        server1 = self.topology_servers["server1_l2gateway"]
        address_list = [server1_floatingip["fixed_ip_address"]]
        address_list.append(self.VM1_ON_VDS_TZ2_VLAN17_IP)
        self.check_server_internal_ips_using_floating_ip(
            server1_floatingip, server1, address_list)
