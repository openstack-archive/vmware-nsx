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
from tempest import exceptions
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.scenario import manager
from tempest import test

from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestMDProxy(manager.NetworkScenarioTest):
    """Test MDProxy.

    Adding test cases to test MDProxy in different scenarios such as
    testing it over multiple created networks, verify MDProxy realization
    with nsxv3 backend, test MDProxy with isolated network and so on.
    """

    def setUp(self):
        super(TestMDProxy, self).setUp()
        self.image_ref = CONF.compute.image_ref
        self.flavor_ref = CONF.compute.flavor_ref
        self.run_ssh = CONF.validation.run_validation
        self.ssh_user = CONF.validation.image_ssh_user
        self.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                            CONF.nsxv3.nsx_user,
                                            CONF.nsxv3.nsx_password)

    @classmethod
    def skip_checks(cls):
        """Class level skip checks.

        Class level check. Skip all teh MDproxy tests, if native_dhcp_metadata
        is not True under nsxv3 section of the config
        """
        if not CONF.nsxv3.native_dhcp_metadata:
            msg = " native_dhcp_metadata is not enabled under nsxv3 config" \
                  ", skipping all the MDProxy tests!!!"
            raise cls.skipException(msg)

    def verify_ssh(self, keypair, instance, port_id=None):
        created_floating_ip = self.create_floating_ip(instance,
                                                      port_id=port_id)
        self.fip = str(created_floating_ip["floating_ip_address"])
        self.assertIsNotNone(self.fip)
        # Check ssh
        self.ssh_client = self.get_remote_client(
            ip_address=self.fip, username=self.ssh_user,
            private_key=keypair["private_key"])

    def _delete_router(self, router):
        body = self.ports_client.list_ports(device_id=router["id"])
        interfaces = body["ports"]
        for interface in interfaces:
            test_utils.call_and_ignore_notfound_exc(
                self.routers_client.remove_router_interface, router["id"],
                subnet_id=interface["fixed_ips"][0]["subnet_id"])
        self.routers_client.delete_router(router["id"])

    def _create_router(self, router_name=None, admin_state_up=True,
                       external_network_id=None, enable_snat=None, **kwargs):
        ext_gw_info = {}
        if external_network_id:
            ext_gw_info["network_id"] = external_network_id
        if enable_snat is not None:
            ext_gw_info["enable_snat"] = enable_snat
        body = self.routers_client.create_router(
            name=router_name, external_gateway_info=ext_gw_info,
            admin_state_up=admin_state_up, **kwargs)
        router = body["router"]
        self.addCleanup(self._delete_router, router)
        return router

    def _create_net_subnet_router_interface(self, router=None):
        network = self._create_network(namestart="network-mdproxy")
        subnet = self._create_subnet(network)
        if router:
            self.routers_client.add_router_interface(
                router["id"], subnet_id=subnet["id"])
            self.addCleanup(self.routers_client.remove_router_interface,
                            router["id"], subnet_id=subnet["id"])
        return network["id"], subnet["id"]

    def _create_server_on_networks(self, networks):
        security_group = self._create_security_group()
        name = data_utils.rand_name("server-mdproxy")
        keypair = self.create_keypair()
        security_groups = [{"name": security_group["name"]}]
        instance = self.create_server(
            image_id=self.image_ref,
            flavor=self.flavor_ref,
            config_drive=CONF.compute_feature_enabled.config_drive, name=name,
            networks=networks, key_name=keypair["name"],
            security_groups=security_groups, wait_until="ACTIVE")
        self.addCleanup(self.servers_client.delete_server, instance["id"])
        return instance, keypair

    def _get_port_id(self, network_id, subnet_id, instance):
        _, instance_addr = instance["addresses"].items()[0]
        instance_fixed_ip = instance_addr[0]["addr"]
        for port in self._list_ports():
            port_fixed_ip = port["fixed_ips"][0]["ip_address"]
            if port["network_id"] == network_id and port["fixed_ips"][0][
                    "subnet_id"] == subnet_id and "compute:" in port[
                    "device_owner"] and port_fixed_ip == instance_fixed_ip:
                port_id = port["id"]
        self.assertIsNotNone(port_id, "Failed to find Instance's port id!!!")
        return port_id

    def _verify_md(self, md_url, expected_value="", check_exist_only=False,
                   sub_result=None):
        def exec_cmd_and_verify_output():
            cmd = "curl " + md_url
            exec_cmd_retried = 0
            import time
            while exec_cmd_retried < \
                    constants.MAX_NO_OF_TIMES_EXECUTION_OVER_SSH:
                result = self.ssh_client.exec_command(cmd)
                self.assertIsNotNone(result)
                if not result == "":
                    break
                    exec_cmd_retried += 1
                time.sleep(constants.INTERVAL_BETWEEN_EXEC_RETRY_ON_SSH)
                LOG.info(_LI("Tried %s times!!!") % exec_cmd_retried)
            if check_exist_only:
                return "Verification is successful!"
            msg = ("Failed while verifying metadata on server. Result "
                   "of command %r is NOT %r." % (cmd, expected_value))
            if sub_result:
                msg2 = ("Failed to verify incorrect passowrd on metadata"
                        "server. Result %r is NOT in %r." % (
                            sub_result, result))
                self.assertIn(sub_result, result, msg2)
                return "Verification is successful!"
            self.assertEqual(expected_value, result, msg)
            return "Verification is successful!"

        if not test_utils.call_until_true(exec_cmd_and_verify_output,
                                          CONF.compute.build_timeout,
                                          CONF.compute.build_interval):
            raise exceptions.TimeoutException("Timed out while waiting to "
                                              "verify metadata on server. "
                                              "%s is empty." % md_url)

    def verify_metadata_in_detail(self, instance):
        # Check floating IPv4 in Metadata.
        md_url_pubic_ipv4 = constants.MD_BASE_URL + \
            "latest/meta-data/public-ipv4"
        self._verify_md(md_url=md_url_pubic_ipv4, expected_value=self.fip)
        # Check hostname in Metadata.
        md_url_hostname = constants.MD_BASE_URL + "latest/meta-data/hostname"
        self._verify_md(md_url=md_url_hostname,
                        expected_value=instance["name"] + ".novalocal")
        # Check local IPv4 in Metadata.
        md_url_local_ipv4 = constants.MD_BASE_URL + \
            "latest/meta-data/local-ipv4"
        self._verify_md(md_url=md_url_local_ipv4, check_exist_only=True)
        # Check hostname in Metadata of 2009-04-04 folder.
        md_url_hostname = constants.MD_BASE_URL + \
            "2009-04-04/meta-data/hostname"
        self._verify_md(md_url=md_url_hostname,
                        expected_value=instance["name"] + ".novalocal")
        # Check hostname in Metadata of 1.0 folder.
        md_url_hostname = constants.MD_BASE_URL + "1.0/meta-data/hostname"
        self._verify_md(md_url=md_url_hostname,
                        expected_value=instance["name"] + ".novalocal")

    def verify_md_proxy_logical_ports_on_backend(self):
        md_counter = 0
        logical_ports = self.nsx.get_os_logical_ports()
        for port_index in range(len(logical_ports)):
            if logical_ports[port_index]["attachment"][
                    "attachment_type"] == "METADATA_PROXY":
                md_counter += 1
                msg = "Admin state of MDProxy logical port is DOWN!!!"
                msg2 = "LS name does not start with mdproxy!!!"
                msg3 = "MDproxy logical port does not have any auto tag!!!"
                self.assertEqual(
                    "UP", logical_ports[port_index]["admin_state"], msg)
                self.assertIn("mdproxy-",
                              logical_ports[port_index]["display_name"], msg2)
                self.assertNotEqual(0, len(logical_ports[port_index]["tags"]),
                                    msg3)
        self.assertNotEqual(0, md_counter, "No logical port found for MD "
                                           "proxy!!!")

    @test.idempotent_id("e9a93161-d852-414d-aa55-36d465ea45df")
    @test.services("compute", "network")
    def test_mdproxy_ping(self):
        router = self._create_router(
            router_name=data_utils.rand_name("router-MDProxy"),
            external_network_id=CONF.network.public_network_id)
        (network_id, subnet_id) = self._create_net_subnet_router_interface(
            router)
        networks_ids = {"uuid": network_id}
        instance, keypair = self._create_server_on_networks([networks_ids])
        port_id = self._get_port_id(network_id, subnet_id, instance)
        self.verify_ssh(keypair=keypair, instance=instance, port_id=port_id)
        md_url_pubic_ipv4 = constants.MD_BASE_URL + \
            "latest/meta-data/public-ipv4"
        self._verify_md(md_url=md_url_pubic_ipv4, expected_value=self.fip)

    @test.idempotent_id("743f34a6-58b8-4288-a07f-7bee21c55051")
    @test.services("compute", "network")
    def test_mdproxy_verify_backend(self):
        router = self._create_router(
            router_name=data_utils.rand_name("router-MDProxy"),
            external_network_id=CONF.network.public_network_id)
        (network_id, subnet_id) = self._create_net_subnet_router_interface(
            router)
        networks_ids = {"uuid": network_id}
        instance, keypair = self._create_server_on_networks([networks_ids])
        port_id = self._get_port_id(network_id, subnet_id, instance)
        self.verify_ssh(keypair=keypair, instance=instance, port_id=port_id)
        self.verify_metadata_in_detail(instance=instance)
        self.verify_md_proxy_logical_ports_on_backend()

    @test.idempotent_id("fce2acc8-b850-40fe-bf02-958dd3cd4343")
    @test.services("compute", "network")
    def test_mdproxy_with_server_on_two_ls(self):
        router = self._create_router(
            router_name=data_utils.rand_name("router-MDProxy"),
            external_network_id=CONF.network.public_network_id)
        (network_id1, subnet_id1) = self._create_net_subnet_router_interface(
            router)
        (network_id2, subnet_id2) = self._create_net_subnet_router_interface(
            router)
        net1 = {"uuid": network_id1}
        net2 = {"uuid": network_id2}
        instance, keypair = self._create_server_on_networks([net1, net2])
        port_id = self._get_port_id(network_id1, subnet_id1, instance)
        self.verify_ssh(keypair=keypair, instance=instance, port_id=port_id)
        self.verify_metadata_in_detail(instance=instance)

    @test.idempotent_id("67332752-1295-42cb-a8c3-99210fb6b00b")
    @test.services("compute", "network")
    def test_mdproxy_isolated_network(self):
        (network_id, _) = self._create_net_subnet_router_interface()
        networks_ids = {"uuid": network_id}
        self._create_server_on_networks([networks_ids])
        self.verify_md_proxy_logical_ports_on_backend()

    @test.idempotent_id("cc8d2ab8-0bea-4e32-bf80-c9c46a7612b7")
    @test.attr(type=["negative"])
    @test.services("compute", "network")
    def test_mdproxy_delete_when_ls_bounded(self):
        (network_id, _) = self._create_net_subnet_router_interface()
        networks_ids = {"uuid": network_id}
        self._create_server_on_networks([networks_ids])
        md_proxy_uuid = self.nsx.get_md_proxies()[0]["id"]
        result = self.nsx.delete_md_proxy(md_proxy_uuid)
        self.assertEqual(str(result["error_code"]),
                         constants.MD_ERROR_CODE_WHEN_LS_BOUNDED)

    @test.idempotent_id("501fc3ea-696b-4e9e-b383-293ab94e2545")
    @test.services("compute", "network")
    def test_mdproxy_with_multiple_ports_on_network(self):
        router = self._create_router(
            router_name=data_utils.rand_name("router-MDProxy"),
            external_network_id=CONF.network.public_network_id)
        (network_id, subnet_id) = self._create_net_subnet_router_interface(
            router)
        networks_ids = {"uuid": network_id}
        instance, keypair = self._create_server_on_networks([networks_ids])
        instance2, keypair2 = self._create_server_on_networks([networks_ids])
        port_id = self._get_port_id(network_id, subnet_id, instance)
        # Verify 1st instance.
        self.verify_ssh(keypair=keypair, instance=instance, port_id=port_id)
        self.verify_metadata_in_detail(instance=instance)
        # Verify 2nd instance.
        port_id2 = self._get_port_id(network_id, subnet_id, instance2)
        self.verify_ssh(keypair=keypair2, instance=instance2, port_id=port_id2)
        self.verify_metadata_in_detail(instance=instance2)

    @test.idempotent_id("eae21afc-50ea-42e5-9c49-2ee38cee9f06")
    @test.services("compute", "network")
    def test_mdproxy_with_multiple_metadata_ports(self):
        router = self._create_router(
            router_name=data_utils.rand_name("router-MDProxy"),
            external_network_id=CONF.network.public_network_id)
        (network_id1, subnet_id1) = self._create_net_subnet_router_interface(
            router)
        (network_id2, subnet_id2) = self._create_net_subnet_router_interface(
            router)
        net1 = {"uuid": network_id1}
        net2 = {"uuid": network_id2}
        instance, keypair = self._create_server_on_networks([net1])
        instance2, keypair2 = self._create_server_on_networks([net2])
        port_id1 = self._get_port_id(network_id1, subnet_id1, instance)
        port_id2 = self._get_port_id(network_id2, subnet_id2, instance2)
        self.verify_ssh(keypair=keypair, instance=instance, port_id=port_id1)
        self.verify_metadata_in_detail(instance=instance)
        self.verify_ssh(keypair=keypair2, instance=instance2, port_id=port_id2)
        self.verify_metadata_in_detail(instance=instance2)

    @test.idempotent_id("29d44d7c-6ea1-4b30-a6c3-a2695c2486fe")
    @test.attr(type=["negative"])
    @test.services("compute", "network")
    def test_mdproxy_with_incorrect_password(self):
        router = self._create_router(
            router_name=data_utils.rand_name("router-MDProxy"),
            external_network_id=CONF.network.public_network_id)
        (network_id, subnet_id) = self._create_net_subnet_router_interface(
            router)
        networks_ids = {"uuid": network_id}
        instance, keypair = self._create_server_on_networks([networks_ids])
        port_id = self._get_port_id(network_id, subnet_id, instance)
        self.verify_ssh(keypair=keypair, instance=instance, port_id=port_id)
        md_url = constants.MD_BASE_URL + "latest/meta-data/public-ipv4"
        self._verify_md(md_url, sub_result="403 Forbidden")
