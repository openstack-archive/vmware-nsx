# Copyright 2017 VMware Inc
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

import time

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from tempest import test
from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF


class NSXv3PortSecurity(base.BaseAdminNetworkTest):
    """Test Port security of Port

    1. Create/Update port with port security enable and disable.
    2. Create/Update port security and check at beckend NSGroup.
    3. Check non admin tenant shouldn't update port security of admin port.
    4. Check non-admin tenant can't delete port security of admin port.
    """

    @classmethod
    def skip_checks(cls):
        super(NSXv3PortSecurity, cls).skip_checks()
        if not test.is_extension_enabled('port-security-enabled', 'network'):
            msg = "Extension port-security-enabled is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(NSXv3PortSecurity, cls).setup_clients()
        cls.cmgr_pri = cls.get_client_manager('primary')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(NSXv3PortSecurity, cls).resource_setup()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)
        cls.network = cls.create_network()

    def get_tag_port_id(self, nsxgroup_data, org_port_id):
        """
        Method to get port of neutron corresponding to backend port-id
        """
        for ports in self.nsx.get_logical_ports():
            for port_id in nsxgroup_data['results']:
                if ports['display_name'] == port_id['target_display_name']:
                    for tag in ports['tags']:
                        if tag['scope'] == "os-neutron-port-id" and \
                                tag['tag'] == org_port_id:
                            corresponding_port_id = ports['display_name']
                            return corresponding_port_id

    def check_port_not_exists_in_os_group(self, nsxgroup_data,
                                          corresponding_port_id):
        """
        Method to check neutron port not exists in neutron OSGroup
        """
        if nsxgroup_data['results'] != []:
            for port_id in nsxgroup_data['results']:
                if corresponding_port_id != port_id['target_display_name']:
                    continue
                else:
                    return False
            return True
        else:
            return False

    def check_port_exists_in_os_group(self, nsxgroup_data,
                                      corresponding_port_id):
        """
        Method to check neutron port exists in neutron OSGroup
        """
        for port_id in nsxgroup_data['results']:
            if corresponding_port_id == port_id['target_display_name']:
                return True

    def _create_network_topo(self, client):
        """
        Method to create network topology which includes network, subnet
        and port
        """
        net_client = client.networks_client
        body = {'name': 'port-security-network'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = client.subnets_client
        subnet = subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id'],
                "admin_state_up": "true",
                "port_security_enabled": "false", "security_groups": []}
        port_client = client.ports_client
        port = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port['port']['id'])
        network_topo = dict(network=network, subnet=subnet, port=port)
        return network_topo

    def _create_security_group_and_return_id(self, client):
        """
        Method to create security group and return id
        """
        security_client = client.security_groups_client
        create_body = security_client.create_security_group(name='sec-group')
        secgroup = create_body['security_group']
        # Sleep for 5 sec
        time.sleep(constants.NSX_BACKEND_VERY_SMALL_TIME_INTERVAL)
        secgroup_id = secgroup['id']
        return secgroup_id

    @test.attr(type='nsxv3')
    @decorators.idempotent_id('50203701-1cda-4f31-806d-7a51514b9664')
    def test_create_port_with_security_enabled_check_in_neutron_database(self):
        secgroup_id = self._create_security_group_and_return_id(self.cmgr_adm)
        network_topo = self._create_network_topo(self.cmgr_adm)
        port_client = self.cmgr_adm.ports_client
        port_id = network_topo['port']['port']['id']
        port_detail = port_client.show_port(port_id)
        self.assertEqual(False, port_detail['port']["port_security_enabled"])
        body = {"port_security_enabled": "true",
                "security_groups": [secgroup_id]}
        port_client.update_port(port_id, **body)
        # Sleep for 10 sec
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        port_detail = port_client.show_port(port_id)
        self.assertEqual(True, port_detail['port']["port_security_enabled"])

    @test.attr(type='nsxv3')
    @decorators.idempotent_id('4b765fa2-345f-4d2c-928f-ad4b347936fd')
    def test_create_port_with_security_enabled_check_at_beckend(self):
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'port-security-network'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "allocation_pools": [{"start": "2.0.0.2",
                                      "end": "2.0.0.254"}],
                "ip_version": 4, "cidr": "2.0.0.0/24"}
        subnet_client = self.cmgr_adm.subnets_client
        subnet_client.create_subnet(**body)
        body = {"network_id": network['network']['id'],
                "admin_state_up": "true",
                "port_security_enabled": "false", "security_groups": []}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.create_port(**body)
        # Sleep for 10 sec
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])
        port_detail = port_client.show_port(port_id['port']['id'])
        self.assertEqual(False, port_detail['port']["port_security_enabled"])
        org_port_id = port_id['port']['id']
        nsgroup_id = self.nsx.get_neutron_ns_group_id()
        nsxgroup_data = self.nsx.get_ns_group_port_members(nsgroup_id)
        # Sleep for 10 sec
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        corresponding_port_id = self.get_tag_port_id(nsxgroup_data,
                                                     org_port_id)
        status = self.check_port_exists_in_os_group(nsxgroup_data,
                                                    corresponding_port_id)
        self.assertEqual(True, status)

    @test.attr(type='nsxv3')
    @decorators.idempotent_id('bcafeb10-fbf1-4c97-9e4f-50e56d32bdcf')
    def test_non_admin_cannot_update_admin_port_with_security(self):
        network_topo = self._create_network_topo(self.cmgr_adm)
        tenant_port_client = self.cmgr_alt.ports_client
        kwargs = {"port_security_enabled": "true"}
        self.assertRaises(exceptions.NotFound,
                          tenant_port_client.update_port,
                          network_topo['port']['port']['id'],
                          **kwargs)

    @test.attr(type='nsxv3')
    @decorators.idempotent_id('cf4b8d28-13c4-4339-993f-66070708e914')
    def test_non_admin_cannot_delete_tenant_port_with_port_security(self):
        network_topo = self._create_network_topo(self.cmgr_pri)
        tenant_port_client = self.cmgr_alt.ports_client
        self.assertRaises(exceptions.NotFound,
                          tenant_port_client.delete_port,
                          network_topo['port']['port']['id'])

    @test.attr(type='nsxv3')
    @decorators.idempotent_id('ee6213ac-dfcd-401b-bbc6-03afd26f203a')
    def test_tenant_port_security_at_beckend_after_enable_disable(self):
        secgroup_id = self._create_security_group_and_return_id(self.cmgr_alt)
        network_topo = self._create_network_topo(self.cmgr_alt)
        port_client = self.cmgr_alt.ports_client
        kwargs = {"port_security_enabled": "false", "security_groups": []}
        org_port_id = network_topo['port']['port']['id']
        port_client.update_port(org_port_id,
                                **kwargs)
        # Sleep for 10 sec
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        nsgroup_id = self.nsx.get_neutron_ns_group_id()
        nsxgroup_data = self.nsx.get_ns_group_port_members(nsgroup_id)
        corresponding_port_id = self.get_tag_port_id(nsxgroup_data,
                                                     org_port_id)
        # Sleep for 10 sec
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        status = self.check_port_exists_in_os_group(nsxgroup_data,
                                                    corresponding_port_id)
        self.assertEqual(True, status)
        kwargs = {"port_security_enabled": "true",
                  "security_groups": [secgroup_id]}
        port_client.update_port(org_port_id,
                                **kwargs)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        nsgroup_id = self.nsx.get_neutron_ns_group_id()
        nsxgroup_data = self.nsx.get_ns_group_port_members(nsgroup_id)
        status = self.check_port_not_exists_in_os_group(nsxgroup_data,
                                                        corresponding_port_id)
        self.assertEqual(False, status)

    @test.attr(type='nsxv3')
    @decorators.idempotent_id('c6f4c2f2-3fc9-4983-a05a-bb3a3dc35ad8')
    def test_admin_port_security_at_beckend_after_enable_disable(self):
        secgroup_id = self._create_security_group_and_return_id(self.cmgr_adm)
        network_topo = self._create_network_topo(self.cmgr_adm)
        port_client = self.cmgr_adm.ports_client
        kwargs = {"port_security_enabled": "false",
                  "security_groups": []}
        org_port_id = network_topo['port']['port']['id']
        port_client.update_port(org_port_id,
                                **kwargs)
        # Sleep for 10 sec
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        nsgroup_id = self.nsx.get_neutron_ns_group_id()
        nsxgroup_data = self.nsx.get_ns_group_port_members(nsgroup_id)
        corresponding_port_id = self.get_tag_port_id(nsxgroup_data,
                                                     org_port_id)
        # Sleep for 10 sec
        time.sleep(constants.NSX_BACKEND_SMALL_TIME_INTERVAL)
        status = self.check_port_exists_in_os_group(nsxgroup_data,
                                                    corresponding_port_id)
        self.assertEqual(True, status)
        kwargs = {"port_security_enabled": "true",
                  "security_groups": [secgroup_id]}
        port_client.update_port(org_port_id, **kwargs)
        time.sleep(constants.NSX_BACKEND_TIME_INTERVAL)
        nsgroup_id = self.nsx.get_neutron_ns_group_id()
        nsxgroup_data = self.nsx.get_ns_group_port_members(nsgroup_id)
        status = self.check_port_not_exists_in_os_group(nsxgroup_data,
                                                        corresponding_port_id)
        self.assertEqual(False, status)
