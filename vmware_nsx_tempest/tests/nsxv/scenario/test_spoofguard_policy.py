# Copyright 2016 OpenStack Foundation
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

import re

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest import test

from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest.services import nsxv_client
from vmware_nsx_tempest.tests.nsxv.scenario import (
    manager_topo_deployment as dmgr)
from vmware_nsx_tempest.tests.nsxv.scenario import (
    network_addon_methods as HELO)

CONF = config.CONF
LOG = dmgr.manager.log.getLogger(__name__)


class TestSpoofGuardBasicOps(dmgr.TopoDeployScenarioManager):
    """Base class provides Spoof Guard basic operations.

    1) Create network, subnet and port
    2) Boot an instance using network.
    2) Ssh to instance and then check below information:
       a) check exclude list whether vm exists in exclude list or not
       b) update port-security to disable and check vm exists in exclude list
          or not
       c) Launch multiple instances anc checks their existence in exclude list
          with port-security disabled/enabled.
       d) Launch instances and check ping packets between various vm's with
          port-security disabled/enabled.
       e) Enabled/disablling of network and check behavior w.r.t. port in that
          network.
    3) Check at beckend(nsx-v) for exclude list.
    """

    @classmethod
    def skip_checks(cls):
        super(TestSpoofGuardBasicOps, cls).skip_checks()
        manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                               CONF.nsxv.manager_uri).group(0)
        cls.vsm = nsxv_client.VSMClient(
            manager_ip, CONF.nsxv.user, CONF.nsxv.password)
        nsxv_version = cls.vsm.get_vsm_version()
        # Raise skip testcase exception if nsx-v version is less than 6.2.3
        if (nsxv_version and nsxv_version < '6.2.3'):
            msg = ('NSX-v version should be greater than or equal to 6.2.3')
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TestSpoofGuardBasicOps, cls).resource_setup()

    @classmethod
    def resource_cleanup(cls):
        super(TestSpoofGuardBasicOps, cls).resource_cleanup()

    def tearDown(self):
        self.remove_project_network()
        super(TestSpoofGuardBasicOps, self).tearDown()

    def remove_project_network(self):
        project_name = 'green'
        tenant = getattr(self, project_name, None)
        if tenant:
            servers_client = tenant['client_mgr'].servers_client
            dmgr.delete_all_servers(servers_client)
            self.disassociate_floatingip(tenant['fip1'],
                                         and_delete=True)

    def create_project_network_subnet(self,
                                      name_prefix='spoofguard-project'):
        network_name = data_utils.rand_name(name_prefix)
        network, subnet = self.create_network_subnet(
            name=network_name)
        return (network['id'], network, subnet)

    def check_server_connected(self, serv):
        # Fetch tenant-network from where vm deployed
        serv_net = list(serv['addresses'].keys())[0]
        serv_addr = serv['addresses'][serv_net][0]
        host_ip = serv_addr['addr']
        self.waitfor_host_connected(host_ip)

    def setup_vm_enviornment(self, client_mgr, t_id,
                             check_outside_world=True,
                             cidr_offset=0):
        t_network, t_subnet, t_router = self.setup_project_network(
            self.public_network_id, namestart=("deploy-%s-spoofuard" % t_id),
            cidr_offset=0)
        t_security_group = self._create_security_group(
            security_groups_client=self.security_groups_client,
            security_group_rules_client=self.security_group_rules_client,
            namestart='adm')
        username, password = self.get_image_userpass()
        security_groups = [{'name': t_security_group['id']}]
        t_serv1 = self.create_server_on_network(
            t_network, security_groups,
            image=self.get_server_image(),
            flavor=self.get_server_flavor(),
            name=t_network['name'])
        self.check_server_connected(t_serv1)
        t_floatingip = self.create_floatingip_for_server(
            t_serv1, client_mgr=self.admin_manager)
        msg = ("Associate t_floatingip[%s] to server[%s]"
               % (t_floatingip, t_serv1['name']))
        self._check_floatingip_connectivity(
            t_floatingip, t_serv1, should_connect=True, msg=msg)
        vm_enviornment = dict(security_group=t_security_group,
                              network=t_network, subnet=t_subnet,
                              router=t_router, client_mgr=client_mgr,
                              serv1=t_serv1, fip1=t_floatingip)
        return vm_enviornment

    def get_port_id(self, port_client, vm_info):
        tenant_name = vm_info['name']
        fixed_ip = vm_info['addresses'][tenant_name][0]['addr']
        list_ports = port_client.list_ports()
        list_ports_extract = list_ports['ports']
        for port in list_ports_extract:
            if port['fixed_ips'][0]['ip_address'] == fixed_ip:
                port_id = port['id']
                return port_id


class TestSpoofGuardFeature(TestSpoofGuardBasicOps):
    @test.attr(type='nsxv')
    @test.idempotent_id('2804f55d-3221-440a-9fa8-ab16a8932634')
    def test_exclude_list_with_new_attach_port(self):
        port_client = self.manager.ports_client
        self.green = self.setup_vm_enviornment(self.manager, 'green', True)
        vm_id = self.green['serv1']['id']
        net_id = self.green['network']['id']
        name = 'disabled-port-security-port'
        kwargs = {'name': name, 'network_id': net_id,
                  'port_security_enabled': 'false'}
        # Create Port
        port = HELO.create_port(self, client=port_client, **kwargs)
        port_id = port['id']
        kwargs = {'port_id': port_id}
        # Attach interface to vm
        self.interface_client.create_interface(vm_id, **kwargs)
        # Fetch exclude list information from beckend
        items = self.vsm.get_excluded_vm_name_list()
        exclude_list = [item.encode('utf-8') for item in items]
        for exclude_vm in exclude_list:
            if vm_id in exclude_vm:
                LOG.info(_LI("Vm in exclude list"))
        # Update Port security to disabled
        port_client.update_port(
            port_id=port_id,
            port_security_enabled='true')
        items = self.vsm.get_excluded_vm_name_list()
        exclude_list = [item.encode('utf-8') for item in items]
        if exclude_vm in exclude_list:
            if vm_id not in exclude_vm:
                LOG.info(_LI("Vm not in exclude list"))
        # Detach interface from vm
        self.interface_client.delete_interface(vm_id, port_id)

    @test.attr(type='nsxv')
    @test.idempotent_id('38c213df-bfc2-4681-9c9c-3a31c05b0e6f')
    def test_exclude_with_multiple_vm(self):
        image = self.get_server_image()
        flavor = self.get_server_flavor()
        port_client = self.manager.ports_client
        self.green = self.setup_vm_enviornment(self.manager, 'green', True)
        vm_id = self.green['serv1']['id']
        security_groups = [{'name': self.green['security_group']['id']}]
        # Boot instance vm2
        t_serv2 = self.create_server_on_network(
            self.green['network'], security_groups,
            image=image,
            flavor=flavor,
            name=self.green['network']['name'])
        # Boot instance vm3
        t_serv3 = self.create_server_on_network(
            self.green['network'], security_groups,
            image=self.get_server_image(),
            flavor=self.get_server_flavor(),
            name=self.green['network']['name'])
        self.check_server_connected(t_serv2)
        port1_id = self.green['fip1']['port_id']
        port2_id = self.get_port_id(port_client=port_client, vm_info=t_serv2)
        port3_id = self.get_port_id(port_client=port_client, vm_info=t_serv3)
        # Update vm1 port to disbale port security
        port_client.update_port(
            port_id=port1_id,
            port_security_enabled='false')
        items = self.vsm.get_excluded_vm_name_list()
        exclude_list = [item.encode('utf-8') for item in items]
        for exclude_vm in exclude_list:
            if vm_id in exclude_vm:
                LOG.info(_LI("Vm1 in exclude list"))
        vm2_id = t_serv2['id']
        # Update vm2 port to disable port security
        port_client.update_port(
            port_id=port2_id,
            port_security_enabled='false')
        items = self.vsm.get_excluded_vm_name_list()
        exclude_list = [item.encode('utf-8') for item in items]
        # Check vm2 in exclude list or not
        for exclude_vm in exclude_list:
            if vm2_id in exclude_vm:
                LOG.info(_LI("Vm2 in exclude list"))
        vm3_id = t_serv3['id']
        # Update vm3 port to enable port security
        port_client.update_port(
            port_id=port3_id,
            port_security_enabled='false')
        items = self.vsm.get_excluded_vm_name_list()
        exclude_list = [item.encode('utf-8') for item in items]
        # Check vm3 in exclude list or not
        for exclude_vm in exclude_list:
            if vm3_id in exclude_vm:
                LOG.info(_LI("Vm3 in exclude list"))
        # Update vm1 port to enable port security
        port_client.update_port(
            port_id=port1_id,
            port_security_enabled='true')
        items = self.vsm.get_excluded_vm_name_list()
        exclude_list = [item.encode('utf-8') for item in items]
        # Check vm should not be in exclude list
        for exclude_vm in exclude_list:
            if vm_id not in exclude_vm:
                LOG.info(_LI("Vm1 not in exclude list"))

    @test.attr(type='nsxv')
    @test.idempotent_id('f034d3e9-d717-4bcd-8e6e-18e9ada7b81a')
    def test_exclude_list_with_single_vm_port(self):
        port_client = self.manager.ports_client
        self.green = self.setup_vm_enviornment(self.manager, 'green', True)
        port_id = self.green['fip1']['port_id']
        # Update vm port to disable port security
        port_client.update_port(
            port_id=port_id,
            port_security_enabled='false')
        vm_id = self.green['serv1']['id']
        # Check vm in exclude list or not
        items = self.vsm.get_excluded_vm_name_list()
        exclude_list = [item.encode('utf-8') for item in items]
        for exclude_vm in exclude_list:
            if vm_id in exclude_vm:
                LOG.info(_LI("Vm in exclude list"))
        port_client.update_port(
            port_id=port_id,
            port_security_enabled='true')
        items = self.vsm.get_excluded_vm_name_list()
        exclude_list = [item.encode('utf-8') for item in items]
        if exclude_vm in exclude_list:
            if vm_id not in exclude_vm:
                LOG.info(_LI("Vm not in exclude list"))
        self.interface_client.delete_interface(vm_id, port_id)

    @test.attr(type='nsxv')
    @test.idempotent_id('3ad04e37-2a9f-4465-86e7-94993eecdfa1')
    def test_disabled_network_port_security(self):
        network_client = self.manager.networks_client
        port_client = self.manager.ports_client
        net_id, network, subnet =\
            self.create_project_network_subnet('admin')
        kwargs = {'port_security_enabled': 'false'}
        # Update network to disbale port security
        network_client.update_network(network_id=net_id, **kwargs)
        name = 'disabled-port-security-port'
        kwargs = {'name': name, 'network_id': net_id}
        # Create port under network
        port = HELO.create_port(self, client=port_client, **kwargs)
        port_id = port['id']
        # Check port security of created port
        port_details = port_client.show_port(port_id=port_id)
        if (port_details['port']['port_security_enabled'] == 'false'):
            LOG.info(_LI("Port security of port is disabled"))
        kwargs = {'port_security_enabled': 'true'}
        # Update port security of network to enabled
        network_client.update_network(network_id=net_id, **kwargs)
        name = 'disabled-port-security-port'
        kwargs = {'name': name, 'network_id': net_id}
        port = HELO.create_port(self, client=port_client, **kwargs)
        port_id = port['id']
        port_details = port_client.show_port(port_id=port_id)
        if (port_details['port']['port_security_enabled'] == 'true'):
            LOG.info(_LI("Port security of port is enabled"))

    @test.attr(type='nsxv')
    @test.idempotent_id('c8683cb7-4be5-4670-95c6-344a0aea3667')
    def test_exclude_list_with_multiple_ports(self):
        port_client = self.manager.ports_client
        self.green = self.setup_vm_enviornment(self.manager, 'green', True)
        vm_id = self.green['serv1']['id']
        net_id = self.green['network']['id']
        name = 'disabled-port-security-port1'
        kwargs = {'name': name, 'network_id': net_id,
                  'port_security_enabled': 'false'}
        port1 = HELO.create_port(self, client=port_client, **kwargs)
        port2 = HELO.create_port(self, client=port_client, **kwargs)
        port1_id = port1['id']
        kwargs = {'port_id': port1_id}
        self.interface_client.create_interface(vm_id, **kwargs)
        items = self.vsm.get_excluded_vm_name_list()
        exclude_list = [item.encode('utf-8') for item in items]
        for exclude_vm in exclude_list:
            if vm_id in exclude_vm:
                LOG.info(_LI("Vm in exclude list"))
        name = 'disabled-port-security-port2'
        kwargs = {'name': name, 'network_id': net_id,
                  'port_security_enabled': 'false'}
        port2_id = port2['id']
        kwargs = {'port_id': port2_id}
        self.interface_client.create_interface(vm_id, **kwargs)
        items = self.vsm.get_excluded_vm_name_list()
        exclude_list = [item.encode('utf-8') for item in items]
        for exclude_vm in exclude_list:
            if vm_id in exclude_vm:
                LOG.info(_LI("Vm in exclude list"))
        port_client.update_port(
            port_id=port2_id,
            port_security_enabled='true')
        items = self.vsm.get_excluded_vm_name_list()
        exclude_list = [item.encode('utf-8') for item in items]
        for exclude_vm in exclude_list:
            if vm_id in exclude_vm:
                LOG.info(_LI("Vm in exclude list"))
        port_client.update_port(
            port_id=port1_id,
            port_security_enabled='true')
        items = self.vsm.get_excluded_vm_name_list()
        exclude_list = [item.encode('utf-8') for item in items]
        if exclude_vm in exclude_list:
            if vm_id not in exclude_vm:
                LOG.info(_LI("Vm not in exclude list"))
        self.interface_client.delete_interface(vm_id, port1_id)
        self.interface_client.delete_interface(vm_id, port2_id)
