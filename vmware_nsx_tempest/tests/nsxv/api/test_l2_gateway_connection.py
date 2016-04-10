# Copyright 2015 OpenStack Foundation
# Copyright 2015 VMware Inc
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

from tempest.api.network import base
from tempest import config
from tempest import test

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from vmware_nsx_tempest.services import base_l2gw
from vmware_nsx_tempest.services import l2_gateway_client as L2GW
from vmware_nsx_tempest.services import \
    l2_gateway_connection_client as L2GWC

CONF = config.CONF
L2GW_RID = 'l2_gateway'
L2GW_RIDs = 'l2_gateways'
L2GWC_RID = 'l2_gateway_connection'
L2GWC_RIDs = 'l2_gateway_connections'
MSG_DIFF = "l2gw %s=%s is not the same as requested=%s"


class L2GatewayConnectionTest(base.BaseAdminNetworkTest):
    """Test l2-gateway-connection operations:

        l2-gateway-connection-create
        l2-gateway-connection-show
        l2-gateway-connection-update (no case)
        l2-gateway-connection-list
        l2-gateway-connection-delete

       over single device/interface/vlan
       over single device/interface/multiple-vlans
       over single device/multiple-interfaces/multiple-vlans
       over multiple-device/multiple-interfaces/multiple-vlans
    """

    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(L2GatewayConnectionTest, cls).skip_checks()
        if not test.is_extension_enabled('l2-gateway', 'network'):
            msg = "l2-gateway extension not enabled."
            raise cls.skipException(msg)
        if not test.is_extension_enabled('l2-gateway-connection',
                                         'network'):
            msg = "l2-gateway-connection extension is not enabled"
            raise cls.skipException(msg)
        # skip test if CONF session:l2gw does not have the following opts
        cls.getattr_or_skip_test("device_one_vlan")
        cls.getattr_or_skip_test("vlan_subnet_ipv4_dict")

    @classmethod
    def getattr_or_skip_test(cls, l2gw_attr_name):
        attr_value = getattr(CONF.l2gw, l2gw_attr_name, None)
        if attr_value:
            return attr_value
        msg = "CONF session:l2gw attr:%s is not defined." % (l2gw_attr_name)
        raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(L2GatewayConnectionTest, cls).setup_clients()
        cls.l2gw_created = {}
        cls.l2gwc_created = {}
        l2gw_mgr = cls.os_adm
        cls.l2gw_client = L2GW.get_client(l2gw_mgr)
        cls.l2gwc_client = L2GWC.get_client(l2gw_mgr)
        cls.l2gw_list_0 = cls.l2gw_client.list_l2_gateways()[L2GW_RIDs]

    @classmethod
    def resource_setup(cls):
        super(L2GatewayConnectionTest, cls).resource_setup()
        # create primary tenant's VLAN network
        _subnet = cls.getattr_or_skip_test("vlan_subnet_ipv4_dict")
        for _x in ('mask_bits',):
            if _x in _subnet:
                _subnet[_x] = int(_subnet[_x])
        # cidr must be presented & in IPNetwork structure
        _subnet['cidr'] = netaddr.IPNetwork(_subnet['cidr'])
        _start = _subnet.pop('start', None)
        _end = _subnet.pop('end', None)
        if _start and _end:
            _subnet['allocation_pools'] = [{'start': _start, 'end': _end}]
        cls.network = cls.create_network()
        # baseAdminNetworkTest does not derive ip_version, mask_bits from cidr
        _subnet['ip_version'] = 4
        if 'mask_bits' not in _subnet:
            _subnet['mask_bits'] = _subnet['cidr'].prefixlen
        cls.subnet = cls.create_subnet(cls.network, **_subnet)

    @classmethod
    def resource_cleanup(cls):
        for _id in cls.l2gwc_created.keys():
            try:
                cls.l2gwc_client.delete_l2_gateway_connection(_id)
            except Exception:
                # log it please
                pass
        for _id in cls.l2gw_created.keys():
            try:
                cls.l2gw_client.delete_l2_gateway(_id)
            except Exception:
                # log it please
                pass
        if hasattr(cls, 'network'):
            cls.networks_client.delete_network(cls.network['id'])

    @classmethod
    def get_ipaddress_from_tempest_conf(cls, ip_version=4):
        """Return first subnet gateway for configured CIDR."""
        if ip_version == 4:
            cidr = netaddr.IPNetwork(CONF.network.project_network_cidr)
        elif ip_version == 6:
            cidr = netaddr.IPNetwork(CONF.network.project_network_v6_cidr)
        return netaddr.IPAddress(cidr)

    def get_segmentation_id(self, _l2gw, d_idx=0, i_idx=0):
        _dev = _l2gw['devices'][d_idx]
        _seg = _dev['interfaces'][i_idx].get('segmentation_id', [])
        return sorted(_seg)

    def get_interfaces(self, _l2gw, d_idx=0):
        _dev = _l2gw['devices'][d_idx]
        return sorted(_dev)

    def pop_segmentation_id(self, _l2gw, d_idx=0, i_idx=0):
        _dev = _l2gw['devices'][d_idx]
        _seg = _dev['interfaces'][i_idx].pop('segmentation_id', [])
        return sorted(_seg)

    def create_l2gw_switch(self, _name, _devices):
        _vlan_id_list = self.get_segmentation_id(_devices)
        _res_new = self.l2gw_client.create_l2_gateway(
            name=_name, **_devices)[L2GW_RID]
        self.l2gw_created[_res_new['id']] = _res_new
        _res_show = self.l2gw_client.show_l2_gateway(
            _res_new['id'])[L2GW_RID]
        return (_res_show, _vlan_id_list)

    def create_l2gw_connection(self, _l2gw, network_id=None, **kwargs):
        network_id = network_id or self.network['id']
        _seg_id = kwargs.pop('default_segmentation_id',
                             kwargs.pop('segmentation_id', None))
        cr_body = {'l2_gateway_id': _l2gw['id'], 'network_id': network_id}
        if _seg_id:
            cr_body['segmentation_id'] = _seg_id
        _res_new = self.l2gwc_client.create_l2_gateway_connection(
            **cr_body)[L2GWC_RID]
        self.l2gwc_created[_res_new['id']] = _res_new
        _res_show = self.l2gwc_client.show_l2_gateway_connection(
            _res_new['id'])[L2GWC_RID]
        return (_res_show, _seg_id)

    def do_suld_l2gw_connection(self, _res_new):
        _res_show = self.l2gwc_client.show_l2_gateway_connection(
            _res_new['id'])[L2GWC_RID]
        for _k in ('l2_gateway_id', 'network_id'):
            self.assertEqual(_res_show[_k], _res_new[_k])
        _res_lst = self.l2gwc_client.list_l2_gateway_connections(
            l2_gateway_id=_res_new['l2_gateway_id'],
            network_id=_res_new['network_id'])[L2GWC_RIDs][0]
        self.assertEqual(_res_show['l2_gateway_id'], _res_lst['l2_gateway_id'])
        self.l2gwc_client.delete_l2_gateway_connection(_res_new['id'])
        _res_lst = self.l2gwc_client.list_l2_gateway_connections(
            l2_gateway_id=_res_new['l2_gateway_id'],
            network_id=_res_new['network_id'])[L2GWC_RIDs]
        self.l2gwc_created.pop(_res_new['id'])
        self.assertEmpty(_res_lst,
                         "l2gwc id=%s not deleted." % (_res_new['id']))

    @test.idempotent_id('6628c662-b997-46cd-8266-77f329bda062')
    def test_csuld_single_device_interface_without_vlan(self):
        """Single device/interface/vlan

           Create l2gw with one and only one VLAN. In this case,
           l2-gateway-connnection does not need to specify VLAN.
        """

        dev_profile = self.getattr_or_skip_test("device_one_vlan")
        _name = data_utils.rand_name('l2gwc-1v1')
        _devices = base_l2gw.get_l2gw_body(dev_profile)
        _vlan_id_list = self.pop_segmentation_id(_devices)
        (_gw, _seg_list) = self.create_l2gw_switch(_name, _devices)
        (_res_new, _seg_id) = self.create_l2gw_connection(
            _gw, segmentation_id=_vlan_id_list[0])
        _seg_new = str(_res_new.get('segmentation_id'))
        self.assertEqual(_seg_new, str(_seg_id))
        self.do_suld_l2gw_connection(_res_new)

    @test.idempotent_id('222104e3-1260-42c1-bdf6-536c1141387c')
    def test_csuld_single_device_interface_vlan(self):
        """Single device/interface/vlan

           Create l2gw without specifying LAN. In this case,
           l2-gateway-connnection need to specify VLAN.
        """

        dev_profile = self.getattr_or_skip_test("device_one_vlan")
        _name = data_utils.rand_name('l2gwc-1v2')
        _devices = base_l2gw.get_l2gw_body(dev_profile)
        (_gw, _seg_list) = self.create_l2gw_switch(_name, _devices)
        (_res_new, _seg_id) = self.create_l2gw_connection(_gw)
        _seg_new = _res_new.get('segmentation_id', None)
        # vlan specified @l2-gateway, so it is empty @l2-gateway-connection
        self.assertEmpty(_seg_new)
        self.do_suld_l2gw_connection(_res_new)

    @decorators.skip_because(bug="1559913")
    @test.idempotent_id('1875eca7-fde9-49ba-be21-47a8cc41f2e5')
    def test_csuld_single_device_interface_mvlan_type2(self):
        dev_profile = self.getattr_or_skip_test("device_multiple_vlans")
        _name = data_utils.rand_name('l2gwc-2v1')
        _devices = base_l2gw.get_l2gw_body(dev_profile)
        _vlan_id_list = self.get_segmentation_id(_devices)
        (_gw, _seg_list) = self.create_l2gw_switch(_name, _devices)
        (_res_new, _seg_id_list) = self.create_l2gw_connection(_gw)
        _seg_id_list = _res_new.get('segmentation_id')
        self.assertEqaul(0, cmp(_vlan_id_list, _seg_id_list),
                         MSG_DIFF % ('vlan', _vlan_id_list, _seg_id_list))
        self.do_suld_l2gw_connection(_res_new)

    @decorators.skip_because(bug="1559913")
    @test.idempotent_id('53755cb0-fdca-4ee7-8e43-a9b8a9d6d90a')
    def test_csuld_single_device_minterface_mvlan_type1(self):
        # NSX-v does not support multiple interfaces
        dev_profile = self.getattr_or_skip_test(
                "multiple_interfaces_multiple_vlans")
        _name = data_utils.rand_name('l2gwc-m2v1')
        _devices = base_l2gw.get_l2gw_body(dev_profile)
        _gw = self.create_l2gw_switch(_name, _devices)
        (_res_new, _seg_id) = self.create_l2gw_connection(_gw)
        self.do_suld_l2gw_connection(_res_new)

    @decorators.skip_because(bug="1559913")
    @test.idempotent_id('723b0b78-35d7-4774-89c1-ec73797a1fe3')
    def test_csuld_single_device_minterface_mvlan_type2(self):
        dev_profile = self.getattr_or_skip_test(
                "multiple_interfaces_multiple_vlans")
        _name = data_utils.rand_name('l2gwc-m2v2')
        _devices = base_l2gw.get_l2gw_body(dev_profile)
        _gw = self.create_l2gw_switch(_name, _devices)
        (_res_new, _seg_id) = self.create_l2gw_connection(_gw)
        self.do_suld_l2gw_connection(_res_new)
