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

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest import test

from vmware_nsx_tempest.services import base_l2gw
from vmware_nsx_tempest.services import l2_gateway_client as L2GW

CONF = config.CONF
L2GW_RID = 'l2_gateway'
L2GW_RIDs = 'l2_gateways'
MSG_DIFF = "l2gw %s=%s is not the same as requested=%s"


class L2GatewayTest(base.BaseAdminNetworkTest):
    """Test l2-gateway operations:

        l2-gateway-create
        l2-gateway-show
        l2-gateway-update
        l2-gateway-list
        l2-gateway-delete

       over single device/interface/vlan
       over single device/interface/multiple-vlans
       over single device/multiple-interfaces/multiple-vlans
       over multiple-device/multiple-interfaces/multiple-vlans
    """

    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(L2GatewayTest, cls).skip_checks()
        if not test.is_extension_enabled('l2-gateway', 'network'):
            msg = "l2-gateway extension not enabled."
            raise cls.skipException(msg)
        # if CONF attr device_on_vlan not defined, SKIP entire test suite
        cls.getattr_or_skip_test("device_one_vlan")

    @classmethod
    def getattr_or_skip_test(cls, l2gw_attr_name):
        attr_value = getattr(CONF.l2gw, l2gw_attr_name, None)
        if attr_value:
            return attr_value
        msg = "CONF session:l2gw attr:%s is not defined." % (l2gw_attr_name)
        raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(L2GatewayTest, cls).setup_clients()
        cls.l2gw_created = {}
        l2gw_mgr = cls.os_adm
        cls.l2gw_client = L2GW.get_client(l2gw_mgr)
        cls.l2gw_list_0 = cls.l2gw_client.list_l2_gateways()[L2GW_RIDs]

    @classmethod
    def resource_setup(cls):
        super(L2GatewayTest, cls).resource_setup()

    @classmethod
    def resource_cleanup(cls):
        for _id in cls.l2gw_created.keys():
            try:
                cls.l2gw_client.delete_l2_gateway(_id)
            except Exception:
                # log it please
                pass

    def get_segmentation_id(self, _l2gw, d_idx=0, i_idx=0):
        _dev = _l2gw['devices'][d_idx]
        _seg = _dev['interfaces'][i_idx].get('segmentation_id', [])
        return sorted(_seg)

    def pop_segmentation_id(self, _l2gw, d_idx=0, i_idx=0):
        _dev = _l2gw['devices'][d_idx]
        _seg = _dev['interfaces'][i_idx].pop('segmentation_id', [])
        return sorted(_seg)

    def get_interfaces(self, _l2gw, d_idx=0):
        _dev = _l2gw['devices'][d_idx]
        return sorted(_dev)

    def do_csuld_single_device_interface_vlan(self, _name, _devices):
        _vlan_id_list = self.get_segmentation_id(_devices, 0, 0)
        _res_new = self.l2gw_client.create_l2_gateway(
            name=_name, **_devices)[L2GW_RID]
        self.l2gw_created[_res_new['id']] = _res_new
        self.assertEqual(_name, _res_new['name'],
                         MSG_DIFF % ('name', _res_new['name'], _name))
        # w/wo vlan provided, need to check it is assigned/not-assigned
        _seg_list = self.get_segmentation_id(_res_new, 0, 0)
        self.assertEqual(0, cmp(_vlan_id_list, _seg_list),
                         MSG_DIFF % ('vlan', _seg_list, _vlan_id_list))
        _res_show = self.l2gw_client.show_l2_gateway(
            _res_new['id'])[L2GW_RID]
        _if_created = _res_new['devices'][0]['interfaces']
        _if_shown = _res_show['devices'][0]['interfaces']
        self.assertEqual(0, cmp(_if_created, _if_shown),
                         MSG_DIFF % ('interfaces', _if_created, _if_shown))
        _name2 = _name + "-day2"
        _res_upd = self.l2gw_client.update_l2_gateway(
            _res_new['id'], name=_name2)[L2GW_RID]
        _res_lst = self.l2gw_client.list_l2_gateways(
            name=_name2)[L2GW_RIDs][0]
        self.assertEqual(_name2 == _res_upd['name'],
                         _name2 == _res_lst['name'],
                         MSG_DIFF % ('name', _res_new['name'], _name2))
        self.l2gw_client.delete_l2_gateway(_res_new['id'])
        _res_lst = self.l2gw_client.list_l2_gateways(name=_name2)[L2GW_RIDs]
        self.l2gw_created.pop(_res_new['id'])
        self.assertEmpty(_res_lst,
                         "l2gw name=%s, id=%s not deleted." %
                         (_name2, _res_new['id']))

    @test.idempotent_id('8b45a9a5-468b-4317-983d-7cceda367074')
    def test_csuld_single_device_interface_without_vlan(self):
        """Single device/interface/vlan

           Create l2gw with one and only one VLAN. In this case,
           l2-gateway-connnection does not need to specify VLAN.
        """

        dev_profile = self.getattr_or_skip_test("device_one_vlan")
        _name = data_utils.rand_name('l2gw-1v1')
        _devices = base_l2gw.get_l2gw_body(dev_profile)
        self.pop_segmentation_id(_devices, 0, 0)
        self.do_csuld_single_device_interface_vlan(_name, _devices)

    @test.idempotent_id('af57cf56-a169-4d88-b32e-7f49365ce407')
    def test_csuld_single_device_interface_vlan(self):
        """Single device/interface/vlan

           Create l2gw without specifying LAN. In this case,
           l2-gateway-connnection need to specify VLAN.
        """

        dev_profile = self.getattr_or_skip_test("device_one_vlan")
        _name = data_utils.rand_name('l2gw-1v2')
        _devices = base_l2gw.get_l2gw_body(dev_profile)
        self.do_csuld_single_device_interface_vlan(_name, _devices)

    @test.idempotent_id('cb59145e-3d2b-46b7-8f7b-f30f794a4d51')
    @decorators.skip_because(bug="1559913")
    def test_csuld_single_device_interface_mvlan(self):
        dev_profile = self.getattr_or_skip_test("device_multiple_vlans")
        _name = data_utils.rand_name('l2gw-2v1')
        _devices = base_l2gw.get_l2gw_body(dev_profile)
        self.do_csuld_single_device_interface_vlan(_name, _devices)

    @decorators.skip_because(bug="1559913")
    @test.idempotent_id('5522bdfe-ebe8-4eea-81b4-f4075bb608cf')
    def test_csuld_single_device_minterface_mvlan_type1(self):
        # NSX-v does not support multiple interfaces
        dev_profile = self.getattr_or_skip_test(
            "multiple_interfaces_multiple_vlans")
        _name = data_utils.rand_name('l2gw-m2v1')
        _devices = base_l2gw.get_l2gw_body(dev_profile)
        self.do_csuld_single_device_interface_vlan(_name, _devices)

    @decorators.skip_because(bug="1559913")
    @test.idempotent_id('5bec26e0-855f-4537-b31b-31663a820ddb')
    def test_csuld_single_device_minterface_mvlan_type2(self):
        # NSX-v does not support multiple interfaces
        dev_profile = self.getattr_or_skip_test(
            "multiple_interfaces_multiple_vlans")
        _name = data_utils.rand_name('l2gw-m2v2')
        _devices = base_l2gw.get_l2gw_body(dev_profile)
        self.do_csuld_single_device_interface_vlan(_name, _devices)
