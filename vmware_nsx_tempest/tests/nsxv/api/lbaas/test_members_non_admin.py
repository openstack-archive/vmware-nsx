# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log as logging

from tempest import config
from tempest.lib import exceptions as ex
from tempest import test

from vmware_nsx_tempest.tests.nsxv.api.lbaas import base

CONF = config.CONF

LOG = logging.getLogger(__name__)


class MemberTest(base.BaseTestCase):

    """Test the following operations in Neutron-LBaaS API

    using the REST client for members:

        list members of a pool
        create a member of a Pool
        update a pool member
        delete a member
    """

    @classmethod
    def resource_setup(cls):
        super(MemberTest, cls).resource_setup()
        # core network setup is moved to base class
        cls.load_balancer = cls._create_active_load_balancer(
            tenant_id=cls.tenant_id,
            vip_subnet_id=cls.subnet.get('id'))
        cls.load_balancer_id = cls.load_balancer.get("id")
        cls.listener = cls._create_listener(
            loadbalancer_id=cls.load_balancer.get('id'),
            protocol='HTTP', protocol_port=80)
        cls.listener_id = cls.listener.get('id')
        cls.pool = cls._create_pool(protocol='HTTP',
                                    tenant_id=cls.tenant_id,
                                    lb_algorithm='ROUND_ROBIN',
                                    listener_id=cls.listener_id)
        cls.pool_id = cls.pool.get('id')

    @classmethod
    def resource_cleanup(cls):
        super(MemberTest, cls).resource_cleanup()

    @test.attr(type='smoke')
    @test.idempotent_id('6dcdc53c-52cf-4b6e-aeec-d13df68ed001')
    def test_list_empty_members(self):
        """Test that pool members are empty."""
        members = self._list_members(self.pool_id)
        self.assertEmpty(members,
                         msg='Initial pool was supposed to be empty')

    @test.attr(type='smoke')
    @test.idempotent_id('346e49ce-0665-4995-a03a-b007052d3619')
    def test_list_3_members(self):
        """Test that we can list members. """
        member_ips_exp = set([u"127.0.0.0", u"127.0.0.1", u"127.0.0.2"])
        for ip in member_ips_exp:
            member_opts = self.build_member_opts()
            member_opts["address"] = ip
            member = self._create_member(self.pool_id, **member_opts)
            self.addCleanup(self._delete_member, self.pool_id, member['id'])
        members = self._list_members(self.pool_id)
        self.assertEqual(3, len(members))
        for member in members:
            self.assertEqual(member["tenant_id"], self.tenant_id)
            self.assertEqual(member["protocol_port"], 80)
            self.assertEqual(member["subnet_id"], self.subnet_id)
        found_member_ips = set([m["address"] for m in members])
        self.assertEqual(found_member_ips, member_ips_exp)

    @test.attr(type='smoke')
    @test.idempotent_id('3121bbdc-81e4-40e3-bf66-3ceefd72a0f5')
    def test_add_member(self):
        """Test that we can add a single member."""
        expect_empty_members = self._list_members(self.pool_id)
        self.assertEmpty(expect_empty_members)
        member_opts = self.build_member_opts()
        member = self._create_member(self.pool_id, **member_opts)
        member_id = member.get("id")
        self.addCleanup(self._delete_member, self.pool_id, member_id)
        self.assertEqual(member_opts["address"], member["address"])
        self.assertEqual(self.tenant_id, member["tenant_id"])
        self.assertEqual(80, member["protocol_port"])
        self.assertEqual(self.subnet_id, member["subnet_id"])
        # Should have default values for admin_state_up and weight
        self.assertEqual(True, member["admin_state_up"])
        self.assertEqual(1, member["weight"])

    @test.attr(type='smoke')
    @test.idempotent_id('fc513a45-4c24-42ea-8807-a9b86a81ee56')
    def test_get_member(self):
        """Test that we can fetch a member by id."""
        member_opts = self.build_member_opts()
        member_id = self._create_member(self.pool_id,
                                        **member_opts)["id"]
        self.addCleanup(self._delete_member, self.pool_id, member_id)
        member = self._show_member(self.pool_id, member_id)
        self.assertEqual(member_id, member["id"])
        self.assertEqual(member_opts["address"], member["address"])
        self.assertEqual(member_opts["tenant_id"], member["tenant_id"])
        self.assertEqual(member_opts["protocol_port"], member["protocol_port"])
        self.assertEqual(member_opts["subnet_id"], member["subnet_id"])

    @test.attr(type='smoke')
    @test.idempotent_id('2cead036-5a63-43a4-9d9d-03c9b744c101')
    def test_create_member_missing_required_field_tenant_id(self):
        """Test if a non_admin user can create a member_opts

        with tenant_id missing
        """
        member_opts = {}
        member_opts['address'] = "127.0.0.1"
        member_opts['protocol_port'] = 80
        member_opts['subnet_id'] = self.subnet_id
        member = self._create_member(self.pool_id, **member_opts)
        self.addCleanup(self._delete_member, self.pool_id, member['id'])

    @test.attr(type='negative')
    @test.idempotent_id('d7ed0870-a065-4fbd-8d95-0ea4d12063c2')
    def test_create_member_missing_required_field_address(self):
        """Test create a member with missing field address"""
        member_opts = {}
        member_opts['protocol_port'] = 80
        member_opts['subnet_id'] = self.subnet_id
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('8d2b9a53-aac7-4fb9-b068-47647289aa21')
    def test_create_member_missing_required_field_protocol_port(self):
        """Test create a member with missing field protocol_port"""
        member_opts = {}
        member_opts['address'] = "127.0.0.1"
        member_opts['subnet_id'] = self.subnet_id
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('9710cd4c-aac0-4b71-b295-82a88c67b0b8')
    def test_create_member_missing_required_field_subnet_id(self):
        """Test create a member with missing field subnet_id """
        member_opts = {}
        member_opts['protocol_port'] = 80
        member_opts['address'] = "127.0.0.1"
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('a6814c49-758d-490a-9557-ef03f0d78c44')
    def test_raises_BadRequest_when_missing_attrs_during_member_create(self):
        """Test failure on missing attributes on member create."""
        member_opts = {}
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('840bfa84-1d16-4149-a863-6f7afec1682f')
    def test_create_member_invalid_tenant_id(self):
        """Test create member with invalid tenant_id"""
        member_opts = {}
        member_opts['address'] = "127.0.0.1"
        member_opts['protocol_port'] = 80
        member_opts['subnet_id'] = self.subnet_id
        member_opts['tenant_id'] = "$232!$pw"
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('a99dbd0a-5f8c-4c96-8900-1a7d297d913b')
    def test_create_member_invalid_address(self):
        """Test create member with invalid address"""
        member_opts = {}
        member_opts['address'] = "127$%<ki"
        member_opts['protocol_port'] = 80
        member_opts['subnet_id'] = self.subnet_id
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('736b0771-b98c-4045-97e0-a44e4e18c22e')
    def test_create_member_invalid_protocol_port(self):
        """Test create member with invalid protocol_port"""
        member_opts = {}
        member_opts['address'] = "127.0.0.1"
        member_opts['protocol_port'] = 8090000
        member_opts['subnet_id'] = self.subnet_id
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('2cc67f5a-3f66-427e-90b8-59a3da5c1d21')
    def test_create_member_invalid_subnet_id(self):
        """Test create member with invalid subnet_id"""
        member_opts = {}
        member_opts['address'] = "127.0.0.1"
        member_opts['protocol_port'] = 80
        member_opts['subnet_id'] = "45k%^"
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('3403c6f5-5a30-4115-ac3a-8a22855fd614')
    def test_create_member_invalid_admin_state_up(self):
        """Test create member with invalid admin_state_up"""
        member_opts = {}
        member_opts['address'] = "127.0.0.1"
        member_opts['protocol_port'] = 80
        member_opts['subnet_id'] = self.subnet_id
        member_opts['admin_state_up'] = "$232!$pw"
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('b12216ec-3442-4239-ba2c-dd17640449d1')
    def test_create_member_invalid_weight(self):
        """Test create member with invalid weight"""
        member_opts = {}
        member_opts['address'] = "127.0.0.1"
        member_opts['protocol_port'] = 80
        member_opts['subnet_id'] = self.subnet_id
        member_opts['weight'] = "$232!$pw"
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('88eb464b-4de6-4ed7-a1e8-bc61581a5c6e')
    def test_create_member_empty_tenant_id(self):
        """Test create member with an empty tenant_id"""
        member_opts = {}
        member_opts['address'] = "127.0.0.1"
        member_opts['protocol_port'] = 80
        member_opts['subnet_id'] = self.subnet_id
        member_opts['tenant_id'] = ""
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('238cd859-2b60-4e42-b356-c6b38768c3e4')
    def test_create_member_empty_address(self):
        """Test create member with an empty address"""
        member_opts = {}
        member_opts['address'] = ""
        member_opts['protocol_port'] = 80
        member_opts['subnet_id'] = self.subnet_id
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('834905ac-5c95-4dfc-900c-1676b6c28247')
    def test_create_member_empty_protocol_port(self):
        """Test create member with an empty protocol_port"""
        member_opts = {}
        member_opts['address'] = "127.0.0.1"
        member_opts['protocol_port'] = ""
        member_opts['subnet_id'] = self.subnet_id
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('a0f2148e-160e-4b12-8e30-567a0448d179')
    def test_create_member_empty_subnet_id(self):
        """Test create member with empty subnet_id"""
        member_opts = {}
        member_opts['address'] = "127.0.0.1"
        member_opts['protocol_port'] = 80
        member_opts['subnet_id'] = ""
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('63cd5897-b82c-4508-8be7-3b7ccab21798')
    def test_create_member_empty_admin_state_up(self):
        """Test create member with an empty admin_state_up"""
        member_opts = {}
        member_opts['address'] = "127.0.0.1"
        member_opts['protocol_port'] = 80
        member_opts['subnet_id'] = self.subnet_id
        member_opts['admin_state_up'] = ""
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('55f16682-74a2-4df7-a6b3-2da3623f4a41')
    def test_create_member_empty_weight(self):
        """Test create member with an empty weight"""
        member_opts = {}
        member_opts['address'] = "127.0.0.1"
        member_opts['protocol_port'] = 80
        member_opts['subnet_id'] = self.subnet_id
        member_opts['weight'] = ""
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='smoke')
    @test.idempotent_id('c99f6146-2c85-4a32-a850-942d6836c175')
    def test_delete_member(self):
        """Test that we can delete a member by id."""
        member_opts = self.build_member_opts()
        member_id = self._create_member(self.pool_id,
                                        **member_opts)["id"]
        members = self._list_members(self.pool_id)
        self.assertEqual(1, len(members))
        self._delete_member(self.pool_id, member_id)
        members = self._list_members(self.pool_id)
        self.assertEmpty(members)

    @test.attr(type='smoke')
    @test.idempotent_id('7d51aa2d-9582-4160-b07b-bf3c3b3e335e')
    def test_update_member(self):
        """Test that we can update a member."""
        member_opts = self.build_member_opts()
        member = self._create_member(self.pool_id,
                                     **member_opts)
        member_id = member["id"]
        self.addCleanup(self._delete_member, self.pool_id, member['id'])
        # Make sure the defaults are correct
        self.assertEqual(True, member["admin_state_up"])
        self.assertEqual(1, member["weight"])
        # Lets overwrite the defaults
        member_opts = {"weight": 10, "admin_state_up": False}
        member = self._update_member(self.pool_id, member_id,
                                     **member_opts)
        # And make sure they stick
        self.assertFalse(member["admin_state_up"])
        self.assertEqual(10, member["weight"])

    @test.attr(type='smoke')
    @test.idempotent_id('101555d6-c472-45e4-b302-b2916ab6fad5')
    def test_update_member_missing_admin_state_up(self):
        """Test that we can update a member with missing admin_state_up."""
        member_opts = self.build_member_opts()
        member = self._create_member(self.pool_id,
                                     **member_opts)
        member_id = member["id"]
        self.addCleanup(self._delete_member, self.pool_id, member_id)
        self.assertEqual(True, member["admin_state_up"])
        self.assertEqual(1, member["weight"])
        member_opts = {"weight": 10}
        member = self._update_member(self.pool_id, member_id,
                                     **member_opts)
        self.assertEqual(True, member["admin_state_up"])
        self.assertEqual(10, member["weight"])

    @test.attr(type='smoke')
    @test.idempotent_id('815c037b-7e3b-474d-a4f6-eec26b44d677')
    def test_update_member_missing_weight(self):
        """Test that we can update a member with missing weight."""
        member_opts = self.build_member_opts()
        member = self._create_member(self.pool_id,
                                     **member_opts)
        member_id = member["id"]
        self.addCleanup(self._delete_member, self.pool_id, member_id)
        self.assertEqual(True, member["admin_state_up"])
        self.assertEqual(1, member["weight"])
        member_opts = {"admin_state_up": False}
        member = self._update_member(self.pool_id, member_id,
                                     **member_opts)
        self.assertFalse(member["admin_state_up"])
        self.assertEqual(1, member["weight"])

    @test.attr(type='negative')
    @test.idempotent_id('3ab3bb11-e287-4693-8ea0-5cfbb4cc2c85')
    def test_update_member_invalid_admin_state_up(self):
        """Test that we can update a member with empty admin_state_up."""
        member_opts = self.build_member_opts()
        member = self._create_member(self.pool_id,
                                     **member_opts)
        member_id = member["id"]
        self.addCleanup(self._delete_member, self.pool_id, member_id)
        self.assertEqual(True, member["admin_state_up"])
        self.assertEqual(1, member["weight"])
        member_opts = {"weight": 10, "admin_state_up": "%^67"}
        self.assertRaises(ex.BadRequest, self._update_member,
                          self.pool_id, member_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('71979c3b-08d6-449b-8de2-1eefc9d0db0e')
    def test_update_member_invalid_weight(self):
        """Test that we can update a member with an empty weight."""
        member_opts = self.build_member_opts()
        member = self._create_member(self.pool_id,
                                     **member_opts)
        member_id = member["id"]
        self.addCleanup(self._delete_member, self.pool_id, member_id)
        self.assertEqual(True, member["admin_state_up"])
        self.assertEqual(1, member["weight"])
        member_opts = {"admin_state_up": False, "weight": "*^$df"}
        self.assertRaises(ex.BadRequest, self._update_member,
                          self.pool_id, member_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('e1470212-0a36-4d8c-8e30-1f69a8d31ae1')
    def test_update_member_empty_admin_state_up(self):
        """Test that we can update a member with empty admin_state_up."""
        member_opts = self.build_member_opts()
        member = self._create_member(self.pool_id,
                                     **member_opts)
        member_id = member["id"]
        self.addCleanup(self._delete_member, self.pool_id, member_id)
        self.assertEqual(True, member["admin_state_up"])
        self.assertEqual(1, member["weight"])
        member_opts = {"weight": 10, "admin_state_up": ""}
        self.assertRaises(ex.BadRequest, self._update_member,
                          self.pool_id, member_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('cd1e276c-b220-439d-a9dc-823a10d11b6a')
    def test_update_member_empty_weight(self):
        """Test that we can update a member with an empty weight."""
        member_opts = self.build_member_opts()
        member = self._create_member(self.pool_id,
                                     **member_opts)
        member_id = member["id"]
        self.addCleanup(self._delete_member, self.pool_id, member_id)
        self.assertEqual(True, member["admin_state_up"])
        self.assertEqual(1, member["weight"])
        member_opts = {"admin_state_up": False, "weight": ""}
        self.assertRaises(ex.BadRequest, self._update_member,
                          self.pool_id, member_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('25779006-1e2c-4155-9126-49f45e7646a3')
    def test_raises_immutable_when_updating_immutable_attrs_on_member(self):
        """Test failure on immutable attribute on member create."""
        member_opts = self.build_member_opts()
        member_id = self._create_member(self.pool_id,
                                        **member_opts)["id"]
        self.addCleanup(self._delete_member, self.pool_id, member_id)
        member_opts = {"address": "127.0.0.69"}
        # The following code actually raises a 400 instead of a 422 as expected
        # Will need to consult with blogan as to what to fix
        self.assertRaises(ex.BadRequest, self._update_member,
                          self.pool_id, member_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('a332ecda-bb18-4cc2-b847-c09a72d90fd1')
    def test_raises_exception_on_invalid_attr_on_create(self):
        """Test failure on invalid attribute on member create."""
        member_opts = self.build_member_opts()
        member_opts["invalid_op"] = "should_break_request"
        self.assertRaises(ex.BadRequest, self._create_member,
                          self.pool_id, **member_opts)

    @test.attr(type='negative')
    @test.idempotent_id('bc4c3eb5-14d5-43dd-93cb-603801fa6f32')
    def test_raises_exception_on_invalid_attr_on_update(self):
        """Test failure on invalid attribute on member update."""
        member_opts = self.build_member_opts()
        member = self._create_member(self.pool_id, **member_opts)
        member_id = member["id"]
        self.addCleanup(self._delete_member, self.pool_id, member_id)
        member_opts["invalid_op"] = "watch_this_break"
        self.assertRaises(ex.BadRequest, self._update_member,
                          self.pool_id, member_id, **member_opts)

    @classmethod
    def build_member_opts(cls, **kw):
        """Build out default member dictionary """
        opts = {"address": kw.get("address", "127.0.0.1"),
                "tenant_id": kw.get("tenant_id", cls.tenant_id),
                "protocol_port": kw.get("protocol_port", 80),
                "subnet_id": kw.get("subnet_id", cls.subnet_id)}
        return opts
