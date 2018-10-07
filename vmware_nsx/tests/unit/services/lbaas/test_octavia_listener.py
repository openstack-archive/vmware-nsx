# Copyright 2018 VMware, Inc.
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

import mock
import testtools

from oslo_utils import uuidutils

from vmware_nsx.services.lbaas.octavia import octavia_listener


class DummyOctaviaResource(object):
    create_called = False
    update_called = False
    delete_called = False

    def create(self, ctx, lb_obj, completor_func, **args):
        self.create_called = True
        completor_func(success=True)

    def update(self, ctx, old_lb_obj, new_lb_obj, completor_func, **args):
        self.update_called = True
        completor_func(success=True)

    def delete(self, ctx, lb_obj, completor_func, **args):
        self.delete_called = True
        completor_func(success=True)


class TestNsxOctaviaListener(testtools.TestCase):
    """Test the NSX Octavia listener"""
    def setUp(self):
        super(TestNsxOctaviaListener, self).setUp()
        self.dummyResource = DummyOctaviaResource()
        self.clientMock = mock.Mock()
        self.clientMock.cast = mock.Mock()

        self.endpoint = octavia_listener.NSXOctaviaListenerEndpoint(
            client=self.clientMock,
            loadbalancer=self.dummyResource,
            listener=self.dummyResource,
            pool=self.dummyResource,
            member=self.dummyResource,
            healthmonitor=self.dummyResource,
            l7policy=self.dummyResource,
            l7rule=self.dummyResource)
        self.dummyObj = {'project_id': uuidutils.generate_uuid(),
                         'id': uuidutils.generate_uuid()}
        self.ctx = None
        self.mock_ctx = mock.patch("neutron_lib.context.Context")
        self.mock_ctx.start()

    def tearDown(self):
        self.mock_ctx.stop()
        super(TestNsxOctaviaListener, self).tearDown()

    def test_loadbalancer_create(self):
        self.dummyResource.create_called = False
        self.endpoint.loadbalancer_create(self.ctx, self.dummyObj)
        self.assertTrue(self.dummyResource.create_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'loadbalancers': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'ACTIVE',
                 'id': mock.ANY}]})

    def test_loadbalancer_delete(self):
        self.dummyResource.delete_called = False
        self.endpoint.loadbalancer_delete(self.ctx, self.dummyObj)
        self.assertTrue(self.dummyResource.delete_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'loadbalancers': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'DELETED',
                 'id': mock.ANY}]})

    def test_loadbalancer_update(self):
        self.dummyResource.update_called = False
        self.endpoint.loadbalancer_update(self.ctx, self.dummyObj,
                                          self.dummyObj)
        self.assertTrue(self.dummyResource.update_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'loadbalancers': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'ACTIVE',
                 'id': mock.ANY}]})

    def test_listener_create(self):
        self.dummyResource.create_called = False
        self.endpoint.listener_create(self.ctx, self.dummyObj, None)
        self.assertTrue(self.dummyResource.create_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'listeners': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'ACTIVE',
                 'id': mock.ANY}]})

    def test_listener_delete(self):
        self.dummyResource.delete_called = False
        self.endpoint.listener_delete(self.ctx, self.dummyObj)
        self.assertTrue(self.dummyResource.delete_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'listeners': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'DELETED',
                 'id': mock.ANY}]})

    def test_listener_update(self):
        self.dummyResource.update_called = False
        self.endpoint.listener_update(self.ctx, self.dummyObj, self.dummyObj,
                                      None)
        self.assertTrue(self.dummyResource.update_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'listeners': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'ACTIVE',
                 'id': mock.ANY}]})

    def test_pool_create(self):
        self.dummyResource.create_called = False
        self.endpoint.pool_create(self.ctx, self.dummyObj)
        self.assertTrue(self.dummyResource.create_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'pools': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'ACTIVE',
                 'id': mock.ANY}]})

    def test_pool_delete(self):
        self.dummyResource.delete_called = False
        self.endpoint.pool_delete(self.ctx, self.dummyObj)
        self.assertTrue(self.dummyResource.delete_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'pools': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'DELETED',
                 'id': mock.ANY}]})

    def test_pool_update(self):
        self.dummyResource.update_called = False
        self.endpoint.pool_update(self.ctx, self.dummyObj, self.dummyObj)
        self.assertTrue(self.dummyResource.update_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'pools': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'ACTIVE',
                 'id': mock.ANY}]})

    def test_member_create(self):
        self.dummyResource.create_called = False
        self.endpoint.member_create(self.ctx, self.dummyObj)
        self.assertTrue(self.dummyResource.create_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'members': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'ACTIVE',
                 'id': mock.ANY}]})

    def test_member_delete(self):
        self.dummyResource.delete_called = False
        self.endpoint.member_delete(self.ctx, self.dummyObj)
        self.assertTrue(self.dummyResource.delete_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'members': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'DELETED',
                 'id': mock.ANY}]})

    def test_member_update(self):
        self.dummyResource.update_called = False
        self.endpoint.member_update(self.ctx, self.dummyObj, self.dummyObj)
        self.assertTrue(self.dummyResource.update_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'members': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'ACTIVE',
                 'id': mock.ANY}]})

    def test_healthmonitor_create(self):
        self.dummyResource.create_called = False
        self.endpoint.healthmonitor_create(self.ctx, self.dummyObj)
        self.assertTrue(self.dummyResource.create_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'healthmonitors': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'ACTIVE',
                 'id': mock.ANY}]})

    def test_healthmonitor_delete(self):
        self.dummyResource.delete_called = False
        self.endpoint.healthmonitor_delete(self.ctx, self.dummyObj)
        self.assertTrue(self.dummyResource.delete_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'healthmonitors': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'DELETED',
                 'id': mock.ANY}]})

    def test_healthmonitor_update(self):
        self.dummyResource.update_called = False
        self.endpoint.healthmonitor_update(self.ctx, self.dummyObj,
                                           self.dummyObj)
        self.assertTrue(self.dummyResource.update_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'healthmonitors': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'ACTIVE',
                 'id': mock.ANY}]})

    def test_l7policy_create(self):
        self.dummyResource.create_called = False
        self.endpoint.l7policy_create(self.ctx, self.dummyObj)
        self.assertTrue(self.dummyResource.create_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'l7policies': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'ACTIVE',
                 'id': mock.ANY}]})

    def test_l7policy_delete(self):
        self.dummyResource.delete_called = False
        self.endpoint.l7policy_delete(self.ctx, self.dummyObj)
        self.assertTrue(self.dummyResource.delete_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'l7policies': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'DELETED',
                 'id': mock.ANY}]})

    def test_l7policy_update(self):
        self.dummyResource.update_called = False
        self.endpoint.l7policy_update(self.ctx, self.dummyObj, self.dummyObj)
        self.assertTrue(self.dummyResource.update_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'l7policies': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'ACTIVE',
                 'id': mock.ANY}]})

    def test_l7rule_create(self):
        self.dummyResource.create_called = False
        self.endpoint.l7rule_create(self.ctx, self.dummyObj)
        self.assertTrue(self.dummyResource.create_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'l7rules': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'ACTIVE',
                 'id': mock.ANY}]})

    def test_l7rule_delete(self):
        self.dummyResource.delete_called = False
        self.endpoint.l7rule_delete(self.ctx, self.dummyObj)
        self.assertTrue(self.dummyResource.delete_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'l7rules': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'DELETED',
                 'id': mock.ANY}]})

    def test_l7rule_update(self):
        self.dummyResource.update_called = False
        self.endpoint.l7rule_update(self.ctx, self.dummyObj, self.dummyObj)
        self.assertTrue(self.dummyResource.update_called)
        self.clientMock.cast.assert_called_once_with(
            {}, 'update_loadbalancer_status',
            status={'l7rules': [
                {'operating_status': 'ONLINE',
                 'provisioning_status': 'ACTIVE',
                 'id': mock.ANY}]})
