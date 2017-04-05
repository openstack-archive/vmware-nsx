# Copyright 2017 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
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

from neutron.tests import base
from neutron_dynamic_routing.db import bgp_db  # noqa
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory

from vmware_nsx.services.dynamic_routing.nsx_v import driver as nsxv_driver


class TestNSXvBgpDriver(base.BaseTestCase):

    def setUp(self):
        super(TestNSXvBgpDriver, self).setUp()
        self.context = context.get_admin_context()
        with mock.patch.object(directory, 'get_plugin',
                               new=mock.Mock()):
            self.provider = nsxv_driver.NSXvBgpDriver(mock.MagicMock())

    def test_create_v6_bgp_speaker(self):
        fake_bgp_speaker = {
            "bgp_speaker": {
                "ip_version": 6,
                "local_as": "1000",
                "name": "bgp-speaker"
            }
        }
        self.assertRaises(n_exc.InvalidInput,
                          self.provider.create_bgp_speaker,
                          self.context, fake_bgp_speaker)

    def test_create_v6_bgp_peer(self):
        fake_bgp_peer = {
            "bgp_peer": {
                "auth_type": "none",
                "remote_as": "1000",
                "name": "bgp-peer",
                "peer_ip": "fc00::/7"
            }
        }
        self.assertRaises(n_exc.InvalidInput,
                          self.provider.create_bgp_peer,
                          self.context, fake_bgp_peer)
