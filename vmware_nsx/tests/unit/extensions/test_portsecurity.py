# Copyright (c) 2014 OpenStack Foundation.
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

import mock

from neutron.tests.unit.extensions import test_portsecurity as psec
from vmware_nsx.common import sync
from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.nsx_mh.apiclient import fake
from vmware_nsx.tests.unit.nsx_v3 import test_constants as v3_constants
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_nsxv3
from vmware_nsx.tests.unit import test_utils


class PortSecurityTestCaseNSXv2(psec.PortSecurityDBTestCase):

    def setUp(self):
        test_utils.override_nsx_ini_test()
        # mock api client
        self.fc = fake.FakeClient(vmware.STUBS_PATH)
        self.mock_nsx = mock.patch(vmware.NSXAPI_NAME, autospec=True)
        instance = self.mock_nsx.start()
        instance.return_value.login.return_value = "the_cookie"
        # Avoid runs of the synchronizer looping call
        patch_sync = mock.patch.object(sync, '_start_loopingcall')
        patch_sync.start()

        instance.return_value.request.side_effect = self.fc.fake_request
        super(PortSecurityTestCaseNSXv2, self).setUp(vmware.PLUGIN_NAME)
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(self.mock_nsx.stop)
        self.addCleanup(patch_sync.stop)


class TestPortSecurityNSXv2(PortSecurityTestCaseNSXv2, psec.TestPortSecurity):
        pass


class TestPortSecurityNSXv3(psec.TestPortSecurity,
                            test_nsxv3.NsxV3PluginTestCaseMixin):
    def setUp(self, plugin=v3_constants.PLUGIN_NAME):
        super(TestPortSecurityNSXv3, self).setUp(plugin=plugin)
