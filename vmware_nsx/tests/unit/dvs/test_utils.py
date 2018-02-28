# Copyright (c) 2014 VMware.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
from oslo_config import cfg
from oslo_vmware import api

from neutron.tests import base
from vmware_nsx.dvs import dvs_utils


class DvsUtilsTestCase(base.BaseTestCase):

    def test_default_configuration(self):
        self.assertFalse(dvs_utils.dvs_is_enabled())

    def _dvs_fake_cfg_set(self):
        cfg.CONF.set_override('host_ip', 'fake_host_ip',
                              group='dvs')
        cfg.CONF.set_override('host_username', 'fake_host_user_name',
                              group='dvs')
        cfg.CONF.set_override('host_password', 'fake_host_password',
                              group='dvs')
        cfg.CONF.set_override('dvs_name', 'fake_dvs', group='dvs')
        cfg.CONF.set_override('host_port', '443', group='dvs')
        cfg.CONF.set_override('ca_file', 'cacert', group='dvs')
        cfg.CONF.set_override('insecure', False, group='dvs')

    def test_dvs_set(self):
        self._dvs_fake_cfg_set()
        self.assertTrue(dvs_utils.dvs_is_enabled())

    @mock.patch.object(api.VMwareAPISession, '__init__',
                       return_value=None)
    def test_dvs_create_session(self, fake_init):
        dvs_utils.dvs_create_session()
        fake_init.assert_called_once_with(cfg.CONF.dvs.host_ip,
                                          cfg.CONF.dvs.host_username,
                                          cfg.CONF.dvs.host_password,
                                          cfg.CONF.dvs.api_retry_count,
                                          cfg.CONF.dvs.task_poll_interval,
                                          port=cfg.CONF.dvs.host_port,
                                          cacert=cfg.CONF.dvs.ca_file,
                                          insecure=cfg.CONF.dvs.insecure)

    def test_dvs_name_get(self):
        cfg.CONF.set_override('dvs_name', 'fake-dvs', group='dvs')
        self.assertEqual('fake-dvs',
                         dvs_utils.dvs_name_get())
