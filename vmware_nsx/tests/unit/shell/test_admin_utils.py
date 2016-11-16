# Copyright 2015 VMware, Inc.
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

import abc
import logging
import mock
import six

from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.callbacks import registry
from neutron.common import config as neutron_config
from neutron.db import servicetype_db  # noqa
from neutron.quota import resource_registry
from neutron.tests import base
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_n_plugin

from vmware_nsx._i18n import _
from vmware_nsx.common import config  # noqa
from vmware_nsx.nsxlib.v3 import resources as nsx_v3_resources
from vmware_nsx.shell import resources
from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.nsx_v.vshield import fake_vcns
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_v3_plugin

LOG = logging.getLogger(__name__)
NSX_INI_PATH = vmware.get_fake_conf('nsx.ini.test')
BASE_CONF_PATH = vmware.get_fake_conf('neutron.conf.test')


@six.add_metaclass(abc.ABCMeta)
class AbstractTestAdminUtils(base.BaseTestCase):

    def setUp(self):
        cfg.CONF.register_cli_opts(resources.cli_opts)

        super(AbstractTestAdminUtils, self).setUp()

        # remove resource registration conflicts
        resource_registry.unregister_all_resources()

        # Init the neutron config
        neutron_config.init(args=['--config-file', BASE_CONF_PATH,
                                  '--config-file', NSX_INI_PATH])
        self._init_mock_plugin()
        self._init_resource_plugin()
        self.addCleanup(resource_registry.unregister_all_resources)

    @abc.abstractmethod
    def _init_mock_plugin(self):
        pass

    @abc.abstractmethod
    def _get_plugin_name(self):
        pass

    def _init_resource_plugin(self):
        plugin_name = self._get_plugin_name()
        resources.init_resource_plugin(
            plugin_name,
            resources.get_plugin_dir(plugin_name))

    def _test_resource(self, res_name, op, **kwargs):
        errors = self._test_resource_with_errors(res_name, op, **kwargs)
        if len(errors) > 0:
            msg = (_("admin util %(res)s/%(op)s failed with message: "
                     "%(err)s") % {'res': res_name,
                                   'op': op,
                                   'err': errors[0]})
            self.fail(msg=msg)

    def _test_resource_with_errors(self, res_name, op, **kwargs):
        # Must call the internal notify_loop in order to get the errors
        return registry._get_callback_manager()._notify_loop(
            res_name, op, 'nsxadmin', **kwargs)

    def _test_resources(self, res_dict):
        for res in res_dict.keys():
            res_name = res_dict[res].name
            for op in res_dict[res].supported_ops:
                self._test_resource(res_name, op)


class TestNsxvAdminUtils(AbstractTestAdminUtils,
                         test_n_plugin.NeutronDbPluginV2TestCase):

    def _init_mock_plugin(self):
        mock_vcns = mock.patch(vmware.VCNS_NAME, autospec=True)
        mock_vcns_instance = mock_vcns.start()
        self.fc = fake_vcns.FakeVcns()
        mock_vcns_instance.return_value = self.fc

        self.addCleanup(self.fc.reset_all)

    def _get_plugin_name(self):
        return 'nsxv'

    def test_nsxv_resources(self):
        self._test_resources(resources.nsxv_resources)

    # This is an example how to test a specific utility with arguments
    def test_with_args(self):
        args = {'property': ["xxx=yyy"]}
        self._test_resource('networks', 'list', **args)

    def test_bad_args(self):
        args = {'property': ["xxx"]}
        errors = self._test_resource_with_errors(
            'networks', 'nsx-update', **args)
        self.assertEqual(1, len(errors))


class TestNsxv3AdminUtils(AbstractTestAdminUtils,
                          test_v3_plugin.NsxV3PluginTestCaseMixin):

    def _patch_object(self, *args, **kwargs):
        patcher = mock.patch.object(*args, **kwargs)
        patcher.start()
        self._patchers.append(patcher)

    def _init_mock_plugin(self):
        test_v3_plugin._mock_nsx_backend_calls()

        # mock resources
        self._patch_object(nsx_v3_resources.LogicalPort,
                           '__init__', return_value=None)
        self._patch_object(nsx_v3_resources.LogicalDhcpServer,
                           '__init__', return_value=None)
        self._patch_object(nsx_v3_resources.LogicalDhcpServer,
                           'list', return_value={'results': []})
        self._patch_object(nsx_v3_resources.LogicalRouter,
                           '__init__', return_value=None)
        self._patch_object(nsx_v3_resources.SwitchingProfile,
                           '__init__', return_value=None)
        self._patch_object(nsx_v3_resources.SwitchingProfile,
                           'find_by_display_name',
                           return_value=[{'id': uuidutils.generate_uuid()}])
        self._patch_object(nsx_v3_resources.LogicalRouterPort,
                           '__init__', return_value=None)

    def _get_plugin_name(self):
        return 'nsxv3'

    def test_nsxv3_resources(self):
        self._test_resources(resources.nsxv3_resources)
