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

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

from tempest.api.network import base
from tempest import config
from tempest import test

CONF = config.CONF


class MultipleTransportZonesNegativeTest(base.BaseAdminNetworkTest):

    @classmethod
    def skip_checks(cls):
        super(MultipleTransportZonesNegativeTest, cls).skip_checks()
        if not hasattr(CONF.nsxv, 'vdn_scope_id'):
            msg = "Testbed Network & Security vdn_scope_id not specified."
            raise cls.skipException(msg)

    def create_mtz_networks(self, networks_client=None, scope_id=None):
        networks_client = networks_client or self.admin_networks_client
        scope_id = scope_id or CONF.nsxv.vdn_scope_id
        network_name = data_utils.rand_name('mtz-negative-')
        create_kwargs = {'provider:network_type': 'vxlan',
                         'provider:physical_network': scope_id}
        resp = networks_client.create_network(name=network_name,
                                              **create_kwargs)
        network = resp['network'] if 'network' in resp else resp
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        networks_client.delete_network,
                        network['id'])
        return network

    @test.attr(type=['negative'])
    @test.idempotent_id('8aff7abc-eacd-409c-8278-4cb7bde6da84')
    def test_create_mtz_networks(self):
        # Multiple Transport Zone use provier network to implement
        # its TZ allocation.
        # Only admin client can create MTZ networks.
        # non-admin client can not create mtz network
        self.assertRaises(lib_exc.Forbidden,
                          self.create_mtz_networks,
                          networks_client=self.networks_client)
