# Copyright 2017 VMware Inc
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

from tempest.lib import decorators

from vmware_nsx_tempest.lib import heat


class HeatTest(heat.HeatSmokeTest):
    """
     Deploy and Test Neutron Resources using HEAT.

     The script loads the neutron resources from template and fully
    validates successful deployment of all resources from the template.

    """

    @decorators.idempotent_id('fcc70627-dee0-466a-a59c-ae844a7ec59d')
    def test_topo1_created_resources(self):
        """Verifies created resources from template ."""
        self.check_created_resources()

    @decorators.idempotent_id('ed1e9058-88b6-417e-bfa1-12531fa16cd0')
    def test_topo1_created_network(self):
        """Verifies created neutron networks."""
        self.check_created_network()

    @decorators.idempotent_id('58a1f904-18c6-43b3-8d7b-c1246b65ac1b')
    def test_topo1_created_router(self):
        """Verifies created router."""
        self.check_created_router()

    @decorators.idempotent_id('dece79ae-03e8-4d77-9484-5552a1f23412')
    def test_topo1_created_server(self):
        """Verifies created sever."""
        self.check_created_server()

    @decorators.idempotent_id('6e6cc35c-d58c-490c-ad88-f085c260bc73')
    def test_topo1_same_network(self):
        """Verifies same network connnectivity for Topology 1 """
        self.check_topo1_same_network_connectivity()

    @decorators.idempotent_id('1ae85f38-c78a-43ca-9b39-278131907681')
    def test_topo1_cross_network(self):
        """Verifies cross network connnectivity for Topology 1 """
        self.check_topo1_cross_network_connectivity()
