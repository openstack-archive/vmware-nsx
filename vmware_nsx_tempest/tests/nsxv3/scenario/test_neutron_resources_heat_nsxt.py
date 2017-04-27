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

    @decorators.idempotent_id('cb772c73-5948-4bd3-91d1-d85af2577362')
    def test_topo1_created_resources(self):
        """Verifies created resources from template ."""
        self.check_created_resources()

    @decorators.idempotent_id('4f4cb71e-404f-4810-8898-5d6d70650016')
    def test_topo1_created_network(self):
        """Verifies created neutron networks."""
        self.check_created_network()

    @decorators.idempotent_id('7e6452de-62c1-4daf-a031-013889b1d4ba')
    def test_topo1_created_router(self):
        """Verifies created router."""
        self.check_created_router()

    @decorators.idempotent_id('24a3c0f8-3482-47fe-8c80-561a264a66d0')
    def test_topo1_created_server(self):
        """Verifies created sever."""
        self.check_created_server()

    @decorators.idempotent_id('1fc3b998-d730-4f90-8ad2-bc4f2eeb7157')
    def test_topo1_same_network(self):
        """Verifies same network connnectivity for Topology 1 """
        self.check_topo1_same_network_connectivity()

    @decorators.idempotent_id('aec9b109-2501-41de-9a24-444ced8b2668')
    def test_topo1_cross_network(self):
        """Verifies cross network connnectivity for Topology 1 """
        self.check_topo1_cross_network_connectivity()
