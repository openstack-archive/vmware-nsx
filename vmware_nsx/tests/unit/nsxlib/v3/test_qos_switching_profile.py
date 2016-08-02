# Copyright (c) 2015 VMware, Inc.
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
#
import mock

from oslo_log import log

from vmware_nsx.tests.unit.nsx_v3 import test_constants as test_constants_v3
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase

LOG = log.getLogger(__name__)


class NsxLibQosTestCase(nsxlib_testcase.NsxClientTestCase):

    def _body(self, qos_marking=None, dscp=None,
              description=test_constants_v3.FAKE_NAME):
        body = {
            "resource_type": "QosSwitchingProfile",
            "tags": []
        }
        if qos_marking:
            body = self.nsxlib._update_dscp_in_args(body, qos_marking, dscp)

        body["display_name"] = test_constants_v3.FAKE_NAME
        body["description"] = description

        return body

    def _body_with_shaping(self, shaping_enabled=False,
                           burst_size=None,
                           peak_bandwidth=None,
                           average_bandwidth=None,
                           description=test_constants_v3.FAKE_NAME,
                           qos_marking=None,
                           dscp=0):
        body = test_constants_v3.FAKE_QOS_PROFILE
        body["display_name"] = test_constants_v3.FAKE_NAME
        body["description"] = description

        for shaper in body["shaper_configuration"]:
            # Neutron currently support only shaping of Egress traffic
            if shaper["resource_type"] == "EgressRateShaper":
                shaper["enabled"] = shaping_enabled
                if burst_size:
                    shaper["burst_size_bytes"] = burst_size
                if peak_bandwidth:
                    shaper["peak_bandwidth_mbps"] = peak_bandwidth
                if average_bandwidth:
                    shaper["average_bandwidth_mbps"] = average_bandwidth
                break

        if qos_marking:
            body = self.nsxlib._update_dscp_in_args(
                body, qos_marking, dscp)

        return body

    def test_create_qos_switching_profile(self):
        """
        Test creating a qos-switching profile returns the correct response
        """

        with mock.patch.object(self.nsxlib.client, 'create') as create:
            self.nsxlib.create_qos_switching_profile(
                tags=[],
                name=test_constants_v3.FAKE_NAME,
                description=test_constants_v3.FAKE_NAME)
            create.assert_called_with(
                'switching-profiles', self._body())

    def test_update_qos_switching_profile(self):
        """
        Test updating a qos-switching profile returns the correct response
        """
        original_profile = self._body()
        new_description = "Test"
        with mock.patch.object(self.nsxlib.client, 'get',
                               return_value=original_profile):
            with mock.patch.object(self.nsxlib.client, 'update') as update:

                # update the description of the profile
                self.nsxlib.update_qos_switching_profile(
                    test_constants_v3.FAKE_QOS_PROFILE['id'],
                    tags=[],
                    description=new_description)
                update.assert_called_with(
                    'switching-profiles/%s'
                    % test_constants_v3.FAKE_QOS_PROFILE['id'],
                    self._body(description=new_description))

    def test_enable_qos_switching_profile_shaping(self):
        """
        Test updating a qos-switching profile returns the correct response
        """

        original_profile = self._body_with_shaping()
        burst_size = 100
        peak_bandwidth = 200
        average_bandwidth = 300
        qos_marking = "untrusted"
        dscp = 10

        with mock.patch.object(self.nsxlib.client, 'get',
                               return_value=original_profile):
            with mock.patch.object(self.nsxlib.client, 'update') as update:
                # update the bw shaping of the profile
                self.nsxlib.update_qos_switching_profile_shaping(
                    test_constants_v3.FAKE_QOS_PROFILE['id'],
                    shaping_enabled=True,
                    burst_size=burst_size,
                    peak_bandwidth=peak_bandwidth,
                    average_bandwidth=average_bandwidth,
                    qos_marking=qos_marking,
                    dscp=dscp)

                update.assert_called_with(
                    'switching-profiles/%s'
                    % test_constants_v3.FAKE_QOS_PROFILE['id'],
                    self._body_with_shaping(
                        shaping_enabled=True,
                        burst_size=burst_size,
                        peak_bandwidth=peak_bandwidth,
                        average_bandwidth=average_bandwidth,
                        qos_marking="untrusted", dscp=10))

    def test_disable_qos_switching_profile_shaping(self):
        """
        Test updating a qos-switching profile returns the correct response
        """
        burst_size = 100
        peak_bandwidth = 200
        average_bandwidth = 300
        original_profile = self._body_with_shaping(
            shaping_enabled=True,
            burst_size=burst_size,
            peak_bandwidth=peak_bandwidth,
            average_bandwidth=average_bandwidth,
            qos_marking="untrusted",
            dscp=10)

        with mock.patch.object(self.nsxlib.client, 'get',
                               return_value=original_profile):
            with mock.patch.object(self.nsxlib.client, 'update') as update:
                # update the bw shaping of the profile
                self.nsxlib.update_qos_switching_profile_shaping(
                    test_constants_v3.FAKE_QOS_PROFILE['id'],
                    shaping_enabled=False, qos_marking="trusted")

                update.assert_called_with(
                    'switching-profiles/%s'
                    % test_constants_v3.FAKE_QOS_PROFILE['id'],
                    self._body_with_shaping(qos_marking="trusted"))

    def test_delete_qos_switching_profile(self):
        """
        Test deleting qos-switching-profile
        """
        with mock.patch.object(self.nsxlib.client, 'delete') as delete:
            self.nsxlib.delete_qos_switching_profile(
                test_constants_v3.FAKE_QOS_PROFILE['id'])
            delete.assert_called_with(
                'switching-profiles/%s'
                % test_constants_v3.FAKE_QOS_PROFILE['id'])
