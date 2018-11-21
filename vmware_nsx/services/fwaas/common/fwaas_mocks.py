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

# This file contains FWaaS mocks, to allow the vmware nsx plugins to work when
# FWaaS code does not exist, and FWaaS is not configured in neutron

FIREWALL_V2 = 'FIREWALL_V2'


class L3WithFWaaS(object):
    def __init__(self, **kwargs):
        self.fwaas_enabled = False


class FwaasDriverBase(object):
    pass


class FirewallPluginV2(object):
    pass


class FirewallCallbacks(object):
    pass
