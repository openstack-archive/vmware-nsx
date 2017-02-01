# Copyright (c) 2013 OpenStack Foundation.
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


class L3NotifyAPI(object):
    """Dummy driver for L3 notifcations - no need - no L3 agenets."""

    # We need this driver as this code is invoked from the L3 mixin code.

    def agent_updated(self, context, admin_state_up, host):
        pass

    def router_deleted(self, context, router_id):
        pass

    def routers_updated(self, context, router_ids, operation=None, data=None,
                        shuffle_agents=False, schedule_routers=True):
        pass

    def add_arp_entry(self, context, router_id, arp_table, operation=None):
        pass

    def del_arp_entry(self, context, router_id, arp_table, operation=None):
        pass

    def delete_fipnamespace_for_ext_net(self, context, ext_net_id):
        pass

    def router_removed_from_agent(self, context, router_id, host):
        pass

    def router_added_to_agent(self, context, router_ids, host):
        pass

    def routers_updated_on_host(self, context, router_ids, host):
        pass
