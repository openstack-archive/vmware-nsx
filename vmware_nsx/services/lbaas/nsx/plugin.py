# Copyright 2017 VMware, Inc.
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
from neutron_lib import exceptions

from neutron_lbaas.services.loadbalancer import plugin
from vmware_nsx.db import db as nsx_db


class LoadBalancerTVDPluginv2(plugin.LoadBalancerPluginv2):

    def _get_project_mapping(self, context, filters):
        project_id = context.project_id
        if filters:
            if filters.get('tenant_id'):
                project_id = filters.get('tenant_id')
            elif filters.get('project_id'):
                project_id = filters.get('project_id')
            # If multiple are requested then we revert to
            # the context's project id
            if isinstance(project_id, list):
                project_id = context.project_id
        mapping = nsx_db.get_project_plugin_mapping(
                context.session, project_id)
        if mapping:
            return mapping['plugin']
        else:
            raise exceptions.ObjectNotFound(id=project_id)

    def _filter_entries(self, method, context, filters=None, fields=None):
        req_p = self._get_project_mapping(context, filters)
        entries = method(context, filters=filters, fields=fields)
        for entry in entries[:]:
            p = self._get_project_mapping(context,
                                          entry['tenant_id'])
            if p != req_p:
                entries.remove(entry)
        return entries

    def get_loadbalancers(self, context, filters=None, fields=None):
        return self._filter_entries(
            super(LoadBalancerTVDPluginv2, self).get_loadbalancers,
            context, filters=filters, fields=fields)

    def get_listeners(self, context, filters=None, fields=None):
        return self._filter_entries(
            super(LoadBalancerTVDPluginv2, self).get_listeners,
            context, filters=filters, fields=fields)

    def get_pools(self, context, filters=None, fields=None):
        return self._filter_entries(
            super(LoadBalancerTVDPluginv2, self).get_pools,
            context, filters=filters, fields=fields)

    def get_healthmonitors(self, context, filters=None, fields=None):
        return self._filter_entries(
            super(LoadBalancerTVDPluginv2, self).get_healthmonitors,
            context, filters=filters, fields=fields)

    def get_l7policies(self, context, filters=None, fields=None):
        return self._filter_entries(
            super(LoadBalancerTVDPluginv2, self).get_l7policies,
            context, filters=filters, fields=fields)
