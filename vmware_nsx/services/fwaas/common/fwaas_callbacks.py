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

from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.l3 import router_info
from neutron.common import config as neutron_config  # noqa
from neutron_fwaas.db.firewall import firewall_db  # noqa
from neutron_fwaas.db.firewall import firewall_router_insertion_db \
    as fw_r_ins_db
from neutron_fwaas.services.firewall.agents.l3reference \
    import firewall_l3_agent
from neutron_lib import constants as nl_constants
from neutron_lib import context as n_context
from neutron_lib.plugins import directory

LOG = logging.getLogger(__name__)


class NsxFwaasCallbacks(firewall_l3_agent.L3WithFWaaS):
    """Common NSX RPC callbacks for Firewall As A Service - V1."""
    def __init__(self):
        # The super code needs a configuration object with the neutron host
        # and an agent_mode, which our driver doesn't use.
        neutron_conf = cfg.CONF
        neutron_conf.agent_mode = 'nsx'
        super(NsxFwaasCallbacks, self).__init__(conf=neutron_conf)

    @property
    def core_plugin(self):
        return directory.get_plugin()

    # Override functions using the agent_api that is not used by our plugin
    def _get_router_ids_for_fw(self, context, fw, to_delete=False):
        """Return the router_ids either from fw dict or tenant routers."""
        routers_in_proj = self._get_routers_in_project(
            context, fw['tenant_id'])
        if self._has_router_insertion_fields(fw):
            # it is a new version of plugin (supports specific routers)
            ids = (fw['del-router-ids'] if to_delete
                   else fw['add-router-ids'])
            project_ids = [router['id'] for router in routers_in_proj
                           if router['id'] in ids]
            if len(project_ids) < len(ids):
                # This means that there is a router from another project.
                LOG.error("Failed to attach routers from a different project "
                          "to firewall %(fw)s: %(routers)s",
                          {'fw': fw['id'],
                           'routers': list(set(ids) - set(project_ids))})
                self.fwplugin_rpc.set_firewall_status(
                    context,
                    fw['id'],
                    nl_constants.ERROR)
            return ids
        else:
            return [router['id'] for router in routers_in_proj]

    def _get_routers_in_project(self, context, project_id):
        return self.core_plugin.get_routers(
            context,
            filters={'project_id': [project_id]})

    def _router_dict_to_obj(self, r):
        # The callbacks expect a router-info object
        return router_info.RouterInfo(
            None, r['id'], router=r,
            agent_conf=None,
            interface_driver=None,
            use_ipv6=False)

    def _get_router_info_list_for_tenant(self, router_ids, tenant_id):
        """Returns the list of router info objects on which to apply the fw."""
        context = n_context.get_admin_context()
        tenant_routers = self._get_routers_in_project(context, tenant_id)
        return [self._router_dict_to_obj(ri) for ri in tenant_routers
                if ri['id'] in router_ids]

    def should_apply_firewall_to_router(self, context, router_id):
        """Return True if the FWaaS rules should be added to this router."""
        if not self.fwaas_enabled:
            return False

        ctx = context.elevated()
        fw_id = self._get_router_firewall_id(ctx, router_id)
        if fw_id is None:
            # No FWaas Firewall was assigned to this router
            return False

        # check the state of this firewall
        firewall = self._get_fw_from_plugin(ctx, fw_id)
        if firewall is not None:
            if firewall.get('status') in (nl_constants.ERROR,
                                          nl_constants.PENDING_DELETE):
                # Do not add rules of firewalls with errors
                LOG.warning("Router %(rtr)s will not get rules from firewall "
                            "%(fw)s which is in %(status)s",
                            {'rtr': router_id, 'fw': fw_id,
                             'status': firewall['status']})
                return False

        return True

    # TODO(asarfaty): add this api to fwaas firewall-router-insertion-db
    def _get_router_firewall_id(self, context, router_id):
        entry = context.session.query(
            fw_r_ins_db.FirewallRouterAssociation).filter_by(
            router_id=router_id).first()
        if entry:
            return entry.fw_id

    def _get_fw_from_plugin(self, context, fw_id):
        # NOTE(asarfaty): currently there is no api to get a specific firewall
        fw_list = self.fwplugin_rpc.get_firewalls_for_tenant(context)
        for fw in fw_list:
            if fw['id'] == fw_id:
                return fw
