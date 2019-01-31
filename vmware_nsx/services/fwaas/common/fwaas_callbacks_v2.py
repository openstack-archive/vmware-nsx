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

from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.l3 import router_info
from neutron.common import config as neutron_config  # noqa
from neutron_lib import constants as nl_constants
from neutron_lib import context as n_context
from neutron_lib.plugins import directory

LOG = logging.getLogger(__name__)

try:
    from neutron_fwaas.db.firewall.v2 import firewall_db_v2
    from neutron_fwaas.services.firewall.service_drivers.agents.l3reference \
        import firewall_l3_agent_v2
except ImportError:
    # FWaaS project no found
    from vmware_nsx.services.fwaas.common import fwaas_mocks \
        as firewall_l3_agent_v2


class DummyAgentApi(object):
    def is_router_in_namespace(self, router_id):
        return True


class NsxFwaasCallbacksV2(firewall_l3_agent_v2.L3WithFWaaS):
    """Common NSX RPC callbacks for Firewall As A Service - V2."""
    def __init__(self, with_rpc):
        # The super code needs a configuration object with the neutron host
        # and an agent_mode, which our driver doesn't use.
        neutron_conf = cfg.CONF
        neutron_conf.agent_mode = 'nsx'
        self.with_rpc = with_rpc
        super(NsxFwaasCallbacksV2, self).__init__(conf=neutron_conf)
        self.agent_api = DummyAgentApi()
        self.core_plugin = self._get_core_plugin()

    def start_rpc_listeners(self, host, conf):
        # Make sure RPC queue will be created only when needed
        if not self.with_rpc:
            return
        return super(NsxFwaasCallbacksV2, self).start_rpc_listeners(host, conf)

    @property
    def plugin_type(self):
        pass

    def _get_core_plugin(self):
        """Get the NSX core plugin"""
        core_plugin = directory.get_plugin()
        if core_plugin.is_tvd_plugin():
            # get the plugin that match this driver
            core_plugin = core_plugin.get_plugin_by_type(
                self.plugin_type)
        return core_plugin

    # Override functions using the agent_api that is not used by our plugin
    def _get_firewall_group_ports(self, context, firewall_group,
            to_delete=False, require_new_plugin=False):
        """Returns in-namespace ports, either from firewall group dict if newer
           version of plugin or from project routers otherwise.

           NOTE: Vernacular move from "tenant" to "project" doesn't yet appear
           as a key in router or firewall group objects.
        """
        fwg_port_ids = []
        if self._has_port_insertion_fields(firewall_group):
            if to_delete:
                fwg_port_ids = firewall_group['del-port-ids']
            else:
                fwg_port_ids = firewall_group['add-port-ids']
            if (not firewall_group.get('del-port-ids') and
                not firewall_group.get('add-port-ids') and
                firewall_group.get('ports')):
                # No change in ports, but policy changed so all ports are
                # relevant
                fwg_port_ids = firewall_group['ports']
                # Mark to the driver that this is not port deletion
                firewall_group['last-port'] = False
        elif not require_new_plugin:
            routers = self._get_routers_in_project(
                    context, firewall_group['tenant_id'])
            for router in routers:
                if router.router['tenant_id'] == firewall_group['tenant_id']:
                    fwg_port_ids.extend([p['id'] for p in
                            router.internal_ports])

        # Return in-namespace port objects.
        ports = self._get_in_ns_ports(fwg_port_ids, ignore_errors=to_delete)
        # On illegal ports - change FW status to Error
        if ports is None:
            self.fwplugin_rpc.set_firewall_group_status(
                context,
                firewall_group['id'],
                nl_constants.ERROR)
        return ports

    def _get_in_ns_ports(self, port_ids, ignore_errors=False):
        """Returns port objects in the local namespace, along with their
           router_info.
        """
        context = n_context.get_admin_context()
        in_ns_ports = {}  # This will be converted to a list later.
        for port_id in port_ids:
            # find the router of this port:
            port = self.core_plugin.get_port(context, port_id)
            # verify that this is a router interface port
            if port['device_owner'] != nl_constants.DEVICE_OWNER_ROUTER_INTF:
                if not ignore_errors:
                    LOG.error("NSX-V3 FWaaS V2 plugin does not support %s "
                              "ports", port['device_owner'])
                    return
                # since this is a deletion of an illegal port, add this port
                # with a dummy router so that the FWaaS plugin will notice the
                # change and change the FW status.
                router_info = 'Dummy'
            else:
                router_id = port['device_id']
                router = self.core_plugin.get_router(context, router_id)
                router_info = self._router_dict_to_obj(router)
            if router_info:
                if router_info in in_ns_ports:
                    in_ns_ports[router_info].append(port_id)
                else:
                    in_ns_ports[router_info] = [port_id]
        return list(in_ns_ports.items())

    def delete_firewall_group(self, context, firewall_group, host):
        """Handles RPC from plugin to delete a firewall group.

        This method is overridden here in order to handle routers
        in Error state without ports, and make sure those are deleted.
        """

        ports_for_fwg = self._get_firewall_group_ports(
            context, firewall_group, to_delete=True)
        if not ports_for_fwg:
            # FW without ports should be deleted without calling the driver
            self.fwplugin_rpc.firewall_group_deleted(
                context, firewall_group['id'])
            return

        return super(NsxFwaasCallbacksV2, self).delete_firewall_group(
            context, firewall_group, host)

    def _get_routers_in_project(self, context, project_id):
        return self.core_plugin.get_routers(
            context,
            filters={'project_id': [project_id]})

    def _router_dict_to_obj(self, r):
        # The callbacks expect a router-info object with an agent config
        agent_conf = cfg.CONF
        agent_conf.metadata_access_mark = '0x1'
        return router_info.RouterInfo(
            None, r['id'], router=r,
            agent_conf=agent_conf,
            interface_driver=None,
            use_ipv6=False)

    def get_port_fwg(self, context, port_id):
        """Return the firewall group of this port

        if the FWaaS rules should be added to the backend router.
        """
        if not self.fwaas_enabled:
            return False

        ctx = context.elevated()
        fwg_id = self._get_port_firewall_group_id(ctx, port_id)
        if fwg_id is None:
            # No FWaas Firewall was assigned to this port
            return

        # check the state of this firewall group
        fwg = self._get_fw_group_from_plugin(ctx, fwg_id)
        if fwg is not None:
            if fwg.get('status') in (nl_constants.ERROR,
                                     nl_constants.PENDING_DELETE):
                # Do not add rules of firewalls with errors
                LOG.warning("Port %(port)s will not get rules from firewall "
                            "group %(fwg)s which is in %(status)s",
                            {'port': port_id, 'fwg': fwg_id,
                             'status': fwg['status']})
                return

        return fwg

    def _get_fw_group_from_plugin(self, context, fwg_id):
        # NOTE(asarfaty): currently there is no api to get a specific firewall
        fwg_list = self.fwplugin_rpc.get_firewall_groups_for_project(context)
        for fwg in fwg_list:
            if fwg['id'] == fwg_id:
                return fwg

    # TODO(asarfaty): add this api to fwaas firewall_db_v2
    def _get_port_firewall_group_id(self, context, port_id):
        entry = context.session.query(
            firewall_db_v2.FirewallGroupPortAssociation).filter_by(
            port_id=port_id).first()
        if entry:
            return entry.firewall_group_id

    def should_apply_firewall_to_router(self, context, router_id):
        """Return True if there are FWaaS rules that are attached to an
        interface of the given router.
        """
        if not self.fwaas_enabled:
            return False

        ctx = context.elevated()
        router_interfaces = self.core_plugin._get_router_interfaces(
            ctx, router_id)
        for port in router_interfaces:
            fwg_id = self._get_port_firewall_group_id(ctx, port['id'])
            if fwg_id:
                # check the state of this firewall group
                fwg = self._get_fw_group_from_plugin(ctx, fwg_id)
                if fwg is not None:
                    if fwg.get('status') not in (nl_constants.ERROR,
                                                 nl_constants.PENDING_DELETE):
                        # Found a router interface port with rules
                        return True
        return False

    def delete_port(self, context, port_id):
        # Mark the FW group as inactive if this is the last port
        fwg = self.get_port_fwg(context, port_id)
        if (fwg and fwg.get('status') == nl_constants.ACTIVE and
            len(fwg.get('ports', [])) <= 1):
            self.fwplugin_rpc.set_firewall_group_status(
                context, fwg['id'], nl_constants.INACTIVE)


class NsxCommonv3FwaasCallbacksV2(NsxFwaasCallbacksV2):
    """NSX-V3+Policy RPC callbacks for Firewall As A Service - V2."""

    def should_apply_firewall_to_router(self, context, router_id):
        """Return True if the FWaaS rules should be added to this router."""
        if not super(NsxCommonv3FwaasCallbacksV2,
                     self).should_apply_firewall_to_router(context,
                                                           router_id):
            return False

        # get all the relevant router info
        ctx_elevated = context.elevated()
        router_data = self.core_plugin.get_router(ctx_elevated, router_id)
        if not router_data:
            LOG.error("Couldn't read router %s data", router_id)
            return False

        # Check if the FWaaS driver supports this router
        if not self.internal_driver.should_apply_firewall_to_router(
            router_data):
            return False

        return True

    def router_with_fwg(self, context, router_interfaces):
        for port in router_interfaces:
            fwg = self.get_port_fwg(context, port['id'])
            if fwg and fwg.get('status') == nl_constants.ACTIVE:
                return True
        return False
