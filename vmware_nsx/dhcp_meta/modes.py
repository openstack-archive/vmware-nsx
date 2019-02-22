# Copyright 2013 VMware, Inc.
#
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
#

import weakref

from neutron_lib.agent import topics
from neutron_lib.api.definitions import agent as agent_apidef
from neutron_lib.api.definitions import dhcpagentscheduler
from neutron_lib import constants as const
from neutron_lib import rpc as n_rpc
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.db import agents_db

from vmware_nsx._i18n import _
from vmware_nsx.common import config
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.dhcp_meta import combined
from vmware_nsx.dhcp_meta import lsnmanager
from vmware_nsx.dhcp_meta import migration
from vmware_nsx.dhcp_meta import nsx as nsx_svc
from vmware_nsx.dhcp_meta import rpc as nsx_rpc
from vmware_nsx.extensions import lsn

LOG = logging.getLogger(__name__)


class SynchronizedDhcpRpcCallback(dhcp_rpc.DhcpRpcCallback):
    """DHCP RPC callbakcs synchronized with VMware plugin mutex."""

    @lockutils.synchronized('vmware', 'neutron-')
    def create_dhcp_port(self, context, **kwargs):
        return super(SynchronizedDhcpRpcCallback, self).create_dhcp_port(
            context, **kwargs)


class DhcpMetadataAccess(object):

    def setup_dhcpmeta_access(self):
        """Initialize support for DHCP and Metadata services."""
        self._init_extensions()
        if cfg.CONF.NSX.agent_mode == config.AgentModes.AGENT:
            self._setup_rpc_dhcp_metadata()
            mod = nsx_rpc
        elif cfg.CONF.NSX.agent_mode == config.AgentModes.AGENTLESS:
            self._setup_nsx_dhcp_metadata()
            mod = nsx_svc
        elif cfg.CONF.NSX.agent_mode == config.AgentModes.COMBINED:
            notifier = self._setup_nsx_dhcp_metadata()
            self._setup_rpc_dhcp_metadata(notifier=notifier)
            mod = combined
        else:
            error = _("Invalid agent_mode: %s") % cfg.CONF.NSX.agent_mode
            LOG.error(error)
            raise nsx_exc.NsxPluginException(err_msg=error)
        self.handle_network_dhcp_access_delegate = (
            mod.handle_network_dhcp_access
        )
        self.handle_port_dhcp_access_delegate = (
            mod.handle_port_dhcp_access
        )
        self.handle_port_metadata_access_delegate = (
            mod.handle_port_metadata_access
        )
        self.handle_metadata_access_delegate = (
            mod.handle_router_metadata_access
        )

    def _setup_rpc_dhcp_metadata(self, notifier=None):
        self.topic = topics.PLUGIN
        self.conn = n_rpc.Connection()
        self.endpoints = [SynchronizedDhcpRpcCallback(),
                          agents_db.AgentExtRpcCallback(),
                          metadata_rpc.MetadataRpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        self.conn.create_consumer(topics.REPORTS,
                                  [agents_db.AgentExtRpcCallback()],
                                  fanout=False)
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            notifier or dhcp_rpc_agent_api.DhcpAgentNotifyAPI())
        self.conn.consume_in_threads()
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )
        self.supported_extension_aliases.extend(
            [agent_apidef.ALIAS, dhcpagentscheduler.ALIAS])

    def _setup_nsx_dhcp_metadata(self):
        self._check_services_requirements()
        nsx_svc.register_dhcp_opts(cfg)
        nsx_svc.register_metadata_opts(cfg)
        lsnmanager.register_lsn_opts(cfg)
        lsn_manager = lsnmanager.PersistentLsnManager(weakref.proxy(self))
        self.lsn_manager = lsn_manager
        if cfg.CONF.NSX.agent_mode == config.AgentModes.AGENTLESS:
            notifier = nsx_svc.DhcpAgentNotifyAPI(weakref.proxy(self),
                                                  lsn_manager)
            self.agent_notifiers[const.AGENT_TYPE_DHCP] = notifier
            # In agentless mode, ports whose owner is DHCP need to
            # be special cased; so add it to the list of special
            # owners list
            if const.DEVICE_OWNER_DHCP not in self.port_special_owners:
                self.port_special_owners.append(const.DEVICE_OWNER_DHCP)
        elif cfg.CONF.NSX.agent_mode == config.AgentModes.COMBINED:
            # This becomes ineffective, as all new networks creations
            # are handled by Logical Services Nodes in NSX
            cfg.CONF.set_override('network_auto_schedule', False)
            LOG.warning('network_auto_schedule has been disabled')
            notifier = combined.DhcpAgentNotifyAPI(weakref.proxy(self),
                                                   lsn_manager)
            self.supported_extension_aliases.append(lsn.ALIAS)
            # Add the capability to migrate dhcp and metadata services over
            self.migration_manager = (
                migration.MigrationManager(
                    weakref.proxy(self), lsn_manager, notifier))
        return notifier

    def _init_extensions(self):
        extensions = (lsn.ALIAS, agent_apidef.ALIAS,
                      dhcpagentscheduler.ALIAS)
        for ext in extensions:
            if ext in self.supported_extension_aliases:
                self.supported_extension_aliases.remove(ext)

    def _check_services_requirements(self):
        try:
            error = None
            nsx_svc.check_services_requirements(self.cluster)
        except nsx_exc.InvalidVersion:
            error = _("Unable to run Neutron with config option '%s', as NSX "
                      "does not support it") % cfg.CONF.NSX.agent_mode
        except nsx_exc.ServiceClusterUnavailable:
            error = _("Unmet dependency for config option "
                      "'%s'") % cfg.CONF.NSX.agent_mode
        if error:
            LOG.error(error)
            raise nsx_exc.NsxPluginException(err_msg=error)

    def get_lsn(self, context, network_id, fields=None):
        report = self.migration_manager.report(context, network_id)
        return {'network': network_id, 'report': report}

    def create_lsn(self, context, lsn):
        network_id = lsn['lsn']['network']
        subnet = self.migration_manager.validate(context, network_id)
        subnet_id = None if not subnet else subnet['id']
        self.migration_manager.migrate(context, network_id, subnet)
        r = self.migration_manager.report(context, network_id, subnet_id)
        return {'network': network_id, 'report': r}

    def handle_network_dhcp_access(self, context, network, action):
        self.handle_network_dhcp_access_delegate(weakref.proxy(self), context,
                                                 network, action)

    def handle_port_dhcp_access(self, context, port_data, action):
        self.handle_port_dhcp_access_delegate(weakref.proxy(self), context,
                                              port_data, action)

    def handle_port_metadata_access(self, context, port, is_delete=False):
        self.handle_port_metadata_access_delegate(weakref.proxy(self), context,
                                                  port, is_delete)

    def handle_router_metadata_access(self, context,
                                      router_id, interface=None):
        self.handle_metadata_access_delegate(weakref.proxy(self), context,
                                             router_id, interface)
