# Copyright 2017 VMware, Inc.
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

from neutron_dynamic_routing.db import bgp_db
from neutron_dynamic_routing.extensions import bgp as bgp_ext
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context as n_context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from oslo_log import log as logging

from vmware_nsx.common import locking
from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import nsxv_db
from vmware_nsx.extensions import edge_service_gateway_bgp_peer as ext_esg
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.services.dynamic_routing.nsx_v import driver as nsxv_driver

LOG = logging.getLogger(__name__)
PLUGIN_NAME = bgp_ext.BGP_EXT_ALIAS + '_nsx_svc_plugin'


class NSXBgpPlugin(service_base.ServicePluginBase, bgp_db.BgpDbMixin):
    """BGP service plugin for NSX-V as well as TVD plugins.

    Currently only the nsx-v is supported. other plugins will be refused.
    """

    supported_extension_aliases = [bgp_ext.BGP_EXT_ALIAS,
                                   ext_esg.ALIAS]

    def __init__(self):
        super(NSXBgpPlugin, self).__init__()
        self._core_plugin = directory.get_plugin()

        # initialize the supported drivers (currently only NSX-v)
        self.drivers = {}
        try:
            self.drivers[projectpluginmap.NsxPlugins.NSX_V] = (
                nsxv_driver.NSXvBgpDriver(self))
        except Exception:
            # No driver found
            LOG.warning("NSXBgpPlugin failed to initialize the NSX-V driver")
            self.drivers[projectpluginmap.NsxPlugins.NSX_V] = None

        self._register_callbacks()

    def get_plugin_name(self):
        return PLUGIN_NAME

    def get_plugin_type(self):
        return bgp_ext.BGP_EXT_ALIAS

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("BGP dynamic routing service for announcement of next-hops "
                "for project networks, floating IP's, and DVR host routes.")

    def _register_callbacks(self):
        registry.subscribe(self.router_interface_callback,
                           resources.ROUTER_INTERFACE,
                           events.AFTER_CREATE)
        registry.subscribe(self.router_interface_callback,
                           resources.ROUTER_INTERFACE,
                           events.AFTER_DELETE)
        registry.subscribe(self.router_gateway_callback,
                           resources.ROUTER_GATEWAY,
                           events.AFTER_UPDATE)
        registry.subscribe(self.router_gateway_callback,
                           resources.ROUTER_GATEWAY,
                           events.AFTER_DELETE)
        registry.subscribe(self._after_service_edge_create_callback,
                           nsxv_constants.SERVICE_EDGE,
                           events.AFTER_CREATE)
        registry.subscribe(self._before_service_edge_delete_callback,
                           nsxv_constants.SERVICE_EDGE,
                           events.BEFORE_DELETE)

    def _get_driver_by_project(self, context, project):
        # Check if the current project id has a matching driver
        # Currently only NSX-V is supported
        if self._core_plugin.is_tvd_plugin():
            plugin_type = self._core_plugin.get_plugin_type_from_project(
                context, project)
        else:
            plugin_type = self._core_plugin.plugin_type()

        if not self.drivers.get(plugin_type):
            msg = (_("Project %(project)s with plugin %(plugin)s has no "
                     "support for dynamic routing") % {
                'project': project,
                'plugin': plugin_type})
            raise n_exc.InvalidInput(error_message=msg)

        return self.drivers[plugin_type]

    def _get_driver_by_speaker(self, context, bgp_speaker_id):
        try:
            speaker = self.get_bgp_speaker(context, bgp_speaker_id)
        except Exception:
            msg = _("BGP speaker %s could not be found") % bgp_speaker_id
            raise n_exc.BadRequest(resource=bgp_ext.BGP_SPEAKER_RESOURCE_NAME,
                                   msg=msg)
        return self._get_driver_by_project(context, speaker['tenant_id'])

    def create_bgp_speaker(self, context, bgp_speaker):
        driver = self._get_driver_by_project(
            context, bgp_speaker['bgp_speaker']['tenant_id'])
        driver.create_bgp_speaker(context, bgp_speaker)
        return super(NSXBgpPlugin, self).create_bgp_speaker(context,
                                                            bgp_speaker)

    def update_bgp_speaker(self, context, bgp_speaker_id, bgp_speaker):
        driver = self._get_driver_by_speaker(context, bgp_speaker_id)
        with locking.LockManager.get_lock(str(bgp_speaker_id)):
            driver.update_bgp_speaker(context, bgp_speaker_id, bgp_speaker)
            # TBD(roeyc): rolling back changes on edges base class call failed.
            return super(NSXBgpPlugin, self).update_bgp_speaker(
                context, bgp_speaker_id, bgp_speaker)

    def delete_bgp_speaker(self, context, bgp_speaker_id):
        driver = self._get_driver_by_speaker(context, bgp_speaker_id)
        with locking.LockManager.get_lock(str(bgp_speaker_id)):
            driver.delete_bgp_speaker(context, bgp_speaker_id)
            super(NSXBgpPlugin, self).delete_bgp_speaker(context,
                                                         bgp_speaker_id)

    def _add_esg_peer_info(self, context, peer):
        # TODO(asarfaty): only if nsxv driver, or do it in the driver itself
        binding = nsxv_db.get_nsxv_bgp_peer_edge_binding(context.session,
                                                         peer['id'])
        if binding:
            peer['esg_id'] = binding['edge_id']

    def get_bgp_peer(self, context, bgp_peer_id, fields=None):
        peer = super(NSXBgpPlugin, self).get_bgp_peer(context,
                                                      bgp_peer_id, fields)
        if not fields or 'esg_id' in fields:
            self._add_esg_peer_info(context, peer)
        return peer

    def get_bgp_peers_by_bgp_speaker(self, context,
                                     bgp_speaker_id, fields=None):
        ret = super(NSXBgpPlugin, self).get_bgp_peers_by_bgp_speaker(
            context, bgp_speaker_id, fields=fields)
        if fields is None or 'esg_id' in fields:
            for peer in ret:
                self._add_esg_peer_info(context, peer)
        return ret

    def _get_driver_by_peer(self, context, bgp_peer_id):
        try:
            peer = self.get_bgp_peer(context, bgp_peer_id)
        except Exception:
            raise bgp_ext.BgpPeerNotFound(id=bgp_peer_id)
        return self._get_driver_by_project(context, peer['tenant_id'])

    def create_bgp_peer(self, context, bgp_peer):
        driver = self._get_driver_by_project(
            context, bgp_peer['bgp_peer']['tenant_id'])
        driver.create_bgp_peer(context, bgp_peer)
        peer = super(NSXBgpPlugin, self).create_bgp_peer(context, bgp_peer)
        # TODO(asarfaty): only if nsxv driver, or do it in the driver itself
        esg_id = bgp_peer['bgp_peer'].get('esg_id')
        if esg_id:
            nsxv_db.add_nsxv_bgp_peer_edge_binding(context.session, peer['id'],
                                                   esg_id)
            peer['esg_id'] = esg_id
        return peer

    def update_bgp_peer(self, context, bgp_peer_id, bgp_peer):
        driver = self._get_driver_by_peer(context, bgp_peer_id)
        super(NSXBgpPlugin, self).update_bgp_peer(context,
                                                  bgp_peer_id, bgp_peer)
        driver.update_bgp_peer(context, bgp_peer_id, bgp_peer)
        return self.get_bgp_peer(context, bgp_peer_id)

    def delete_bgp_peer(self, context, bgp_peer_id):
        driver = self._get_driver_by_peer(context, bgp_peer_id)
        bgp_peer_info = {'bgp_peer_id': bgp_peer_id}
        bgp_speaker_ids = driver._get_bgp_speakers_by_bgp_peer(
            context, bgp_peer_id)
        for speaker_id in bgp_speaker_ids:
            try:
                self.remove_bgp_peer(context, speaker_id, bgp_peer_info)
            except bgp_ext.BgpSpeakerPeerNotAssociated:
                LOG.debug("Couldn't find bgp speaker %s peer binding while "
                          "deleting bgp peer %s", speaker_id, bgp_peer_id)
        super(NSXBgpPlugin, self).delete_bgp_peer(context, bgp_peer_id)

    def add_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        # speaker & peer must belong to the same driver
        if not bgp_peer_info.get('bgp_peer_id'):
            msg = _("bgp_peer_id must be specified")
            raise n_exc.BadRequest(resource='bgp-peer', msg=msg)
        peer_driver = self._get_driver_by_peer(
            context, bgp_peer_info['bgp_peer_id'])
        speaker_driver = self._get_driver_by_speaker(context, bgp_speaker_id)
        if peer_driver != speaker_driver:
            msg = _("Peer and Speaker must belong to the same plugin")
            raise n_exc.InvalidInput(error_message=msg)
        with locking.LockManager.get_lock(str(bgp_speaker_id)):
            speaker_driver.add_bgp_peer(context,
                                        bgp_speaker_id, bgp_peer_info)
            return super(NSXBgpPlugin, self).add_bgp_peer(context,
                                                          bgp_speaker_id,
                                                          bgp_peer_info)

    def remove_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        driver = self._get_driver_by_speaker(context, bgp_speaker_id)
        with locking.LockManager.get_lock(str(bgp_speaker_id)):
            ret = super(NSXBgpPlugin, self).remove_bgp_peer(
                context, bgp_speaker_id, bgp_peer_info)
            driver.remove_bgp_peer(context, bgp_speaker_id, bgp_peer_info)
            return ret

    def _validate_network_plugin(
        self, context, network_info,
        plugin_type=projectpluginmap.NsxPlugins.NSX_V):
        """Make sure the network belongs to the NSX0-V plugin"""
        if not network_info.get('network_id'):
            msg = _("network_id must be specified")
            raise n_exc.BadRequest(resource=bgp_ext.BGP_SPEAKER_RESOURCE_NAME,
                                   msg=msg)
        net_id = network_info['network_id']
        p = self._core_plugin._get_plugin_from_net_id(context, net_id)
        if p.plugin_type() != plugin_type:
            msg = (_('Network should belong to the %s plugin as the bgp '
                     'speaker') % plugin_type)
            raise n_exc.InvalidInput(error_message=msg)

    def add_gateway_network(self, context, bgp_speaker_id, network_info):
        driver = self._get_driver_by_speaker(context, bgp_speaker_id)
        if self._core_plugin.is_tvd_plugin():
            # The plugin of the network and speaker must be the same
            self._validate_network_plugin(context, network_info)

        with locking.LockManager.get_lock(str(bgp_speaker_id)):
            driver.add_gateway_network(context,
                                       bgp_speaker_id,
                                       network_info)
            return super(NSXBgpPlugin, self).add_gateway_network(
                context, bgp_speaker_id, network_info)

    def remove_gateway_network(self, context, bgp_speaker_id, network_info):
        driver = self._get_driver_by_speaker(context, bgp_speaker_id)
        with locking.LockManager.get_lock(str(bgp_speaker_id)):
            super(NSXBgpPlugin, self).remove_gateway_network(
                context, bgp_speaker_id, network_info)
            driver.remove_gateway_network(context,
                                          bgp_speaker_id,
                                          network_info)

    def get_advertised_routes(self, context, bgp_speaker_id):
        driver = self._get_driver_by_speaker(context, bgp_speaker_id)
        return driver.get_advertised_routes(context, bgp_speaker_id)

    def router_interface_callback(self, resource, event, trigger, **kwargs):
        if not kwargs['network_id']:
            # No GW network, hence no BGP speaker associated
            return

        context = kwargs['context'].elevated()
        router_id = kwargs['router_id']
        subnets = kwargs.get('subnets')
        network_id = kwargs['network_id']
        port = kwargs['port']

        speakers = self._bgp_speakers_for_gateway_network(context,
                                                          network_id)
        for speaker in speakers:
            speaker_id = speaker.id
            with locking.LockManager.get_lock(str(speaker_id)):
                speaker = self.get_bgp_speaker(context, speaker_id)
                driver = self._get_driver_by_project(
                    context, speaker['tenant_id'])
                if network_id not in speaker['networks']:
                    continue
                if event == events.AFTER_CREATE:
                    driver.advertise_subnet(context, speaker_id,
                                            router_id, subnets[0])
                if event == events.AFTER_DELETE:
                    subnet_id = port['fixed_ips'][0]['subnet_id']
                    driver.withdraw_subnet(context, speaker_id,
                                           router_id, subnet_id)

    def router_gateway_callback(self, resource, event, trigger, **kwargs):
        context = kwargs.get('context') or n_context.get_admin_context()
        context = context.elevated()
        router_id = kwargs['router_id']
        network_id = kwargs['network_id']
        speakers = self._bgp_speakers_for_gateway_network(context, network_id)

        for speaker in speakers:
            speaker_id = speaker.id
            driver = self._get_driver_by_project(
                context, speaker['tenant_id'])
            with locking.LockManager.get_lock(str(speaker_id)):
                speaker = self.get_bgp_speaker(context, speaker_id)
                if network_id not in speaker['networks']:
                    continue
                if event == events.AFTER_DELETE:
                    gw_ips = kwargs['gateway_ips']
                    driver.disable_bgp_on_router(context,
                                                 speaker,
                                                 router_id,
                                                 gw_ips[0])
                if event == events.AFTER_UPDATE:
                    updated_port = kwargs['updated_port']
                    router = kwargs['router']
                    driver.process_router_gw_port_update(
                        context, speaker, router, updated_port)

    def _before_service_edge_delete_callback(self, resource, event,
                                             trigger, payload=None):
        context = payload.context.elevated()
        router = payload.latest_state
        ext_net_id = router.gw_port and router.gw_port['network_id']
        gw_ip = router.gw_port and router.gw_port['fixed_ips'][0]['ip_address']
        edge_id = payload.resource_id
        speakers = self._bgp_speakers_for_gateway_network(context, ext_net_id)
        for speaker in speakers:
            driver = self._get_driver_by_project(
                context, speaker['tenant_id'])
            with locking.LockManager.get_lock(speaker.id):
                speaker = self.get_bgp_speaker(context, speaker.id)
                if ext_net_id not in speaker['networks']:
                    continue
                driver.disable_bgp_on_router(context, speaker,
                                             router['id'],
                                             gw_ip, edge_id)

    def _after_service_edge_create_callback(self, resource, event,
                                            trigger, payload=None):
        context = payload.context.elevated()
        router = payload.latest_state
        ext_net_id = router.gw_port and router.gw_port['network_id']
        speakers = self._bgp_speakers_for_gateway_network(context, ext_net_id)
        for speaker in speakers:
            driver = self._get_driver_by_project(
                context, speaker['tenant_id'])
            with locking.LockManager.get_lock(speaker.id):
                speaker = self.get_bgp_speaker(context, speaker.id)
                if ext_net_id not in speaker['networks']:
                    continue
                driver.enable_bgp_on_router(context, speaker, router['id'])


class NSXvBgpPlugin(NSXBgpPlugin):
    """Defined for backwards compatibility only"""
    pass
