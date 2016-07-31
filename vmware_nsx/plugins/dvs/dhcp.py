# Copyright 2012 OpenStack Foundation
# All Rights Reserved.
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

from neutron.agent.common import ovs_lib
from neutron.agent.linux import dhcp

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('dvs_integration_bridge',
               default='br-dvs',
               help=_('Name of Open vSwitch bridge to use for DVS networks')),
    cfg.StrOpt('dhcp_override_mac',
               help=_('Override the MAC address of the DHCP interface')),
]

cfg.CONF.register_opts(OPTS)


class DeviceManager(dhcp.DeviceManager):

    def plug(self, network, port, interface_name):
        mac_address = (cfg.CONF.dhcp_override_mac
                       if cfg.CONF.dhcp_override_mac
                       else port.mac_address)
        self.driver.plug(network.id,
                         port.id,
                         interface_name,
                         mac_address,
                         namespace=network.namespace,
                         mtu=network.get('mtu'),
                         bridge=cfg.CONF.dvs_integration_bridge)
        vlan_tag = getattr(network, 'provider:segmentation_id',
                           None)
        # Treat vlans
        if vlan_tag and vlan_tag != 0:
            br_dvs = ovs_lib.OVSBridge(self.conf.dvs_integration_bridge)
            # When ovs_use_veth is set to True, the DEV_NAME_PREFIX
            # will be changed from 'tap' to 'ns-' in
            # OVSInterfaceDriver
            dvs_port_name = interface_name.replace('ns-', 'tap')
            br_dvs.set_db_attribute("Port", dvs_port_name, "tag", vlan_tag)

    def unplug(self, device_name, network):
        self.driver.unplug(
            device_name, bridge=cfg.CONF.dvs_integration_bridge,
            namespace=network.namespace)


class Dnsmasq(dhcp.Dnsmasq):

    def __init__(self, conf, network, process_monitor,
                 version=None, plugin=None):
        super(Dnsmasq, self).__init__(conf, network, process_monitor,
                                      version=version, plugin=plugin)
        # Using the DeviceManager that enables us to directly plug the OVS
        LOG.debug("Using the DVS DeviceManager")
        self.device_manager = DeviceManager(conf, plugin)
