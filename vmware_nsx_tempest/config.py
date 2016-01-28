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
from tempest import config

scenario_group = config.scenario_group
ScenarioGroup = [
    cfg.FloatOpt('waitfor_disassoc',
                 default=15.0,
                 help="Wait for seconds after disassociation."),
    cfg.FloatOpt('waitfor_assoc',
                 default=5.0,
                 help="Waitfor seconds after association."),
    cfg.FloatOpt('waitfor_connectivity',
                 default=120.0,
                 help="Wait for seconds to become connected."),
    cfg.ListOpt('outside_world_servers',
                default=["8.8.8.8", "8.8.4.4"],
                help="List of servers reside outside of openstack env."
                     " which is used to test default gateway behavior"
                     " when VMs are under logical routers,"
                     " & DNS are local to provider's settings."),
    cfg.DictOpt('flat_alloc_pool_dict',
                default={},
                help=" Define flat network ip range."
                     " required attributes are gateway, start, end"
                     " and cidr. Example value: gateway:10.1.1.253,"
                     " start:10.1.1.30,end:10.1.1.49,cidr=10.1.1.0/24"),
]

network_group = config.network_group
NetworkGroup = [
    cfg.StrOpt('l2gw_switch',
               default='',
               help="Distributed Virtual Portgroup to create VLAN port."),
    cfg.DictOpt('l2gw_switch_dict',
                default={},
                help="dict version of l2gw_switch:"
                     "device_name:,interfaces:,segmentation_id:,"),
]

nsxv_group = cfg.OptGroup(name='nsxv',
                          title="NSX-v Configuration Options")
NSXvGroup = [
    cfg.StrOpt('manager_uri',
               default='https://10.0.0.10',
               help="NSX-v manager ip address"),
    cfg.StrOpt('user',
               default='admin',
               help="NSX-v manager username"),
    cfg.StrOpt('password',
               default='default',
               help="NSX-v manager password"),
    cfg.StrOpt('vdn_scope_id',
               default='vdnscope-1',
               help="NSX-v vdn scope id"),
    cfg.DictOpt('flat_alloc_pool_dict',
                default={},
                help=" Define flat network ip range."
                     " required attributes are gateway, start, end"
                     " and cidr. Example value: gateway:10.1.1.253,"
                     " start:10.1.1.30,end:10.1.1.49,cidr=10.1.1.0/24"),
    cfg.StrOpt('vlan_physical_network',
               default='',
               help="physval_network to create vlan."),
    cfg.IntOpt('provider_vlan_id',
               default=888,
               help="The default vlan_id for admin vlan."),
]


l2gw_group = cfg.OptGroup(name='l2gw',
                          title="l2-gateway Configuration Options")
L2gwGroup = [
    cfg.DictOpt('vlan_subnet_ipv4_dict',
                default={},
                help="Tenant's VLAN subnet cdir to connect to l2gw/VXLAN."
                     " Example: cidr=192.168.99.0/24,start:192.168.99.41"
                     "          ,end:192.168.99.50,gateway=192.168.99.253"),
    cfg.StrOpt('device_one_vlan',
               default="",
               help="l2g2 device with one VLAN"
                    " l2gw-1::dvportgroup-14420|3845"),
    cfg.StrOpt('device_multiple_vlans',
               default="",
               help="l2gw device with multiple VLANs"
                    " l2gw-x::dvportgroup-14429|3880#3381#3382"),
    cfg.StrOpt('multiple_interfaces_multiple_vlans',
               default="",
               help="l2gw multiple devices, interface has multiple VLANs"
                    " m-ifs::dvportgroup-144|138#246;dvportgroup-155|339"),
]

nsxv3_group = cfg.OptGroup(name='nsxv3',
                           title="NSXv3 Configuration Options")

NSXv3Group = [
    cfg.StrOpt('nsx_manager',
               default='',
               help="NSX manager IP address"),
    cfg.StrOpt('nsx_user',
               default='admin',
               help="NSX manager username"),
    cfg.StrOpt('nsx_password',
               default='default',
               help="NSX manager password"),
]
