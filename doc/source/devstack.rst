NSX DevStack Configurations
===========================

Below are the options for configuring the NSX plugin with DevStack. Prior
to doing this DevStack needs to be downloaded. After updating the relevant
configuration file(s) run ./stack.sh

NSX-V
-----

LBaaS v2 Driver
~~~~~~~~~~~~~~~

Add lbaas repo as an external repository and configure following flags in ``local.conf``::

    [[local]|[localrc]]
    enable_plugin neutron-lbaas https://git.openstack.org/openstack/neutron-lbaas
    enable_service q-lbaasv2

Configure the service provider::
    [[post-config|$NEUTRON_LBAAS_CONF]]
    [service_providers]
    service_provider = LOADBALANCERV2:VMWareEdge:neutron_lbaas.drivers.vmware.edge_driver_v2.EdgeLoadBalancerDriverV2:default

QoS Driver
~~~~~~~~~~

Enable the qos in ``local.conf``::

     [[local|localrc]]
     ENABLED_SERVICES=q-qos
     Q_SERVICE_PLUGIN_CLASSES=vmware_nsxv_qos
     NSXV_USE_DVS_FEATURES = True

Optional: Update the nsx qos_peak_bw_multiplier in nsx.ini (default value is 2.0)::

    [NSX]
    qos_peak_bw_multiplier = <i.e 10.0>

L2GW Driver
~~~~~~~~~~~

Add networking-l2gw repo as an external repository and configure following flags in ``local.conf``::

     [[local|localrc]]
     enable_plugin networking-l2gw https://github.com/openstack/networking-l2gw
     ENABLED_SERVICES+=l2gw-plugin
     NETWORKING_L2GW_SERVICE_DRIVER=L2GW:vmware-nsx-l2gw:vmware_nsx.services.l2gateway.nsx_v.driver.NsxvL2GatewayDriver:default

IPAM Driver
~~~~~~~~~~~

Update the ``local.conf`` file::

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    ipam_driver = vmware_nsxv_ipam

Flow Classifier
~~~~~~~~~~~~~~~

Update the ``local.conf`` file::

    [[local|localrc]]
    enable_plugin networking-sfc https://git.openstack.org/openstack/networking-sfc master
    Q_SERVICE_PLUGIN_CLASSES=networking_sfc.services.flowclassifier.plugin.FlowClassifierPlugin

    [[post-config|$NEUTRON_CONF]]
    [flowclassifier]
    drivers = vmware-nsxv-sfc

    [nsxv]
    service_insertion_profile_id = <service profile id. i.e. serviceprofile-1>

In order to prevent tenants from changing the flow classifier, please add the following
lines to the policy.json file::

    "create_flow_classifier": "rule:admin_only",
    "update_flow_classifier": "rule:admin_only",
    "delete_flow_classifier": "rule:admin_only",
    "get_flow_classifier": "rule:admin_only"

FWaaS (V1) Driver
~~~~~~~~~~~~~~~~~

Add neutron-fwaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-fwaas https://git.openstack.org/openstack/neutron-fwaas
    ENABLED_SERVICES+=,q-fwaas-v1
    Q_SERVICE_PLUGIN_CLASSES=neutron_fwaas.services.firewall.fwaas_plugin.FirewallPlugin

    [[post-config|$NEUTRON_CONF]]
    [fwaas]
    enabled = True
    driver = vmware_nsxv_edge

Neutron dynamic routing plugin (bgp)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add neutron-dynamic-routing repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-dynamic-routing https://git.openstack.org/openstack/neutron-dynamic-routing
    DR_MODE=dr_plugin
    BGP_PLUGIN=vmware_nsx.services.dynamic_routing.bgp_plugin.NSXvBgpPlugin

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    api_extensions_path = $DEST/neutron-dynamic-routing/neutron_dynamic_routing/extensions

Neutron VPNaaS
~~~~~~~~~~~~~~

Add neutron-vpnaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-vpnaas https://git.openstack.org/openstack/neutron-vpnaas
    NEUTRON_VPNAAS_SERVICE_PROVIDER=VPN:vmware:vmware_nsx.services.vpnaas.nsxv.ipsec_driver.NSXvIPsecVpnDriver:default


NSX-T
-----

QoS Driver
~~~~~~~~~~

Enable the qos in ``local.conf``::

    [[local|localrc]]
    ENABLED_SERVICES+=,q-qos
    Q_SERVICE_PLUGIN_CLASSES=neutron.services.qos.qos_plugin.QoSPlugin

Optional: Update the nsx qos_peak_bw_multiplier in nsx.ini (default value is 2.0)::

    [NSX]
    qos_peak_bw_multiplier = <i.e 10.0>

L2GW Driver
~~~~~~~~~~~

Add networking-l2gw repo as an external repository and configure following flags in ``local.conf``::

     [[local|localrc]]
     enable_plugin networking-l2gw https://github.com/openstack/networking-l2gw
     ENABLED_SERVICES+=l2gw-plugin
     NETWORKING_L2GW_SERVICE_DRIVER=L2GW:vmware-nsx-l2gw:vmware_nsx.services.l2gateway.nsx_v3.driver.NsxV3Driver:default
     DEFAULT_BRIDGE_CLUSTER_UUID=

IPAM Driver
~~~~~~~~~~~

Update the ``local.conf`` file::

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    ipam_driver = vmware_nsxv3_ipam

Trunk Driver
~~~~~~~~~~~~

Enable trunk service and configure following flags in ``local.conf``::

    [[local]|[localrc]]
    # Trunk plugin NSX-T driver config
    ENABLED_SERVICES+=,q-trunk
    Q_SERVICE_PLUGIN_CLASSES=trunk

FWaaS (V1) Driver
~~~~~~~~~~~~~~~~~

Add neutron-fwaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-fwaas https://git.openstack.org/openstack/neutron-fwaas
    ENABLED_SERVICES+=,q-fwaas
    Q_SERVICE_PLUGIN_CLASSES=neutron_fwaas.services.firewall.fwaas_plugin.FirewallPlugin

    [[post-config|$NEUTRON_CONF]]
    [fwaas]
    enabled = True
    driver = vmware_nsxv3_edge_v1


FWaaS (V2) Driver
~~~~~~~~~~~~~~~~~

Add neutron-fwaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-fwaas https://git.openstack.org/openstack/neutron-fwaas
    ENABLED_SERVICES+=,q-fwaas-v2
    Q_SERVICE_PLUGIN_CLASSES=neutron_fwaas.services.firewall.fwaas_plugin_v2.FirewallPluginV2

    [[post-config|$NEUTRON_CONF]]
    [fwaas]
    enabled = True
    driver = vmware_nsxv3_edge_v2

    [service_providers]
    service_provider = FIREWALL_V2:fwaas_db:neutron_fwaas.services.firewall.service_drivers.agents.agents.FirewallAgentDriver:default

LBaaS v2 Driver
~~~~~~~~~~~~~~~

Add lbaas repo as an external repository and configure following flags in ``local.conf``::

    [[local]|[localrc]]
    enable_plugin neutron-lbaas https://git.openstack.org/openstack/neutron-lbaas
    enable_service q-lbaasv2

Configure the service provider::
    [[post-config|$NEUTRON_LBAAS_CONF]]
    [service_providers]
    service_provider = LOADBALANCERV2:VMWareEdge:neutron_lbaas.drivers.vmware.edge_driver_v2.EdgeLoadBalancerDriverV2:default

Neutron VPNaaS
~~~~~~~~~~~~~~

Add neutron-vpnaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-vpnaas https://git.openstack.org/openstack/neutron-vpnaas
    NEUTRON_VPNAAS_SERVICE_PROVIDER=VPN:vmware:vmware_nsx.services.vpnaas.nsxv3.ipsec_driver.NSXv3IPsecVpnDriver:default


NSX-TVD
-------

LBaaS v2 Driver
~~~~~~~~~~~~~~~

Add lbaas repo as an external repository and configure following flags in ``local.conf``::

    [[local]|[localrc]]
    enable_plugin neutron-lbaas https://git.openstack.org/openstack/neutron-lbaas
    enable_service q-lbaasv2
    Q_SERVICE_PLUGIN_CLASSES=vmware_nsxtvd_lbaasv2

Configure the service provider::
    [[post-config|$NEUTRON_LBAAS_CONF]]
    [service_providers]
    service_provider = LOADBALANCERV2:VMWareEdge:neutron_lbaas.drivers.vmware.edge_driver_v2.EdgeLoadBalancerDriverV2:default

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    api_extensions_path = $DEST/neutron-lbaas/neutron_lbaas/extensions

FWaaS (V1) Driver
~~~~~~~~~~~~~~~~~

Add neutron-fwaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-fwaas https://git.openstack.org/openstack/neutron-fwaas
    ENABLED_SERVICES+=,q-fwaas
    Q_SERVICE_PLUGIN_CLASSES=vmware_nsxtvd_fwaasv1

    [[post-config|$NEUTRON_CONF]]
    [fwaas]
    enabled = True
    driver = vmware_nsxtvd_edge_v1
    [DEFAULT]
    api_extensions_path = $DEST/neutron-fwaas/neutron_fwaas/extensions


FWaaS (V2) Driver
~~~~~~~~~~~~~~~~~

Add neutron-fwaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-fwaas https://git.openstack.org/openstack/neutron-fwaas
    ENABLED_SERVICES+=,q-fwaas-v2
    Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsxtvd_fwaasv2

    [[post-config|$NEUTRON_CONF]]
    [fwaas]
    enabled = True
    driver = vmware_nsxtvd_edge_v2
    [DEFAULT]
    api_extensions_path = $DEST/neutron-fwaas/neutron_fwaas/extensions

    [service_providers]
    service_provider = FIREWALL_V2:fwaas_db:neutron_fwaas.services.firewall.service_drivers.agents.agents.FirewallAgentDriver:default

L2GW Driver
~~~~~~~~~~~

Add networking-l2gw repo as an external repository and configure following flags in ``local.conf``::

     [[local|localrc]]
     enable_plugin networking-l2gw https://github.com/openstack/networking-l2gw
     ENABLED_SERVICES+=l2gw-plugin
     NETWORKING_L2GW_SERVICE_DRIVER=L2GW:vmware-nsx-l2gw:vmware_nsx.services.l2gateway.nsx_tvd.driver.NsxTvdL2GatewayDriver:default
     DEFAULT_BRIDGE_CLUSTER_UUID=
     Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsxtvd_l2gw

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    api_extensions_path = $DEST/networking-l2gateway/networking_l2gw/extensions

QoS Driver
~~~~~~~~~~

Enable the qos in ``local.conf``::

    [[local|localrc]]
    ENABLED_SERVICES+=,q-qos
    Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsxtvd_qos

Neutron dynamic routing plugin (bgp)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add neutron-dynamic-routing repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-dynamic-routing https://git.openstack.org/openstack/neutron-dynamic-routing
    DR_MODE=dr_plugin
    BGP_PLUGIN=vmware_nsx.services.dynamic_routing.bgp_plugin.NSXBgpPlugin

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    api_extensions_path = $DEST/neutron-dynamic-routing/neutron_dynamic_routing/extensions

Neutron VPNaaS
~~~~~~~~~~~~~~

Add neutron-vpnaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_plugin neutron-vpnaas https://git.openstack.org/openstack/neutron-vpnaas
    NEUTRON_VPNAAS_SERVICE_PROVIDER=VPN:vmware:vmware_nsx.services.vpnaas.nsx_tvd.ipsec_driver.NSXIPsecVpnDriver:default
    Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsxtvd_vpnaas

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    api_extensions_path = $DEST/neutron-vpnaas/neutron_vpnaas/extensions

IPAM Driver
~~~~~~~~~~~

Update the ``local.conf`` file::

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    ipam_driver = vmware_nsxtvd_ipam

