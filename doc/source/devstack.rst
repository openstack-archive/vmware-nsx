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
    enable_service q-lbaasv2
    Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsx_lbaasv2

Configure the service provider::
    [[post-config|$NEUTRON_CONF]]
    [service_providers]
    service_provider = LOADBALANCERV2:VMWareEdge:neutron_lbaas.drivers.vmware.edge_driver_v2.EdgeLoadBalancerDriverV2:default

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    api_extensions_path = $DEST/neutron-lbaas/neutron_lbaas/extensions

QoS Driver
~~~~~~~~~~

Enable the qos in ``local.conf``::

     [[local|localrc]]
     ENABLED_SERVICES+=,q-qos
     Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsxv_qos
     NSXV_USE_DVS_FEATURES = True

Optional: Update the nsx qos_peak_bw_multiplier in nsx.ini (default value is 2.0)::

    [NSX]
    qos_peak_bw_multiplier = <i.e 10.0>

FWaaS (V2) Driver
~~~~~~~~~~~~~~~~~

Add neutron-fwaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_service q-fwaas-v2
    Q_SERVICE_PLUGIN_CLASSES+=,firewall_v2

    [[post-config|$NEUTRON_CONF]]
    [fwaas]
    enabled = True
    driver = vmware_nsxv_edge_v2

    [service_providers]
    service_provider = FIREWALL_V2:fwaas_db:neutron_fwaas.services.firewall.service_drivers.agents.agents.FirewallAgentDriver:default

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
    Q_SERVICE_PLUGIN_CLASSES+=,networking_sfc.services.flowclassifier.plugin.FlowClassifierPlugin

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

Octavia
~~~~~~~

Add octavia and python-octaviaclient repos as external repositories and configure following flags in ``local.conf``::

    [[local|localrc]]
    OCTAVIA_NODE=api
    DISABLE_AMP_IMAGE_BUILD=True
    LIBS_FROM_GIT=python-openstackclient,python-octaviaclient
    enable_plugin octavia https://git.openstack.org/openstack/octavia.git
    enable_plugin octavia-dashboard https://git.openstack.org/openstack/octavia-dashboard
    enable_service octavia
    enable_service o-api,o-da

    [[post-config|$OCTAVIA_CONF]]
    [DEFAULT]
    verbose = True
    debug = True

    [api_settings]
    default_provider_driver=vmwareedge
    enabled_provider_drivers=vmwareedge:NSX

    [oslo_messaging]
    topic=vmwarensxv_edge_lb

    [controller_worker]
    network_driver = network_noop_driver

NSX-T
-----

QoS Driver
~~~~~~~~~~

Enable the qos in ``local.conf``::

    [[local|localrc]]
    ENABLED_SERVICES+=,q-qos
    Q_SERVICE_PLUGIN_CLASSES+=,neutron.services.qos.qos_plugin.QoSPlugin

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
    Q_SERVICE_PLUGIN_CLASSES+=,trunk

FWaaS (V2) Driver
~~~~~~~~~~~~~~~~~

Add neutron-fwaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_service q-fwaas-v2
    Q_SERVICE_PLUGIN_CLASSES+=,firewall_v2

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
    enable_service q-lbaasv2
    Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsx_lbaasv2

Configure the service provider::
    [[post-config|$NEUTRON_CONF]]
    [service_providers]
    service_provider = LOADBALANCERV2:VMWareEdge:neutron_lbaas.drivers.vmware.edge_driver_v2.EdgeLoadBalancerDriverV2:default

    [DEFAULT]
    api_extensions_path = $DEST/neutron-lbaas/neutron_lbaas/extensions

Neutron VPNaaS
~~~~~~~~~~~~~~

Add neutron-vpnaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    NEUTRON_VPNAAS_SERVICE_PROVIDER=VPN:vmware:vmware_nsx.services.vpnaas.nsxv3.ipsec_driver.NSXv3IPsecVpnDriver:default
    Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsx_vpnaas

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    api_extensions_path = $DEST/neutron-vpnaas/neutron_vpnaas/extensions

Octavia
~~~~~~~

Add octavia and python-octaviaclient repos as external repositories and configure following flags in ``local.conf``::

    [[local|localrc]]
    OCTAVIA_NODE=api
    DISABLE_AMP_IMAGE_BUILD=True
    LIBS_FROM_GIT=python-openstackclient,python-octaviaclient
    enable_plugin octavia https://git.openstack.org/openstack/octavia.git
    enable_plugin octavia-dashboard https://git.openstack.org/openstack/octavia-dashboard
    enable_service octavia
    enable_service o-api,o-da

    [[post-config|$OCTAVIA_CONF]]
    [DEFAULT]
    verbose = True
    debug = True

    [api_settings]
    default_provider_driver=vmwareedge
    enabled_provider_drivers=vmwareedge:NSX

    [oslo_messaging]
    topic=vmwarensxv_edge_lb

    [controller_worker]
    network_driver = network_noop_driver


NSX-P
-----

QoS Driver
~~~~~~~~~~

Enable the qos in ``local.conf``::

    [[local|localrc]]
    ENABLED_SERVICES+=,q-qos
    Q_SERVICE_PLUGIN_CLASSES+=,neutron.services.qos.qos_plugin.QoSPlugin

Optional: Update the nsx qos_peak_bw_multiplier in nsx.ini (default value is 2.0)::

    [NSX]
    qos_peak_bw_multiplier = <i.e 10.0>

FWaaS (V2) Driver
~~~~~~~~~~~~~~~~~

Add neutron-fwaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_service q-fwaas-v2
    Q_SERVICE_PLUGIN_CLASSES+=,firewall_v2

    [[post-config|$NEUTRON_CONF]]
    [fwaas]
    enabled = True
    driver = vmware_nsxp_edge_v2

    [service_providers]
    service_provider = FIREWALL_V2:fwaas_db:neutron_fwaas.services.firewall.service_drivers.agents.agents.FirewallAgentDriver:default

LBaaS v2 Driver
~~~~~~~~~~~~~~~

Add lbaas repo as an external repository and configure following flags in ``local.conf``::

    [[local]|[localrc]]
    enable_service q-lbaasv2
    Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsx_lbaasv2

Configure the service provider::
    [[post-config|$NEUTRON_CONF]]
    [service_providers]
    service_provider = LOADBALANCERV2:VMWareEdge:neutron_lbaas.drivers.vmware.edge_driver_v2.EdgeLoadBalancerDriverV2:default

    [DEFAULT]
    api_extensions_path = $DEST/neutron-lbaas/neutron_lbaas/extensions

Octavia
~~~~~~~

Add octavia and python-octaviaclient repos as external repositories and configure following flags in ``local.conf``::

    [[local|localrc]]
    OCTAVIA_NODE=api
    DISABLE_AMP_IMAGE_BUILD=True
    LIBS_FROM_GIT=python-openstackclient,python-octaviaclient
    enable_plugin octavia https://git.openstack.org/openstack/octavia.git
    enable_plugin octavia-dashboard https://git.openstack.org/openstack/octavia-dashboard
    enable_service octavia
    enable_service o-api,o-da

    [[post-config|$OCTAVIA_CONF]]
    [DEFAULT]
    verbose = True
    debug = True

    [api_settings]
    default_provider_driver=vmwareedge
    enabled_provider_drivers=vmwareedge:NSX

    [oslo_messaging]
    topic=vmwarensxv_edge_lb

    [controller_worker]
    network_driver = network_noop_driver


NSX-TVD
-------

LBaaS v2 Driver
~~~~~~~~~~~~~~~

Add lbaas repo as an external repository and configure following flags in ``local.conf``::

    [[local]|[localrc]]
    enable_service q-lbaasv2
    Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsxtvd_lbaasv2

Configure the service provider::
    [[post-config|$NEUTRON_LBAAS_CONF]]
    [service_providers]
    service_provider = LOADBALANCERV2:VMWareEdge:neutron_lbaas.drivers.vmware.edge_driver_v2.EdgeLoadBalancerDriverV2:default

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    api_extensions_path = $DEST/neutron-lbaas/neutron_lbaas/extensions

FWaaS (V2) Driver
~~~~~~~~~~~~~~~~~

Add neutron-fwaas repo as an external repository and configure following flags in ``local.conf``::

    [[local|localrc]]
    enable_service q-fwaas-v2
    Q_SERVICE_PLUGIN_CLASSES+=,vmware_nsxtvd_fwaasv2

    [[post-config|$NEUTRON_CONF]]
    [fwaas]
    enabled = True
    driver = vmware_nsxtvd_edge_v2
    [DEFAULT]
    api_extensions_path = $DEST/neutron-fwaas/neutron_fwaas/extensions

    [service_providers]
    service_provider = FIREWALL_V2:fwaas_db:neutron_fwaas.services.firewall.service_drivers.agents.agents.FirewallAgentDriver:default

Note - if devstack fails due to ml2_conf.ini being missing, please copy neutron/plugins/ml2/ml2_conf.ini.sample to /etc/neutron/plugins/ml2/ml2_conf.ini and stack again.

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

