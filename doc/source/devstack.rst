NSX DevStack Configurations
===========================

Below are the options for configuring the NSX plugin with DevStack. Prior
to doing this DevStack needs to be downloaded. After updating the relevant
configuration file(s) run ./stack.sh

NSXv
----

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

For NSXv set the service plugin in ``local.conf``, and enable the dvs features::

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    service_plugins = vmware_nsxv_qos

    [[local|localrc]]
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

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    service_plugins = networking_sfc.services.flowclassifier.plugin.FlowClassifierPlugin

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

NSXv3
-----

QoS Driver
~~~~~~~~~~

Enable the qos in ``local.conf``::

    [[local|localrc]]
    ENABLED_SERVICES=q-qos

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    service_plugins = neutron.services.qos.qos_plugin.QoSPlugin

    [qos]
    notification_drivers = vmware_nsxv3_message_queue

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
    # Trunk plugin NSXv3 driver config
    ENABLED_SERVICES+=,q-trunk
    Q_SERVICE_PLUGIN_CLASSES=trunk

TaaS Driver
~~~~~~~~~~~

Add tap-as-a-service repo as an external repository and configure following flags in ``local.conf``::

    [[local]|[localrc]]
    # TaaS plugin NSXv3 driver config
    enable_plugin tap-as-a-service https://github.com/openstack/tap-as-a-service
    enable_service taas
    TAAS_SERVICE_DRIVER=TAAS:vmware_nsx_taas:vmware_nsx.services.neutron_taas.nsx_v3.driver.NsxV3Driver:default

