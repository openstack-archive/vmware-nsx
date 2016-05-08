============================================
 Enabling NSX L2 Gateway Plugin in DevStack
============================================

Following steps are meant for L2GW service in neutron for stable/mitaka* release onwards.

1. Download DevStack

2. Add networking-l2gw repo as an external repository and configure following flags in ``local.conf``::

     [[local|localrc]]
     enable_plugin networking-l2gw https://github.com/openstack/networking-l2gw
     ENABLED_SERVICES=l2gw-plugin

3. For NSXv3 include the following additional flags in ``local.conf``::
     [[local|localrc]]
     NETWORKING_L2GW_SERVICE_DRIVER=L2GW:vmware-nsx-l2gw:vmware_nsx.services.l2gateway.nsx_v3.driver.NsxV3Driver:default
     DEFAULT_BRIDGE_CLUSTER_UUID=

4. run ``stack.sh``

* Configuration for stable/liberty release in ``local.conf``::
    [[local|localrc]]
    enable_plugin networking-l2gw https://github.com/openstack/networking-l2gw
    NSX_L2GW_DRIVER='vmware_nsx.services.l2gateway.nsx_v3.driver.NsxV3Driver'
    Q_SERVICE_PLUGIN_CLASSES=vmware_nsx_l2gw
    DEFAULT_BRIDGE_CLUSTER_UUID=
