============================================
 Enabling NSX L2 Gateway Plugin in DevStack
============================================

1. Download DevStack

2. Add networking-l2gw repo as an external repository and configure following flags in ``local.conf``::

     [[local|localrc]]
     enable_plugin networking-l2gw https://github.com/openstack/networking-l2gw
     ENABLED_SERVICES=l2gw-plugin
     NETWORKING_L2GW_SERVICE_DRIVER=L2GW:vmware-nsx-l2gw:vmware_nsx.services.l2gateway.common.plugin.NsxL2GatewayPlugin:default

3. For NSXv3 include the following additional flags in ``local.conf``::
     [[local|localrc]]
     NSX_L2GW_DRIVER='vmware_nsx.services.l2gateway.nsx_v3.driver.NsxV3Driver'
     DEFAULT_BRIDGE_CLUSTER_UUID=

4. run ``stack.sh``
