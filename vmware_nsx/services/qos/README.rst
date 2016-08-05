============================================
 Enabling NSX QoS in DevStack
============================================

1. Download DevStack

2. Enable the qos in ``local.conf``::

     [[local|localrc]]
     ENABLED_SERVICES=q-qos

3. For NSXv set the service plugin in ``local.conf``, and enable the dvs features::

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    service_plugins = vmware_nsxv_qos

    [[local|localrc]]
    NSXV_USE_DVS_FEATURES = True

4. For NSXv3 set the service plugin and notification_driver in ``local.conf``::

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    service_plugins = neutron.services.qos.qos_plugin.QoSPlugin

    [qos]
    notification_drivers = vmware_nsxv3_message_queue

5. Optional: Update the nsx qos_peak_bw_multiplier in nsx.ini (default value is 2.0)::

    [NSX]
    qos_peak_bw_multiplier = <i.e 10.0>

6. run ``stack.sh``
