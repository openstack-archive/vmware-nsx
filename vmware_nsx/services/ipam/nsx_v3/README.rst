=================================================================
 Enabling NSXv3 IPAM for external & provider networks in Devstack
=================================================================

1. Download DevStack

2. Update the ``local.conf`` file::

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    ipam_driver = vmware_nsxv3_ipam

3. run ``stack.sh``
