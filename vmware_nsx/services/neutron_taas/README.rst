=================================================
 Enabling NSX Tap-as-a-Service Plugin in DevStack
=================================================

1. Download DevStack

2. Add tap-as-a-service repo as an external repository and configure following flags in ``local.conf``::

    [[local]|[localrc]]
    # TaaS plugin NSXv3 driver config
    enable_plugin tap-as-a-service https://github.com/openstack/tap-as-a-service
    enable_service taas
    Q_PLUGIN_EXTRA_CONF_PATH=/etc/neutron
    Q_PLUGIN_EXTRA_CONF_FILES=(taas_plugin.ini)
    TAAS_SERVICE_DRIVER=TAAS:vmware_nsx_taas:vmware_nsx.services.neutron_taas.nsx_v3.driver.NsxV3Driver:default
