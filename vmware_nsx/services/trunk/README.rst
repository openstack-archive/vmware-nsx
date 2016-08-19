=========================================
 Enabling NSX trunk driver using DevStack
=========================================

1. Download DevStack

2. Enable trunk service and configure following flags in ``local.conf``::

    [[local]|[localrc]]
    # Trunk plugin NSXv3 driver config
    ENABLED_SERVICES+=,q-trunk
    Q_SERVICE_PLUGIN_CLASSES=trunk
