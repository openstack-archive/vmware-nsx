===============================================================
 Enabling NSX Flow Classifier for service insertion in DevStack
===============================================================

1. Download DevStack

2. Update the ``local.conf`` file::

    [[local|localrc]]
    enable_plugin networking-sfc https://git.openstack.org/openstack/networking-sfc master

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    service_plugins = networking_sfc.services.flowclassifier.plugin.FlowClassifierPlugin

    [flowclassifier]
    drivers = vmware-nsxv-sfc

    [nsxv]
    service_insertion_profile_id = <service profile id. i.e. serviceprofile-1>

3. In order to prevent tenants from changing the flow classifier, please add the following
   lines to the policy.json file:

    "create_flow_classifier": "rule:admin_only",
    "update_flow_classifier": "rule:admin_only",
    "delete_flow_classifier": "rule:admin_only",
    "get_flow_classifier": "rule:admin_only"

4. run ``stack.sh``
