Plugin Housekeeper
==================

During the Neutron plugin's operation, system may enter an inconsistent state
due to synchronization issues between different components, e.g Neutron and NSX
or NSX and vCenter.
Some of these inconsistencies may impact the operation of various system
elements.

The Housekeeping mechanism should:
a) Detect such inconsistencies and warn about them.
b) Resolve inconsistencies when possible.

Some of these inconsistencies can be resolved using the Admin utility, yet it
requires manual operation by the administrator while the housekeeping mechanism
should be automatic.

Configuration
-------------

Housekeeping mechanism uses two configuration parameters:

nsxv/v3.housekeeping_jobs: The housekeeper can be configured which tasks to
execute and which should be skipped.

nsxv/v3.housekeeping_readonly: Housekeeper may attempt to fix a broken environment
when this flag is set to False, or otherwise will just warn about
inconsistencies.

Operation
---------

The housekeeping mechanism is an extension to the Neutron plugin. Therefore
it can be triggered by accessing the extension's URL with an administrator
context.

A naive devstack example could be::

    source devstack/openrc admin demo
    export AUTH_TOKEN=`openstack token issue | awk '/ id /{print $4}'`

    curl -X GET -s -H "X-Auth-Token: $AUTH_TOKEN" -H 'Content-Type: application/json' -d '{"housekeeper": {}}' http://<IP address>:9696/v2.0/housekeepers/all

    curl -X PUT -s -H "X-Auth-Token: $AUTH_TOKEN" -H 'Content-Type: application/json' -d '{"housekeeper": {}}' http://<IP address>:9696/v2.0/housekeepers/all

Where <IP address> would be the Neutron controller's IP or the virtual IP of
the load balancer which manages the Neutron controllers.
It is important to use the virtual IP in case of a load balanced active-backup
Neutron servers, as otherwise the housekeeping request may be handled by the
wrong controller.

The GET curl call will run all jobs in readonly mode
the PUT curl call will run all jobs in readwrite mode (for that the housekeeping_readonly should be set to False)

To operate the housekeeper periodically as it should, it should be scheduled
via a timing mechanism such as Linux cron.

Plugin Jobs
-----------

NSX-V
~~~~~

error_dhcp_edge: scans for DHCP Edge appliances which are in ERROR state.
When in non-readonly mode, the job will attempt recovery of the DHCP edges by
removing stale elements from the Neutron DB and reconfigure the interfaces at
the backend when required.

error_backup_edge: scans from backup Edge appliances which are in ERROR state.
When in non-readonly mode, the job will reset the Edge appliance configuration.

lbaas_pending: scans the neutron DB for LBaaS objects which are pending for too
long. Report it, and if in non-readonly mode change its status to ERROR

NSX-v3
~~~~~~

orphaned_logical_router: scans the NSX backend for logical routers which are
missing from the neutron DB. Report it, and if in non-readonly mode delete them.

orphaned_logical_swithces: scans the NSX backend for logical switches which are
missing from the neutron DB. Report it, and if in non-readonly mode delete them.

orphaned_dhcp_server: scans the NSX backend for DHCP servers which are
missing a matching network in the neutron DB. Report it, and if in non-readonly
mode delete them.

orphaned_firewall_section: scans the NSX backend for firewall sections which are
missing a matching security group in the neutron DB. Report it, and if in non-readonly
mode delete them.
