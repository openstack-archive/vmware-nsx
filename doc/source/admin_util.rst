Admin Utility
=============

The NSXv and the NSXv3 support the nsxadmin utility. This enables and administrator to determine and rectify inconsistencies between the Neutron DB and the NSX.
usage: nsxadmin -r <resources> -o <operation>

NSXv
----

The following resources are supported: 'security-groups', 'edges', 'networks', 'firewall-sections', 'orphaned-edges', 'spoofguard-policy', 'missing-edges', 'backup-edges', 'nsx-security-groups', 'dhcp-binding' and  'metadata'

Edges
~~~~~

- NSX list::

    nsxadmin -r edges -o nsx-list

- Neutron list::

    nsxadmin -r edges -o neutron-list

- Update Datastore HA of an edge: This admin utility can be used on upgrade after the customer added ha_datastore_id to the nsx.ini configuration, in order to update the deployment of existing edges. The new edge appliances configuration will be taken from the nsx.ini, including the datastrore_id, ha_datastore_id, edge_ha. The edge current resource pool & appliance size will not change::

    nsxadmin -r edges -o nsx-update --property edge-id=<edge-id> --property appliances=True

- Update the size of an edge::

   nsxadmin -r edges -o nsx-update --property edge-id=edge-55 --property size=compact

- Update the high availability of an edge: enable/disable high availability of an edge::

   nsxadmin -r edges -o nsx-update --property edge-id=edge-55 --property highavailability=<True/False>

Orphaned Edges
~~~~~~~~~~~~~~

- List orphaned edges (exist on NSXv backend but don't have a corresponding binding in Neutron DB)::

    nsxadmin -r orphaned-edges -o list

- Clean orphaned edges (delete edges from NSXv backend)::

    nsxadmin -r orphaned-edges -o clean

Missing Edges
~~~~~~~~~~~~~

-  List missing edges on NSX. This includes missing networks on those edges::

    nsxadmin -r missing-edges -o list

Backup Edges
~~~~~~~~~~~~

- List backup edges::

   nsxadmin -r backup-edges -o list

- Delete backup edge::

   nsxadmin -r backup-edges -o clean --property edge-id=edge-9

- List Edge name mismatches between DB and backend, and backup edges that are missing from the backend::

   nsxadmin -r backup-edges -o list-mismatches

- Fix Edge name mismatch between DB and backend by updating the name on the backend::

   nsxadmin -r backup-edges -o fix-mismatch --property edge-id=edge-9

DHCP Bindings
~~~~~~~~~~~~~
- List missing DHCP bindings: list dhcp edges that are missing from the NSXv backend::

   nsxadmin -r dhcp-binding -o list

- Update DHCP bindings on an edge::

   nsxadmin -r dhcp-binding -o nsx-update --property edge-id=edge-15


Networks
~~~~~~~~

- Ability to update or get the teaming policy for a DVS::

   nsxadmin -r networks -o nsx-update --property dvs-id=<id> --property teamingpolicy=<policy>

- List backend networks and their network morefs::

   nsxadmin -r networks -o list

Missing Networks
~~~~~~~~~~~~~~~~

- List networks which are missing from the backend::

   nsxadmin -r missing-networks -o list

Security Groups, Firewall and Spoofguard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Security groups. This adds support to list security-groups mappings and miss-matches between the mappings and backend resources as: firewall-sections and nsx-security-groups::

   nsxadmin --resource security-groups --operation list
   nsxadmin -r nsx-security-groups -o {list, list-missmatches}
   nsxadmin -r firewall-sections -o {list, list-missmatches}

- Spoofguard support::

   nsxadmin -r spoofguard-policy -o list-mismatches
   nsxadmin -r spoofguard-policy -o clean --property policy-id=spoofguardpolicy-10
   nsxadmin -r spoofguard-policy -o list --property reverse (entries defined on NSXv and not in Neutron)

Metadata
~~~~~~~~

- Update loadbalancer members on router and DHCP edges::

   nsxadmin -r metadata -o nsx-update

- Update shared secret on router and DHCP edges::

   nsxadmin -r metadata -o nsx-update-secret

NSXv3
-----

The following resources are supported: 'security-groups', 'routers', 'networks', 'nsx-security-groups', 'dhcp-binding' and 'ports'.

Networks
~~~~~~~~

- List missing networks::

    nsxadmin -r networks -o list-mismatches

Routers
~~~~~~~

- List missing routers::

    nsxadmin -r routers -o list-mismatches

Ports
~~~~~

- List missing ports, and ports that exist on backend but without the expected switch profiles::

    nsxadmin -r ports -o list-mismatches

Security Groups
~~~~~~~~~~~~~~~

- List backed security groups::

    nsx -r security-groups -o nsx-list

- List neutron DB security groups::

    nsx -r security-groups -o neutron-list

- List both backend and neutron security groups::

    nsx -r security-groups -o list

- Cleanup NSX backend sections and nsgroups::

    nsx -r security-groups -o nsx-clean

- Cleanup Neutron DB security groups::

    nsx -r security-groups -o neutron-clean

- Cleanup both Neutron DB security groups and NSX backend sections and nsgroups::

    nsx -r security-groups -o clean

- Update NSX security groups dynamic criteria for NSXv3 CrossHairs::

    nsx -r nsx-security-groups -o migrate-to-dynamic-criteria

DHCP Bindings
~~~~~~~~~~~~~

- List DHCP bindings in Neutron::

    nsxadmin -r dhcp-binding -o list

- Resync DHCP bindings for NSXv3 CrossHairs::

    nsxadmin -r dhcp-binding -o nsx-update
