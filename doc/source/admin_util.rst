Admin Utility
=============

The NSXv and the NSXv3 support the nsxadmin utility. This enables and administrator to determine and rectify inconsistencies between the Neutron DB and the NSX.
usage: nsxadmin -r <resources> -o <operation>

NSXv
----

The following resources are supported: 'security-groups', 'edges', 'networks', 'firewall-sections', 'orphaned-edges', 'spoofguard-policy', 'missing-edges', 'backup-edges', 'nsx-security-groups', 'dhcp-binding' and  'metadata'

Edges
~~~~~

- List backend NSX edges with their id, name and some more information::

    nsxadmin -r edges -o nsx-list

- List backend NSX edges with more details::

    nsxadmin -r edges -o nsx-list --verbose

- Neutron list::

    nsxadmin -r edges -o neutron-list

- Update Resource pool / Datastore on all edges in the backend. This utility can update resource pool and datastore ID of all edges to the nsx.ini configuration::

    nsxadmin -r edges -o nsx-update-all --property appliances=True

- Update Resource pool / Datastore / edge HA of an edge: This utility can be used on upgrade after the customer added ha_datastore_id to the nsx.ini configuration or after changing the resource pool / data store globally or per availability zone. This Utility can update the deployment of existing edges::

    nsxadmin -r edges -o nsx-update --property edge-id=<edge-id> --property appliances=True

- Update the size of an edge::

    nsxadmin -r edges -o nsx-update --property edge-id=edge-55 --property size=compact

- Update the high availability of an edge: enable/disable high availability of an edge::

    nsxadmin -r edges -o nsx-update --property edge-id=edge-55 --property highavailability=<True/False>

- Update syslog config on edge (syslog-proto and syslog-server2 are optional)::

    nsxadmin -o nsx-update -r edges -p edge-id=edge-55 --property syslog-server=<server ip> --property syslog-server2=<server ip> --property syslog-proto=<tcp|udp>

- Delete syslog config on edge::

    nsxadmin -o nsx-update -r edges -p edge-id=edge-55 --property syslog-server=none

- Enable logging with specified log level for specific module (routing, dns, dhcp, highavailability, loadbalancer) on edge::

    nsxadmin -o nsx-update -r edges -p edge-id=edge-55 --property routing-log-level=debug

- Enable logging with specified log level for all supported modules on edge::

    nsxadmin -o nsx-update -r edges -p edge-id=edge-55 --property log-level=debug

- Disable logging on edge::

    nsxadmin -o nsx-update -r edges -p edge-id=edge-55 --property log-level=none

- Update reservations of an edge::

    nsxadmin -o nsx-update -r edges -p edge-id=edge-55 --property resource=<cpu|memory> --property limit=<limit> --property reservation=<reservation> --property shares=<shares>

- Update DRS hostgroups for an edge::

    nsxadmin -o nsx-update -r edges -p edge-id=edge-55 --property hostgroup=update|all

- Update DRS hostgroups for all edges::

    nsxadmin -o nsx-update -r edges --property hostgroup=all

- Clean all DRS hostgroups for all edges::

    nsxadmin -o nsx-update -r edges --property hostgroup=clean

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

- List backend backup edges with their id, name and some more information::

    nsxadmin -r backup-edges -o list

- Delete backup edge::

    nsxadmin -r backup-edges -o clean --property edge-id=edge-9

- Delete all backup edges::

    nsxadmin -r backup-edges -o clean-all

- List Edge name mismatches between DB and backend, and backup edges that are missing from the backend::

    nsxadmin -r backup-edges -o list-mismatches

- Fix Edge name mismatch between DB and backend by updating the name on the backend::

    nsxadmin -r backup-edges -o fix-mismatch --property edge-id=edge-9

- Delete a backup edge from the DB and NSX by it's router ID::

    nsxadmin -r backup-edges -o neutron-clean --property router-id=backup-26ab1a3a-d73d

DHCP Bindings
~~~~~~~~~~~~~
- List missing DHCP bindings: list dhcp edges that are missing from the NSXv backend::

    nsxadmin -r dhcp-binding -o list

- Update DHCP bindings on an edge::

    nsxadmin -r dhcp-binding -o nsx-update --property edge-id=edge-15

- Recreate DHCP edge by moving all the networks to other edges::

    nsxadmin -r dhcp-binding -o nsx-recreate --property edge-id=edge-222

- Recreate DHCP edge for a specific network (when the edge does not exist)::

    nsxadmin -r dhcp-binding -o nsx-recreate --property net-id=5253ae45-75b4-4489-8aa1-6a9e1cfa80a6

Routers
~~~~~~~
- Recreate a router edge by moving the router/s to other edge/s::

    nsxadmin -r routers -o nsx-recreate --property edge-id=edge-308

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

Orphaned Networks
~~~~~~~~~~~~~~~~~

- List networks which are missing from the neutron DB::

    nsxadmin -r orphaned-networks -o list

- Delete a backend network by it's moref::

    nsxadmin -r orphaned-networks -o nsx-clean --property moref=<moref>

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

- Migrate a security group from using rules to using a policy

    nsxadmin -r security-groups -o migrate-to-policy --property policy-id=policy-10 --property security-group-id=733f0741-fa2c-4b32-811c-b78e4dc8ec39

- Reorder the nsx L3 firewall sections to correctly support the policy security groups

    nsxadmin -r firewall-sections -o nsx-reorder

Metadata
~~~~~~~~

- Update loadbalancer members on router and DHCP edges::

    nsxadmin -r metadata -o nsx-update

- Update shared secret on router and DHCP edges::

    nsxadmin -r metadata -o nsx-update-secret

- Retrieve metadata connectivity - optionally for a specific network::

    nsxadmin -r metadata -o status [--property network_id=<net_id>]

NSXv3
-----

The following resources are supported: 'security-groups', 'routers', 'networks', 'nsx-security-groups', 'dhcp-binding', 'metadata-proxy', 'orphaned-dhcp-servers', and 'ports'.

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

- Update the VMs ports on the backend after migrating nsx-v -> nsx-v3::

    nsxadmin -r ports -o nsx-migrate-v-v3

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

Metadata Proxy
~~~~~~~~~~~~~~

- List version 1.0.0 metadata networks in Neutron::

    nsxadmin -r metadata-proxy -o list

- Resync metadata proxies for NSXv3 version 1.1.0 and above::

    nsxadmin -r metadata-proxy -o nsx-update --property metadata_proxy_uuid=<metadata_proxy_uuid>

DHCP Bindings
~~~~~~~~~~~~~

- List DHCP bindings in Neutron::

    nsxadmin -r dhcp-binding -o list

- Resync DHCP bindings for NSXv3 version 1.1.0 and above::

    nsxadmin -r dhcp-binding -o nsx-update --property dhcp_profile_uuid=<dhcp_profile_uuid>

Orphaned DHCP Servers
~~~~~~~~~~~~~~~~~~~~~

- List orphaned DHCP servers (exist on NSXv3 backend but don't have a corresponding binding in Neutron DB)::

    nsxadmin -r orphaned-dhcp-servers -o nsx-list

- Clean orphaned DHCP servers (delete logical DHCP servers from NSXv3 backend)::

    nsxadmin -r orphaned-dhcp-servers -o nsx-clean

Client Certificate
~~~~~~~~~~~~~~~~~~

- Generate new client certificate (this command will delete previous certificate if exists)::

    nsxadmin -r certificate -o generate [--property username=<username> --property password=<password> --property key-size=<size> --property sig-alg=<alg> --property valid-days=<days> --property country=<country> --property state=<state> --property org=<organization> --property unit=<unit> --property host=<hostname>]

- Delete client certificate::

    nsxadmin -r certificate -o clean

- Show client certificate details::

    nsxadmin -r certificate -o show

- Import external certificate to NSX::

    nsxadmin -r certificate -o import --property username=<username> --property password=<password>

- List certificates associated with openstack principal identity in NSX::

    nsxadmin -r certificate -o nsx-list


Upgrade Steps (Version 1.0.0 to Version 1.1.0)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Upgrade NSX backend from version 1.0.0 to version 1.1.0

2. Create a DHCP-Profile and a Metadata-Proxy in NSX backend

3. Stop Neutron

4. Install version 1.1.0 Neutron plugin

5. Run admin tools to migrate version 1.0.0 objects to version 1.1.0 objects

     nsxadmin -r metadata-proxy -o nsx-update --property metadata_proxy_uuid=<UUID of Metadata-Proxy created in Step 2>

     nsxadmin -r dhcp-binding -o nsx-update --property dhcp_profile_uuid=<UUID of DHCP-Profile created in Step 2>

6. Start Neutron

7. Make sure /etc/nova/nova.conf has
   metadata_proxy_shared_secret = <Secret of Metadata-Proxy created in Step 2>

8. Restart VMs or ifdown/ifup their network interface to get new DHCP options
