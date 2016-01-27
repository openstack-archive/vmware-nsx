This folder contains services for managing NSX-v, NSX-v3.

Services provided:

# Openstack tempest service clients
l2_gateway_client.py
    based on tempest BaseNetworkClient implements client APIs to manage
    neutron l2-gateway resources

l2_gateway_connection_client.py
    based on tempest BaseNetworkClient implements client APIs to manage
    neutron l2-gateway-connection resources

lbaas v2 clients: ported from neutron_lbaas to comply with tempest services.
    lbaas/load_balancers_client.py
    lbaas/listeners_client.py
    lbaas/pools_client.py
    lbaas/health_monitorys_client.py
    lbaas/members_client.py

lbv1_client.py
    based on tempest BaseNetworkClient implements client APIs to manage
    neutron v1 load-balancer resources

network_client_base.py
    due to tempest network services are in the process of migrating to
    tempest-lib, some features to be used by tests are not in
    BaseNetworkClient. Inherent here and used by all vmware-nsx-tempest
    client for now.

# NSX speific services
nsxv_client.py implements API to manage NSX-v components
    - Logical switch (Tenant network)
    - Edge (Service edge, DHCP edge, and VDR edge)
    - DFW firewall rules (Security group)
    - SpoofGuard

nsxv3_client.py implements API to manage NSX backend resources:
    - logical switch
    - firewall section
    - nsgroup
    - logical router
