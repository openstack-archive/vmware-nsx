This folder contains services for managing NSX-t, NSX-v and
neutron sub-services not yet migrating to tempest-lib. 

Services provided:

# Openstack tempest service clients
l2_gateway_client.py
    based on tempest BaseNetworkClient implements client APIs to manage
    neutron l2-gateway resources

l2_gateway_connection_client.py
    based on tempest BaseNetworkClient implements client APIs to manage
    neutron l2-gateway-connection resources

lbv1_client.py
    based on tempest BaseNetworkClient implements client APIs to manage
    neutron v1 load-balancer resources

network_client_base.py
    due to tempest network services are in the process of migrating to
    tempest-lib, some features to be used by tests are not in
    BaseNetworkClient. Inherent here and used by all vmware-nsx-tempest
    client for now.

# NSXv speific services
nsxv_client.py which it has API ops on the following NSX-v components
    - Logical switch (Tenant network)
    - Edge (Service edge, DHCP edge, and VDR edge)
    - DFW firewall rules (Security group)
    - SpoofGuard
