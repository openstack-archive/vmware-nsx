========================
Devstack external plugin
========================

Add and set the following in your local.conf/localrc file:

enable_plugin vmware-nsx https://git.openstack.org/openstack/vmware-nsx

For Nsx-mh:
-----------

Q_PLUGIN=vmware_nsx

PUBLIC_BRIDGE                    # bridge used for external connectivity, typically br-ex
NSX_GATEWAY_NETWORK_INTERFACE    # interface used to communicate with the NSX Gateway
NSX_GATEWAY_NETWORK_CIDR         # CIDR to configure $PUBLIC_BRIDGE, e.g. 172.24.4.211/24


For Nsx-v:
----------

Q_PLUGIN=vmware_nsx_v

NSXV_MANAGER_URI        # URL for NSXv manager (e.g - https://management_ip).
NSXV_USER               # NSXv username.
NSXV_PASSWORD           # NSXv password.
NSXV_CLUSTER_MOID       # clusters ids containing OpenStack hosts.
NSXV_DATACENTER_MOID    # datacenter id for edge deployment.
NSXV_RESOURCE_POOL_ID   # resource-pool id for edge deployment.
NSXV_AVAILABILITY_ZONES # alternative resource-pools/data stores ids/edge_ha for edge deployment
NSXV_DATASTORE_ID       # datastore id for edge deployment.
NSXV_EXTERNAL_NETWORK   # id of logic switch for physical network connectivity.
NSXV_VDN_SCOPE_ID       # network scope id for VXLAN virtual-wires.
NSXV_DVS_ID             # Dvs id for VLAN based networks.
NSXV_BACKUP_POOL        # backup edge pools management range,
                        # <edge_type>:[edge_size]:<minimum_pooled_edges>:<maximum_pooled_edges>.
                        # edge_type:'service'(service edge) or 'vdr'(distributed edge).
                        # edge_size: 'compact', 'large'(by default), 'xlarge' or 'quadlarge'.

# To enable the metadata service, the following variables should be also set:
NSXV_MGT_NET_PROXY_IPS      # management network IP address for metadata proxy.
NSXV_MGT_NET_PROXY_NETMASK  # management network netmask for metadata proxy.
NSXV_NOVA_METADATA_IPS      # IP addresses used by Nova metadata service.
NSXV_NOVA_METADATA_PORT     # TCP Port used by Nova metadata server.
NSXV_MGT_NET_MOID           # Network ID for management network connectivity
