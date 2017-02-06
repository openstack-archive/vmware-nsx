# VMware NSX OpenStack Neutron REST API Extensions



## General Information
This document describes the REST API extensions integrated with the
VMware [NSX OpenStack neutron plugins](https://wiki.openstack.org/wiki/Neutron/VMware_NSX_plugins).
The intent of this document is to supplement the
[OpenStack neutron REST API guide](https://developer.openstack.org/api-ref/networking/v2) by describing
the extensions implemented by the VMware NSX neutron plugins.

The VMware NSX neutron plugins implement
[Neutron API extensions](https://wiki.openstack.org/wiki/NeutronDevelopment#API_Extensions)
by defining new top-level REST resources, operations (e.g. verbs) and attribute extensions
to existing neutron REST API entities (depending on the extension). As all extensions apply
to the neutron REST API, the
[general information](https://developer.openstack.org/api-ref/networking/v2/#general-information)
for the neutron API applies here as well.

The VMware NSX neutron extensions supported by your plugin will depend on the version
of VMware NSX used. Two versions described herein are:
  * [NSX for vSphere](https://www.vmware.com/support/pubs/nsx_pubs.html) aka 'NSX-v'.
  * [NSX Transformers](https://my.vmware.com/web/vmware/details?productId=580&downloadGroup=NSX-v3-101)
    aka 'NSX-v3'.



## API Reference
  * [Advanced Service Providers](#advanced-service-providers)
  * [DHCP MTU](#dhcp-mtu)
  * [DNS Search Domain](#dns-search-domain)
  * [MAC Learning](#mac-learning)
  * [Provider Networks](#provider-networks)
  * [Provider Security Groups](#provider-security-groups)
  * [Router Size](#router-size)
  * [Router Type](#router-type)
  * [Security Group Rule IP Prefix](#security-group-rule-ip-prefix)
  * [Security Group Logging](#security-group-logging)
  * [VNIC Index](#vnic-index)



### [Advanced Service Providers](#advanced-service-providers)

###### Description
This resource attribute extensions adds the `advanced_service_providers`
attribute to neutron [subnets](https://developer.openstack.org/api-ref/networking/v2/#subnets).
This read-only attribute is a list of NSX advanced service provider IDs associated on a per-subnet
basis. The advanced service provider IDs are populated by the plugin automatically
when interfacing with the NSX manager backend.

###### Extension Type
Resource attribute extension.

###### Supported NSX Versions
NSX-v.

###### Supported Verbs
None (read-only).

###### Extended Resource
[subnet](https://developer.openstack.org/api-ref/networking/v2/#subnets)

###### Extension Attribute(s)
  * `advanced_service_providers`: A list of NSX advanced service provider IDs (in `string` format)
    associated with the subnet.

###### Example Response
```json
{
    "subnet":{
        "description":"",
        "enable_dhcp":true,
        "network_id":"7ea9964a-45b0-45eb-8b67-da47ce53cf5f",
        "tenant_id":"64b39295ba3942ca8be4a8a25d9b5157",
        "created_at":"2016-08-28T13:49:32",
        "dns_nameservers":[

        ],
        "updated_at":"2016-08-28T13:49:32",
        "gateway_ip":"10.0.0.1",
        "ipv6_ra_mode":null,
        "allocation_pools":[
            {
                "start":"10.0.0.2",
                "end":"10.0.0.254"
            }
        ],
        "host_routes":[

        ],
        "advanced_service_providers":[
            "edge-1",
            "edge-2"
        ],
        "ip_version":4,
        "ipv6_address_mode":null,
        "cidr":"10.0.0.0/24",
        "id":"f1153a28-8f36-4547-a024-3eb08e4e44b1",
        "subnetpool_id":null,
        "name":"private-subnet"
    }
}
```



### [DHCP MTU](#dhcp-mtu)

###### Description
Extends neutron [subnets](https://developer.openstack.org/api-ref/networking/v2/#subnets)
providing the ability to specify per-subnet DHCP MTU via the
`dhcp_mtu` attribute.

###### Extension Type
Resource attribute extension.

###### Supported NSX Versions
NSX-v.

###### Supported Verbs
POST, PUT

###### Extended Resource
[subnet](https://developer.openstack.org/api-ref/networking/v2/#subnets)

###### Extension Attribute(s)
  * `dhcp_mtu`: The DHCP MTU to use for the associated subnet. Must be a valid DHCP
     MTU value between 68 and 65535.

###### Example Response
```json
{
    "subnet":{
        "description":"",
        "enable_dhcp":true,
        "network_id":"91abf611-44a8-4c5e-bf19-92f91ee34d6d",
        "tenant_id":"16f24183154f4e51bebe3f10e810e19a",
        "created_at":"2016-09-16T16:28:34",
        "dhcp_mtu": 8048,
        "dns_nameservers":[

        ],
        "updated_at":"2016-09-16T16:28:34",
        "gateway_ip":"192.168.1.1",
        "ipv6_ra_mode":null,
        "allocation_pools":[
            {
                "start":"192.168.1.9",
                "end":"192.168.1.99"
            }
        ],
        "host_routes":[

        ],
        "revision_number":2,
        "ip_version":4,
        "ipv6_address_mode":null,
        "cidr":"192.168.1.0/24",
        "project_id":"16f24183154f4e51bebe3f10e810e19a",
        "id":"8300a4ff-09db-4f64-955b-7e215044c9c3",
        "subnetpool_id":null,
        "name":"snet1"
    }
}

```



### [DNS Search Domain](#dns-search-domain)

###### Description
Extends neutron [subnets](https://developer.openstack.org/api-ref/networking/v2/#subnets)
providing the ability to specify per-subnet DNS search via the
`dns_search_domain` attribute.

###### Extension Type
Resource attribute extension.

###### Supported NSX Versions
NSX-v.

###### Supported Verbs
POST, PUT

###### Extended Resource
[subnet](https://developer.openstack.org/api-ref/networking/v2/#subnets)

###### Extension Attribute(s)
  * `dns_search_domain`: The DNS search domain to use for networking on the associated
    subnet. The value must be a valid DNS search domain.

###### Example Response
```json
{
    "subnet":{
        "description":"",
        "enable_dhcp":true,
        "network_id":"91abf611-44a8-4c5e-bf19-92f91ee34d6d",
        "tenant_id":"16f24183154f4e51bebe3f10e810e19a",
        "created_at":"2016-09-16T16:28:34",
        "dns_search_domain": "example.com",
        "dns_nameservers":[

        ],
        "updated_at":"2016-09-16T16:28:34",
        "gateway_ip":"192.168.1.1",
        "ipv6_ra_mode":null,
        "allocation_pools":[
            {
                "start":"192.168.1.9",
                "end":"192.168.1.99"
            }
        ],
        "host_routes":[

        ],
        "revision_number":2,
        "ip_version":4,
        "ipv6_address_mode":null,
        "cidr":"192.168.1.0/24",
        "project_id":"16f24183154f4e51bebe3f10e810e19a",
        "id":"8300a4ff-09db-4f64-955b-7e215044c9c3",
        "subnetpool_id":null,
        "name":"snet1"
    }
}

```



### [MAC Learning](#mac-learning)

###### Description
Extends neutron [ports](https://developer.openstack.org/api-ref/networking/v2/#ports)
providing the ability to enable MAC learning on the associated port via the
`mac_learning_enabled` attribute.

###### Extension Type
Resource attribute extension.

###### Supported NSX Versions
NSX-v3.

###### Supported Verbs
POST, PUT

###### Extended Resource
[ports](https://developer.openstack.org/api-ref/networking/v2/#ports)

###### Extension Attribute(s)
  * `mac_learning_enabled`: A boolean value that indicates if MAC Learning is enabled
     on the associated port.

###### Example Response
```json
{
    "port":{
        "allowed_address_pairs":[

        ],
        "extra_dhcp_opts":[

        ],
        "updated_at":"2016-09-16T16:28:35",
        "device_owner":"network:dhcp",
        "revision_number":3,
        "port_security_enabled":false,
        "mac_learning_enabled":true,
        "fixed_ips":[
            {
                "subnet_id":"8300a4ff-09db-4f64-955b-7e215044c9c3",
                "ip_address":"192.168.1.9"
            }
        ],
        "id":"0093f4cc-f936-448a-9a25-ae57f66a6d57",
        "security_groups":[

        ],
        "binding:vif_details":{
            "port_filter":true,
            "nsx-logical-switch-id":"785f0bb4-3341-4e8c-abc4-cd3068f333f2"
        },
        "binding:vif_type":"ovs",
        "mac_address":"fa:16:3e:2d:19:96",
        "project_id":"16f24183154f4e51bebe3f10e810e19a",
        "status":"ACTIVE",
        "binding:host_id":"l2b",
        "description":"",
        "device_id":"dhcp559b5e8d-0b9d-5e4c-a8ff-819ade66d01d-91abf611-44a8-4c5e-bf19-92f91ee34d6d",
        "name":"",
        "admin_state_up":true,
        "network_id":"91abf611-44a8-4c5e-bf19-92f91ee34d6d",
        "tenant_id":"16f24183154f4e51bebe3f10e810e19a",
        "created_at":"2016-09-16T16:28:35",
        "provider_security_groups":[

        ],
        "binding:vnic_type":"normal"
    }
}

```



### [Provider Networks](#provider-networks)

###### Description
The VMware NSX neutron plugins also support the
[neutron provider networks extension](https://docs.openstack.org/admin-guide/networking-adv-features.html#provider-networks).
Provider network extensions add [attributes](https://docs.openstack.org/admin-guide/networking-adv-features.html#provider-attributes)
to neutron [networks](https://developer.openstack.org/api-ref/networking/v2/#networks)
enabling providers to map virtual networks onto physical networks, or in this case
onto physical networks in NSX.

###### Extension Type
Resource attribute extensions.

###### Supported NSX Versions
NSX-v3, NSX-v.

###### Supported Verbs
See the
[neutron provider networks extension](https://developer.openstack.org/api-ref/networking/v2/#networks-provider-extended-attributes-networks)
API reference documentation.

###### Extended Resource
  * [networks](https://developer.openstack.org/api-ref/networking/v2/#networks)

###### Extension Attribute(s)
  * `provider:network_type`: For the NSX plugins valid values are `flat` or `vlan`.
  * `provider:physical_network`: For the NSX plugins, this value should be the UUID
     of the NSX transport zone to bridge the network on.
  * `provider:segmentation_id`: For the NSX plugins, this value should be set to the
     VLAN identifier of the physical network, or unset of the network type is `flat`.

###### Example Response
```json
{
    "network": {
        "status": "ACTIVE",
        "subnets": [
            "54d6f61d-db07-451c-9ab3-b9609b6b6f0b"
        ],
        "name": "private-network",
        "router:external": false,
        "admin_state_up": true,
        "tenant_id": "4fd44f30292945e481c7b8a0c8908869",
        "created_at": "2016-03-08T20:19:41",
        "mtu": 0,
        "shared": true,
        "port_security_enabled": true,
        "provider:network_type": "vlan",
        "provider:physical_network": "00cff66d-5fa8-4fda-bd7d-87e372fe86c7",
        "provider:segmentation_id": 101,
        "updated_at": "2016-03-08T20:19:41",
        "id": "d32019d3-bc6e-4319-9c1d-6722fc136a22"
    }
}
```



### [Provider Security Groups](#provider-security-groups)

###### Description
This extension enables support for provider-only created/managed neutron
[security groups](https://developer.openstack.org/api-ref/networking/v2/#security-groups-security-groups).
To enable this support a `provider` boolean attribute is added to neutron security
groups indicating if the group is a provider-only group. Additionally, neutron
[ports](https://developer.openstack.org/api-ref/networking/v2/#ports) are extended with
a `provider_security_groups` attribute that indicates a list of provider-only
security groups belonging to the said port.

###### Extension Type
Resource attribute extensions.

###### Supported NSX Versions
NSX-v3, NSX-v.

###### Supported Verbs
The `provider` attribute on neutron security groups is only settable during creation (POST).
However the `provider_security_groups` attribute on ports supports both POST and PUT.

###### Extended Resource
  * [ports](https://developer.openstack.org/api-ref/networking/v2/#ports)
  * [security groups](https://developer.openstack.org/api-ref/networking/v2/#security-groups-security-groups)

###### Extension Attribute(s)
  * `provider`: A boolean indicating if the security group is provider-only.
  * `provider_security_groups`: A list of provider-only security group UUIDs associated
    with a said port.

###### Example Response

GET security-group
```json
{
    "security_group":{
        "logging":false,
        "description":"My security group",
        "tenant_id":"1efff4cd762944a6bbdb6d3bba0468ef",
        "created_at":"2016-09-16T16:34:55",
        "updated_at":"2016-09-16T16:34:55",
        "provider":true,
        "security_group_rules":[
            {
                "local_ip_prefix":null,
                "direction":"ingress",
                "protocol":null,
                "description":null,
                "port_range_max":null,
                "updated_at":"2016-09-16T16:34:55",
                "revision_number":1,
                "id":"98acaf6e-0b9d-45d6-b4ec-d9dd0df3a52b",
                "remote_group_id":"3a729518-0214-44d6-9f25-704db70710a5",
                "remote_ip_prefix":null,
                "created_at":"2016-09-16T16:34:55",
                "security_group_id":"3a729518-0214-44d6-9f25-704db70710a5",
                "tenant_id":"1efff4cd762944a6bbdb6d3bba0468ef",
                "port_range_min":null,
                "ethertype":"IPv6",
                "project_id":"1efff4cd762944a6bbdb6d3bba0468ef"
            },
            {
                "local_ip_prefix":null,
                "direction":"egress",
                "protocol":null,
                "description":null,
                "port_range_max":null,
                "updated_at":"2016-09-16T16:34:55",
                "revision_number":1,
                "id":"9fba2f50-9eef-48c0-8b45-c2fae98e7294",
                "remote_group_id":null,
                "remote_ip_prefix":null,
                "created_at":"2016-09-16T16:34:55",
                "security_group_id":"3a729518-0214-44d6-9f25-704db70710a5",
                "tenant_id":"1efff4cd762944a6bbdb6d3bba0468ef",
                "port_range_min":null,
                "ethertype":"IPv4",
                "project_id":"1efff4cd762944a6bbdb6d3bba0468ef"
            },
            {
                "local_ip_prefix":null,
                "direction":"egress",
                "protocol":null,
                "description":null,
                "port_range_max":null,
                "updated_at":"2016-09-16T16:34:55",
                "revision_number":1,
                "id":"c2eecacb-5328-4081-8fe7-701777fbb2a1",
                "remote_group_id":null,
                "remote_ip_prefix":null,
                "created_at":"2016-09-16T16:34:55",
                "security_group_id":"3a729518-0214-44d6-9f25-704db70710a5",
                "tenant_id":"1efff4cd762944a6bbdb6d3bba0468ef",
                "port_range_min":null,
                "ethertype":"IPv6",
                "project_id":"1efff4cd762944a6bbdb6d3bba0468ef"
            },
            {
                "local_ip_prefix":null,
                "direction":"ingress",
                "protocol":null,
                "description":null,
                "port_range_max":null,
                "updated_at":"2016-09-16T16:34:55",
                "revision_number":1,
                "id":"e073a066-bc14-41e7-939b-84ec4af0606f",
                "remote_group_id":"3a729518-0214-44d6-9f25-704db70710a5",
                "remote_ip_prefix":null,
                "created_at":"2016-09-16T16:34:55",
                "security_group_id":"3a729518-0214-44d6-9f25-704db70710a5",
                "tenant_id":"1efff4cd762944a6bbdb6d3bba0468ef",
                "port_range_min":null,
                "ethertype":"IPv4",
                "project_id":"1efff4cd762944a6bbdb6d3bba0468ef"
            }
        ],
        "revision_number":1,
        "provider":false,
        "project_id":"1efff4cd762944a6bbdb6d3bba0468ef",
        "id":"3a729518-0214-44d6-9f25-704db70710a5",
        "name":"my provider group"
    }
}
```

GET port
```json
{
    "port":{
        "allowed_address_pairs":[

        ],
        "extra_dhcp_opts":[

        ],
        "updated_at":"2016-09-16T16:28:35",
        "device_owner":"network:dhcp",
        "revision_number":3,
        "port_security_enabled":false,
        "provider_security_groups":["910da4ff-09db-4f64-955b-7e215044ca56"],
        "fixed_ips":[
            {
                "subnet_id":"8300a4ff-09db-4f64-955b-7e215044c9c3",
                "ip_address":"192.168.1.9"
            }
        ],
        "id":"0093f4cc-f936-448a-9a25-ae57f66a6d57",
        "security_groups":[

        ],
        "binding:vif_details":{
            "port_filter":true,
            "nsx-logical-switch-id":"785f0bb4-3341-4e8c-abc4-cd3068f333f2"
        },
        "binding:vif_type":"ovs",
        "mac_address":"fa:16:3e:2d:19:96",
        "project_id":"16f24183154f4e51bebe3f10e810e19a",
        "status":"ACTIVE",
        "binding:host_id":"l2b",
        "description":"",
        "device_id":"dhcp559b5e8d-0b9d-5e4c-a8ff-819ade66d01d-91abf611-44a8-4c5e-bf19-92f91ee34d6d",
        "name":"",
        "admin_state_up":true,
        "network_id":"91abf611-44a8-4c5e-bf19-92f91ee34d6d",
        "tenant_id":"16f24183154f4e51bebe3f10e810e19a",
        "created_at":"2016-09-16T16:28:35",
        "provider_security_groups":[

        ],
        "binding:vnic_type":"normal"
    }
}

```


### [Router Size](#router-size)

###### Description
Extends neutron [routers](https://developer.openstack.org/api-ref/networking/v2/#routers-routers)
by adding the `router_size` attribute to support configuration of NSX-v
edge size.

###### Extension Type
Resource attribute extension.

###### Supported NSX Versions
NSX-v.

###### Supported Verbs
POST, PUT

###### Extended Resource
[routers](https://developer.openstack.org/api-ref/networking/v2/#routers-routers)

###### Extension Attribute(s)
  * `router_size`: The NSX-v edge size to use.

###### Example Response
```json
{
    "router":{
        "admin_state_up":true,
        "availability_zone_hints":[

        ],
        "availability_zones":[
            "nova"
        ],
        "description":"",
        "router_size":"xlarge",
        "distributed":false,
        "external_gateway_info":{
            "enable_snat":true,
            "external_fixed_ips":[
                {
                    "ip_address":"172.24.4.6",
                    "subnet_id":"b930d7f6-ceb7-40a0-8b81-a425dd994ccf"
                },
                {
                    "ip_address":"2001:db8::9",
                    "subnet_id":"0c56df5d-ace5-46c8-8f4c-45fa4e334d18"
                }
            ],
            "network_id":"ae34051f-aa6c-4c75-abf5-50dc9ac99ef3"
        },
        "ha":false,
        "id":"f8a44de0-fc8e-45df-93c7-f79bf3b01c95",
        "name":"router1",
        "routes":[

        ],
        "status":"ACTIVE",
        "tenant_id":"0bd18306d801447bb457a46252d82d13"
    }
}
```



### [Router Type](#router-type)

###### Description
Extends neutron [routers](https://developer.openstack.org/api-ref/networking/v2/#routers-routers)
by adding the `router_type` attribute to support configuration of NSX-v
router type.

###### Extension Type
Resource attribute extension.

###### Supported NSX Versions
NSX-v.

###### Supported Verbs
POST, PUT

###### Extended Resource
[routers](https://developer.openstack.org/api-ref/networking/v2/#routers-routers)

###### Extension Attribute(s)
  * `router_type`: The NSX-v router type. Must be either `shared` or `exclusive`.

###### Example Response
```json
{
    "router":{
        "admin_state_up":true,
        "availability_zone_hints":[

        ],
        "availability_zones":[
            "nova"
        ],
        "description":"",
        "router_type":"exclusive",
        "distributed":false,
        "external_gateway_info":{
            "enable_snat":true,
            "external_fixed_ips":[
                {
                    "ip_address":"172.24.4.6",
                    "subnet_id":"b930d7f6-ceb7-40a0-8b81-a425dd994ccf"
                },
                {
                    "ip_address":"2001:db8::9",
                    "subnet_id":"0c56df5d-ace5-46c8-8f4c-45fa4e334d18"
                }
            ],
            "network_id":"ae34051f-aa6c-4c75-abf5-50dc9ac99ef3"
        },
        "ha":false,
        "id":"f8a44de0-fc8e-45df-93c7-f79bf3b01c95",
        "name":"router1",
        "routes":[

        ],
        "status":"ACTIVE",
        "tenant_id":"0bd18306d801447bb457a46252d82d13"
    }
}

```



### [Security Group Rule IP Prefix](#security-group-rule-ip-prefix)

###### Description
Extends neutron
[security group rules](https://developer.openstack.org/api-ref/networking/v2/#security-group-rules-security-group-rules)
by adding a `local_ip_prefix` attribute allowing rules to be created with IP prefixes.

###### Extension Type
Resource attribute extension.

###### Supported NSX Versions
NSX-v3, NSXv.

###### Supported Verbs
POST; using an IP prefix on a rule can only be done when creating the rule.

###### Extended Resource
[security group rules](https://developer.openstack.org/api-ref/networking/v2/#security-group-rules-security-group-rules)

###### Extension Attribute(s)
  * `local_ip_prefix`: The local IP prefix used for the rule.

###### Example Response
```json
{
    "security_group_rule":{
        "direction":"ingress",
        "port_range_min":"80",
        "ethertype":"IPv4",
        "port_range_max":"80",
        "protocol":"tcp",
        "local_prefix_ip":"239.240.1.0/16",
        "remote_prefix_ip":"192.168.1.0/24",
        "security_group_id":"a7734e61-b545-452d-a3cd-0189cbd9747a"
    }
}

```



### [Security Group Logging](#security-group-logging)

###### Description
Extends neutron
[security groups](https://developer.openstack.org/api-ref/networking/v2/#security-groups-security-groups)
with a boolean attribute `logging` to enable per security group logging on NSX.

###### Extension Type
Resource attribute extension.

###### Supported NSX Versions
NSX-v3, NSX-v.

###### Supported Verbs
POST, PUT.

###### Extended Resource
[security groups](https://developer.openstack.org/api-ref/networking/v2/#security-groups-security-groups)

###### Extension Attribute(s)
  * `logging`: A boolean attribute indicating if logging is enabled for the group.

###### Example Response
```json
{
    "security_group":{
        "Description":"logged secgroup",
        "id":"85cc3048-abc3-43cc-89b3-377341426ac5",
        "name":"logged secgroup",
        "logging":true,
        "security_group_rules":[
            {
                "direction":"egress",
                "ethertype":"IPv6",
                "id":"3c0e45ff-adaf-4124-b083-bf390e5482ff",
                "port_range_max":null,
                "port_range_min":null,
                "protocol":null,
                "remote_group_id":null,
                "remote_ip_prefix":null,
                "security_group_id":"85cc3048-abc3-43cc-89b3-377341426ac5",
                "tenant_id":"e4f50856753b4dc6afee5fa6b9b6c550"
            },
            {
                "direction":"egress",
                "ethertype":"IPv4",
                "id":"93aa42e5-80db-4581-9391-3a608bd0e448",
                "port_range_max":null,
                "port_range_min":null,
                "protocol":null,
                "remote_group_id":null,
                "remote_ip_prefix":null,
                "security_group_id":"85cc3048-abc3-43cc-89b3-377341426ac5",
                "tenant_id":"e4f50856753b4dc6afee5fa6b9b6c550"
            },
            {
                "direction":"ingress",
                "ethertype":"IPv6",
                "id":"c0b09f00-1d49-4e64-a0a7-8a186d928138",
                "port_range_max":null,
                "port_range_min":null,
                "protocol":null,
                "remote_group_id":"85cc3048-abc3-43cc-89b3-377341426ac5",
                "remote_ip_prefix":null,
                "security_group_id":"85cc3048-abc3-43cc-89b3-377341426ac5",
                "tenant_id":"e4f50856753b4dc6afee5fa6b9b6c550"
            },
            {
                "direction":"ingress",
                "ethertype":"IPv4",
                "id":"f7d45c89-008e-4bab-88ad-d6811724c51c",
                "port_range_max":null,
                "port_range_min":null,
                "protocol":null,
                "remote_group_id":"85cc3048-abc3-43cc-89b3-377341426ac5",
                "remote_ip_prefix":null,
                "security_group_id":"85cc3048-abc3-43cc-89b3-377341426ac5",
                "tenant_id":"e4f50856753b4dc6afee5fa6b9b6c550"
            }
        ],
        "tenant_id":"e4f50856753b4dc6afee5fa6b9b6c550"
    }
}

```



### [VNIC Index](#vnic-index)

###### Description
Extends neutron
[ports](https://developer.openstack.org/api-ref/networking/v2/#ports) by adding
the `vnic_index` attribute enabling per-port assignment of a VNIC index.

###### Extension Type
Resource attribute extension.

###### Supported NSX Versions
NSX-v.

###### Supported Verbs
POST, PUT.

###### Extended Resource
[ports](https://developer.openstack.org/api-ref/networking/v2/#ports)

###### Extension Attribute(s)
  * `vnic_index`: The VNIC index (integer value) assigned to the port.

###### Example Response
```json
{
    "port":{
        "status":"ACTIVE",
        "vnic_index":3,
        "name":"",
        "allowed_address_pairs":[

        ],
        "admin_state_up":true,
        "network_id":"a87cc70a-3e15-4acf-8205-9b711a3531b7",
        "tenant_id":"7e02058126cc4950b75f9970368ba177",
        "created_at":"2016-03-08T20:19:41",
        "extra_dhcp_opts":[

        ],
        "device_owner":"network:router_interface",
        "mac_address":"fa:16:3e:23:fd:d7",
        "fixed_ips":[
            {
                "subnet_id":"a0304c3a-4f08-4c43-88af-d796509c97d2",
                "ip_address":"10.0.0.1"
            }
        ],
        "id":"46d4bfb9-b26e-41f3-bd2e-e6dcc1ccedb2",
        "updated_at":"2016-03-08T20:19:41",
        "security_groups":[

        ],
        "device_id":"5e3898d7-11be-483e-9732-b2f5eccd2b2e"
    }
}
```
