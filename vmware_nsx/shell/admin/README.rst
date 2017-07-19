Admin Utility
=============

Introduction
------------
Purpose of this script is to build a framework which can be leveraged to build
utilities to help the on-field ops in system debugging.


Adding custom functions
-----------------------
Refer to the security groups example for reference implementation under,
admin/plugins/nsx_v3/resources/securitygroups.py


Adding new functions is fairly straightforward:

* Define the function under appropriate package. We use neutron callbacks to provide hooks.
  So your function definition should be like,

::
  def function(resource, event, trigger, **kwargs)


* Add the Resources and Operations enums if they don't exist.

::
  class Operations(object):
      NEUTRON_CLEAN = 'neutron_clean'

::
 nsxv3_resources = {
    constants.SECURITY_GROUPS: Resource(constants.SECURITY_GROUPS, ops)
 }


* In resource.py, add the function to the callback registry.

::
    registry.subscribe(neutron_clean_security_groups,
                       Resources.SECURITY_GROUPS.value,
                       Operations.NEUTRON_CLEAN.value)


* To test, do

::
    cd vmware-nsx/shell 

    sudo pip install -e .

    nsxadmin -r <resource_name_you_added> -o <operation_you_added>


TODO
----

* Use Cliff
* Auto complete command line args.


Directory Structure
-------------------
admin/

  plugins/
      common/
        Contains code specific to different plugin versions.
      nsx_v3/
        resources/
          Contains modules for various resources supported by the
          admin utility. These modules contains methods to perform
          operations on these resources.


Installation
------------
::
  sudo pip install -e .

Usage
-----
::
 nsxadmin -r <resource> -o <operation>


Example
-------
::
     $ nsxadmin -r security-groups -o list
     ==== [NSX] List Security Groups ====
     Firewall Sections
     +------------------------------------------------+--------------------------------------+
     | display_name                                   | id                                   |
     |------------------------------------------------+--------------------------------------|
     | default - 261343f8-4f35-4e57-9cc7-6c4fc7723b72 | 91a05fbd-054a-48b6-8e60-3b5d445be8c7 |
     | default - 823247b6-bdb3-47be-8bac-0d1114fc1ad7 | 78116d4a-de77-4a8f-b3e5-e76f458840ea |
     | OS default section for security-groups         | 10a2fc6c-29c9-4d8d-ac2c-b24aafa15c79 |
     | Default Layer3 Section                         | e479e404-e712-4adb-879c-e432d510c056 |
     +------------------------------------------------+--------------------------------------+
     Firewall NS Groups
     +------------------------------------------------+--------------------------------------+
     | display_name                                   | id                                   |
     |------------------------------------------------+--------------------------------------|
     | NSGroup Container                              | c0b26e82-d49b-49f0-b68e-7449a59366e9 |
     | default - 261343f8-4f35-4e57-9cc7-6c4fc7723b72 | 2e5b5ca1-f687-4556-8130-9524b313474b |
     | default - 823247b6-bdb3-47be-8bac-0d1114fc1ad7 | b5cd9ae4-42b5-47a7-a1bf-9767ac62466e |
     +------------------------------------------------+--------------------------------------+
     ==== [NEUTRON] List Security Groups Mappings ====
     security-groups
     +---------+--------------------------------------+-----------------------------------------------------------+----------------------+
     | name    | id                                   | section-uri                                               | nsx-securitygroup-id |
     +---------+--------------------------------------+-----------------------------------------------------------+----------------------+
     | default | f785c82a-5b28-42ac-aa0a-ad56720ccbbc | /api/4.0/firewall/globalroot-0/config/layer3sections/1006 | securitygroup-12     |
     +---------+--------------------------------------+-----------------------------------------------------------+----------------------+

     $ nsxadmin -r security-groups -o list -f json
     ==== [NSX] List Security Groups ====
     {
         "Firewall Sections": [
             {
                 "display_name": "default - 261343f8-4f35-4e57-9cc7-6c4fc7723b72",
                 "id": "91a05fbd-054a-48b6-8e60-3b5d445be8c7"
             },
             {
                 "display_name": "default - 823247b6-bdb3-47be-8bac-0d1114fc1ad7",
                 "id": "78116d4a-de77-4a8f-b3e5-e76f458840ea"
             },
             {
                 "display_name": "OS default section for security-groups",
                 "id": "10a2fc6c-29c9-4d8d-ac2c-b24aafa15c79"
             },
             {
                 "display_name": "Default Layer3 Section",
                 "id": "e479e404-e712-4adb-879c-e432d510c056"
             }
         ]
     }
     {
         "Firewall NS Groups": [
             {
                 "display_name": "NSGroup Container",
                 "id": "c0b26e82-d49b-49f0-b68e-7449a59366e9"
             },
             {
                 "display_name": "default - 261343f8-4f35-4e57-9cc7-6c4fc7723b72",
                 "id": "2e5b5ca1-f687-4556-8130-9524b313474b"
             },
             {
                 "display_name": "default - 823247b6-bdb3-47be-8bac-0d1114fc1ad7",
                 "id": "b5cd9ae4-42b5-47a7-a1bf-9767ac62466e"
             }
         ]
     }
     ==== [NEUTRON] List Security Groups Mappings ====
     security-groups
     {
         "security-groups": [
             {
                "id": "f785c82a-5b28-42ac-aa0a-ad56720ccbbc",
                "name": "default",
                "nsx-securitygroup-id": "securitygroup-12",
                "section-uri": "/api/4.0/firewall/globalroot-0/config/layer3sections/1006"
             }
     }

Upgrade Steps (Version 1.0.0 to Version 1.1.0)
----------------------------------------------

1. Upgrade NSX backend from version 1.0.0 to version 1.1.0

2. Create a DHCP-Profile and a Metadata-Proxy in NSX backend

3. Stop Neutron

4. Install version 1.1.0 Neutron plugin

5. Run admin tools to migrate version 1.0.0 objects to version 1.1.0 objects

   * nsxadmin -r metadata-proxy -o nsx-update --property metadata_proxy_uuid=<UUID of Metadata-Proxy created in Step 2>

   * nsxadmin -r dhcp-binding -o nsx-update --property dhcp_profile_uuid=<UUID of DHCP-Profile created in Step 2>

6. Start Neutron

7. Make sure /etc/nova/nova.conf has
   metadata_proxy_shared_secret = <Secret of Metadata-Proxy created in Step 2>

8. Restart VMs or ifdown/ifup their network interface to get new DHCP options


Help
----
::
 $ nsxadmin --help
