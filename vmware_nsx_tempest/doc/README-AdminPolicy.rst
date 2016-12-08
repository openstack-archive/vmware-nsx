Admin Policy
============

Admin policy, neutron extension secuirty-group-policy provides organization
to enforce traffic forwarding utilizing NSX security policy.

The "Admin Policy" feature is admin priviledge, normal project/tenant is not
able to create security-group-policy.

This feature can be enabled from devstack or manually.

Enable security-group-policy extention at bring up devstack
===========================================================

You can enable security-group-policy when starting up devstack.
However, if the policy-id does not exist, starting will fail.

To enable it, add the following tokens to local.conf:

    NSXV_USE_NSX_POLICIES=True
    NSXV_DEFAULT_POLICY_ID=policy-11
    NSXV_ALLOW_TENANT_RULES_WITH_POLICY=True

Change values according to your needs though.

Enable security-group-policy extention manually
===============================================

Instruction is from the view of devstack

#. Add following items to /etc/neutron/policy.json::

    "create_security_group:logging": "rule:admin_only",
    "update_security_group:logging": "rule:admin_only",
    "get_security_group:logging": "rule:admin_only",
    "create_security_group:provider": "rule:admin_only",
    "create_port:provider_security_groups": "rule:admin_only",
    "create_security_group:policy": "rule:admin_only",
    "update_security_group:policy": "rule:admin_only",

#. Add following key=value pair to session [nsxv] of /etc/neutron/plugin/vmware/nsx.ini::

    use_nsx_policies = True
    default_policy_id = policy-11
    allow_tenant_rules_with_policy = False

    # NOTE: For automation, set allow_tenant_rules_with_policy to True

tempest.conf
============

At session [nsxv] add the following 3 key=value pair:

    default_policy_id = policy-11
    alt_policy_id = policy-22
    allow_tenant_rules_with_policy = False

    # NOTE: default_policy_id and allow_tenant_rules_with_policy need to match nsx.ini

default_policy_id and alt_policy_id:

    For API tests, both must exist at NSX.

    For scenario tests, please refer to nsxv/scenario/test_admin_policy_basic_ops.py

    In short::

    policy-11 (policy-AA at script & test-plan) firewall rules::
        action-1: dhcp-in/any/policy-security-groups/dhcp/Allow
        action-2: dhcp-out/policy-security-groups/dhcp/Allow
        action-3: ping-in/any/policy-security-groups/ICMP/Allow
        action-4: ping-out/policy-security-groups/any/ICMP/Allow/
        action-5: ssh-in/any/policy-security-groups/SSH/Allow/
        action-6: ssh-in/any/policy-security-groups/SSH/Allow/
        action-7: http-ok/any/policy-security-groups/HTTP,HTTPS/Allow/
        action-8: sorry-nothing-allowed/any/policy-security-groups/Any/Reject

        You can import policy-AA to NSX using the admin-policy-AA.blueprint

    policy-22 (policy-BB at script & test-plan) firewall rules::
        action-1: dhcp-in/any/policy-security-groups/dhcp/Allow
        action-2: dhcp-out/policy-security-groups/dhcp/Allow
        action-3: group-ping/policy-security-groups/policy-security-groups/ICMP/Allow/
        action-4: ssh-in/any/policy-security-groups/SSH/Allow/
        action-5: ssh-in/any/policy-security-groups/SSH/Allow/
        action-6: http-ok/any/policy-security-groups/HTTP,HTTPS/Allow/
        pction-7: sorry-nothing-allowed/any/policy-security-groups/Any/Reject

        NOTE on ping: same as policy-11 but only allowed from policy-security-groups
        You can import policy-BB to NSX using the admin-policy-BB.blueprint
