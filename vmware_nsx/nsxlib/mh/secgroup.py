# Copyright 2014 VMware, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron_lib import constants
from neutron_lib import exceptions
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import excutils

from vmware_nsx.common import utils
from vmware_nsx.nsxlib import mh as nsxlib

HTTP_GET = "GET"
HTTP_POST = "POST"
HTTP_DELETE = "DELETE"
HTTP_PUT = "PUT"

SECPROF_RESOURCE = "security-profile"

LOG = log.getLogger(__name__)


def mk_body(**kwargs):
    """Convenience function creates and dumps dictionary to string.

    :param kwargs: the key/value pirs to be dumped into a json string.
    :returns: a json string.
    """
    return jsonutils.dumps(kwargs, ensure_ascii=False)


def query_security_profiles(cluster, fields=None, filters=None):
    return nsxlib.get_all_query_pages(
        nsxlib._build_uri_path(SECPROF_RESOURCE,
                               fields=fields,
                               filters=filters),
        cluster)


def create_security_profile(cluster, tenant_id, neutron_id, security_profile):
    """Create a security profile on the NSX backend.

    :param cluster: a NSX cluster object reference
    :param tenant_id: identifier of the Neutron tenant
    :param neutron_id: neutron security group identifier
    :param security_profile: dictionary with data for
    configuring the NSX security profile.
    """
    path = "/ws.v1/security-profile"
    # Allow all dhcp responses and all ingress traffic
    hidden_rules = {'logical_port_egress_rules':
                    [{'ethertype': 'IPv4',
                      'protocol': constants.PROTO_NUM_UDP,
                      'port_range_min': constants.DHCP_RESPONSE_PORT,
                      'port_range_max': constants.DHCP_RESPONSE_PORT,
                      'ip_prefix': '0.0.0.0/0'}],
                    'logical_port_ingress_rules':
                    [{'ethertype': 'IPv4'},
                     {'ethertype': 'IPv6'}]}
    display_name = utils.check_and_truncate(security_profile.get('name'))
    # NOTE(salv-orlando): neutron-id tags are prepended with 'q' for
    # historical reasons
    body = mk_body(
        tags=utils.get_tags(os_tid=tenant_id, q_sec_group_id=neutron_id),
        display_name=display_name,
        logical_port_ingress_rules=(
            hidden_rules['logical_port_ingress_rules']),
        logical_port_egress_rules=hidden_rules['logical_port_egress_rules']
    )
    rsp = nsxlib.do_request(HTTP_POST, path, body, cluster=cluster)
    if security_profile.get('name') == 'default':
        # If security group is default allow ip traffic between
        # members of the same security profile is allowed and ingress traffic
        # from the switch
        rules = {'logical_port_egress_rules': [{'ethertype': 'IPv4',
                                                'profile_uuid': rsp['uuid']},
                                               {'ethertype': 'IPv6',
                                                'profile_uuid': rsp['uuid']}],
                 'logical_port_ingress_rules': [{'ethertype': 'IPv4'},
                                                {'ethertype': 'IPv6'}]}

        update_security_group_rules(cluster, rsp['uuid'], rules)
    LOG.debug("Created Security Profile: %s", rsp)
    return rsp


def update_security_group_rules(cluster, spid, rules):
    path = "/ws.v1/security-profile/%s" % spid

    # Allow all dhcp responses in
    rules['logical_port_egress_rules'].append(
        {'ethertype': 'IPv4', 'protocol': constants.PROTO_NUM_UDP,
         'port_range_min': constants.DHCP_RESPONSE_PORT,
         'port_range_max': constants.DHCP_RESPONSE_PORT,
         'ip_prefix': '0.0.0.0/0'})
    # If there are no ingress rules add bunk rule to drop all ingress traffic
    if not rules['logical_port_ingress_rules']:
        rules['logical_port_ingress_rules'].append(
            {'ethertype': 'IPv4', 'ip_prefix': '127.0.0.1/32'})
    try:
        body = mk_body(
            logical_port_ingress_rules=summarize_security_group_rules(rules[
                'logical_port_ingress_rules']),
            logical_port_egress_rules=summarize_security_group_rules(rules[
                'logical_port_egress_rules']))
        rsp = nsxlib.do_request(HTTP_PUT, path, body, cluster=cluster)
    except exceptions.NotFound as e:
        LOG.error(nsxlib.format_exception("Unknown", e, locals()))
        #FIXME(salvatore-orlando): This should not raise NeutronException
        raise exceptions.NeutronException()
    LOG.debug("Updated Security Profile: %s", rsp)
    return rsp


def update_security_profile(cluster, spid, name):
    return nsxlib.do_request(
        HTTP_PUT,
        nsxlib._build_uri_path(SECPROF_RESOURCE, resource_id=spid),
        jsonutils.dumps({"display_name": utils.check_and_truncate(name)}),
        cluster=cluster)


def delete_security_profile(cluster, spid):
    path = "/ws.v1/security-profile/%s" % spid

    try:
        nsxlib.do_request(HTTP_DELETE, path, cluster=cluster)
    except exceptions.NotFound:
        with excutils.save_and_reraise_exception():
            # This is not necessarily an error condition
            LOG.warning("Unable to find security profile %s on NSX "
                        "backend", spid)


def summarize_security_group_rules(logical_port_rules):
    """
    Summarizes security group rules and remove duplicates. Given a set of
    arbitrary security group rules, determining the optimum (minimum) rule set
    is a complex (NP-hard) problem. This method does not attempt to obtain the
    optimum rules. Instead, it summarizes a set of common rule patterns.
    """

    # Remove port_range_min & port_range_max if it covers the entire port
    # range. Also, remove quad-zero default IPv4 and default IPv6 routes
    for rule in logical_port_rules:
        if ('port_range_min' in rule and 'port_range_max' in rule and
                rule['port_range_min'] <= 1 and
                rule['port_range_max'] == 65535):
            del rule['port_range_min']
            del rule['port_range_max']

        if ('ip_prefix' in rule and
                rule['ip_prefix'] in ['0.0.0.0/0', '::/0']):
            del rule['ip_prefix']

    # Remove duplicate rules. Loop through each rule rule_i and exclude a
    # rule if it is part of another rule.
    logical_port_rules_summarized = []
    for i in range(len(logical_port_rules)):
        for j in range(len(logical_port_rules)):
            if i != j:
                if is_sg_rules_identical(logical_port_rules[i],
                                         logical_port_rules[j]):
                    pass
                elif is_sg_rule_subset(logical_port_rules[i],
                                       logical_port_rules[j]):
                    break
        else:
            logical_port_rules_summarized.append(logical_port_rules[i])

    return logical_port_rules_summarized


def is_sg_rules_identical(sgr1, sgr2):
    """
    determines if security group rule sgr1 and sgr2 are identical
    """
    return (sgr1['ethertype'] == sgr2['ethertype'] and
            sgr1.get('protocol') == sgr2.get('protocol') and
            sgr1.get('port_range_min') == sgr2.get('port_range_min') and
            sgr1.get('port_range_max') == sgr2.get('port_range_max') and
            sgr1.get('ip_prefix') == sgr2.get('ip_prefix') and
            sgr1.get('profile_uuid') == sgr2.get('profile_uuid'))


def is_sg_rule_subset(sgr1, sgr2):
    """
    determine if security group rule sgr1 is a strict subset of sgr2
    """
    all_protocols = set(range(256))
    sgr1_protocols = {sgr1['protocol']} if 'protocol' in sgr1 else \
        all_protocols
    sgr2_protocols = {sgr2['protocol']} if 'protocol' in sgr2 else \
        all_protocols

    return (sgr1['ethertype'] == sgr2['ethertype'] and
            sgr1_protocols.issubset(sgr2_protocols) and
            sgr1.get('port_range_min', 0) >= sgr2.get('port_range_min', 0) and
            sgr1.get('port_range_max', 65535) <= sgr2.get('port_range_max',
                                                          65535) and
            (sgr2.get('ip_prefix') is None or
             sgr1.get('ip_prefix') == sgr2.get('prefix')) and
            (sgr2.get('profile_uuid') is None or
             sgr1.get('profile_uuid') == sgr2.get('profile_uuid')))
